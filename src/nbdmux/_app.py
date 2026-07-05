"""FastAPI app factory for nbdmux (v0.3.0 port).

Replaces the stdlib ``http.server``-based ``server.py`` request
handler with a FastAPI application. :func:`create_app` returns a
FastAPI instance the caller mounts under whatever ASGI server it
picks -- uvicorn for the daemon (``server.main`` boots it via
:mod:`uvicorn`) and TestClient for tests.

Layout mirrors ``bty.web._app``. A ``lifespan`` hook starts the
Warmer thread + nbd-server subprocess on daemon startup and stops
them on shutdown; it fires only when ``run_lifecycle=True`` is
passed, so TestClient callers don't spawn threads or subprocesses.
"""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from starlette.middleware.sessions import SessionMiddleware

from . import __version__
from ._api import register_api_routes
from .server import Auth, Store, _detect_format, resolve_secret
from .server import _valid_export_name as _valid_export_name_local

_STATIC_DIR = Path(__file__).parent / "static"
_TEMPLATES_DIR = Path(__file__).parent / "_templates"

# Starlette's SessionMiddleware stores the flag under a namespaced
# key inside ``request.session`` (a dict-like), and the UI dependency
# reads that flag to gate authenticated routes. Matches the shape of
# bty's ``SESSION_AUTHED_KEY`` for cross-project consistency.
SESSION_AUTHED_KEY = "nbdmux_authed"


class NotAuthenticated(Exception):
    """Raised by :func:`require_ui_auth` when the request lacks an
    authed session. The exception handler redirects to ``/ui/login``.
    """


def _build_jinja(templates_dir: Path) -> Environment:
    """Configure the Jinja environment. Autoescape is on for all
    ``.html`` templates so operator-supplied strings can't inject
    markup. Mirrors bty's Environment shape."""
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env


class _NoopWarmer:
    """Stub :class:`~nbdmux.server.Warmer` for the FastAPI app that
    isn't yet the runtime daemon. The real Warmer thread starts
    from ``server.main()`` and drains queued warms out-of-process;
    inside the FastAPI TestClient path we accept enqueue calls but
    don't spawn a thread. When the port migrates the runtime, the
    lifespan hook will pass a real Warmer here."""

    def enqueue(self, name: str) -> None:  # pragma: no cover - stub
        del name


class _NoopNbdServer:
    """Stub :class:`~nbdmux.server.NbdServer` for the FastAPI app.
    Same reasoning as :class:`_NoopWarmer`: reload calls no-op so
    the JSON handlers can call ``nbd.reload(store.list_ready())``
    exactly like the pre-port code does, without launching an
    actual nbd-server subprocess in tests."""

    def reload(self, exports: list[Any]) -> None:  # pragma: no cover - stub
        del exports


def create_app(
    *,
    data_dir: str | os.PathLike[str],
    secret_key: bytes | None = None,
    store: Store | None = None,
    warmer: Any | None = None,
    nbd: Any | None = None,
    images_dir: str | os.PathLike[str] | None = None,
    nbd_port: int = 10809,
    run_lifecycle: bool = False,
) -> FastAPI:
    """Build the FastAPI application for the nbdmux control plane.

    ``data_dir`` is the persistent state directory (where the
    stdlib server writes ``state.db`` + ``session-secret``). We
    borrow ``resolve_secret`` from the legacy module so a running
    daemon and the ported UI share one signing key across the
    migration.

    ``secret_key`` overrides the persisted secret; tests pass a
    stable bytes value so cookies stay valid across the fixture's
    lifetime without touching the disk.
    """
    data_dir_str = str(data_dir)
    Path(data_dir_str).mkdir(parents=True, exist_ok=True)
    secret = secret_key or resolve_secret(data_dir_str)
    admin_password = os.environ.get("NBDMUX_ADMIN_PASSWORD") or None
    auth = Auth(secret=secret, password=admin_password)

    jinja = _build_jinja(_TEMPLATES_DIR)

    @contextlib.asynccontextmanager
    async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
        """Start/stop the Warmer thread + nbd-server subprocess.

        Fires only when ``run_lifecycle=True`` (the daemon path via
        :func:`server.main`). TestClient callers omit the flag so
        the fixture doesn't spawn threads or launch nbd-server.
        Resume-pending re-enqueues any rows the Warmer was
        mid-processing at the last shutdown so an operator restart
        picks up where the previous run left off."""
        if run_lifecycle:
            _app.state.nbd.start(_app.state.store.list_ready_exports())
            _app.state.warmer.start()
            # Resume rows that were mid-warm at the last shutdown; the
            # Warmer walks each through fetch -> decompress -> ready
            # in the same order the pre-port stdlib server did.
            for row in _app.state.store.list_pending_exports():
                _app.state.warmer.enqueue(row["name"])
            print(
                f"nbdmux: NBD tcp://:{_app.state.nbd_port}/ "
                f"data={_app.state.data_dir} "
                f"images={_app.state.images_dir}",
                file=sys.stderr,
                flush=True,
            )
        try:
            yield
        finally:
            if run_lifecycle:
                _app.state.warmer.stop()
                _app.state.nbd.stop()
                print("nbdmux: shut down", file=sys.stderr, flush=True)

    app = FastAPI(
        title="nbdmux",
        version=__version__,
        # OpenAPI is off by default: this is an operator control
        # plane, not a public API; the JSON routes are documented
        # in the client library. Turn on with a query flag in
        # dev if needed.
        docs_url=None,
        redoc_url=None,
        lifespan=_lifespan,
    )

    # SessionMiddleware signs a cookie so tests + the UI can share
    # one login flow. Cookie name matches the pre-port
    # ``nbdmux-token`` shape so a rolling deploy doesn't invalidate
    # existing browser sessions.
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret.decode("utf-8", errors="replace"),
        session_cookie="nbdmux-token",
        max_age=Auth.MAX_AGE,
        same_site="lax",
        https_only=False,
    )

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Runtime objects the JSON handlers reach via ``request.app.state``.
    # Store writes a real state.db under data_dir so tests exercise the
    # SQLite path unchanged. Warmer + NbdServer default to no-op stubs
    # because the runtime daemon (still stdlib server.py) owns the
    # actual thread + subprocess. When the port migrates the runtime,
    # a lifespan hook will hand real instances in here.
    app.state.store = store if store is not None else Store(data_dir_str)
    app.state.warmer = warmer if warmer is not None else _NoopWarmer()
    app.state.nbd = nbd if nbd is not None else _NoopNbdServer()
    app.state.images_dir = (
        str(images_dir) if images_dir is not None else str(Path(data_dir_str) / "images")
    )
    app.state.data_dir = data_dir_str
    app.state.nbd_port = nbd_port
    Path(app.state.images_dir).mkdir(parents=True, exist_ok=True)

    register_api_routes(app, auth=auth, session_authed_key=SESSION_AUTHED_KEY)

    def render(name: str, request: Request, **ctx: Any) -> HTMLResponse:
        """Render a Jinja template + always-injected context.

        Mirrors :func:`bty.web._ui.render`: version + logged_in +
        nav_active are context vars every template can rely on.
        """
        ctx.setdefault("version", __version__)
        # ``logged_in`` gates the nav-btns + user-bar in the layout.
        # Auth-disabled deploys (open-mode LAN sidecar) treat every
        # request as authed; there's no login flow so hiding the nav
        # would leave the operator stuck on a chromeless page. Auth-
        # enabled deploys defer to the session flag.
        ctx.setdefault(
            "logged_in",
            (not auth.enabled) or bool(request.session.get(SESSION_AUTHED_KEY)),
        )
        path_parts = request.url.path.strip("/").split("/")
        nav_active = path_parts[1] if len(path_parts) > 1 and path_parts[0] == "ui" else None
        ctx.setdefault("nav_active", nav_active)
        template = jinja.get_template(name)
        return HTMLResponse(template.render(**ctx))

    def require_ui_auth(request: Request) -> None:
        """FastAPI dependency: require an authed session for UI
        routes. Raises :class:`NotAuthenticated`, which the
        exception handler turns into a 303 to ``/ui/login``."""
        if not auth.enabled:
            # No password configured: every /ui/* route is public.
            # Same as the pre-port behaviour when
            # ``NBDMUX_ADMIN_PASSWORD`` is unset.
            return
        if not request.session.get(SESSION_AUTHED_KEY):
            raise NotAuthenticated()

    @app.exception_handler(NotAuthenticated)
    async def _not_authed_handler(_request: Request, _exc: NotAuthenticated) -> RedirectResponse:
        return RedirectResponse(url="/ui/login", status_code=status.HTTP_303_SEE_OTHER)

    # ---------- Health --------------------------------------------------

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        """Liveness probe. Returns 200 + a static JSON body so the
        sibling services' probes (bty-web's Settings > Ramboot
        reachability pill, container orchestrators) can key on the
        HTTP status. Same shape the pre-port stdlib server emitted."""
        return JSONResponse({"status": "ok", "service": "nbdmux", "version": __version__})

    # ---------- Login / logout ------------------------------------------

    @app.get("/ui/login", response_class=HTMLResponse)
    def ui_login_form(request: Request, error: str | None = None) -> HTMLResponse:
        """Login form. If the operator is already authed, redirect
        to the Exports view rather than showing the form."""
        if request.session.get(SESSION_AUTHED_KEY):
            return RedirectResponse(url="/ui/exports", status_code=status.HTTP_303_SEE_OTHER)  # type: ignore[return-value]
        return render("ui/login.html", request, error=error)

    @app.post("/ui/login")
    def ui_login_submit(request: Request, password: str = Form(...)) -> Any:
        """Verify the password + mint the session flag. On success
        redirect to ``/ui/exports``; on failure re-render the form
        with an error message."""
        if not auth.check_password(password):
            return render("ui/login.html", request, error="Invalid password.")
        request.session[SESSION_AUTHED_KEY] = True
        return RedirectResponse(url="/ui/exports", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/ui/logout")
    def ui_logout(request: Request) -> RedirectResponse:
        request.session.clear()
        return RedirectResponse(url="/ui/login", status_code=status.HTTP_303_SEE_OTHER)

    # ---------- Root redirect + exports placeholder ---------------------

    @app.get("/")
    def _root() -> RedirectResponse:
        return RedirectResponse(url="/ui/exports", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/ui/exports", response_class=HTMLResponse)
    def ui_exports(
        request: Request,
        error: str | None = None,
        _auth_check: None = Depends(require_ui_auth),
    ) -> HTMLResponse:
        """The operator dashboard: one row per registered export
        with status pill + progress bar. Reads ``app.state.store``
        (same instance the JSON API mutates) and the withcache
        URL for the subnav's "warms via ..." indicator. The
        ``?error=`` query param carries the flash from a failed
        admin-form submission back into the render context so the
        redirect target shows the reason inline."""
        exports = app.state.store.list_exports()
        withcache_url = (os.environ.get("NBDMUX_WITHCACHE_URL") or "").strip() or None
        return render(
            "ui/exports.html",
            request,
            nav_active="exports",
            exports=exports,
            withcache_url=withcache_url,
            flash=error,
            flash_kind="danger" if error else None,
        )

    # ---------- Admin form endpoints ------------------------------------
    #
    # Form-encoded siblings of the JSON /exports control plane so
    # the operator UI can create + delete exports via <form> POST
    # without needing to reach into the JSON API from JavaScript.
    # Both redirect back to /ui/exports with ``?error=<msg>`` on
    # validation failure so the render shows the reason inline.

    @app.post("/admin/create_export")
    def ui_admin_create_export(
        request: Request,
        name: str = Form(...),
        src_url: str = Form(...),
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """UI create-export: name + src_url form -> forwards through
        the same warm-via-withcache logic ``POST /exports`` uses.
        Pre-warmed ``{name, file}`` exports don't have a browser
        form (operators pre-placing an image on disk are already
        shelled in; the JSON API is the natural entry) so this
        handler only supports the warm shape.

        On success, 303 to /ui/exports so the browser flips to GET
        and the dashboard shows the newly queued row. On any
        validation failure, 303 to /ui/exports with an ``?error=``
        query so the operator sees why nothing was created."""
        del request  # accepted for FastAPI DI symmetry; unused here
        n = (name or "").strip()
        s = (src_url or "").strip()
        if not n or not _valid_export_name_local(n):
            return _redirect_with_error("name: invalid; alnum-leading, alnum/./-/_ only, max 64")
        if not s:
            return _redirect_with_error("src_url: non-empty string required")
        if (os.environ.get("NBDMUX_WITHCACHE_URL") or "").strip() == "":
            return _redirect_with_error(
                "NBDMUX_WITHCACHE_URL is not configured; the warm pipeline "
                "needs a withcache upstream. Set the env var and restart."
            )
        format_hint = _detect_format(s, None)
        dest = os.path.join(str(app.state.images_dir), f"{n}.img")
        app.state.store.upsert_export(
            n,
            dest,
            readonly=True,
            status="queued",
            src_url=s,
            format=format_hint,
        )
        app.state.warmer.enqueue(n)
        return RedirectResponse(url="/ui/exports", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/admin/delete_export/{name}")
    def ui_admin_delete_export(
        name: str,
        request: Request,
        _auth_check: None = Depends(require_ui_auth),
    ) -> RedirectResponse:
        """UI delete-export: form-encoded POST to the same underlying
        delete-export flow the JSON DELETE /exports/{name} runs.
        Idempotent from the operator's perspective (a repeat click
        on a row that already vanished still lands on /ui/exports;
        the row just isn't there).

        Warm-created rows (``src_url`` set) also unlink the on-disk
        .img the daemon owns; pre-warmed rows leave their file alone
        because the operator placed it there. Same file-cleanup
        branch the JSON DELETE handler uses."""
        row = app.state.store.get_export(name)
        existed = app.state.store.delete_export(name)
        app.state.nbd.reload(app.state.store.list_ready_exports())
        if existed and row and row.get("src_url"):
            path = row.get("file") or ""
            if path:
                with contextlib.suppress(FileNotFoundError, OSError):
                    Path(path).unlink()
        return RedirectResponse(url="/ui/exports", status_code=status.HTTP_303_SEE_OTHER)

    def _redirect_with_error(msg: str) -> RedirectResponse:
        """Build a 303 back to /ui/exports carrying ``?error=<msg>``
        so the render context shows the reason inline. Encoded with
        ``urllib.parse.quote`` so message text with reserved chars
        can't break the URL shape."""
        import urllib.parse

        return RedirectResponse(
            url="/ui/exports?error=" + urllib.parse.quote(msg, safe=""),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/ui/settings", response_class=HTMLResponse)
    def ui_settings(
        request: Request,
        _auth_check: None = Depends(require_ui_auth),
    ) -> HTMLResponse:
        """Effective-configuration view. Read-only for this pass -- all
        knobs still come from CLI flags or environment at startup.
        Follow-up commits add form-driven persistence for the
        runtime-tunable ones (withcache URL, log level, admin
        password rotation) mirroring bty's Override / Effective /
        Default three-column pattern."""
        withcache_url = (os.environ.get("NBDMUX_WITHCACHE_URL") or "").strip() or None
        session_secret_from_env = bool((os.environ.get("NBDMUX_SESSION_SECRET") or "").strip())
        return render(
            "ui/settings.html",
            request,
            nav_active="settings",
            data_dir=data_dir_str,
            images_dir=str(app.state.images_dir),
            withcache_url=withcache_url,
            # nbd-server port threaded through from ``create_app``
            # (default 10809; CLI ``--nbd-port`` on ``server.main``
            # overrides). Reads from app.state so a rolling redeploy
            # sees the new value on the next render.
            nbd_port=app.state.nbd_port,
            auth_enabled=auth.enabled,
            session_secret_from_env=session_secret_from_env,
        )

    return app


def _bind_callable(app: FastAPI, name: str, fn: Callable[..., Any]) -> None:
    """Attach an operational helper to the app's state so tests can
    reach into it via ``client.app.state.<name>``. Kept simple; the
    lifespan-driven wiring for the Warmer + nbd-server subprocess
    lands with the full port."""
    setattr(app.state, name, fn)
    raise NotImplementedError  # placeholder; called from follow-up code path
