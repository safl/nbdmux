"""FastAPI app factory for nbdmux (v0.3.0 port).

Replaces the stdlib ``http.server``-based ``server.py`` request
handler with a FastAPI application. The port is intentionally
staged: this module currently hosts only the scaffolding (Jinja +
static + session middleware + healthz + login) so a TestClient-
backed test can prove the pattern works. The JSON control-plane
endpoints (``/exports`` verbs), the operator Exports page, the
Warmer thread lifespan wiring, and the new Settings page migrate
in follow-up commits.

The stdlib ``server.py`` remains the runtime daemon during the
port; ``main()`` there is unchanged. That keeps the existing 100
tests green while this file lands and gets iterated.

Layout mirrors ``bty.web._app``: :func:`create_app` returns a
FastAPI instance the caller mounts under whatever ASGI server it
picks (uvicorn for production, TestClient for tests).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from starlette.middleware.sessions import SessionMiddleware

from . import __version__
from .server import Auth, resolve_secret

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


def create_app(
    *,
    data_dir: str | os.PathLike[str],
    secret_key: bytes | None = None,
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
    app = FastAPI(
        title="nbdmux",
        version=__version__,
        # OpenAPI is off by default: this is an operator control
        # plane, not a public API; the JSON routes are documented
        # in the client library. Turn on with a query flag in
        # dev if needed.
        docs_url=None,
        redoc_url=None,
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

    def render(name: str, request: Request, **ctx: Any) -> HTMLResponse:
        """Render a Jinja template + always-injected context.

        Mirrors :func:`bty.web._ui.render`: version + logged_in +
        nav_active are context vars every template can rely on.
        """
        ctx.setdefault("version", __version__)
        ctx.setdefault("logged_in", bool(request.session.get(SESSION_AUTHED_KEY)))
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
        _auth_check: None = Depends(require_ui_auth),
    ) -> HTMLResponse:
        """Exports view -- currently a scaffolding placeholder while
        the port is in flight. The stdlib server's Exports page
        remains the live surface at ``server.py``; this stub proves
        the auth gate + layout render. Real content lands in a
        follow-up commit."""
        return render(
            "ui/_layout.html",
            request,
            nav_active="exports",
        )

    return app


def _bind_callable(app: FastAPI, name: str, fn: Callable[..., Any]) -> None:
    """Attach an operational helper to the app's state so tests can
    reach into it via ``client.app.state.<name>``. Kept simple; the
    lifespan-driven wiring for the Warmer + nbd-server subprocess
    lands with the full port."""
    setattr(app.state, name, fn)
    raise NotImplementedError  # placeholder; called from follow-up code path
