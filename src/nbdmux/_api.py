"""JSON control-plane routes for the nbdmux FastAPI app.

Ports the ``/exports`` control endpoints from the stdlib
``server.py`` handler with byte-identical JSON shape so downstream
consumers (bty at ``bty.web._ramboot.status_by_ref``, the
``nbdmux.client`` library) don't need to change. The Store /
Warmer / NbdServer implementations remain in ``server.py`` for
now; this module imports them and delegates.

Wire-contract invariants pinned:

- ``GET /exports`` returns a JSON array of records, each with the
  keys :func:`nbdmux.server._row_to_export` emits (``name``,
  ``status``, ``file``, ``readonly``, ``src_url``, ``format``,
  ``bytes_total``, ``bytes_done``, ``progress``, ``enqueued_at``,
  ``started_at``, ``completed_at``, ``updated_at``, ``error``).
- ``POST /exports`` accepts the same two shapes:
  ``{name, file, readonly?}`` (pre-warmed) or
  ``{name, src_url, format?, readonly?}`` (warm-via-withcache).
- ``DELETE /exports/{name}`` returns 204 on success, 404 when the
  name is unknown (the client-side wrapper treats 404 as no-op).
- ``GET /export/{name}`` returns the single record or 404.

Auth gate: control endpoints are open when ``NBDMUX_ADMIN_PASSWORD``
is unset (single-tenant LAN deploy), and require a valid session
cookie otherwise. Read routes (``GET /exports``, ``GET /healthz``)
stay open regardless -- bty polls ``list_exports`` from a sibling
container without minting a session.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from .server import Auth, _detect_format, _valid_export_name


class _StoreProto:
    """Structural interface for the pieces of ``server.Store`` the
    JSON handlers touch. Kept as a documentation aid; the actual
    instance handed in is ``server.Store``."""

    def upsert_export(self, *args: Any, **kwargs: Any) -> dict[str, Any]: ...
    def get_export(self, name: str) -> dict[str, Any] | None: ...
    def delete_export(self, name: str) -> bool: ...
    def list_exports(self) -> list[dict[str, Any]]: ...
    def list_ready_exports(self) -> list[dict[str, Any]]: ...


class _WarmerProto:
    """Minimal Warmer surface the ``src_url`` POST path needs."""

    def enqueue(self, name: str) -> None: ...


class _NbdProto:
    """Minimal NbdServer surface the mutation routes need."""

    def reload(self, exports: list[dict[str, Any]]) -> None: ...


def register_api_routes(
    app: FastAPI,
    *,
    auth: Auth,
    session_authed_key: str,
) -> None:
    """Attach the JSON control-plane routes to ``app``.

    Runtime objects (``store``, ``warmer``, ``nbd``, ``images_dir``)
    are read from ``app.state`` at request time so tests can swap
    them in a fixture without recreating the app.
    """

    def _get_store(app_: FastAPI) -> _StoreProto:
        return app_.state.store  # type: ignore[no-any-return]

    def _get_warmer(app_: FastAPI) -> _WarmerProto:
        return app_.state.warmer  # type: ignore[no-any-return]

    def _get_nbd(app_: FastAPI) -> _NbdProto:
        return app_.state.nbd  # type: ignore[no-any-return]

    def _get_images_dir(app_: FastAPI) -> str:
        return str(app_.state.images_dir)

    def control_authed(request: Request) -> None:
        """Auth dependency for the mutation routes.

        - No password configured (``auth.enabled = False``): every
          route is open (single-tenant LAN deploy).
        - Password configured + session cookie present: OK.
        - Password configured + no session: 401 with a JSON body
          (not a redirect -- these routes are JSON, not UI).
        """
        if not auth.enabled:
            return
        if not request.session.get(session_authed_key):
            raise HTTPException(status_code=401, detail="auth required")

    # ---------- GET /exports (open, no auth) ------------------------------

    @app.get("/exports", response_model=None)
    def list_exports(request: Request) -> list[dict[str, Any]]:
        """Return every registered export as a list of records. Open
        route: bty polls this from a sibling container without a
        session. No pagination -- the export set is small (dozens
        at most) and consumers scan the full list to find one by
        name."""
        return _get_store(request.app).list_exports()

    @app.get("/export/{name}", response_model=None)
    def get_export(name: str, request: Request) -> dict[str, Any]:
        """Return a single export record, or 404 when the name is
        unknown. No bty caller uses it today; kept for the client
        library + operator curl surface."""
        record = _get_store(request.app).get_export(name)
        if record is None:
            raise HTTPException(status_code=404, detail=f"no export named {name!r}")
        return record

    # ---------- POST /exports (auth-gated) --------------------------------

    @app.post("/exports", response_model=None)
    def post_export(
        request: Request,
        body: dict[str, Any],
        _auth_check: None = Depends(control_authed),
    ) -> JSONResponse:
        """Register a pre-warmed export or enqueue a warm.

        Two body shapes accepted (exactly one of ``file`` / ``src_url``):

        - ``{name, file, readonly?}``: ``file`` is an absolute path
          that already exists on disk; the row lands at
          ``status='ready'`` and nbd-server picks it up on the next
          reload.
        - ``{name, src_url, format?, readonly?}``: nbdmux allocates
          ``<images-dir>/<name>.img``, records ``status='queued'``,
          and hands off to the Warmer. ``$NBDMUX_WITHCACHE_URL``
          must be set (nbdmux only warms via withcache).

        Validation errors return HTTP 400 with a JSON body; the
        client library at ``nbdmux.client.warm_export`` catches by
        status code.
        """
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object")

        name = body.get("name")
        path = body.get("file")
        src_url = body.get("src_url")
        format_override = body.get("format")
        readonly = bool(body.get("readonly", True))

        if not isinstance(name, str) or not name.strip():
            raise HTTPException(status_code=400, detail="name: non-empty string required")
        if not _valid_export_name(name):
            raise HTTPException(
                status_code=400,
                detail=(
                    "name: alnum-leading, alnum/./-/_ only, max 64 chars "
                    "(constrained so it can't corrupt nbd-server.conf sections)"
                ),
            )
        if (path is None) == (src_url is None):
            raise HTTPException(
                status_code=400, detail="exactly one of {file, src_url} must be set"
            )

        store = _get_store(request.app)
        nbd = _get_nbd(request.app)

        if path is not None:
            if not isinstance(path, str) or not os.path.isabs(path):
                raise HTTPException(status_code=400, detail="file: absolute path required")
            if not os.path.isfile(path):
                raise HTTPException(status_code=400, detail=f"file: not found: {path}")
            record = store.upsert_export(name, path, readonly=readonly, status="ready")
            nbd.reload(store.list_ready_exports())
            return JSONResponse(status_code=200, content=record)

        if not isinstance(src_url, str) or not src_url.strip():
            raise HTTPException(status_code=400, detail="src_url: non-empty string required")
        if (os.environ.get("NBDMUX_WITHCACHE_URL") or "").strip() == "":
            raise HTTPException(
                status_code=400,
                detail=(
                    "NBDMUX_WITHCACHE_URL is not configured; nbdmux only warms via "
                    "withcache. Set the env var or pre-populate the file on disk "
                    "and POST {name, file}."
                ),
            )
        format_hint = _detect_format(src_url, format_override)
        dest = os.path.join(_get_images_dir(request.app), f"{name}.img")
        record = store.upsert_export(
            name,
            dest,
            readonly=readonly,
            status="queued",
            src_url=src_url,
            format=format_hint,
        )
        _get_warmer(request.app).enqueue(name)
        return JSONResponse(status_code=200, content=record)

    # ---------- DELETE /exports/{name} ------------------------------------

    @app.delete("/exports/{name}")
    def delete_export(
        name: str, request: Request, _auth_check: None = Depends(control_authed)
    ) -> Response:
        """Unregister an export by name. Idempotent from the client's
        perspective: :func:`nbdmux.client.remove_export` collapses
        the 404 into a no-op for the operator's "make sure this is
        gone" intent.

        Warm-created exports (rows with ``src_url``) also unlink the
        on-disk .img so the images-dir doesn't accumulate stale
        content. Pre-warmed exports (rows without ``src_url``) leave
        the file alone -- the operator put it there, we don't own it.
        """
        store = _get_store(request.app)
        nbd = _get_nbd(request.app)

        # Read the row before dropping it so the unlink branch below
        # sees the original ``src_url`` + ``file``; delete_export()
        # removes the row before we can inspect it.
        row = store.get_export(name)
        existed = store.delete_export(name)
        nbd.reload(store.list_ready_exports())
        if existed and row and row.get("src_url"):
            path = row.get("file") or ""
            if path:
                with contextlib.suppress(FileNotFoundError, OSError):
                    Path(path).unlink()
        if existed:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        return Response(status_code=status.HTTP_404_NOT_FOUND)
