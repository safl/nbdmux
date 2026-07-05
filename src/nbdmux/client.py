"""A tiny stdlib-only client for consuming an nbdmux daemon.

Lets a consumer (e.g. bty) register / list / unregister NBD exports
without reimplementing the HTTP control plane. The functions degrade
gracefully on an unreachable / timed-out daemon -- a caller can ``try /
except NbdmuxError`` to decide whether to surface the failure or fall
through to a no-cache path.

    from nbdmux import client

    client.add_export("debian-sysdev", "/var/lib/bty/live-images/abc.img")
    [...]
    for e in client.list_exports():
        print(e["name"], e["file"])

Authentication: when the daemon runs with ``NBDMUX_ADMIN_PASSWORD``
set (which the bty deploy always does), the write endpoints
(``add_export``, ``warm_export``, ``remove_export``) require the
caller to send the password as ``Authorization: Bearer <pw>``.
Pass ``password=`` on each write call, or set
``NBDMUX_ADMIN_PASSWORD`` in the caller's environment and the
client picks it up automatically. Read endpoints
(``list_exports``, ``is_healthy``) stay open and don't need it.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

__all__ = [
    "DEFAULT_TIMEOUT",
    "NbdmuxError",
    "add_export",
    "control_base",
    "is_healthy",
    "list_exports",
    "remove_export",
    "warm_export",
]

DEFAULT_TIMEOUT = 5.0  # seconds; never block the caller on a slow / unreachable daemon


class NbdmuxError(Exception):
    """Raised on a control-plane failure: network, HTTP error, parse error.

    Inherits from ``Exception`` (not ``OSError``) so callers can opt-
    into surfacing nbdmux failures distinctly from generic network
    errors. Callers that want to fall through silently on any failure
    catch ``Exception`` themselves.
    """


def control_base(server: str) -> str:
    """Normalise a server value to ``http://<host>:<port>``.

    Accepts ``host``, ``host:8082``, or ``http://host:8082``. The
    trailing slash is stripped. Mirrors ``withcache.client.cache_base``
    in shape so consumers configuring both services can use the same
    helper convention.
    """
    s = server.strip().rstrip("/")
    if "://" not in s:
        s = f"http://{s}"
    return s


def _resolve_password(password: str | None) -> str | None:
    """Return ``password`` if given, else fall back to
    ``$NBDMUX_ADMIN_PASSWORD``, else ``None``. Empty / whitespace
    values are treated as unset -- an empty Bearer token would
    round-trip to the daemon and get rejected on the constant-time
    compare, so short-circuit here."""
    if password:
        return password
    env = (os.environ.get("NBDMUX_ADMIN_PASSWORD") or "").strip()
    return env or None


def _request(
    method: str,
    server: str,
    path: str,
    body: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
    password: str | None = None,
) -> Any:
    url = f"{control_base(server)}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    resolved_pw = _resolve_password(password)
    if resolved_pw is not None:
        req.add_header("Authorization", f"Bearer {resolved_pw}")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 204:
                return None
            raw = resp.read()
            if not raw:
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        # Read the body for the operator-facing error detail; ignore
        # parse failures (some 4xx / 5xx responses don't carry JSON).
        try:
            payload = json.loads(exc.read() or b"{}")
            detail = payload.get("error") if isinstance(payload, dict) else None
        except (json.JSONDecodeError, ValueError):
            detail = None
        raise NbdmuxError(f"{method} {path} -> HTTP {exc.code}: {detail or exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NbdmuxError(f"{method} {path} -> {exc}") from exc
    except json.JSONDecodeError as exc:
        raise NbdmuxError(f"{method} {path} -> invalid JSON: {exc}") from exc


def add_export(
    name: str,
    file: str,
    *,
    readonly: bool = True,
    server: str = "http://localhost:8082",
    timeout: float = DEFAULT_TIMEOUT,
    password: str | None = None,
) -> dict[str, Any]:
    """Register a pre-warmed file as a named NBD export.

    ``name`` is the export name nbd-client connects to; ``file`` is an
    absolute path that the nbdmux daemon process can read. Idempotent:
    re-registering the same name replaces the mapping. The returned
    record lands at ``status='ready'`` immediately because no warming
    pipeline runs for this path.

    Returns the export record. Raises :class:`NbdmuxError` on any
    failure (including the daemon refusing the file because it does
    not exist on the daemon's filesystem).
    """
    return _request(
        "POST",
        server,
        "/exports",
        body={"name": name, "file": file, "readonly": readonly},
        timeout=timeout,
        password=password,
    )


def warm_export(
    name: str,
    src_url: str,
    *,
    format_hint: str | None = None,
    readonly: bool = True,
    server: str = "http://localhost:8082",
    timeout: float = DEFAULT_TIMEOUT,
    password: str | None = None,
) -> dict[str, Any]:
    """Enqueue a warm: nbdmux fetches ``src_url`` via the configured
    withcache, decompresses on the fly, and lands the raw .img under
    ``<images-dir>/<name>.img``. Returns immediately with the
    ``status='queued'`` record; caller polls :func:`list_exports`
    (or watches the dashboard) for progress / ready.

    ``format_hint`` overrides the decompressor selector if the URL's
    extension doesn't tell the story (``img`` / ``img.gz`` /
    ``img.zst`` / ``img.xz``). Default: auto-derive from the URL.
    Named ``format_hint`` (not ``format``) to avoid shadowing the
    builtin and to match the server-side slot in ``_detect_format``.

    Raises :class:`NbdmuxError` if ``NBDMUX_WITHCACHE_URL`` isn't
    configured on the daemon, or on any HTTP failure.
    """
    body: dict[str, Any] = {"name": name, "src_url": src_url, "readonly": readonly}
    if format_hint is not None:
        body["format"] = format_hint
    return _request("POST", server, "/exports", body=body, timeout=timeout, password=password)


def list_exports(
    server: str = "http://localhost:8082",
    timeout: float = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    """Return the current set of registered exports as a list of records.

    Raises :class:`NbdmuxError` on any failure.
    """
    return _request("GET", server, "/exports", timeout=timeout) or []


def remove_export(
    name: str,
    server: str = "http://localhost:8082",
    timeout: float = DEFAULT_TIMEOUT,
    password: str | None = None,
) -> None:
    """Unregister an export by name. 404 (no such export) is treated
    as success so the call is idempotent for the operator's "make sure
    this is gone" intent.

    Raises :class:`NbdmuxError` on transport failure but NOT on 404.
    """
    try:
        _request("DELETE", server, f"/exports/{name}", timeout=timeout, password=password)
    except NbdmuxError as exc:
        if "HTTP 404" in str(exc):
            return
        raise


def is_healthy(
    server: str = "http://localhost:8082",
    timeout: float = DEFAULT_TIMEOUT,
) -> bool:
    """True iff ``GET /healthz`` returns 200. Suitable for a startup probe.

    Direct urlopen (bypassing :func:`_request`) because the healthz
    response body is plain text, not JSON, and we don't care what's in
    it -- the status code is the whole signal.
    """
    url = f"{control_base(server)}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return bool(resp.status == 200)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        return False
