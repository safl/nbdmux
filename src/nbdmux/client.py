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
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

__all__ = [
    "DEFAULT_TIMEOUT",
    "NbdmuxError",
    "add_export",
    "control_base",
    "list_exports",
    "remove_export",
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

    Accepts ``host``, ``host:4040``, or ``http://host:4040``. The
    trailing slash is stripped. Mirrors ``withcache.client.cache_base``
    in shape so consumers configuring both services can use the same
    helper convention.
    """
    s = server.strip().rstrip("/")
    if "://" not in s:
        s = f"http://{s}"
    return s


def _request(
    method: str,
    server: str,
    path: str,
    body: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
) -> Any:
    url = f"{control_base(server)}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
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
    server: str = "http://localhost:4040",
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Register ``file`` as a named NBD export.

    ``name`` is the export name nbd-client will pass via ``-name``;
    ``file`` is an absolute path that the nbdmux daemon process can
    read. Idempotent: re-registering the same name with the same file
    is a no-op (200 OK); re-registering with a different file replaces
    the mapping.

    Returns the export record (``{"name", "file", "readonly"}``).
    Raises :class:`NbdmuxError` on any failure.
    """
    return _request(
        "POST",
        server,
        "/exports",
        body={"name": name, "file": file, "readonly": readonly},
        timeout=timeout,
    )


def list_exports(
    server: str = "http://localhost:4040",
    timeout: float = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    """Return the current set of registered exports as a list of records.

    Raises :class:`NbdmuxError` on any failure.
    """
    return _request("GET", server, "/exports", timeout=timeout) or []


def remove_export(
    name: str,
    server: str = "http://localhost:4040",
    timeout: float = DEFAULT_TIMEOUT,
) -> None:
    """Unregister an export by name. 404 (no such export) is treated
    as success so the call is idempotent for the operator's "make sure
    this is gone" intent.

    Raises :class:`NbdmuxError` on transport failure but NOT on 404.
    """
    try:
        _request("DELETE", server, f"/exports/{name}", timeout=timeout)
    except NbdmuxError as exc:
        if "HTTP 404" in str(exc):
            return
        raise


def is_healthy(
    server: str = "http://localhost:4040",
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
