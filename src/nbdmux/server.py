"""nbdmux daemon -- HTTP control plane + nbd-server subprocess management.

One Python process; one supervised ``nbd-server`` child; a SQLite
state.db tracking registered exports so a daemon restart restores them.

Layout mirrors withcache's ``server.py`` so reviewers move between the
two by muscle memory:

- ``Store``: SQLite-backed exports table, ``record_export`` / ``delete_export``
  / ``list_exports``. Single ``state.db`` under ``--data-dir``.
- ``Auth``: server-signed HMAC cookie, ``NBDMUX_ADMIN_PASSWORD`` env gate.
- ``NbdServer``: writes nbd-server's INI config and supervises the
  subprocess; SIGHUP on every export-set change to reload without
  dropping in-flight connections.
- ``Handler``: ``http.server.BaseHTTPRequestHandler`` routing the four
  HTTP control endpoints + the operator dashboard.

Stdlib only. The system-level dependency is ``nbd-server``
(Debian / Ubuntu: ``apt install nbd-server``; Fedora: ``dnf install nbd``).
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import html
import http.cookies
import http.server
import json
import os
import secrets
import signal
import socketserver
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, ClassVar

from . import __version__

USER_AGENT = f"nbdmux/{__version__}"
_DB_WRITE_LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Auth -- server-signed session cookie, password gate (withcache-pattern)
# --------------------------------------------------------------------------
def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def resolve_secret(data_dir: str) -> bytes:
    """``$NBDMUX_SESSION_SECRET`` if set + non-empty, else a random key
    persisted to ``<data-dir>/session-secret`` so cookies survive restarts.
    A blank env value must NOT silently weaken signing."""
    env = (os.environ.get("NBDMUX_SESSION_SECRET") or "").strip()
    if env:
        return env.encode("utf-8")
    path = os.path.join(data_dir, "session-secret")
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read().strip()
        if data:
            return data
    secret = secrets.token_hex(32).encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(secret)
    return secret


class Auth:
    COOKIE = "nbdmux-token"
    MAX_AGE = 7 * 24 * 3600  # cookie lifetime, seconds

    def __init__(self, secret: bytes, password: str | None):
        self.secret = secret
        self.password = password or None

    @property
    def enabled(self) -> bool:
        return self.password is not None

    def _sign(self, payload_b64: str) -> str:
        mac = hmac.new(self.secret, payload_b64.encode("ascii"), hashlib.sha256)
        return _b64e(mac.digest())

    def make_token(self) -> str:
        payload = _b64e(json.dumps({"a": 1, "iat": int(time.time())}).encode())
        return f"{payload}.{self._sign(payload)}"

    def valid(self, token: str) -> bool:
        try:
            payload, sig = token.split(".", 1)
            if not hmac.compare_digest(sig, self._sign(payload)):
                return False
            data = json.loads(_b64d(payload))
            iat = int(data.get("iat", 0))
            return time.time() - iat < self.MAX_AGE
        except (ValueError, json.JSONDecodeError, KeyError):
            return False

    def check_password(self, pw: str) -> bool:
        if not self.password:
            return False  # auth disabled = no password check passes
        return hmac.compare_digest(pw.encode("utf-8"), self.password.encode("utf-8"))


# --------------------------------------------------------------------------
# Store -- SQLite-backed exports table
# --------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS exports (
    name        TEXT PRIMARY KEY,
    file        TEXT NOT NULL,
    readonly    INTEGER NOT NULL DEFAULT 1,
    added_at    TEXT NOT NULL
);
"""


class Store:
    """Single-file SQLite store for the registered exports.

    Schema is one table. WAL is fine here but we don't bother since
    writes are rare (only on operator/bty register/unregister) and
    reads are HTTP-handler-scoped; the global ``_DB_WRITE_LOCK``
    serialises the writes.
    """

    def __init__(self, data_dir: str):
        os.makedirs(data_dir, exist_ok=True)
        self.db_path = os.path.join(data_dir, "state.db")
        with self.conn() as c:
            c.executescript(_SCHEMA)

    def conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db_path, isolation_level=None)
        c.row_factory = sqlite3.Row
        return c

    def record_export(self, name: str, file: str, readonly: bool = True) -> dict[str, Any]:
        with _DB_WRITE_LOCK, self.conn() as c:
            c.execute(
                "INSERT INTO exports (name, file, readonly, added_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET file=excluded.file, "
                "readonly=excluded.readonly, added_at=excluded.added_at",
                (name, file, 1 if readonly else 0, now_iso()),
            )
        return {"name": name, "file": file, "readonly": readonly}

    def delete_export(self, name: str) -> bool:
        with _DB_WRITE_LOCK, self.conn() as c:
            cur = c.execute("DELETE FROM exports WHERE name=?", (name,))
            return cur.rowcount > 0

    def list_exports(self) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT name, file, readonly, added_at FROM exports ORDER BY name"
            ).fetchall()
        return [
            {
                "name": r["name"],
                "file": r["file"],
                "readonly": bool(r["readonly"]),
                "added_at": r["added_at"],
            }
            for r in rows
        ]


# --------------------------------------------------------------------------
# NbdServer -- nbd-server subprocess + INI config supervision
# --------------------------------------------------------------------------
class NbdServer:
    """Manages the nbd-server child and its INI config file.

    nbd-server (from the classical ``nbd`` project) reads exports from
    a config file with one ``[name]`` section per export. SIGHUP makes
    the running daemon reload the config without dropping live
    connections, so we rewrite the file and signal on every change.

    The config file lives under ``--data-dir`` so ``data-dir/`` is the
    one mount/bind point a container deploy needs to persist.
    """

    def __init__(
        self,
        data_dir: str,
        port: int,
        bind: str,
        nbd_server_bin: str = "nbd-server",
        pid_file: str | None = None,
    ):
        self.data_dir = data_dir
        self.config_path = os.path.join(data_dir, "nbd-server.conf")
        self.pid_file = pid_file or os.path.join(data_dir, "nbd-server.pid")
        self.port = port
        self.bind = bind
        self.bin = nbd_server_bin
        self._proc: subprocess.Popen[bytes] | None = None
        self._lock = threading.Lock()

    def _render_config(self, exports: list[dict[str, Any]]) -> str:
        # nbd-server INI: [generic] for daemon-wide knobs, then one
        # [<name>] section per export. ``user`` / ``group`` left
        # unset -- the daemon runs as whatever uid started it (the
        # container's nbdmux user). ``listenaddr`` / ``port`` pin the
        # listening socket explicitly so a config change doesn't move
        # the daemon by accident.
        lines = [
            "[generic]",
            f"    port = {self.port}",
            f"    listenaddr = {self.bind}",
            f"    pid_file = {self.pid_file}",
            "    allowlist = false",
            "",
        ]
        for e in exports:
            lines.append(f"[{e['name']}]")
            lines.append(f"    exportname = {e['file']}")
            if e.get("readonly", True):
                lines.append("    readonly = true")
            lines.append("")
        return "\n".join(lines)

    def write_config(self, exports: list[dict[str, Any]]) -> None:
        """Atomically rewrite the config file."""
        body = self._render_config(exports)
        tmp = self.config_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(body)
        os.replace(tmp, self.config_path)

    def start(self, exports: list[dict[str, Any]]) -> None:
        """Spawn nbd-server in foreground mode. Idempotent."""
        with self._lock:
            if self._proc and self._proc.poll() is None:
                return
            self.write_config(exports)
            # ``-d`` runs nbd-server in foreground (don't fork). We
            # supervise the subprocess directly, so an early exit is
            # observable via ``poll()`` rather than orphaned.
            self._proc = subprocess.Popen(
                [self.bin, "-d", "-C", self.config_path],
                stdout=sys.stderr,  # mingle with nbdmux's own logs
                stderr=sys.stderr,
            )
            # Give the child a moment to bind the port or fail loudly.
            time.sleep(0.2)
            if self._proc.poll() is not None:
                rc = self._proc.returncode
                self._proc = None
                raise RuntimeError(
                    f"nbd-server exited immediately (rc={rc}); "
                    f"check {self.config_path} and that the binary is installed"
                )

    def reload(self, exports: list[dict[str, Any]]) -> None:
        """Rewrite the config and SIGHUP the running daemon."""
        with self._lock:
            self.write_config(exports)
            if self._proc and self._proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    self._proc.send_signal(signal.SIGHUP)

    def stop(self) -> None:
        with self._lock:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    self._proc.wait(timeout=3)
                if self._proc.poll() is None:
                    self._proc.kill()
            self._proc = None

    def is_running(self) -> bool:
        return bool(self._proc and self._proc.poll() is None)


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"nbdmux/{__version__}"
    protocol_version = "HTTP/1.1"

    JSON_ROUTES: ClassVar[set[str]] = {
        "/exports",
        "/healthz",
    }

    @property
    def store(self) -> Store:
        return self.server.store  # type: ignore[attr-defined]

    @property
    def auth(self) -> Auth:
        return self.server.auth  # type: ignore[attr-defined]

    @property
    def nbd(self) -> NbdServer:
        return self.server.nbd  # type: ignore[attr-defined]

    @property
    def nbd_port(self) -> int:
        return self.server.nbd_port  # type: ignore[attr-defined]

    def log_message(self, format, *args):  # quieter, single-line
        print(f"{self.address_string()} - {format % args}", flush=True)

    # -- routing -----------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/healthz":
            self.send_text(200, "ok\n")
        elif parsed.path == "/exports":
            self.send_json(200, self.store.list_exports())
        elif parsed.path == "/ui/login":
            self.handle_login_form()
        elif parsed.path == "/":
            if self.auth.enabled and not self.is_authed():
                self.redirect("/ui/login")
            else:
                self.send_html(200, self.render_dash())
        else:
            self.send_text(404, "not found\n")

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/exports":
            if not self._control_authed():
                self.send_json(401, {"error": "auth required"})
                return
            self.handle_post_export()
        elif parsed.path == "/ui/login":
            self.handle_login_submit()
        else:
            self.send_text(404, "not found\n")

    def do_DELETE(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path.startswith("/exports/"):
            if not self._control_authed():
                self.send_json(401, {"error": "auth required"})
                return
            name = urllib.parse.unquote(parsed.path[len("/exports/") :])
            existed = self.store.delete_export(name)
            self.nbd.reload(self.store.list_exports())
            self.send_response(204 if existed else 404)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_text(404, "not found\n")

    # -- control endpoints -------------------------------------------------
    def _control_authed(self) -> bool:
        """The control endpoints accept either a session cookie (UI
        callers) or an unauthenticated request when ``$NBDMUX_ADMIN_
        PASSWORD`` is unset (open mode). bty connecting from another
        container falls in the latter bucket; operators relying on the
        port being LAN-only get to skip the auth dance."""
        if not self.auth.enabled:
            return True
        return self.is_authed()

    def handle_post_export(self):
        body = self._read_json()
        if not isinstance(body, dict):
            self.send_json(400, {"error": "body must be a JSON object"})
            return
        name = body.get("name")
        path = body.get("file")
        readonly = bool(body.get("readonly", True))
        if not isinstance(name, str) or not name.strip():
            self.send_json(400, {"error": "name: non-empty string required"})
            return
        if "/" in name or name.startswith(".") or len(name) > 64:
            # nbd-server section names get used verbatim; reject
            # anything that could escape the INI or trip the daemon.
            self.send_json(400, {"error": "name: must be a short identifier with no slashes"})
            return
        if not isinstance(path, str) or not os.path.isabs(path):
            self.send_json(400, {"error": "file: absolute path required"})
            return
        if not os.path.isfile(path):
            self.send_json(400, {"error": f"file: not found: {path}"})
            return
        record = self.store.record_export(name, path, readonly=readonly)
        self.nbd.reload(self.store.list_exports())
        self.send_json(200, record)

    # -- operator UI -------------------------------------------------------
    def render_dash(self) -> str:
        exports = self.store.list_exports()
        host = self.headers.get("Host", "<host>").split(":", 1)[0]
        nbd_endpoint = f"tcp://{host}:{self.nbd_port}"
        rows = (
            "".join(
                f"""<tr>
                    <td><code>{html.escape(e["name"])}</code></td>
                    <td class="mono"><small>{html.escape(e["file"])}</small></td>
                    <td><small>{"ro" if e["readonly"] else "rw"}</small></td>
                    <td><small>{html.escape(e["added_at"])}</small></td>
                </tr>"""
                for e in exports
            )
            or '<tr><td colspan="4"><em>No exports registered yet.</em></td></tr>'
        )
        running = "running" if self.nbd.is_running() else "<strong>STOPPED</strong>"
        return f"""<!doctype html><html><head>
<meta charset="utf-8"><title>nbdmux</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 60rem;
         margin: 2rem auto; padding: 0 1rem; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ border-bottom: 1px solid #ddd; padding: .4rem .5rem; text-align: left; }}
  .mono {{ font-family: ui-monospace, monospace; }}
  code {{ background: #f4f4f4; padding: 0 .2rem; border-radius: 3px; }}
</style>
</head><body>
<h1>nbdmux <small>{__version__}</small></h1>
<p><small>nbd-server: {running} &middot; endpoint:
<code>{html.escape(nbd_endpoint)}</code> &middot; {len(exports)} export(s)</small></p>
<table><thead><tr><th>Name</th><th>File</th><th>Mode</th><th>Added</th></tr></thead>
<tbody>{rows}</tbody></table>
<hr>
<p><small>HTTP control: <code>POST /exports</code> /
<code>DELETE /exports/&lt;name&gt;</code> /
<code>GET /exports</code>. See README for the wire format.</small></p>
</body></html>"""

    def handle_login_form(self, error: str | None = None):
        if not self.auth.enabled:
            self.redirect("/")
            return
        err = f'<p style="color:#c00"><small>{html.escape(error)}</small></p>' if error else ""
        body_style = "font-family:system-ui;max-width:24rem;margin:5rem auto"
        self.send_html(
            200 if not error else 401,
            f"""<!doctype html><html><body style="{body_style}">
<h2>nbdmux</h2>{err}
<form method="post" action="/ui/login">
  <label>Password
    <input type="password" name="password" autofocus required style="width:100%">
  </label>
  <button type="submit" style="margin-top:1rem">Sign in</button>
</form>
</body></html>""",
        )

    def handle_login_submit(self):
        form = self.read_form()
        pw = form.get("password", "")
        if self.auth.check_password(pw):
            cookie = (
                f"{Auth.COOKIE}={self.auth.make_token()}; HttpOnly; SameSite=Lax; "
                f"Path=/; Max-Age={Auth.MAX_AGE}"
            )
            self.redirect("/", set_cookie=cookie)
        else:
            print(f"{self.address_string()} - login failed", flush=True)
            self.handle_login_form(error="Invalid password.")

    # -- helpers -----------------------------------------------------------
    def is_authed(self) -> bool:
        if not self.auth.enabled:
            return True
        token = self.cookie(Auth.COOKIE)
        return bool(token and self.auth.valid(token))

    def cookie(self, name: str) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            jar = http.cookies.SimpleCookie(raw)
        except http.cookies.CookieError:
            return None
        morsel = jar.get(name)
        return morsel.value if morsel else None

    def read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8") if length else ""
        return {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}

    def _read_json(self) -> Any:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def send_text(self, code: int, text: str):
        data = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_html(self, code: int, html_str: str):
        data = html_str.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, code: int, payload: Any):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location: str, set_cookie: str | None = None):
        self.send_response(303)
        self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()


# --------------------------------------------------------------------------
# main / wiring
# --------------------------------------------------------------------------
class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    summary = (__doc__ or "nbdmux daemon").splitlines()[0]
    p = argparse.ArgumentParser(prog="nbdmux-server", description=summary)
    p.add_argument("--data-dir", required=True, help="directory for state.db + nbd-server.conf")
    p.add_argument("--port", type=int, default=4040, help="HTTP control plane port")
    p.add_argument("--nbd-port", type=int, default=10809, help="NBD listening port")
    p.add_argument("--bind", default="0.0.0.0", help="bind address (HTTP + NBD)")
    p.add_argument("--nbd-server-bin", default="nbd-server", help="nbd-server binary to spawn")
    args = p.parse_args()

    data_dir = os.path.abspath(args.data_dir)
    os.makedirs(data_dir, exist_ok=True)

    secret = resolve_secret(data_dir)
    password = (os.environ.get("NBDMUX_ADMIN_PASSWORD") or "").strip() or None
    if password is None:
        print(
            "nbdmux: WARNING -- NBDMUX_ADMIN_PASSWORD unset; operator UI + control API "
            "are open. LAN-only deployments only.",
            file=sys.stderr,
            flush=True,
        )

    store = Store(data_dir)
    auth = Auth(secret, password)
    nbd = NbdServer(
        data_dir=data_dir, port=args.nbd_port, bind=args.bind, nbd_server_bin=args.nbd_server_bin
    )
    nbd.start(store.list_exports())

    httpd = _ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.store = store  # type: ignore[attr-defined]
    httpd.auth = auth  # type: ignore[attr-defined]
    httpd.nbd = nbd  # type: ignore[attr-defined]
    httpd.nbd_port = args.nbd_port  # type: ignore[attr-defined]

    def _shutdown(_signum, _frame):
        print("nbdmux: shutting down", file=sys.stderr, flush=True)
        nbd.stop()
        httpd.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    print(
        f"nbdmux: HTTP http://{args.bind}:{args.port}/ "
        f"NBD tcp://{args.bind}:{args.nbd_port}/ "
        f"data={data_dir}",
        file=sys.stderr,
        flush=True,
    )
    try:
        httpd.serve_forever()
    finally:
        nbd.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
