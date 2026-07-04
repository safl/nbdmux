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
from typing import Any

from . import __version__

USER_AGENT = f"nbdmux/{__version__}"
_DB_WRITE_LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MIME_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}


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
    name           TEXT PRIMARY KEY,
    -- Path on the nbdmux container's filesystem the decompressed
    -- .img lands at. Convention: ``<data-dir>/images/<name>.img``
    -- so the same dir can be bind-mounted into a sibling container
    -- (e.g. bty-web) for cross-service visibility without duplication.
    file           TEXT NOT NULL,
    readonly       INTEGER NOT NULL DEFAULT 1,
    -- State machine driven by the Warmer worker.
    --   queued        -- enqueued; worker hasn't picked it up
    --   fetching      -- streaming bytes from the upstream withcache
    --   decompressing -- piping the bytes through gunzip / zstd into ``file``
    --   ready         -- bytes on disk + export visible to nbd-server
    --   failed        -- ``error`` column carries the reason; operator re-enqueues to retry
    -- ``ready`` is the only state nbd-server's INI config includes.
    -- Other states are visible in the dashboard + the JSON API but
    -- the on-the-wire NBD listener won't surface them.
    status         TEXT NOT NULL DEFAULT 'ready',
    -- Upstream URL the Warmer pulls from (always routed through the
    -- configured withcache; nbdmux refuses src_urls that don't have
    -- ``NBDMUX_WITHCACHE_URL`` set). NULL when the operator
    -- pre-populated ``file`` directly and POSTed just ``{name, file}``.
    src_url        TEXT,
    -- Decompressor selector. Auto-derived from ``src_url``'s suffix
    -- when present (``.img`` -> raw / no decompression; ``.img.gz``
    -- -> gunzip; ``.img.zst`` -> zstd). Operator can override via
    -- the POST body's ``format`` field if the URL has no usable
    -- extension.
    format         TEXT,
    bytes_total    INTEGER,        -- expected response size from upstream (Content-Length)
    bytes_done     INTEGER,        -- decompressed bytes written to disk so far
    error          TEXT,           -- populated when status='failed'
    enqueued_at    TEXT NOT NULL,
    started_at     TEXT,
    completed_at   TEXT,
    updated_at     TEXT NOT NULL
);
"""


_SCHEMA_VERSION = 2  # v0.2.0 adds the warming state-machine columns


class Store:
    """Single-file SQLite store for the registered exports.

    Schema is one table plus a one-row version marker. WAL is fine
    here but we don't bother since writes are rare (only on register
    / unregister / worker state transitions) and reads are
    HTTP-handler-scoped; the global ``_DB_WRITE_LOCK`` serialises
    the writes.

    Pre-1.0 schema policy: on a version mismatch the existing
    ``state.db`` is rotated to ``state.db.v<N>.<ts>.bak`` and a
    fresh schema is created. Operator state is regenerable
    (operators re-POST their exports; bty-web does this
    automatically when a machine boots ramboot), so an alpha-grade
    migration apparatus would be over-engineering. The version
    transition gets logged so a startup audit shows what happened.
    """

    def __init__(self, data_dir: str):
        os.makedirs(data_dir, exist_ok=True)
        self.db_path = os.path.join(data_dir, "state.db")
        self._maybe_rotate_on_schema_mismatch()
        with self.conn() as c:
            c.executescript(_SCHEMA)
            c.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")
            c.execute(
                "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
                (_SCHEMA_VERSION,),
            )

    def _maybe_rotate_on_schema_mismatch(self) -> None:
        """If state.db exists but its schema_version disagrees with
        :data:`_SCHEMA_VERSION`, rotate it to a ``.bak`` so the
        caller's ``executescript`` lands on an empty file. No-op when
        the DB is missing or already on the current version."""
        if not os.path.exists(self.db_path):
            return
        try:
            with self.conn() as c:
                row = c.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            current = int(row["version"]) if row is not None else 1
        except sqlite3.OperationalError:
            # ``schema_version`` table absent -> definitely pre-v0.2.0
            current = 1
        if current == _SCHEMA_VERSION:
            return
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        bak = f"{self.db_path}.v{current}.{ts}.bak"
        os.rename(self.db_path, bak)
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = f"{self.db_path}{suffix}"
            if os.path.exists(sidecar):
                os.unlink(sidecar)
        sys.stderr.write(
            f"nbdmux: schema v{current} -> v{_SCHEMA_VERSION}; rotated old state.db to {bak}\n"
        )

    def conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db_path, isolation_level=None)
        c.row_factory = sqlite3.Row
        return c

    def upsert_export(
        self,
        name: str,
        file: str,
        readonly: bool = True,
        *,
        status: str = "ready",
        src_url: str | None = None,
        format: str | None = None,
        bytes_total: int | None = None,
    ) -> dict[str, Any]:
        """Insert a new export or refresh an existing one.

        Default status is ``ready`` so a pre-warmed-file POST (no
        ``src_url``) lands directly servable. The Warmer flips the
        status through the state machine when ``src_url`` is set.
        """
        now = now_iso()
        with _DB_WRITE_LOCK, self.conn() as c:
            c.execute(
                "INSERT INTO exports "
                "(name, file, readonly, status, src_url, format, "
                "bytes_total, bytes_done, enqueued_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET "
                "file=excluded.file, readonly=excluded.readonly, "
                "status=excluded.status, src_url=excluded.src_url, "
                "format=excluded.format, bytes_total=excluded.bytes_total, "
                "bytes_done=0, error=NULL, started_at=NULL, "
                "completed_at=CASE WHEN excluded.status='ready' "
                "THEN excluded.enqueued_at ELSE NULL END, "
                "updated_at=excluded.updated_at",
                (
                    name,
                    file,
                    1 if readonly else 0,
                    status,
                    src_url,
                    format,
                    bytes_total,
                    now,
                    now,
                ),
            )
        return self.get_export(name) or {}

    def set_status(
        self,
        name: str,
        status: str,
        *,
        error: str | None = None,
        bytes_done: int | None = None,
        bytes_total: int | None = None,
        set_started: bool = False,
        set_completed: bool = False,
    ) -> None:
        """Atomic status + companion-field update for the worker."""
        now = now_iso()
        sets: list[str] = ["status=?", "updated_at=?"]
        params: list[Any] = [status, now]
        if error is not None:
            sets.append("error=?")
            params.append(error)
        if bytes_done is not None:
            sets.append("bytes_done=?")
            params.append(bytes_done)
        if bytes_total is not None:
            sets.append("bytes_total=?")
            params.append(bytes_total)
        if set_started:
            sets.append("started_at=?")
            params.append(now)
        if set_completed:
            sets.append("completed_at=?")
            params.append(now)
        params.append(name)
        with _DB_WRITE_LOCK, self.conn() as c:
            c.execute(
                f"UPDATE exports SET {', '.join(sets)} WHERE name=?",
                params,
            )

    def get_export(self, name: str) -> dict[str, Any] | None:
        with self.conn() as c:
            row = c.execute("SELECT * FROM exports WHERE name=?", (name,)).fetchone()
        return _row_to_export(row) if row is not None else None

    def delete_export(self, name: str) -> bool:
        with _DB_WRITE_LOCK, self.conn() as c:
            cur = c.execute("DELETE FROM exports WHERE name=?", (name,))
            return cur.rowcount > 0

    def list_exports(self) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM exports ORDER BY name").fetchall()
        return [_row_to_export(r) for r in rows]

    def list_ready_exports(self) -> list[dict[str, Any]]:
        """Subset visible to nbd-server: only ``status='ready'``."""
        return [e for e in self.list_exports() if e["status"] == "ready"]

    def list_pending_exports(self) -> list[dict[str, Any]]:
        """Subset the Warmer resumes on startup: non-terminal states."""
        return [
            e for e in self.list_exports() if e["status"] in ("queued", "fetching", "decompressing")
        ]


def _row_to_export(row: sqlite3.Row) -> dict[str, Any]:
    """Normalise a sqlite3.Row into the dict shape the JSON API + the
    dashboard renderer expect. Booleans come back as bools, missing
    columns as None, the ``progress`` shorthand is derived for the UI."""
    bytes_total = row["bytes_total"]
    bytes_done = row["bytes_done"] or 0
    progress = None
    if bytes_total and bytes_total > 0:
        progress = round(min(100.0, (bytes_done * 100.0) / bytes_total), 1)
    return {
        "name": row["name"],
        "file": row["file"],
        "readonly": bool(row["readonly"]),
        "status": row["status"],
        "src_url": row["src_url"],
        "format": row["format"],
        "bytes_total": bytes_total,
        "bytes_done": bytes_done,
        "progress": progress,
        "error": row["error"],
        "enqueued_at": row["enqueued_at"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "updated_at": row["updated_at"],
    }


# --------------------------------------------------------------------------
# Warmer -- async fetch + decompress pipeline (one ref at a time)
# --------------------------------------------------------------------------
def _detect_format(src_url: str | None, override: str | None) -> str:
    """Pick the decompressor for an export.

    ``override`` from the POST body wins (so an operator can force
    decompression of a URL whose extension is missing or misleading);
    else derive from the URL suffix; else raw ``img`` as the default.
    """
    if override:
        return override.lower()
    if src_url:
        lowered = src_url.lower()
        if lowered.endswith(".img.gz") or lowered.endswith(".gz"):
            return "img.gz"
        if lowered.endswith(".img.zst") or lowered.endswith(".zst"):
            return "img.zst"
        if lowered.endswith(".img.xz") or lowered.endswith(".xz"):
            return "img.xz"
    return "img"


def _resolve_withcache_url(src_url: str) -> str:
    """Route ``src_url`` through the configured withcache. Returns the
    URL the worker should HTTP-GET.

    Contract: ``NBDMUX_WITHCACHE_URL`` MUST be set. nbdmux refuses to
    pull from arbitrary upstreams; the only allowed bytes path is via
    the operator's withcache, which gives a single auditable point of
    LAN caching + outbound HTTP.

    The withcache URL construction matches withcache's own ``/b/<b64(src)>``
    shape: base64url-encode the canonical src URL into the path segment
    so withcache can deduplicate on the canonical URL across rolling
    tags / ``latest`` aliases.
    """
    base = (os.environ.get("NBDMUX_WITHCACHE_URL") or "").strip().rstrip("/")
    if not base:
        raise ValueError(
            "NBDMUX_WITHCACHE_URL is not set; nbdmux only pulls "
            "via withcache. Configure the env var (or pre-populate the "
            "file on disk and POST without src_url)."
        )
    encoded = _b64e(src_url.encode("utf-8"))
    return f"{base}/b/{encoded}"


class Warmer:
    """Single-thread worker that walks each enqueued export through
    fetch -> decompress -> ready. One in-flight job at a time so a
    fleet of operators registering the same ref converges on a single
    decompress pass rather than racing duplicates.

    The state machine + persistence layer lives in :class:`Store`;
    this class owns the in-process queue + the thread that drains it.
    Re-enqueuing a ``ready`` ref is a no-op (Store.upsert_export
    leaves the row at ``ready`` when called without a src_url).
    Re-enqueuing a ``failed`` ref restarts at ``queued``.
    """

    def __init__(self, store: Store, nbd: NbdServer, images_dir: str):
        self._store = store
        self._nbd = nbd
        self._images_dir = images_dir
        self._queue: list[str] = []
        self._cv = threading.Condition()
        self._thread: threading.Thread | None = None
        self._stop = False

    def start(self) -> None:
        if self._thread is not None:
            return
        os.makedirs(self._images_dir, exist_ok=True)
        self._thread = threading.Thread(target=self._run, name="nbdmux-warmer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        with self._cv:
            self._stop = True
            self._cv.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def enqueue(self, name: str) -> None:
        """Drop ``name`` onto the work queue. The DB row should already
        be in ``status='queued'``; the caller is responsible for the
        Store.upsert_export call that creates it."""
        with self._cv:
            if name not in self._queue:
                self._queue.append(name)
            self._cv.notify()

    def _run(self) -> None:
        while True:
            with self._cv:
                while not self._queue and not self._stop:
                    self._cv.wait()
                if self._stop:
                    return
                name = self._queue.pop(0)
            try:
                self._process(name)
            except Exception as exc:  # noqa: BLE001
                sys.stderr.write(f"nbdmux: warmer crashed on {name}: {exc}\n")

    def _process(self, name: str) -> None:
        row = self._store.get_export(name)
        if row is None:
            sys.stderr.write(f"nbdmux: warmer: row vanished before pickup: {name}\n")
            return
        if row["status"] not in ("queued", "failed"):
            sys.stderr.write(f"nbdmux: warmer: ref={name} status={row['status']}, skipping\n")
            return
        src_url = row["src_url"]
        if not src_url:
            self._store.set_status(
                name,
                "failed",
                error="no src_url; can't warm",
                set_started=True,
                set_completed=True,
            )
            return
        try:
            fetch_url = _resolve_withcache_url(src_url)
        except ValueError as exc:
            self._store.set_status(
                name,
                "failed",
                error=str(exc),
                set_started=True,
                set_completed=True,
            )
            return
        format_hint = row["format"] or _detect_format(src_url, None)
        dest = row["file"]
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        self._store.set_status(name, "fetching", set_started=True)
        try:
            written = self._fetch_and_decompress(name, fetch_url, dest, format_hint)
        except Exception as exc:  # noqa: BLE001
            for candidate in (dest, dest + ".inflight"):
                with contextlib.suppress(OSError):
                    os.unlink(candidate)
            self._store.set_status(
                name,
                "failed",
                error=f"{type(exc).__name__}: {exc}",
                set_completed=True,
            )
            return
        self._store.set_status(
            name,
            "ready",
            bytes_done=written,
            set_completed=True,
        )
        # Make the new ready row visible to nbd-server.
        self._nbd.reload(self._store.list_ready_exports())

    def _fetch_and_decompress(
        self,
        name: str,
        url: str,
        dest: str,
        format_hint: str,
    ) -> int:
        """Stream ``url`` through the matching decompressor into
        ``dest``. Returns the number of decompressed bytes written.

        The fetch + decompress are pipelined via a subprocess that
        reads gzip/zstd/xz from stdin and writes raw bytes to stdout;
        urllib feeds the upstream response into the pipe so peak disk
        is the destination file, not destination + an intermediate
        compressed staging copy.

        Progress is updated in the DB every ~5% so the dashboard's
        progress bar advances without thrashing sqlite.
        """
        import urllib.request

        tmp = dest + ".inflight"
        with urllib.request.urlopen(url) as resp:  # noqa: S310
            content_length = resp.headers.get("Content-Length")
            bytes_total = int(content_length) if content_length else None
            if bytes_total:
                self._store.set_status(
                    name,
                    "fetching",
                    bytes_total=bytes_total,
                )
            self._store.set_status(name, "decompressing")
            proc: subprocess.Popen[bytes] | None
            writer: Any
            if format_hint in ("img", ""):
                # No decompression -- just copy bytes.
                proc = None
                writer = open(tmp, "wb")  # noqa: SIM115
            else:
                cmd = _decompressor_cmd(format_hint)
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=open(tmp, "wb"),  # noqa: SIM115
                    stderr=subprocess.PIPE,
                )
                writer = proc.stdin
            assert writer is not None
            try:
                written = 0
                last_progress_bucket = 0
                chunk_size = 1024 * 1024
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    writer.write(chunk)
                    written += len(chunk)
                    if bytes_total:
                        bucket = int((written * 20) // bytes_total)
                        if bucket > last_progress_bucket:
                            last_progress_bucket = bucket
                            self._store.set_status(
                                name,
                                "decompressing",
                                bytes_done=written,
                            )
            finally:
                if proc is not None:
                    assert proc.stdin is not None
                    proc.stdin.close()
                    err = b""
                    if proc.stderr is not None:
                        err = proc.stderr.read()
                    rc = proc.wait()
                    if rc != 0:
                        raise RuntimeError(f"decompressor exited rc={rc}: {err.decode('replace')}")
                else:
                    writer.close()
        # The decompressed-size = the size on disk (after the
        # decompressor wrote everything through).
        final_size = os.path.getsize(tmp)
        os.replace(tmp, dest)
        self._store.set_status(name, "decompressing", bytes_done=final_size)
        return final_size


def _decompressor_cmd(format_hint: str) -> list[str]:
    """Map a format hint to a stdin-to-stdout decompressor command.

    Each of these reads compressed bytes from stdin and writes raw
    bytes to stdout: ``gunzip -c`` / ``zstd -d -c`` / ``xz -d -c``.
    The binaries are pulled in by the container; on a non-container
    install the operator gets a friendly ``command not found`` from
    the subprocess Popen call when the binary is missing.
    """
    if format_hint in ("img.gz", "gz", ".gz"):
        return ["gunzip", "-c"]
    if format_hint in ("img.zst", "zst", ".zst"):
        return ["zstd", "-d", "-c"]
    if format_hint in ("img.xz", "xz", ".xz"):
        return ["xz", "-d", "-c"]
    raise ValueError(f"unsupported format for nbdmux warm: {format_hint!r}")


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
        """Write the config + spawn nbd-server in foreground mode.

        Idempotent. If ``exports`` is empty, the subprocess is NOT
        launched: nbd-server hard-fails with ``No configured exports;
        quitting`` when its INI carries only ``[generic]``, and a
        fresh nbdmux container legitimately has zero exports until
        the first ``POST /exports`` completes. The HTTP control
        plane stays up to accept that POST; ``reload`` lifts off as
        soon as the first ``ready`` export lands.
        """
        with self._lock:
            if self._proc and self._proc.poll() is None:
                return
            self.write_config(exports)
            if not exports:
                # No-op: defer the subprocess to the first reload()
                # that has at least one export. Loud-on-stderr so
                # the operator can see the deferred state in
                # ``podman logs``.
                sys.stderr.write(
                    "nbdmux: nbd-server deferred (no exports yet); "
                    "will start on first POST /exports + ready\n"
                )
                return
            self._spawn()

    def reload(self, exports: list[dict[str, Any]]) -> None:
        """Rewrite the config + SIGHUP the running daemon, OR launch
        it if this reload is the first non-empty one and the daemon
        is dormant per :meth:`start`'s deferral. Idempotent."""
        with self._lock:
            self.write_config(exports)
            if not exports:
                # Empty reload: keep the daemon down if it isn't up
                # yet (deferred-start case); if it IS up, leave it
                # alone -- the SIGHUP would land on a config nbd-
                # server would reject, killing the process.
                if not (self._proc and self._proc.poll() is None):
                    return
                # Up-but-now-empty: stop it cleanly rather than let
                # SIGHUP kill it with the no-exports error.
                self._terminate_proc_locked()
                return
            if self._proc and self._proc.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    self._proc.send_signal(signal.SIGHUP)
                return
            # Daemon dormant + non-empty exports: lift off.
            self._spawn()

    def _spawn(self) -> None:
        """Launch the nbd-server subprocess. Caller holds ``self._lock``
        and has already written the config."""
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

    def _terminate_proc_locked(self) -> None:
        """Stop the subprocess; caller holds ``self._lock``."""
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self._proc.wait(timeout=3)
            if self._proc.poll() is None:
                self._proc.kill()
        self._proc = None

    def stop(self) -> None:
        with self._lock:
            self._terminate_proc_locked()

    def is_running(self) -> bool:
        return bool(self._proc and self._proc.poll() is None)


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"nbdmux/{__version__}"
    protocol_version = "HTTP/1.1"

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

    @property
    def warmer(self) -> Warmer:
        return self.server.warmer  # type: ignore[attr-defined]

    @property
    def images_dir(self) -> str:
        return self.server.images_dir  # type: ignore[attr-defined]

    def log_message(self, format, *args):  # quieter, single-line
        print(f"{self.address_string()} - {format % args}", flush=True)

    # -- routing -----------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/healthz":
            # HEALTHCHECK for the container -- gate on the nbd-server
            # subprocess actually being up so orchestration reacts to
            # a mid-life crash. Returning 200 while the daemon is down
            # would keep the container marked healthy while NBD
            # clients get connection refused on 10809.
            if self.nbd.is_running():
                self.send_text(200, "ok\n")
            else:
                self.send_text(503, "nbd-server not running\n")
        elif parsed.path == "/exports":
            self.send_json(200, self.store.list_exports())
        elif parsed.path == "/ui/login":
            self.handle_login_form()
        elif parsed.path.startswith("/static/"):
            self.serve_static(parsed)
        elif parsed.path == "/":
            if self.auth.enabled and not self.is_authed():
                self.redirect("/ui/login")
            else:
                self.send_html(200, self.render_dash())
        else:
            self.send_text(404, "not found\n")

    def serve_static(self, parsed):
        """Serve files under ``src/nbdmux/static/`` (Bootstrap CSS +
        Bootstrap Icons CSS + htmx.min.js + the icon font files under
        ``static/fonts/`` that bootstrap-icons.min.css references via
        a relative ``fonts/…`` src). Constrain to ``static/`` and
        ``static/fonts/`` explicitly; abspath+startswith rejects any
        ``..`` traversal past the static root."""
        rel = parsed.path[len("/static/") :]
        if not rel or rel.endswith("/"):
            self.send_text(404, "not found\n")
            return
        target = os.path.abspath(os.path.join(STATIC_DIR, rel))
        static_root = os.path.abspath(STATIC_DIR) + os.sep
        if not target.startswith(static_root) or not os.path.isfile(target):
            self.send_text(404, "not found\n")
            return
        with open(target, "rb") as f:
            data = f.read()
        ext = os.path.splitext(target)[1]
        self.send_response(200)
        self.send_header("Content-Type", MIME_TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/exports":
            if not self._control_authed():
                self.send_json(401, {"error": "auth required"})
                return
            self.handle_post_export()
        elif parsed.path == "/ui/login":
            self.handle_login_submit()
        elif parsed.path == "/ui/logout":
            self.handle_logout()
        elif parsed.path == "/admin/create_export":
            if not self.is_authed():
                self.redirect("/ui/login")
                return
            self.handle_create_export_form()
        else:
            self.send_text(404, "not found\n")

    def do_DELETE(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path.startswith("/exports/"):
            if not self._control_authed():
                self.send_json(401, {"error": "auth required"})
                return
            name = urllib.parse.unquote(parsed.path[len("/exports/") :])
            # Read the row before dropping it so we can unlink the
            # warm-created file below. Warm-created exports (src_url
            # is set) live at a nbdmux-owned path under images_dir;
            # pre-warmed exports (JSON POST with a ``file`` field)
            # were placed on disk by the operator and MUST NOT be
            # unlinked here.
            row = self.store.get_export(name)
            existed = self.store.delete_export(name)
            self.nbd.reload(self.store.list_ready_exports())
            if existed and row and row.get("src_url"):
                path = row.get("file") or ""
                if path:
                    with contextlib.suppress(FileNotFoundError, OSError):
                        os.unlink(path)
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
        """Register or warm an export.

        Two shapes accepted on POST /exports:

        * ``{name, file, readonly?}``: pre-warmed; ``file`` is an
          absolute path that already exists on disk. nbdmux records
          it at ``status='ready'`` and SIGHUP-reloads nbd-server.
        * ``{name, src_url, format?, readonly?}``: warm. nbdmux
          allocates a path under ``<images-dir>/<name>.img``, marks
          the row ``status='queued'``, and the Warmer worker fetches
          via the configured withcache, decompresses, and flips to
          ready. ``src_url`` is the canonical upstream URL; nbdmux
          routes via ``$NBDMUX_WITHCACHE_URL``.

        Either the ``file`` key or the ``src_url`` key must be set;
        not both. ``name`` is the NBD-server export name, must be a
        short identifier with no slashes (matches nbd-server's INI
        rules).
        """
        body = self._read_json()
        if not isinstance(body, dict):
            self.send_json(400, {"error": "body must be a JSON object"})
            return
        name = body.get("name")
        path = body.get("file")
        src_url = body.get("src_url")
        format_override = body.get("format")
        readonly = bool(body.get("readonly", True))
        if not isinstance(name, str) or not name.strip():
            self.send_json(400, {"error": "name: non-empty string required"})
            return
        if "/" in name or name.startswith(".") or len(name) > 64:
            self.send_json(400, {"error": "name: must be a short identifier with no slashes"})
            return
        if (path is None) == (src_url is None):
            self.send_json(
                400,
                {"error": "exactly one of {file, src_url} must be set"},
            )
            return
        if path is not None:
            if not isinstance(path, str) or not os.path.isabs(path):
                self.send_json(400, {"error": "file: absolute path required"})
                return
            if not os.path.isfile(path):
                self.send_json(400, {"error": f"file: not found: {path}"})
                return
            record = self.store.upsert_export(
                name,
                path,
                readonly=readonly,
                status="ready",
            )
            self.nbd.reload(self.store.list_ready_exports())
            self.send_json(200, record)
            return
        if not isinstance(src_url, str) or not src_url.strip():
            self.send_json(400, {"error": "src_url: non-empty string required"})
            return
        if (os.environ.get("NBDMUX_WITHCACHE_URL") or "").strip() == "":
            self.send_json(
                400,
                {
                    "error": (
                        "NBDMUX_WITHCACHE_URL is not configured; nbdmux "
                        "only warms via withcache. Set the env var or "
                        "pre-populate the file on disk and POST {name, file}."
                    )
                },
            )
            return
        format_hint = _detect_format(src_url, format_override)
        dest = os.path.join(self.images_dir, f"{name}.img")
        record = self.store.upsert_export(
            name,
            dest,
            readonly=readonly,
            status="queued",
            src_url=src_url,
            format=format_hint,
        )
        self.warmer.enqueue(name)
        self.send_json(200, record)

    # -- operator UI -------------------------------------------------------
    # All three ecosystem services (bty, nbdmux, withcache) share a
    # Bootstrap 5 + Bootstrap Icons + htmx stack and the same page
    # chrome (accent strip, sticky header, dark navbar, brand pill,
    # user-bar); only ``--bs-primary`` differs so operators moving
    # between the three consoles learn one UI grammar. The trio sits
    # on a navy -> dark-magenta -> magenta gradient (cool -> hot);
    # nbdmux is the magenta terminus (the visible runtime that
    # clients actually connect to over the NBD wire).
    _PRIMARY_HEX = "#d63384"  # magenta -- Bootstrap --bs-pink
    _PRIMARY_HOVER = "#c02576"
    _PRIMARY_RGB = "214, 51, 132"

    def _head(self, title: str) -> str:
        primary = self._PRIMARY_HEX
        hover = self._PRIMARY_HOVER
        rgb = self._PRIMARY_RGB
        return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="/static/bootstrap.min.css">
<link rel="stylesheet" href="/static/bootstrap-icons.min.css">
<script src="/static/htmx.min.js"></script>
<style>
  /* Palette overrides (Bootstrap 5). --bs-primary + the -rgb
     triplet feed every translucent variant (alerts, focus rings,
     .bg-*-subtle) so re-tinting the whole stock component set is
     just this block -- no bootstrap.min.css patching needed. */
  :root {{
    --bs-primary: {primary};
    --bs-primary-rgb: {rgb};
    --bs-link-color: {primary};
    --bs-link-hover-color: {hover};
  }}
  .btn-primary {{
    --bs-btn-bg: {primary}; --bs-btn-border-color: {primary};
    --bs-btn-hover-bg: {hover}; --bs-btn-hover-border-color: {hover};
    --bs-btn-active-bg: {hover}; --bs-btn-active-border-color: {hover};
  }}
  .bg-primary {{ --bs-bg-opacity: 1; background-color: {primary} !important; }}
  .text-primary {{ --bs-text-opacity: 1; color: {primary} !important; }}
  .border-primary {{ --bs-border-opacity: 1; border-color: {primary} !important; }}

  /* Brand accent strip: 3px navy -> dark-magenta -> magenta
     gradient shared by all three services so the trio reads as
     one product family from any console. */
  .brand-accent {{
    height: 3px;
    background: linear-gradient(90deg, #0d3585 0%, #8f1b71 50%, #d63384 100%);
  }}
  /* Accent + navbar pin to the top together so the brand pill +
     logout stay reachable while scrolling. */
  .sticky-header {{ position: sticky; top: 0; z-index: 1030; }}
  html {{ scroll-padding-top: 5rem; scroll-behavior: smooth; }}

  /* Brand pill. Same padding + radius on every visit; the active
     state only swaps background colour so the layout doesn't
     shift as the operator navigates. */
  .navbar-brand {{
    border-radius: 0.5rem;
    padding-left: 0.6rem;
    padding-right: 0.6rem;
    margin-right: 0.25rem;
    transition: background-color 0.15s;
  }}
  .navbar-brand.brand-active {{ background-color: rgba({rgb}, 0.85); }}
  .navbar-brand:hover {{ background-color: rgba(255, 255, 255, 0.06); }}
  .navbar-brand.brand-active:hover {{ background-color: rgba({rgb}, 0.95); }}
  .navbar-brand .brand-icon {{
    font-size: 1.05rem;
    vertical-align: -0.1rem;
  }}
  /* Version sits alongside the brand pill but outside it, so the
     click target stays clean and the version reads as adjacent
     metadata. */
  .navbar-version {{
    color: rgba(255, 255, 255, 0.55);
    font-weight: 400;
    font-size: 0.85rem;
    align-self: center;
    white-space: nowrap;
  }}
  /* nav-btn cascade for the (currently empty) middle-of-navbar
     link zone; kept ready so a future Settings / Docs pill can
     drop in without a style diff. */
  .navbar .nav-btn {{
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.4rem 0.8rem;
    margin-right: 0.25rem;
    border-radius: 0.5rem;
    color: rgba(255, 255, 255, 0.85);
    text-decoration: none;
    transition: background-color 0.15s;
  }}
  .navbar .nav-btn:hover {{
    background-color: rgba(255, 255, 255, 0.10);
    color: #fff;
  }}
  .navbar .nav-btn.active {{
    background-color: {primary};
    color: #fff;
    box-shadow: 0 0 0 1px rgba({rgb}, 0.6);
  }}
  .navbar .nav-btn i {{ font-size: 1.05rem; }}

  /* User-bar: a single pill containing operator identity + logout,
     divided by a thin vertical rule. Visually one widget, but two
     click targets and zero JavaScript. */
  .user-bar {{
    display: inline-flex;
    align-items: stretch;
    border-radius: 999px;
    background-color: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.12);
    overflow: hidden;
    font-size: 0.85rem;
  }}
  .user-bar-name {{
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.35rem 0.8rem;
    color: rgba(255, 255, 255, 0.92);
  }}
  .user-bar-name code {{
    color: #fff;
    background: transparent;
    padding: 0;
  }}
  .user-bar-divider {{
    width: 1px;
    background-color: rgba(255, 255, 255, 0.18);
  }}
  .user-bar-action {{
    display: inline-flex;
    align-items: center;
    padding: 0.35rem 0.7rem;
    background: transparent;
    border: none;
    color: rgba(255, 255, 255, 0.85);
    text-decoration: none;
    transition: background-color 0.15s, color 0.15s;
  }}
  .user-bar-action:hover,
  .user-bar-action:focus {{
    background-color: rgba(255, 255, 255, 0.10);
    color: #fff;
    outline: none;
  }}
  .user-bar-action.active {{
    background-color: rgba(255, 255, 255, 0.16);
    color: #fff;
  }}
  /* Logout hover keeps the danger-red signal so it's not
     confusable with the account/gear action. */
  .user-bar-logout:hover,
  .user-bar-logout:focus {{
    background-color: rgba(220, 53, 69, 0.65);
    color: #fff;
  }}

  /* nbdmux-specific status colouring for the exports table. */
  code {{ color: inherit; }}
  .file, .url {{ word-break: break-all; }}
  .status-ready {{ color: var(--bs-success); font-weight: 600; }}
  .status-queued, .status-fetching, .status-decompressing {{
    color: var(--bs-primary); font-weight: 600;
  }}
  .status-failed {{ color: var(--bs-danger); font-weight: 600; }}
  .status-idle {{ color: var(--bs-secondary); font-weight: 600; }}
  .status-stopped {{ color: var(--bs-danger); font-weight: 600; }}
  .progress.warm {{ height: .5rem; width: 8rem; margin: .25rem 0 .15rem; }}
</style>
</head>"""

    def _user_bar_html(self) -> str:
        """Right-side operator identity + logout pill. Only rendered
        when auth is enabled AND the request is authed; on the login
        page and on unauth-disabled deploys the space stays empty."""
        if not self.auth.enabled or not self.is_authed():
            return ""
        # nbdmux runs its operator UI under a single admin identity;
        # the container image drops privileges to the ``nbdmux``
        # user which is what the operator sees inside the pill.
        return (
            '<div class="user-bar mt-2 mt-md-0" title="Operator identity">'
            '<span class="user-bar-name" title="Signed in as">'
            '<i class="bi bi-person-circle"></i>'
            "<code>admin</code>"
            "</span>"
            '<span class="user-bar-divider"></span>'
            '<form action="/ui/logout" method="post" class="m-0 d-inline-flex">'
            '<button type="submit" class="user-bar-action user-bar-logout" '
            'title="Sign out">'
            '<i class="bi bi-box-arrow-right"></i>'
            "</button>"
            "</form>"
            "</div>"
        )

    def _chrome_open(self, *, brand_active: bool, subnav_html: str = "") -> str:
        """Open <body> + the shared accent + dark-navbar + brand pill
        + user-bar chrome. Optional ``subnav_html`` renders inside a
        ``.subnav-strip`` immediately below the top navbar, visually
        attached to the sticky header (matches bty's page-level action
        strip). Caller emits the ``<main>`` content and the closing
        tags. Kept as one helper so login + dashboard
        render an identical header without drift."""
        active_class = " brand-active" if brand_active else ""
        subnav = (
            f'<div class="subnav-strip"><div class="container">{subnav_html}</div></div>'
            if subnav_html
            else ""
        )
        return f"""<body class="bg-light">
<div class="sticky-header">
<div class="brand-accent"></div>
<nav class="navbar navbar-expand-md bg-dark navbar-dark py-2">
  <div class="container">
    <a class="navbar-brand fw-semibold{active_class}" href="/">
      <i class="bi bi-hdd-network brand-icon me-1"></i>NBDMUX
    </a>
    <div class="d-flex flex-grow-1 align-items-center flex-wrap">
      <div class="me-auto d-flex flex-wrap"></div>
      <span class="navbar-version me-2">v{html.escape(__version__)}</span>
      {self._user_bar_html()}
    </div>
  </div>
</nav>
{subnav}
</div>"""

    _ERR_MESSAGES: dict[str, str] = {
        "name": "Name is required; no '/' characters, must not start with '.', max 64 chars.",
        "src_url": "Source URL is required.",
        "withcache_unset": (
            "NBDMUX_WITHCACHE_URL is not configured; nbdmux cannot warm the "
            "export. Set the env var and restart, or POST /exports with a "
            "pre-warmed {name, file} pair."
        ),
        "malformed": "Form submission was malformed (duplicate fields?).",
    }

    def render_dash(self) -> str:
        exports = self.store.list_exports()
        host = self.headers.get("Host", "<host>").split(":", 1)[0]
        nbd_endpoint = f"tcp://{host}:{self.nbd_port}"
        withcache = (os.environ.get("NBDMUX_WITHCACHE_URL") or "").strip()
        # ``?err=<kind>`` is the signal handle_create_export_form uses
        # to send the operator back to the dashboard with a reason.
        # Render an alert banner above the nbd-server card so the
        # form failure is visible instead of a silent no-op redirect.
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        err_kind = (query.get("err") or [""])[0]
        err_banner = ""
        if err_kind:
            msg = self._ERR_MESSAGES.get(err_kind, f"Create export failed: {err_kind}.")
            # Non-dismissible: only bootstrap-icons + htmx are bundled
            # (see /static assets in _head); bootstrap.bundle.js is not,
            # so ``data-bs-dismiss`` would no-op. The banner clears on
            # the next full-page navigation (form submit or refresh).
            err_banner = (
                '<div class="alert alert-danger" role="alert">'
                '<i class="bi bi-exclamation-triangle-fill me-1"></i>'
                f"{html.escape(msg)}"
                "</div>"
            )
        rows = "".join(self._render_export_row(e) for e in exports) or (
            '<tr><td colspan="5" class="text-center text-muted">'
            "<em>No exports registered yet.</em></td></tr>"
        )
        ready = [e for e in exports if (e.get("status") or "ready") == "ready"]
        if self.nbd.is_running():
            status_line = (
                '<span class="status-ready"><i class="bi bi-play-circle-fill"></i> running</span>'
            )
        elif not ready:
            status_line = (
                '<span class="status-idle"><i class="bi bi-pause-circle"></i> idle</span>'
                ' <small class="text-muted">(starts on first ready export)</small>'
            )
        else:
            status_line = (
                '<span class="status-stopped">'
                '<i class="bi bi-exclamation-octagon-fill"></i> STOPPED</span>'
            )
        upstream = (
            f"upstream withcache: <code>{html.escape(withcache)}</code>"
            if withcache
            else '<span class="text-muted">upstream withcache: '
            "<em>unset</em> (src_url warms disabled)</span>"
        )
        # Subnav strip: single "Exports" pill on the left (single view
        # today) + a compact "New export" form on the right (bty's
        # subnav-actions convention). The form is name + src_url; the
        # advanced pre-warmed-file path stays available via the JSON
        # POST /exports API for power users.
        withcache_configured = bool(withcache)
        create_disabled = "" if withcache_configured else " disabled"
        placeholder = (
            "https://catalog/image.img.zst"
            if withcache_configured
            else "NBDMUX_WITHCACHE_URL unset -- see docs"
        )
        subnav_html = f"""<ul class="nav nav-pills subnav-jumps m-0">
  <li class="nav-item"><a class="nav-link active" href="#exports">Exports</a></li>
</ul>
<div class="subnav-actions ms-auto d-flex align-items-center">
  <form method="post" action="/admin/create_export"
        class="m-0 d-flex align-items-center gap-1">
    <label for="new-name" class="text-muted small mb-0">name</label>
    <input class="form-control form-control-sm" id="new-name" name="name"
           style="width: 10rem;" placeholder="debian-13" required{create_disabled}>
    <label for="new-src" class="text-muted small mb-0 ms-2">src_url</label>
    <input class="form-control form-control-sm" id="new-src" name="src_url"
           style="width: 20rem;" placeholder="{placeholder}" required{create_disabled}>
    <button class="btn btn-sm btn-primary ms-1" type="submit"{create_disabled}
            >Add</button>
  </form>
</div>"""
        return f"""{self._head("nbdmux")}
{self._chrome_open(brand_active=True, subnav_html=subnav_html)}
<main class="container py-4">
  {err_banner}
  <div class="card mb-4">
    <div class="card-header d-flex align-items-center justify-content-between">
      <span><i class="bi bi-broadcast text-primary"></i> nbd-server</span>
      <small class="text-muted">{len(exports)} export(s)</small>
    </div>
    <div class="card-body">
      <p class="mb-2">{status_line}</p>
      <p class="mb-1"><small>endpoint <code>{html.escape(nbd_endpoint)}</code></small></p>
      <p class="mb-0"><small>{upstream}</small></p>
    </div>
  </div>
  <div class="card">
    <div class="card-header"><i class="bi bi-collection text-primary"></i> Exports</div>
    <div class="table-responsive">
    <table class="table table-sm table-striped table-hover align-middle mb-0">
      <thead class="table-light">
        <tr><th>Name</th><th>File</th><th>Mode</th><th>Status</th><th>Added</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    </div>
    <div class="card-footer bg-white">
      <small class="text-muted">HTTP control:
      <code>POST /exports {{name, file}}</code> (pre-warmed) or
      <code>POST /exports {{name, src_url}}</code> (warm via withcache) /
      <code>POST /admin/create_export</code> (form-encoded, subnav) /
      <code>DELETE /exports/&lt;name&gt;</code> /
      <code>GET /exports</code>. See README for the wire format.</small>
    </div>
  </div>
</main>
</body></html>"""

    def _render_export_row(self, e: dict[str, Any]) -> str:
        """One <tr> for an export. Renders progress bar + status pill
        when the row is mid-warm; renders plain status text + the
        completed timestamp when ready or failed."""
        status = e.get("status") or "ready"
        status_html = f'<span class="status-{html.escape(status)}">{html.escape(status)}</span>'
        if status in ("fetching", "decompressing"):
            pct = e.get("progress")
            if pct is not None:
                bar = (
                    f'<progress class="warm" value="{pct:.1f}" max="100"></progress>'
                    f" <small>{pct:.1f}%</small>"
                )
            else:
                bar = '<progress class="warm"></progress> <small><em>streaming</em></small>'
            status_html = f"{status_html}<br>{bar}"
        elif status == "failed":
            err = html.escape(e.get("error") or "(no error message)")
            status_html = f"{status_html}<br><small>{err}</small>"
        ts_line = e.get("completed_at") or e.get("started_at") or e.get("enqueued_at") or "-"
        return (
            "<tr>"
            f"<td><code>{html.escape(e['name'])}</code></td>"
            f'<td class="file mono"><small>{html.escape(e["file"])}</small></td>'
            f"<td><small>{'ro' if e['readonly'] else 'rw'}</small></td>"
            f"<td>{status_html}</td>"
            f"<td><small>{html.escape(str(ts_line))}</small></td>"
            "</tr>"
        )

    def handle_login_form(self, error: str | None = None):
        if not self.auth.enabled:
            self.redirect("/")
            return
        err = f'<div class="alert alert-danger">{html.escape(error)}</div>' if error else ""
        self.send_html(
            200 if not error else 401,
            f"""{self._head("nbdmux - login")}
{self._chrome_open(brand_active=False)}
<main class="container py-5">
  <div class="card mx-auto" style="max-width: 24rem;">
    <div class="card-body">
      <h4 class="card-title fw-semibold mb-1">Operator login</h4>
      <p class="text-muted small mb-3">Sign in to the nbdmux control plane.</p>
      {err}
      <form method="post" action="/ui/login">
        <div class="mb-3">
          <label class="form-label" for="pw">Admin password</label>
          <input class="form-control" id="pw" type="password" name="password"
                 autofocus required>
        </div>
        <button class="btn btn-primary w-100" type="submit">Log in</button>
      </form>
    </div>
  </div>
</main></body></html>""",
        )

    def handle_create_export_form(self):
        """UI create-export: reads form-encoded ``{name, src_url}``,
        forwards through the same validation the JSON POST ``/exports``
        uses, then 303-redirects back to ``/`` so the browser flips
        into GET and the dashboard shows the new queued row.
        Validation failures 303 back to ``/?err=<kind>`` with the
        reason; ``render_dash`` reads the query and renders an
        alert banner above the nbd-server card so the operator
        sees why nothing was created."""
        try:
            form = self.read_form()
        except ValueError:
            self.redirect("/?err=malformed")
            return
        name = form.get("name", "").strip()
        src_url = form.get("src_url", "").strip()
        if not name or "/" in name or name.startswith(".") or len(name) > 64:
            self.redirect("/?err=name")
            return
        if not src_url:
            self.redirect("/?err=src_url")
            return
        if (os.environ.get("NBDMUX_WITHCACHE_URL") or "").strip() == "":
            self.redirect("/?err=withcache_unset")
            return
        # Mirror handle_post_export's warm-path logic.
        format_hint = _detect_format(src_url, None)
        dest = os.path.join(self.images_dir, f"{name}.img")
        self.store.upsert_export(
            name,
            dest,
            readonly=True,
            status="queued",
            src_url=src_url,
            format=format_hint,
        )
        self.warmer.enqueue(name)
        self.redirect("/")

    def handle_logout(self):
        """Blow away the session cookie and redirect to the login
        form. Mirrors bty-web's ``/ui/logout`` shape so the trio's
        auth semantics stay identical from the operator's side."""
        expired = f"{Auth.COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
        target = "/ui/login" if self.auth.enabled else "/"
        self.redirect(target, set_cookie=expired)

    def handle_login_submit(self):
        """Verify the posted password. On match, set the session
        cookie and 303 to /; on mismatch, re-render the login form
        with a generic error. Both branches log the attempt (before
        the response, so the line lands even if the client drops
        the connection mid-write) so operators can grep ``podman
        logs`` for who authenticated when."""
        try:
            form = self.read_form()
        except ValueError:
            # Malformed submission (duplicate password fields, etc.)
            # -- fail auth silently like a bad password rather than
            # surface parser internals.
            self.handle_login_form(error="Invalid password.")
            return
        pw = form.get("password", "")
        if self.auth.check_password(pw):
            print(f"{self.address_string()} - login succeeded", flush=True)
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
        """Parse form-encoded body into ``{key: value}``. Rejects
        duplicate keys with ValueError -- an operator-facing form
        never has repeated field names, so ``name=a&name=b`` is
        either a bug or a client trying to hide a payload from a
        naive read of the first value. Callers wrap the call and
        turn a ValueError into a 4xx / redirect."""
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8") if length else ""
        pairs = urllib.parse.parse_qs(body)
        dups = [k for k, v in pairs.items() if len(v) > 1]
        if dups:
            raise ValueError(f"duplicate form field(s): {', '.join(sorted(dups))}")
        return {k: v[0] for k, v in pairs.items()}

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


PROBE_EXPORT_NAME = "probe"
PROBE_EXPORT_SIZE = 1 << 20  # 1 MiB -- small on disk, big enough to `dd` against


def _ensure_probe_export(store: Store, data_dir: str) -> None:
    """Guarantee a ``probe`` export is registered ``ready`` so
    nbd-server has something to serve on daemon start, regardless of
    whether any operator has POSTed a real export yet.

    Two things this buys us:

    * ``nbd-server`` runs unconditionally, so the "STOPPED" state is
      an actual signal (the process crashed or refused to start) and
      not a design-time deferred idle.
    * Operators get a permanent smoke-test target -- ``qemu-nbd -c
      /dev/nbd0 nbd://<host>:10809/probe`` should always answer, so
      "does the whole warm -> serve pipeline work end-to-end?"
      collapses to a single command that doesn't require an image
      to be POSTed first.

    File contents: a 1 MiB payload starting with a magic banner
    string (version-stamped) padded with zeros. Read-only. Written
    idempotently: only regenerated if the file is missing OR its
    size drifted (e.g. someone truncated it) OR the banner version
    differs (so a nbdmux upgrade refreshes the marker).
    """
    path = os.path.join(data_dir, "probe.img")
    banner = f"NBDMUX PROBE v{__version__}\n".encode("ascii")
    need_write = True
    if os.path.isfile(path) and os.path.getsize(path) == PROBE_EXPORT_SIZE:
        with open(path, "rb") as f:
            head = f.read(len(banner))
        if head == banner:
            need_write = False
    if need_write:
        # Write via a tempfile + rename so a crashed writer never
        # leaves a half-formed probe.img that would fail nbd-server
        # startup on the next boot.
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(banner)
            f.write(b"\x00" * (PROBE_EXPORT_SIZE - len(banner)))
        os.replace(tmp, path)
    store.upsert_export(
        name=PROBE_EXPORT_NAME,
        file=path,
        readonly=True,
        status="ready",
    )


# --------------------------------------------------------------------------
# main / wiring
# --------------------------------------------------------------------------
class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    summary = (__doc__ or "nbdmux daemon").splitlines()[0]
    p = argparse.ArgumentParser(prog="nbdmux-server", description=summary)
    # ``--data-dir`` falls back to ``$NBDMUX_DATA_DIR`` so the
    # container's ENV NBDMUX_DATA_DIR=/data (deploy/Containerfile) is
    # actually consulted; only when neither is set do we bail.
    p.add_argument(
        "--data-dir",
        default=os.environ.get("NBDMUX_DATA_DIR"),
        help="directory for state.db + nbd-server.conf (env: NBDMUX_DATA_DIR)",
    )
    p.add_argument("--port", type=int, default=8082, help="HTTP control plane port")
    p.add_argument("--nbd-port", type=int, default=10809, help="NBD listening port")
    p.add_argument("--bind", default="0.0.0.0", help="bind address (HTTP + NBD)")
    p.add_argument("--nbd-server-bin", default="nbd-server", help="nbd-server binary to spawn")
    p.add_argument(
        "--images-dir",
        default=None,
        help="where decompressed .img files land (default: <data-dir>/images)",
    )
    args = p.parse_args()

    if not args.data_dir:
        p.error("--data-dir is required (or set NBDMUX_DATA_DIR)")
    data_dir = os.path.abspath(args.data_dir)
    os.makedirs(data_dir, exist_ok=True)
    images_dir = os.path.abspath(args.images_dir or os.path.join(data_dir, "images"))
    os.makedirs(images_dir, exist_ok=True)

    secret = resolve_secret(data_dir)
    password = (os.environ.get("NBDMUX_ADMIN_PASSWORD") or "").strip() or None
    if password is None:
        print(
            "nbdmux: WARNING -- NBDMUX_ADMIN_PASSWORD unset; operator UI + control API "
            "are open. LAN-only deployments only.",
            file=sys.stderr,
            flush=True,
        )
    withcache_url = (os.environ.get("NBDMUX_WITHCACHE_URL") or "").strip()
    if not withcache_url:
        print(
            "nbdmux: NBDMUX_WITHCACHE_URL unset; src_url-based warm requests "
            "will be rejected. Pre-populated {name, file} POSTs still work.",
            file=sys.stderr,
            flush=True,
        )

    store = Store(data_dir)
    auth = Auth(secret, password)
    nbd = NbdServer(
        data_dir=data_dir, port=args.nbd_port, bind=args.bind, nbd_server_bin=args.nbd_server_bin
    )
    _ensure_probe_export(store, data_dir)
    # nbd-server only sees ``ready`` exports; in-flight + failed
    # rows stay invisible to NBD clients but visible to the dashboard
    # + the JSON API.
    nbd.start(store.list_ready_exports())

    warmer = Warmer(store=store, nbd=nbd, images_dir=images_dir)
    warmer.start()
    # Resume any rows that were mid-warm at the last shutdown.
    for row in store.list_pending_exports():
        warmer.enqueue(row["name"])

    httpd = _ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.store = store  # type: ignore[attr-defined]
    httpd.auth = auth  # type: ignore[attr-defined]
    httpd.nbd = nbd  # type: ignore[attr-defined]
    httpd.nbd_port = args.nbd_port  # type: ignore[attr-defined]
    httpd.warmer = warmer  # type: ignore[attr-defined]
    httpd.images_dir = images_dir  # type: ignore[attr-defined]

    def _shutdown(_signum, _frame):
        print("nbdmux: shutting down", file=sys.stderr, flush=True)
        warmer.stop()
        nbd.stop()
        httpd.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    print(
        f"nbdmux: HTTP http://{args.bind}:{args.port}/ "
        f"NBD tcp://{args.bind}:{args.nbd_port}/ "
        f"data={data_dir} images={images_dir}",
        file=sys.stderr,
        flush=True,
    )
    try:
        httpd.serve_forever()
    finally:
        warmer.stop()
        nbd.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
