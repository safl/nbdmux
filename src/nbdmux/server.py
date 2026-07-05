"""nbdmux daemon -- pipeline state machine + nbd-server subprocess supervision.

One Python process; one supervised ``nbd-server`` child; a SQLite
state.db tracking registered exports so a daemon restart restores them.

Post-v0.3.0 the HTTP control plane + operator UI moved out to
:mod:`nbdmux._app` (FastAPI + Jinja + Bootstrap); this module now
owns the parts of the daemon that stay stdlib:

- ``Store``: SQLite-backed exports table, ``record_export`` /
  ``delete_export`` / ``list_exports``. Single ``state.db`` under
  ``--data-dir``.
- ``Auth``: server-signed HMAC cookie, ``NBDMUX_ADMIN_PASSWORD`` env
  gate. Signing key resolution via :func:`resolve_secret`.
- ``NbdServer``: writes nbd-server's INI config and supervises the
  subprocess; SIGHUP on every export-set change to reload without
  dropping in-flight connections.
- ``Warmer``: fetch + decompress worker that walks each queued
  export through queued -> fetching -> decompressing -> ready.
- ``main``: argparse + ``uvicorn.run`` against
  :func:`nbdmux._app.create_app`. The FastAPI lifespan hook owns
  Warmer + NbdServer start / stop.

The system-level dependency is ``nbd-server``
(Debian / Ubuntu: ``apt install nbd-server``; Fedora: ``dnf install nbd``).
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any

from . import __version__

# The export name goes into two places that both parse it structurally:
#   * ``[<name>]`` section header in ``nbd-server.conf``, which
#     nbd-server reads as INI. Any ``]``, ``[``, ``\n``, ``#``,
#     ``;``, or ``=`` in the name corrupts the section OR silently
#     injects a new one.
#   * ``<images-dir>/<name>.img`` when warm-created; ``/`` escapes
#     the images dir and ``.`` prefix makes it dotfile-hidden.
# Constrain to alnum-leading + alnum/dot/dash/underscore, max 64
# chars, matching bty's label validator (bty/web/_models.py):
_EXPORT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _valid_export_name(name: str) -> bool:
    return bool(_EXPORT_NAME_RE.match(name))


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

    def check_bearer(self, token: str) -> bool:
        """Constant-time compare a raw Bearer token against the
        configured admin password. Used by the JSON control-plane's
        service-to-service path (bty-web reads
        ``$NBDMUX_ADMIN_PASSWORD`` and sends it as
        ``Authorization: Bearer <pw>``). Equivalent trust surface
        to ``check_password`` -- both are password comparisons --
        so callers can pick whichever channel their transport
        supports."""
        if not self.password:
            return False
        return hmac.compare_digest(token.encode("utf-8"), self.password.encode("utf-8"))


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
                        # ``decode(errors="replace")`` -- ``'replace'`` is the
                        # error handler, not a codec name; ``err.decode('replace')``
                        # (the previous form) raises LookupError instead of
                        # surfacing the decompressor's stderr.
                        raise RuntimeError(
                            f"decompressor exited rc={rc}: {err.decode('utf-8', errors='replace')}"
                        )
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


def main() -> int:
    """Daemon entry point.

    Constructs Store + Warmer + NbdServer, hands them to
    :func:`nbdmux._app.create_app`, then boots uvicorn. Warmer +
    NbdServer lifecycle (start / stop / resume-pending) runs from
    the FastAPI lifespan hook; SIGTERM / SIGINT handling is
    uvicorn's.
    """
    import uvicorn

    from ._app import create_app

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

    # Instantiate the real Store + Warmer + NbdServer before create_app
    # so the FastAPI app.state carries the same instances the
    # lifespan hook will start / stop. ``_ensure_probe_export`` runs
    # here (not in the lifespan) so a fresh state.db has the probe
    # row before nbd-server first reads the ready list.
    store = Store(data_dir)
    _ensure_probe_export(store, data_dir)
    nbd = NbdServer(
        data_dir=data_dir, port=args.nbd_port, bind=args.bind, nbd_server_bin=args.nbd_server_bin
    )
    warmer = Warmer(store=store, nbd=nbd, images_dir=images_dir)

    app = create_app(
        data_dir=data_dir,
        store=store,
        warmer=warmer,
        nbd=nbd,
        images_dir=images_dir,
        nbd_port=args.nbd_port,
        run_lifecycle=True,
    )

    print(
        f"nbdmux: HTTP http://{args.bind}:{args.port}/ "
        f"NBD tcp://{args.bind}:{args.nbd_port}/ "
        f"data={data_dir} images={images_dir}",
        file=sys.stderr,
        flush=True,
    )
    uvicorn.run(app, host=args.bind, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
