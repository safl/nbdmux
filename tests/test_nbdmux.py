"""Stdlib-only tests for nbdmux. Run with:  python -m unittest -v

No third-party deps; src/ is put on the path so the package imports
without an install.
"""

import gzip
import http.client
import http.server
import os
import shutil
import socketserver
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nbdmux import client, server  # noqa: E402


# --------------------------------------------------------------------------
# Auth: signed-cookie round-trip
# --------------------------------------------------------------------------
class TestResolveSecret(unittest.TestCase):
    """resolve_secret is the whole basis of the cookie-auth trust
    boundary: the HMAC key that signs session tokens. Three branches
    -- env-set, file-persisted, fresh-generation -- and a
    security-adjacent invariant (blank env must NOT silently weaken
    signing). All exercised here."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._saved = os.environ.get("NBDMUX_SESSION_SECRET")

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("NBDMUX_SESSION_SECRET", None)
        else:
            os.environ["NBDMUX_SESSION_SECRET"] = self._saved

    def test_env_set_wins(self):
        os.environ["NBDMUX_SESSION_SECRET"] = "operator-chosen-secret"
        self.assertEqual(server.resolve_secret(self.tmpdir), b"operator-chosen-secret")

    def test_env_blank_falls_through_to_fresh_generation(self):
        """The docstring promises a blank env value must NOT silently
        weaken signing. A fresh secret must land under data_dir and
        NOT be the empty string."""
        os.environ["NBDMUX_SESSION_SECRET"] = "   "
        got = server.resolve_secret(self.tmpdir)
        self.assertGreaterEqual(len(got), 32)
        self.assertNotEqual(got, b"")
        # And it was persisted.
        persisted = os.path.join(self.tmpdir, "session-secret")
        self.assertTrue(os.path.exists(persisted))

    def test_env_unset_generates_and_persists(self):
        os.environ.pop("NBDMUX_SESSION_SECRET", None)
        got = server.resolve_secret(self.tmpdir)
        self.assertGreaterEqual(len(got), 32)
        with open(os.path.join(self.tmpdir, "session-secret"), "rb") as f:
            self.assertEqual(f.read(), got)

    def test_file_persisted_returned_on_second_call(self):
        os.environ.pop("NBDMUX_SESSION_SECRET", None)
        first = server.resolve_secret(self.tmpdir)
        # Second call reads the persisted file rather than regenerating.
        second = server.resolve_secret(self.tmpdir)
        self.assertEqual(first, second)

    def test_persisted_file_permissions_are_private(self):
        os.environ.pop("NBDMUX_SESSION_SECRET", None)
        server.resolve_secret(self.tmpdir)
        path = os.path.join(self.tmpdir, "session-secret")
        mode = os.stat(path).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class TestAuth(unittest.TestCase):
    def test_token_roundtrip(self):
        a = server.Auth(b"secret-key", "pw")
        self.assertTrue(a.enabled)
        self.assertTrue(a.valid(a.make_token()))

    def test_tampered_token_rejected(self):
        a = server.Auth(b"secret-key", "pw")
        tok = a.make_token()
        payload = tok.split(".", 1)[0]
        self.assertFalse(a.valid(payload + ".deadbeef"))

    def test_wrong_secret_rejected(self):
        a = server.Auth(b"secret-A", "pw")
        b = server.Auth(b"secret-B", "pw")
        self.assertFalse(b.valid(a.make_token()))

    def test_password_check(self):
        a = server.Auth(b"k", "letmein")
        self.assertTrue(a.check_password("letmein"))
        self.assertFalse(a.check_password("wrong"))

    def test_disabled_without_password(self):
        a = server.Auth(b"k", None)
        self.assertFalse(a.enabled)
        self.assertFalse(a.check_password("anything"))


# --------------------------------------------------------------------------
# Store: round-trip + idempotent upsert + delete-missing
# --------------------------------------------------------------------------
class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = server.Store(self.tmpdir)

    def test_record_then_list(self):
        self.store.upsert_export("foo", "/tmp/foo.img", readonly=True)
        rows = self.store.list_exports()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "foo")
        self.assertEqual(rows[0]["file"], "/tmp/foo.img")
        self.assertTrue(rows[0]["readonly"])

    def test_upsert_replaces_existing(self):
        """Re-registering an existing name replaces file + readonly --
        operator's `make sure this export points HERE` intent."""
        self.store.upsert_export("foo", "/tmp/foo.img", readonly=True)
        self.store.upsert_export("foo", "/tmp/foo2.img", readonly=False)
        rows = self.store.list_exports()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["file"], "/tmp/foo2.img")
        self.assertFalse(rows[0]["readonly"])

    def test_delete_existing_returns_true(self):
        self.store.upsert_export("foo", "/tmp/foo.img")
        self.assertTrue(self.store.delete_export("foo"))
        self.assertEqual(self.store.list_exports(), [])

    def test_delete_missing_returns_false(self):
        self.assertFalse(self.store.delete_export("never-existed"))

    def test_list_sorted_by_name(self):
        self.store.upsert_export("c", "/tmp/c.img")
        self.store.upsert_export("a", "/tmp/a.img")
        self.store.upsert_export("b", "/tmp/b.img")
        names = [e["name"] for e in self.store.list_exports()]
        self.assertEqual(names, ["a", "b", "c"])


class TestEnsureProbeExport(unittest.TestCase):
    """The always-on ``probe`` export gives nbd-server something to
    serve unconditionally (so its subprocess is always up + STOPPED
    stays a real signal) and gives operators a smoke-test target
    (``qemu-nbd nbd://host:10809/probe`` should always answer)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = server.Store(self.tmpdir)

    def test_probe_file_created_and_registered(self):
        server._ensure_probe_export(self.store, self.tmpdir)
        probe_path = os.path.join(self.tmpdir, "probe.img")
        self.assertTrue(os.path.isfile(probe_path))
        self.assertEqual(os.path.getsize(probe_path), server.PROBE_EXPORT_SIZE)
        # Banner at head so an operator dd-ing the export sees a
        # human-readable marker before the zero-pad.
        with open(probe_path, "rb") as f:
            head = f.read(64)
        self.assertTrue(head.startswith(b"NBDMUX PROBE v"))
        rows = self.store.list_exports()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], server.PROBE_EXPORT_NAME)
        self.assertEqual(rows[0]["status"], "ready")
        self.assertTrue(rows[0]["readonly"])

    def test_probe_is_idempotent(self):
        """A second call must not rewrite the file (spares an IO
        round-trip on every daemon start) or duplicate the row."""
        server._ensure_probe_export(self.store, self.tmpdir)
        probe_path = os.path.join(self.tmpdir, "probe.img")
        first_mtime = os.path.getmtime(probe_path)
        time.sleep(0.05)  # mtime resolution guard
        server._ensure_probe_export(self.store, self.tmpdir)
        second_mtime = os.path.getmtime(probe_path)
        self.assertEqual(first_mtime, second_mtime)
        self.assertEqual(len(self.store.list_exports()), 1)

    def test_probe_regenerates_when_truncated(self):
        """If someone truncated probe.img, the next daemon start must
        rewrite it (else nbd-server would export a bad-sized file
        that fails client reads at the tail)."""
        server._ensure_probe_export(self.store, self.tmpdir)
        probe_path = os.path.join(self.tmpdir, "probe.img")
        with open(probe_path, "wb") as f:
            f.write(b"short")
        server._ensure_probe_export(self.store, self.tmpdir)
        self.assertEqual(os.path.getsize(probe_path), server.PROBE_EXPORT_SIZE)


# --------------------------------------------------------------------------
# NbdServer: config rendering (subprocess not actually spawned)
# --------------------------------------------------------------------------
class TestNbdServerConfig(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.nbd = server.NbdServer(
            data_dir=self.tmpdir, port=10809, bind="0.0.0.0", nbd_server_bin="/bin/true"
        )

    def test_render_no_exports(self):
        body = self.nbd._render_config([])
        self.assertIn("[generic]", body)
        self.assertIn("port = 10809", body)
        self.assertIn("listenaddr = 0.0.0.0", body)
        # No export sections when nothing's registered.
        self.assertNotIn("\n[", body[body.index("[generic]") + len("[generic]") :])

    def test_render_one_readonly_export(self):
        body = self.nbd._render_config(
            [{"name": "debian", "file": "/var/lib/nbdmux/debian.img", "readonly": True}]
        )
        self.assertIn("[debian]", body)
        self.assertIn("exportname = /var/lib/nbdmux/debian.img", body)
        self.assertIn("readonly = true", body)

    def test_render_writable_export_omits_readonly(self):
        """``readonly = true`` only appears when readonly is asserted;
        absence is nbd-server's writable default."""
        body = self.nbd._render_config(
            [{"name": "rw", "file": "/var/lib/nbdmux/rw.img", "readonly": False}]
        )
        self.assertIn("[rw]", body)
        self.assertNotIn("readonly", body[body.index("[rw]") :])

    def test_write_config_atomic(self):
        self.nbd.write_config([{"name": "x", "file": "/tmp/x.img", "readonly": True}])
        with open(self.nbd.config_path) as f:
            self.assertIn("[x]", f.read())
        # No leftover .tmp file
        self.assertFalse(os.path.exists(self.nbd.config_path + ".tmp"))


def _write_fake_nbd_bin(tmpdir: str) -> str:
    """Write a tiny shell script that ignores its args and blocks
    forever (via ``exec sleep``). Lets NbdServer.start /
    reload / stop exercise real subprocess supervision without
    needing nbd-server on the runner."""
    path = os.path.join(tmpdir, "fake-nbd-server")
    with open(path, "w") as f:
        f.write("#!/bin/sh\nexec sleep 60\n")
    os.chmod(path, 0o755)
    return path


@unittest.skipUnless(os.path.exists("/bin/sh"), "sh not available")
class TestNbdServerLifecycle(unittest.TestCase):
    """Exercise NbdServer's supervision surface end-to-end against a
    fake nbd-server binary that blocks on ``sleep``. The audit noted
    the deferred-start path (empty exports -> no subprocess) + the
    empty-reload path (config drops to zero exports -> stop the
    daemon) had zero coverage."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.fake_bin = _write_fake_nbd_bin(self.tmpdir)
        self.nbd = server.NbdServer(
            data_dir=self.tmpdir,
            port=10809,
            bind="0.0.0.0",
            nbd_server_bin=self.fake_bin,
        )

    def tearDown(self):
        self.nbd.stop()

    def _one_export(self):
        return [{"name": "demo", "file": "/tmp/demo.img", "readonly": True}]

    def test_start_with_empty_exports_is_deferred(self):
        # No exports -> config gets written, but no subprocess is
        # spawned (nbd-server would hard-fail with 'No configured
        # exports; quitting').
        self.nbd.start([])
        self.assertFalse(self.nbd.is_running())
        self.assertTrue(os.path.exists(self.nbd.config_path))

    def test_start_with_one_export_spawns_subprocess(self):
        self.nbd.start(self._one_export())
        self.assertTrue(self.nbd.is_running())

    def test_reload_from_empty_starts_deferred_daemon(self):
        # start([]) deferred it; first non-empty reload() lifts off.
        self.nbd.start([])
        self.assertFalse(self.nbd.is_running())
        self.nbd.reload(self._one_export())
        self.assertTrue(self.nbd.is_running())

    def test_reload_to_empty_stops_running_daemon(self):
        # An empty reload() with a currently-running daemon must stop
        # it cleanly; SIGHUP-ing an empty-INI would kill it messily.
        self.nbd.start(self._one_export())
        self.assertTrue(self.nbd.is_running())
        self.nbd.reload([])
        self.assertFalse(self.nbd.is_running())

    def test_reload_while_empty_and_stopped_is_no_op(self):
        # Neither the daemon nor the config had exports; a subsequent
        # empty reload() should just rewrite the (still-empty) config
        # and stay dormant, not crash.
        self.nbd.start([])
        self.nbd.reload([])
        self.assertFalse(self.nbd.is_running())

    def test_start_is_idempotent(self):
        self.nbd.start(self._one_export())
        pid_before = self.nbd._proc.pid  # type: ignore[union-attr]
        self.nbd.start(self._one_export())
        pid_after = self.nbd._proc.pid  # type: ignore[union-attr]
        self.assertEqual(pid_before, pid_after)

    def test_stop_transitions_running_to_not_running(self):
        self.nbd.start(self._one_export())
        self.assertTrue(self.nbd.is_running())
        self.nbd.stop()
        self.assertFalse(self.nbd.is_running())


# --------------------------------------------------------------------------
# Shared fixture: fake NbdServer that records reload() calls without
# spawning the real nbd-server subprocess. Used by the Warmer /
# schema-rotation / dedup / corrupt-payload tests below whose scope is
# the pipeline state machine, not the on-the-wire nbd-server flow.
# --------------------------------------------------------------------------
class _FakeNbdServer:
    def __init__(self):
        self.reload_calls = []
        self.running = True

    def reload(self, exports):
        self.reload_calls.append(list(exports))

    def is_running(self):
        return self.running


# --------------------------------------------------------------------------
# Warm pipeline unit tests (no HTTP, no nbd-server subprocess)
# --------------------------------------------------------------------------
class TestDetectFormat(unittest.TestCase):
    def test_override_wins(self):
        self.assertEqual(server._detect_format("x.zst", "img.gz"), "img.gz")

    def test_gz_extension(self):
        self.assertEqual(server._detect_format("http://h/x.img.gz", None), "img.gz")
        self.assertEqual(server._detect_format("http://h/x.gz", None), "img.gz")

    def test_zst_extension(self):
        self.assertEqual(server._detect_format("http://h/x.img.zst", None), "img.zst")
        self.assertEqual(server._detect_format("http://h/x.zst", None), "img.zst")

    def test_xz_extension(self):
        self.assertEqual(server._detect_format("http://h/x.img.xz", None), "img.xz")
        self.assertEqual(server._detect_format("http://h/x.xz", None), "img.xz")

    def test_default_is_raw_img(self):
        self.assertEqual(server._detect_format("http://h/x.blob", None), "img")

    def test_none_src_url(self):
        self.assertEqual(server._detect_format(None, None), "img")


class TestDecompressorCmd(unittest.TestCase):
    def test_gz_maps_to_gunzip(self):
        self.assertEqual(server._decompressor_cmd("img.gz"), ["gunzip", "-c"])
        self.assertEqual(server._decompressor_cmd("gz"), ["gunzip", "-c"])

    def test_zst_maps_to_zstd(self):
        self.assertEqual(server._decompressor_cmd("img.zst"), ["zstd", "-d", "-c"])

    def test_xz_maps_to_xz(self):
        self.assertEqual(server._decompressor_cmd("img.xz"), ["xz", "-d", "-c"])

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            server._decompressor_cmd("img")


class TestResolveWithcacheUrl(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.get("NBDMUX_WITHCACHE_URL")

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        else:
            os.environ["NBDMUX_WITHCACHE_URL"] = self._saved

    def test_wraps_src_url_in_b64_path_segment(self):
        os.environ["NBDMUX_WITHCACHE_URL"] = "http://withcache:8081"
        got = server._resolve_withcache_url("https://origin/x.img.gz")
        self.assertTrue(got.startswith("http://withcache:8081/b/"))
        # The tail is a base64url-encoded canonical src URL.
        encoded = got.rsplit("/", 1)[-1]
        import base64

        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        self.assertEqual(decoded, b"https://origin/x.img.gz")

    def test_strips_trailing_slash_from_base(self):
        os.environ["NBDMUX_WITHCACHE_URL"] = "http://withcache:8081/"
        got = server._resolve_withcache_url("https://origin/x")
        self.assertNotIn("//b/", got.replace("http://", ""))

    def test_unset_raises(self):
        os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        with self.assertRaises(ValueError):
            server._resolve_withcache_url("https://origin/x")


class _WarmOrigin(http.server.BaseHTTPRequestHandler):
    """Serves the fixed payload at any path. The warm request goes
    through ``/b/<b64(src)>`` so the actual path is the encoded src
    URL; decode the tail to decide whether to serve raw or gzipped
    bytes so a single origin exercises both decompression branches."""

    PAYLOAD_RAW = b"NBDMUX-WARM-TEST-" * 64  # 1088 bytes; non-trivial
    PAYLOAD_GZ = gzip.compress(PAYLOAD_RAW)

    def do_GET(self):
        # Decode the b64 tail of the /b/<encoded> path. If the
        # encoded src URL contains ``.raw`` we serve raw bytes,
        # otherwise gzipped. Falls back to gzipped for non-/b/
        # paths (defensive).
        tail = self.path.rsplit("/", 1)[-1]
        try:
            import base64

            decoded = base64.urlsafe_b64decode(tail + "=" * (-len(tail) % 4)).decode(
                "utf-8", "replace"
            )
        except (ValueError, UnicodeDecodeError):
            decoded = ""
        if ".raw" in decoded:
            body = self.PAYLOAD_RAW
        else:
            body = self.PAYLOAD_GZ
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class TestWarmerProcess(unittest.TestCase):
    """Warmer._process is nbdmux's core pipeline; it selects a
    decompressor, streams through the withcache-wrapped URL, atomically
    lands the raw .img, and transitions the row queued -> fetching ->
    decompressing -> ready. Failures leave a ``failed`` row + no
    lingering .inflight file."""

    def setUp(self):
        self.origin = socketserver.TCPServer(("127.0.0.1", 0), _WarmOrigin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_port = self.origin.server_address[1]
        self.tmpdir = tempfile.mkdtemp()
        self.images_dir = os.path.join(self.tmpdir, "images")
        os.makedirs(self.images_dir, exist_ok=True)
        self.store = server.Store(self.tmpdir)
        self.nbd = _FakeNbdServer()
        self.warmer = server.Warmer(store=self.store, nbd=self.nbd, images_dir=self.images_dir)
        self._saved = os.environ.get("NBDMUX_WITHCACHE_URL")
        # Point the warmer at the local origin; the ``/b/<b64>``
        # rewriting sits above the transport and the local origin
        # serves any path.
        os.environ["NBDMUX_WITHCACHE_URL"] = f"http://127.0.0.1:{self.origin_port}"

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        else:
            os.environ["NBDMUX_WITHCACHE_URL"] = self._saved
        self.origin.shutdown()
        self.origin.server_close()

    def _seed_row(self, name: str, src_url: str, fmt: str) -> str:
        dest = os.path.join(self.images_dir, f"{name}.img")
        self.store.upsert_export(
            name, dest, readonly=True, status="queued", src_url=src_url, format=fmt
        )
        return dest

    def test_row_missing_returns_without_touching_state(self):
        self.warmer._process("does-not-exist")
        self.assertEqual(self.store.list_exports(), [])
        self.assertEqual(self.nbd.reload_calls, [])

    def test_non_queued_row_is_skipped(self):
        self._seed_row("skipme", "https://origin/foo.img.gz", "img.gz")
        self.store.set_status("skipme", "ready", set_completed=True)
        self.warmer._process("skipme")
        # Still "ready", not touched -> nbd_server never re-reloaded.
        self.assertEqual(self.store.get_export("skipme")["status"], "ready")
        self.assertEqual(self.nbd.reload_calls, [])

    def test_no_src_url_row_is_failed(self):
        # Seed a row and then null the src_url in-place.
        self._seed_row("orphan", "https://origin/x", "img")
        with self.store.conn() as c:
            c.execute("UPDATE exports SET src_url=NULL WHERE name='orphan'")
        self.warmer._process("orphan")
        row = self.store.get_export("orphan")
        self.assertEqual(row["status"], "failed")
        self.assertIn("src_url", row["error"])

    def test_withcache_env_unset_lands_row_in_failed(self):
        os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        self._seed_row("nowarm", "https://origin/foo.img.gz", "img.gz")
        self.warmer._process("nowarm")
        row = self.store.get_export("nowarm")
        self.assertEqual(row["status"], "failed")
        self.assertIn("NBDMUX_WITHCACHE_URL", row["error"])

    def test_happy_path_raw_img_writes_dest_and_marks_ready(self):
        # format=img -> no decompressor, straight copy of bytes.
        # ``.raw`` in the src_url makes the origin serve raw bytes.
        dest = self._seed_row("raw", "https://origin/x.raw.img", "img")
        self.warmer._process("raw")
        row = self.store.get_export("raw")
        self.assertEqual(row["status"], "ready")
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), _WarmOrigin.PAYLOAD_RAW)
        # nbd-server was re-reloaded with the new ready row.
        self.assertEqual(len(self.nbd.reload_calls), 1)
        self.assertEqual(self.nbd.reload_calls[0][0]["name"], "raw")
        # No .inflight left behind.
        self.assertFalse(os.path.exists(dest + ".inflight"))

    @unittest.skipUnless(shutil.which("gunzip"), "gunzip not installed")
    def test_happy_path_gz_decompresses_and_marks_ready(self):
        dest = self._seed_row("warm", "https://origin/x.img.gz", "img.gz")
        self.warmer._process("warm")
        row = self.store.get_export("warm")
        self.assertEqual(row["status"], "ready", f"error={row.get('error')!r}")
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), _WarmOrigin.PAYLOAD_RAW)
        self.assertFalse(os.path.exists(dest + ".inflight"))

    def test_fetch_failure_lands_row_in_failed_and_cleans_inflight(self):
        # Point at a port nothing is listening on so urlopen fails.
        os.environ["NBDMUX_WITHCACHE_URL"] = "http://127.0.0.1:1"
        dest = self._seed_row("bust", "https://origin/x.img.gz", "img.gz")
        self.warmer._process("bust")
        row = self.store.get_export("bust")
        self.assertEqual(row["status"], "failed")
        self.assertFalse(os.path.exists(dest + ".inflight"))
        self.assertFalse(os.path.exists(dest))


class TestStoreSchemaRotation(unittest.TestCase):
    """Store._maybe_rotate_on_schema_mismatch preserves an old-schema
    state.db as ``.v<N>.<ts>.bak`` and lands a fresh schema. Silent
    data loss on upgrade if this path breaks, so cover all three
    branches: pre-v0.2.0 (schema_version table absent), current
    version match (no-op), and other-version rotate."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _db_path(self):
        return os.path.join(self.tmpdir, "state.db")

    def _write_v1_db(self):
        """Emulate a pre-v0.2.0 state.db: create an ``exports`` table
        with the v1 columns and NO ``schema_version`` table."""
        path = self._db_path()
        with sqlite3.connect(path) as c:
            c.execute("CREATE TABLE exports (name TEXT PRIMARY KEY, file TEXT)")
            c.execute("INSERT INTO exports (name, file) VALUES ('legacy', '/tmp/x.img')")

    def test_missing_db_is_noop(self):
        # Fresh dir, no state.db -> instantiate Store -> creates fresh.
        s = server.Store(self.tmpdir)
        self.assertTrue(os.path.exists(self._db_path()))
        # No .bak files land because there was nothing to rotate.
        self.assertEqual([f for f in os.listdir(self.tmpdir) if ".bak" in f], [])
        self.assertEqual(s.list_exports(), [])

    def test_current_version_is_noop(self):
        # First Store instance creates schema_version=CURRENT.
        s1 = server.Store(self.tmpdir)
        s1.upsert_export("keeper", "/tmp/keep.img")
        # Second instance sees version-match, does NOT rotate.
        s2 = server.Store(self.tmpdir)
        names = [e["name"] for e in s2.list_exports()]
        self.assertIn("keeper", names)
        self.assertEqual([f for f in os.listdir(self.tmpdir) if ".bak" in f], [])

    def test_pre_v0_2_0_rotates(self):
        """schema_version table absent (interpreted as v1) -> rotate."""
        self._write_v1_db()
        s = server.Store(self.tmpdir)
        # The legacy row is gone (fresh DB); the .bak file exists.
        self.assertEqual(s.list_exports(), [])
        baks = [f for f in os.listdir(self.tmpdir) if f.endswith(".bak")]
        self.assertEqual(len(baks), 1, f"expected 1 .bak, got {baks!r}")
        self.assertIn(".v1.", baks[0])

    def test_other_version_rotates_and_cleans_sidecars(self):
        """schema_version=99 (some future or corrupt value) -> rotate.
        Also verify -journal / -wal / -shm sidecars get unlinked."""
        path = self._db_path()
        with sqlite3.connect(path) as c:
            c.execute("CREATE TABLE schema_version (version INTEGER)")
            c.execute("INSERT INTO schema_version (version) VALUES (99)")
        # Drop stub sidecar files that the rotation should unlink.
        for suffix in ("-journal", "-wal", "-shm"):
            open(path + suffix, "w").close()
        server.Store(self.tmpdir)
        baks = [f for f in os.listdir(self.tmpdir) if f.endswith(".bak")]
        self.assertEqual(len(baks), 1)
        self.assertIn(".v99.", baks[0])
        # Sidecars gone.
        for suffix in ("-journal", "-wal", "-shm"):
            self.assertFalse(os.path.exists(path + suffix))


class TestAuthExpiry(unittest.TestCase):
    """Auth.valid rejects a token whose ``iat`` claim is older than
    MAX_AGE. Parity with withcache's TestAuth.test_expired_token_rejected;
    nbdmux dropped this test."""

    def test_expired_token_rejected(self):
        a = server.Auth(b"secret-key", "pw")
        a.MAX_AGE = -1  # every token is instantly stale
        self.assertFalse(a.valid(a.make_token()))


class TestControlBase(unittest.TestCase):
    """client.control_base normalises the ``server=`` argument the
    consumer passes to add_export / list_exports / etc. Direct tests
    since the live-server tests all pass fully-qualified URLs."""

    def test_bare_host_gets_http_prefix(self):
        self.assertEqual(client.control_base("host"), "http://host")

    def test_host_port_gets_http_prefix(self):
        self.assertEqual(client.control_base("host:8082"), "http://host:8082")

    def test_full_url_preserved(self):
        self.assertEqual(client.control_base("http://host:8082"), "http://host:8082")

    def test_trailing_slash_stripped(self):
        self.assertEqual(client.control_base("http://host:8082/"), "http://host:8082")

    def test_https_preserved(self):
        self.assertEqual(client.control_base("https://host"), "https://host")


class TestWarmerEnqueueDedup(unittest.TestCase):
    """Warmer.enqueue(name) coalesces duplicate calls into a single
    queue entry. Matters when handle_create_export_form fires twice
    because of a browser double-submit; a refactor that dropped the
    dedup would let Warmer._run double-process the same warm."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = server.Store(self.tmpdir)
        self.nbd = _FakeNbdServer()
        # Do NOT call .start(); we only exercise .enqueue().
        self.warmer = server.Warmer(store=self.store, nbd=self.nbd, images_dir=self.tmpdir)

    def test_dedup_across_multiple_calls(self):
        self.warmer.enqueue("x")
        self.warmer.enqueue("x")
        self.warmer.enqueue("x")
        self.assertEqual(list(self.warmer._queue), ["x"])

    def test_distinct_names_kept(self):
        self.warmer.enqueue("a")
        self.warmer.enqueue("b")
        self.warmer.enqueue("a")  # dup of first
        self.assertEqual(list(self.warmer._queue), ["a", "b"])


class TestWarmerCorruptPayload(unittest.TestCase):
    """When the decompressor exits rc!=0 (upstream served garbage as
    the wrong format), _fetch_and_decompress raises RuntimeError and
    _process should land the row in ``failed`` and clean the
    .inflight tempfile. TestWarmerProcess covers connection-refused
    (URL failure BEFORE the decompressor spawns); this covers the
    more common 'valid HTTP response but corrupt payload' failure."""

    def setUp(self):
        # Serve raw bytes but tell the warmer to gunzip them.
        class _RawOrigin(http.server.BaseHTTPRequestHandler):
            PAYLOAD = b"this is not gzipped bytes" * 100

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(self.PAYLOAD)))
                self.end_headers()
                self.wfile.write(self.PAYLOAD)

            def log_message(self, format, *args):
                pass

        self.origin = socketserver.TCPServer(("127.0.0.1", 0), _RawOrigin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.tmpdir = tempfile.mkdtemp()
        self.images_dir = os.path.join(self.tmpdir, "images")
        os.makedirs(self.images_dir)
        self.store = server.Store(self.tmpdir)
        self.nbd = _FakeNbdServer()
        self.warmer = server.Warmer(store=self.store, nbd=self.nbd, images_dir=self.images_dir)
        self._saved = os.environ.get("NBDMUX_WITHCACHE_URL")
        os.environ["NBDMUX_WITHCACHE_URL"] = f"http://127.0.0.1:{self.origin.server_address[1]}"

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        else:
            os.environ["NBDMUX_WITHCACHE_URL"] = self._saved
        self.origin.shutdown()
        self.origin.server_close()

    @unittest.skipUnless(shutil.which("gunzip"), "gunzip not installed")
    def test_corrupt_gz_payload_lands_row_in_failed(self):
        dest = os.path.join(self.images_dir, "corrupt.img")
        self.store.upsert_export(
            "corrupt",
            dest,
            readonly=True,
            status="queued",
            src_url="https://origin/x.img.gz",
            format="img.gz",
        )
        self.warmer._process("corrupt")
        row = self.store.get_export("corrupt")
        self.assertEqual(row["status"], "failed")
        self.assertIn("decompressor", row["error"] or "")
        # Both the .inflight tempfile and the dest are cleaned up so
        # a retry starts from scratch.
        self.assertFalse(os.path.exists(dest + ".inflight"))
        self.assertFalse(os.path.exists(dest))


if __name__ == "__main__":
    unittest.main(verbosity=2)
