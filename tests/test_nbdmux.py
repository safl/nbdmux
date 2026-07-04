"""Stdlib-only tests for nbdmux. Run with:  python -m unittest -v

No third-party deps; src/ is put on the path so the package imports
without an install.
"""

import gzip
import http.client
import http.server
import json
import os
import shutil
import socketserver
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

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
# HTTP control plane (live server, no nbd-server subprocess)
# --------------------------------------------------------------------------
class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _FakeNbdServer:
    """Stand-in for NbdServer that records reload() calls but doesn't
    spawn anything. Lets the HTTP handler exercise the register/unregister
    flow without needing nbd-server installed on the test runner."""

    def __init__(self):
        self.reload_calls = []
        self.running = True

    def reload(self, exports):
        self.reload_calls.append(list(exports))

    def is_running(self):
        return self.running


def _start_nbdmux(password=None):
    tmpdir = tempfile.mkdtemp()
    images_dir = os.path.join(tmpdir, "images")
    os.makedirs(images_dir, exist_ok=True)
    store = server.Store(tmpdir)
    auth = server.Auth(b"k", password)
    nbd = _FakeNbdServer()
    # The warmer is wired but not started; the tests in this file
    # only exercise the {name, file} pre-warmed POST path (no
    # src_url warming), so the worker thread doesn't need to be
    # running. Tests that exercise the warmer build their own
    # fixture.
    warmer = server.Warmer(store=store, nbd=nbd, images_dir=images_dir)
    httpd = _ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    httpd.store = store
    httpd.auth = auth
    httpd.nbd = nbd
    httpd.nbd_port = 10809
    httpd.warmer = warmer
    httpd.images_dir = images_dir
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, store, nbd


class TestHttpExports(unittest.TestCase):
    def setUp(self):
        self.httpd, self.store, self.nbd = _start_nbdmux()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        # A real file the handler can validate against.
        self.fd, self.img = tempfile.mkstemp(suffix=".img")
        os.write(self.fd, b"fake disk image")
        os.close(self.fd)

    def tearDown(self):
        os.remove(self.img)
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_post_lists_and_deletes(self):
        # POST /exports
        body = json.dumps({"name": "demo", "file": self.img, "readonly": True}).encode()
        req = urllib.request.Request(
            self.base + "/exports", data=body, headers={"Content-Type": "application/json"}
        )
        resp = json.loads(urllib.request.urlopen(req).read())
        self.assertEqual(resp["name"], "demo")
        self.assertEqual(resp["file"], self.img)
        # The fake nbd-server received exactly one reload with the new export.
        self.assertEqual(len(self.nbd.reload_calls), 1)
        self.assertEqual(self.nbd.reload_calls[0][0]["name"], "demo")

        # GET /exports
        rows = json.loads(urllib.request.urlopen(self.base + "/exports").read())
        self.assertEqual([r["name"] for r in rows], ["demo"])

        # DELETE /exports/demo -> 204
        req = urllib.request.Request(self.base + "/exports/demo", method="DELETE")
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 204)
        self.assertEqual(json.loads(urllib.request.urlopen(self.base + "/exports").read()), [])
        # And the reload that followed the delete.
        self.assertEqual(len(self.nbd.reload_calls), 2)
        self.assertEqual(self.nbd.reload_calls[1], [])

    def test_post_rejects_missing_file(self):
        body = json.dumps({"name": "x", "file": "/nonexistent/path.img"}).encode()
        req = urllib.request.Request(
            self.base + "/exports", data=body, headers={"Content-Type": "application/json"}
        )
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)
        # No reload fired for a rejected request.
        self.assertEqual(self.nbd.reload_calls, [])

    def test_post_rejects_relative_path(self):
        body = json.dumps({"name": "x", "file": "relative.img"}).encode()
        req = urllib.request.Request(
            self.base + "/exports", data=body, headers={"Content-Type": "application/json"}
        )
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)

    def test_post_rejects_name_with_slash(self):
        """Name goes into nbd-server's INI [section] header; reject
        anything that could escape the section name."""
        body = json.dumps({"name": "foo/bar", "file": self.img}).encode()
        req = urllib.request.Request(
            self.base + "/exports", data=body, headers={"Content-Type": "application/json"}
        )
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)

    def test_delete_unknown_returns_404(self):
        req = urllib.request.Request(self.base + "/exports/ghost", method="DELETE")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 404)

    def test_healthz_ok_when_nbd_running(self):
        self.assertEqual(urllib.request.urlopen(self.base + "/healthz").read(), b"ok\n")

    def test_healthz_503_when_nbd_down(self):
        """The container HEALTHCHECK hits /healthz to decide whether
        the container is alive. When nbd-server is down (crash, kill,
        deferred-start with no exports yet), /healthz must reflect
        that so orchestration sees the container as unhealthy and
        fires the restart policy."""
        self.nbd.running = False
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.base + "/healthz")
        self.assertEqual(cm.exception.code, 503)

    def test_delete_prewarmed_does_not_unlink_operator_file(self):
        """Pre-warmed exports (POST /exports {name, file}) point at a
        file the operator placed on disk. Deleting the export must
        drop the DB row but NEVER unlink the operator's file."""
        body = json.dumps({"name": "op", "file": self.img, "readonly": True}).encode()
        req = urllib.request.Request(
            self.base + "/exports", data=body, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req).read()
        req = urllib.request.Request(self.base + "/exports/op", method="DELETE")
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 204)
        self.assertTrue(os.path.exists(self.img), "operator's file was unlinked; must not be")


class TestDeleteUnlinksWarmCreated(unittest.TestCase):
    """Warm-created exports (row has ``src_url``) live at a
    nbdmux-owned path under ``images_dir``. DELETE /exports/<name>
    must both drop the row AND unlink the file, otherwise a
    create-then-delete cycle leaks disk space forever."""

    def setUp(self):
        self.httpd, self.store, _ = _start_nbdmux()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.images_dir = self.httpd.images_dir  # type: ignore[attr-defined]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_delete_warm_created_unlinks_img_file(self):
        # Simulate a completed warm: row with src_url + a file on disk
        # at the nbdmux-allocated path.
        dest = os.path.join(self.images_dir, "warm.img")
        with open(dest, "wb") as f:
            f.write(b"warmed bytes")
        self.store.upsert_export(
            "warm",
            dest,
            readonly=True,
            status="ready",
            src_url="https://example/foo.img.zst",
            format="img.zst",
        )
        self.assertTrue(os.path.exists(dest))
        req = urllib.request.Request(self.base + "/exports/warm", method="DELETE")
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 204)
        self.assertFalse(
            os.path.exists(dest),
            "warm-created .img was not unlinked; DELETE leaks disk space",
        )

    def test_delete_warm_created_row_gone_even_if_file_missing(self):
        # If the file is already gone (external cleanup), DELETE
        # still succeeds and drops the row; the unlink is
        # best-effort.
        dest = os.path.join(self.images_dir, "ghost.img")
        self.store.upsert_export(
            "ghost",
            dest,
            readonly=True,
            status="failed",
            src_url="https://example/ghost.img.zst",
            format="img.zst",
        )
        req = urllib.request.Request(self.base + "/exports/ghost", method="DELETE")
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 204)


class TestDashboardErrBanner(unittest.TestCase):
    """render_dash surfaces ``?err=<kind>`` (the redirect target for
    handle_create_export_form validation failures) as a visible
    alert banner. Without it, submitting a bad form silently
    navigates back to / and the operator gets no signal."""

    def setUp(self):
        self.httpd, _, _ = _start_nbdmux()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _get(self, path: str) -> str:
        return urllib.request.urlopen(self.base + path).read().decode("utf-8")

    def test_err_name_renders_name_message(self):
        body = self._get("/?err=name")
        self.assertIn("alert-danger", body)
        self.assertIn("Name is required", body)

    def test_err_src_url_renders_src_url_message(self):
        body = self._get("/?err=src_url")
        self.assertIn("alert-danger", body)
        self.assertIn("Source URL is required", body)

    def test_err_withcache_unset_renders_withcache_message(self):
        body = self._get("/?err=withcache_unset")
        self.assertIn("alert-danger", body)
        self.assertIn("NBDMUX_WITHCACHE_URL", body)

    def test_no_err_renders_no_banner(self):
        body = self._get("/")
        self.assertNotIn("alert-danger", body)

    def test_unknown_err_kind_still_shows_generic_banner(self):
        body = self._get("/?err=mysterious")
        self.assertIn("alert-danger", body)
        self.assertIn("mysterious", body)


# --------------------------------------------------------------------------
# Auth-gated control endpoints
# --------------------------------------------------------------------------
class TestAuthGate(unittest.TestCase):
    def setUp(self):
        self.httpd, _, self.nbd = _start_nbdmux(password="letmein")
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_post_export_without_cookie_returns_401(self):
        body = json.dumps({"name": "x", "file": "/tmp/x"}).encode()
        req = urllib.request.Request(
            self.base + "/exports", data=body, headers={"Content-Type": "application/json"}
        )
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 401)

    def test_get_exports_is_open_even_with_auth_enabled(self):
        """Reading the export list is unauthenticated -- consumers (bty)
        may need to poll status from another container without holding a
        session cookie. Writes still require auth."""
        urllib.request.urlopen(self.base + "/exports").read()  # 200, no auth header

    def test_healthz_is_open(self):
        """The auth gate does not apply to /healthz. Assert that we get
        past the gate (no 401) rather than the specific 200/503 -- the
        supervision-status split is exercised in TestHttpExports."""
        # Pin the fixture state so the test doesn't rot when
        # _FakeNbdServer's default flips.
        self.nbd.running = True
        urllib.request.urlopen(self.base + "/healthz").read()  # 200, no auth header


# --------------------------------------------------------------------------
# /admin/create_export -- the New Export subnav form
# --------------------------------------------------------------------------
def _post_form(host: str, port: int, path: str, form: dict) -> tuple[int, str | None]:
    """POST a form-encoded body without following redirects; the form
    handler always answers with a 303 and urllib would silently follow
    it, hiding the Location value that the tests are verifying.
    Returns ``(status, location)``; the response body is discarded."""
    body = urllib.parse.urlencode(form)
    conn = http.client.HTTPConnection(host, port)
    try:
        conn.request(
            "POST",
            path,
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp = conn.getresponse()
        location = resp.getheader("Location")
        status = resp.status
        resp.read()
        return status, location
    finally:
        conn.close()


class TestCreateExportForm(unittest.TestCase):
    """POST /admin/create_export is the operator-visible create path
    (New Export subnav). Verifies redirects, validation, and store
    state; no auth (open mode)."""

    def setUp(self):
        self.httpd, self.store, self.nbd = _start_nbdmux()
        self.host = "127.0.0.1"
        self.port = self.httpd.server_address[1]
        self._saved = os.environ.get("NBDMUX_WITHCACHE_URL")
        os.environ["NBDMUX_WITHCACHE_URL"] = "http://withcache-test:8081"

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        else:
            os.environ["NBDMUX_WITHCACHE_URL"] = self._saved
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_valid_form_creates_queued_export_and_303s(self):
        status, location = _post_form(
            self.host,
            self.port,
            "/admin/create_export",
            {"name": "demo", "src_url": "https://example/demo.img.zst"},
        )
        self.assertEqual(status, 303)
        self.assertEqual(location, "/")
        rows = self.store.list_exports()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "demo")
        self.assertEqual(rows[0]["status"], "queued")
        self.assertEqual(rows[0]["src_url"], "https://example/demo.img.zst")

    def test_empty_name_redirects_with_err(self):
        status, location = _post_form(
            self.host,
            self.port,
            "/admin/create_export",
            {"name": "", "src_url": "https://example/demo.img"},
        )
        self.assertEqual(status, 303)
        self.assertEqual(location, "/?err=name")
        self.assertEqual(self.store.list_exports(), [])

    def test_slash_in_name_redirects_with_err(self):
        status, location = _post_form(
            self.host,
            self.port,
            "/admin/create_export",
            {"name": "foo/bar", "src_url": "https://example/demo.img"},
        )
        self.assertEqual(status, 303)
        self.assertEqual(location, "/?err=name")

    def test_ini_metachars_in_name_redirects_with_err(self):
        """Characters that could corrupt the ``[<name>]`` INI section
        header nbd-server parses must be rejected -- otherwise an
        authenticated operator could inject a rogue export section
        via ``name=x]\\n[rogue\\nexportname=...``. Covers ``]``,
        ``[``, ``#``, ``;``, ``=``, ``\\n``, plus a leading dot."""
        for bad in ("x]y", "x[y", "x#y", "x;y", "x=y", "x\ny", ".hidden"):
            with self.subTest(name=bad):
                status, location = _post_form(
                    self.host,
                    self.port,
                    "/admin/create_export",
                    {"name": bad, "src_url": "https://example/x.img"},
                )
                self.assertEqual(status, 303)
                self.assertEqual(location, "/?err=name")
        # A valid alnum-leading name still lands (control).
        status, location = _post_form(
            self.host,
            self.port,
            "/admin/create_export",
            {"name": "demo-1.2_3", "src_url": "https://example/x.img"},
        )
        self.assertEqual(status, 303)
        self.assertEqual(location, "/")

    def test_ini_metachars_rejected_on_json_post_exports(self):
        """Same validation must fire on POST /exports so the JSON API
        can't sidestep it."""
        import urllib.request

        body = json.dumps({"name": "x]y", "src_url": "https://example/x.img.zst"}).encode()
        req = urllib.request.Request(
            f"http://{self.host}:{self.port}/exports",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)
        self.assertIn(b"nbd-server.conf", cm.exception.read())

    def test_missing_src_url_redirects_with_err(self):
        status, location = _post_form(
            self.host,
            self.port,
            "/admin/create_export",
            {"name": "demo", "src_url": ""},
        )
        self.assertEqual(status, 303)
        self.assertEqual(location, "/?err=src_url")

    def test_withcache_unset_redirects_with_err(self):
        os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        status, location = _post_form(
            self.host,
            self.port,
            "/admin/create_export",
            {"name": "demo", "src_url": "https://example/demo.img.zst"},
        )
        self.assertEqual(status, 303)
        self.assertEqual(location, "/?err=withcache_unset")

    def test_duplicate_form_field_redirects_with_err_malformed(self):
        """read_form rejects duplicate keys so a client can't hide a
        payload behind a first-value-wins collapse. The redirect goes
        to /?err=malformed and no row is created."""
        # Craft a raw body with duplicate ``name`` fields; urlencode
        # + a dict argument would collapse them client-side.
        conn = http.client.HTTPConnection(self.host, self.port)
        try:
            body = "name=evil&name=demo&src_url=https%3A%2F%2Fexample%2Fx.img.zst"
            conn.request(
                "POST",
                "/admin/create_export",
                body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 303)
            self.assertEqual(resp.getheader("Location"), "/?err=malformed")
            resp.read()
        finally:
            conn.close()
        self.assertEqual(self.store.list_exports(), [])


class TestCreateExportFormAuthGate(unittest.TestCase):
    """With NBDMUX_ADMIN_PASSWORD set, POST /admin/create_export must
    require a session cookie; without one, redirect to /ui/login."""

    def setUp(self):
        self.httpd, _, _ = _start_nbdmux(password="letmein")
        self.host = "127.0.0.1"
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_unauth_redirects_to_login(self):
        status, location = _post_form(
            self.host,
            self.port,
            "/admin/create_export",
            {"name": "demo", "src_url": "https://x/y.img"},
        )
        self.assertEqual(status, 303)
        self.assertEqual(location, "/ui/login")


# --------------------------------------------------------------------------
# Client library against the live HTTP server
# --------------------------------------------------------------------------
class TestClientLibrary(unittest.TestCase):
    def setUp(self):
        self.httpd, _, self.nbd = _start_nbdmux()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.fd, self.img = tempfile.mkstemp(suffix=".img")
        os.write(self.fd, b"abc")
        os.close(self.fd)

    def tearDown(self):
        os.remove(self.img)
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_add_list_remove_roundtrip(self):
        rec = client.add_export("demo", self.img, server=self.base)
        self.assertEqual(rec["name"], "demo")
        self.assertEqual([e["name"] for e in client.list_exports(self.base)], ["demo"])
        client.remove_export("demo", self.base)
        self.assertEqual(client.list_exports(self.base), [])

    def test_remove_missing_is_idempotent(self):
        """remove_export on a non-existent name swallows the 404 --
        operator's "make sure this is gone" intent."""
        client.remove_export("never-existed", self.base)  # must not raise

    def test_add_rejects_relative_path_via_NbdmuxError(self):
        with self.assertRaises(client.NbdmuxError):
            client.add_export("x", "relative-path.img", server=self.base)

    def test_is_healthy(self):
        self.assertTrue(client.is_healthy(self.base))

    def test_is_healthy_false_on_unreachable(self):
        self.assertFalse(client.is_healthy("http://127.0.0.1:1", timeout=0.5))

    def test_warm_export_wire_shape_reaches_handler(self):
        """warm_export POSTs ``{name, src_url, readonly}`` to /exports.
        With NBDMUX_WITHCACHE_URL unset on the daemon the server
        returns 400 with the ``withcache`` reason -- the fact we get
        that specific error back proves the wire payload was
        well-formed and the src_url branch of POST /exports fired."""
        saved = os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        try:
            with self.assertRaises(client.NbdmuxError) as cm:
                client.warm_export(
                    "warmme",
                    "https://example/foo.img.zst",
                    server=self.base,
                )
            self.assertIn("withcache", str(cm.exception).lower())
        finally:
            if saved is not None:
                os.environ["NBDMUX_WITHCACHE_URL"] = saved

    def test_warm_export_forwards_format_override(self):
        """When ``format`` is explicit, it lands in the row so the
        warmer picks the matching decompressor even if the src_url's
        extension doesn't tell the story."""
        os.environ["NBDMUX_WITHCACHE_URL"] = "http://withcache.test:8081"
        try:
            record = client.warm_export(
                "gz-explicit",
                "https://example/foo.blob",  # no .gz extension
                format_hint="img.gz",
                server=self.base,
            )
            self.assertEqual(record["format"], "img.gz")
            self.assertEqual(record["src_url"], "https://example/foo.blob")
            self.assertEqual(record["status"], "queued")
        finally:
            os.environ.pop("NBDMUX_WITHCACHE_URL", None)


# --------------------------------------------------------------------------
# Warm pipeline: _detect_format, _decompressor_cmd, _resolve_withcache_url,
# and Warmer._process end-to-end against a local origin.
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


class TestServeStatic(unittest.TestCase):
    """Handler.serve_static serves the bundled Bootstrap CSS / htmx
    assets and refuses ``..`` path-traversal. Security-adjacent guard
    on a public (unauthenticated) endpoint."""

    def setUp(self):
        self.httpd, _, _ = _start_nbdmux()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_bundled_asset_serves_with_correct_mime(self):
        r = urllib.request.urlopen(self.base + "/static/bootstrap.min.css")
        self.assertEqual(r.status, 200)
        # Some Python releases append ``; charset=utf-8`` to text/css;
        # assert on the prefix so both shapes accept.
        self.assertTrue(r.getheader("Content-Type").startswith("text/css"))
        self.assertGreater(int(r.getheader("Content-Length")), 0)

    def test_empty_static_path_returns_404(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.base + "/static/")
        self.assertEqual(cm.exception.code, 404)

    def test_dotdot_traversal_rejected(self):
        # abspath resolves and startswith(static_root) rejects.
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.base + "/static/../server.py")
        self.assertEqual(cm.exception.code, 404)

    def test_absent_asset_returns_404(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.base + "/static/does-not-exist.css")
        self.assertEqual(cm.exception.code, 404)


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
