"""Stdlib-only tests for nbdmux. Run with:  python -m unittest -v

No third-party deps; src/ is put on the path so the package imports
without an install.
"""

import http.client
import http.server
import json
import os
import socketserver
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

    def test_healthz(self):
        self.assertEqual(urllib.request.urlopen(self.base + "/healthz").read(), b"ok\n")


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
        self.httpd, _, _ = _start_nbdmux(password="letmein")
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
