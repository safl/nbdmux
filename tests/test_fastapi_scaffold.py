"""FastAPI smoke tests.

Pins the baseline shape of the operator control plane:

- /healthz returns 200 + a JSON body naming service + version.
- /ui/login renders on GET without auth.
- Un-authed /ui/exports 303s to /ui/login.
- Login with the right password mints the session; /ui/exports
  then renders (200) rather than redirecting.
- Login with the wrong password stays on the form + reports
  "Invalid password" so the operator gets a clear signal.

Uses FastAPI TestClient. Written as unittest.TestCase (not
pytest) so ``make test`` (``python3 -m unittest discover``)
picks these up alongside the legacy ``test_nbdmux.py`` suite.
When the wider port lands the whole suite will move to pytest;
until then, unittest keeps the CI matrix (3.10-3.13) uniform.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from fastapi.testclient import TestClient  # noqa: E402
except ImportError:  # pragma: no cover
    # Older matrix rows / stripped venvs without the port deps skip
    # this file rather than hard-erroring at collection time.
    raise unittest.SkipTest("fastapi + httpx not installed") from None

from nbdmux._app import create_app  # noqa: E402

TEST_PASSWORD = "test-admin-pw"
TEST_SECRET = b"test-secret-not-for-prod-use-32b_"


class FastAPIScaffoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_pw = os.environ.get("NBDMUX_ADMIN_PASSWORD")
        os.environ["NBDMUX_ADMIN_PASSWORD"] = TEST_PASSWORD
        self._tmpdir = tempfile.mkdtemp()
        app = create_app(data_dir=self._tmpdir, secret_key=TEST_SECRET)
        self.client = TestClient(app, follow_redirects=False)

    def tearDown(self) -> None:
        self.client.close()
        if self._saved_pw is None:
            os.environ.pop("NBDMUX_ADMIN_PASSWORD", None)
        else:
            os.environ["NBDMUX_ADMIN_PASSWORD"] = self._saved_pw
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _login(self, password: str = TEST_PASSWORD) -> None:
        r = self.client.post("/ui/login", data={"password": password}, follow_redirects=False)
        self.assertIn(r.status_code, (200, 303))

    def test_healthz_returns_200_json(self) -> None:
        """/healthz returns 200 + a single-line JSON body naming the
        service. Container probes and bty-web's reachability pill
        key on this shape."""
        r = self.client.get("/healthz")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["service"], "nbdmux")
        self.assertIn("version", body)

    def test_ui_login_form_renders_without_auth(self) -> None:
        r = self.client.get("/ui/login")
        self.assertEqual(r.status_code, 200)
        body = r.text
        self.assertIn("Log in", body)
        self.assertIn('name="password"', body)
        self.assertIn("NBDMUX_ADMIN_PASSWORD", body)

    def test_ui_exports_without_auth_redirects_to_login(self) -> None:
        """Un-authed request 303s to /ui/login (same shape as bty's
        require_ui_auth dependency)."""
        r = self.client.get("/ui/exports")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/login")

    def test_root_redirects_to_dashboard(self) -> None:
        r = self.client.get("/")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/dashboard")

    def test_ui_login_wrong_password_re_renders_with_error(self) -> None:
        r = self.client.post("/ui/login", data={"password": "not-the-password"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("Invalid password", r.text)

    def test_ui_login_valid_password_sets_session_and_reaches_dashboard(self) -> None:
        r = self.client.post("/ui/login", data={"password": TEST_PASSWORD}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/dashboard")
        r2 = self.client.get("/ui/dashboard")
        self.assertEqual(r2.status_code, 200)
        self.assertIn("NBDMUX", r2.text)
        self.assertIn("brand-accent", r2.text)

    def test_ui_logout_clears_session_and_redirects(self) -> None:
        self._login()
        r = self.client.post("/ui/logout", follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/login")
        r2 = self.client.get("/ui/exports")
        self.assertEqual(r2.status_code, 303)
        self.assertEqual(r2.headers["location"], "/ui/login")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
