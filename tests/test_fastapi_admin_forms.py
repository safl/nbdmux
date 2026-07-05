"""TestClient tests for the /admin/* form-encoded routes.

Pins the operator-UI create + delete flow: form POSTs land the
same rows the JSON /exports control plane does, validation errors
303 back to /ui/exports with ``?error=<msg>``, and the auth gate
mirrors the JSON API's semantics.

Written as unittest.TestCase to match the rest of the port's
test scaffolding (``make test`` = ``python3 -m unittest discover``).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from fastapi.testclient import TestClient  # noqa: E402
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("fastapi + httpx not available (port scaffolding deps)") from None

from nbdmux._app import create_app  # noqa: E402

TEST_PASSWORD = "test-admin-pw"
TEST_SECRET = b"test-secret-not-for-prod-use-32b_"


class _AdminFormsBase(unittest.TestCase):
    ENABLE_AUTH = False
    WITHCACHE_URL: str | None = "http://withcache.invalid:8081"

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._saved_pw = os.environ.get("NBDMUX_ADMIN_PASSWORD")
        self._saved_wc = os.environ.get("NBDMUX_WITHCACHE_URL")
        if self.ENABLE_AUTH:
            os.environ["NBDMUX_ADMIN_PASSWORD"] = TEST_PASSWORD
        else:
            os.environ.pop("NBDMUX_ADMIN_PASSWORD", None)
        if self.WITHCACHE_URL is None:
            os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        else:
            os.environ["NBDMUX_WITHCACHE_URL"] = self.WITHCACHE_URL
        app = create_app(data_dir=self._tmpdir, secret_key=TEST_SECRET)
        self.client = TestClient(app, follow_redirects=False)

    def tearDown(self) -> None:
        self.client.close()
        for key, saved in (
            ("NBDMUX_ADMIN_PASSWORD", self._saved_pw),
            ("NBDMUX_WITHCACHE_URL", self._saved_wc),
        ):
            if saved is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = saved
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _login(self) -> None:
        r = self.client.post("/ui/login", data={"password": TEST_PASSWORD}, follow_redirects=False)
        self.assertEqual(r.status_code, 303, r.text)


class CreateExportFormHappyPathTests(_AdminFormsBase):
    """Form-encoded name + src_url -> row lands as queued and the
    browser 303s to /ui/exports so the dashboard reflects it."""

    def test_valid_form_creates_queued_row_and_redirects(self) -> None:
        r = self.client.post(
            "/admin/create_export",
            data={
                "name": "demo",
                "src_url": "https://upstream.invalid/demo.img.gz",
            },
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/exports")
        # Row visible via the JSON API + on the Jinja-rendered page.
        listing = self.client.get("/exports").json()
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]["name"], "demo")
        self.assertEqual(listing[0]["status"], "queued")
        self.assertEqual(listing[0]["src_url"], "https://upstream.invalid/demo.img.gz")
        body = self.client.get("/ui/exports").text
        self.assertIn("demo", body)


class CreateExportFormValidationTests(_AdminFormsBase):
    """Every validation branch 303s back to /ui/exports with an
    ``?error=<msg>`` query so the render shows the reason inline
    -- no 400 / 500 stack traces bleeding to the operator."""

    def test_empty_name_redirects_with_error(self) -> None:
        r = self.client.post(
            "/admin/create_export",
            data={"name": "  ", "src_url": "https://upstream.invalid/demo"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertTrue(r.headers["location"].startswith("/ui/exports?error="))
        self.assertIn("name", r.headers["location"])

    def test_bad_name_shape_redirects_with_error(self) -> None:
        """Names get injected as ``[<name>]`` in nbd-server.conf;
        reject anything with slashes / spaces / brackets so the
        INI stays parseable."""
        for bad in ("has space", "has/slash", "]bracket", "-leading-dash"):
            with self.subTest(name=bad):
                r = self.client.post(
                    "/admin/create_export",
                    data={"name": bad, "src_url": "https://upstream.invalid/demo"},
                    follow_redirects=False,
                )
                self.assertEqual(r.status_code, 303)
                self.assertIn("error=", r.headers["location"])

    def test_missing_src_url_redirects_with_error(self) -> None:
        # FastAPI's Form(...) requires the field; a missing field
        # 422s at the framework layer rather than reaching our
        # handler. Test the "empty after strip" branch instead --
        # a blank submission the operator would actually make.
        r = self.client.post(
            "/admin/create_export",
            data={"name": "demo", "src_url": "   "},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertIn("src_url", r.headers["location"])

    def test_missing_withcache_url_redirects_with_error(self) -> None:
        os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        r = self.client.post(
            "/admin/create_export",
            data={"name": "demo", "src_url": "https://upstream.invalid/demo"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertIn("NBDMUX_WITHCACHE_URL", r.headers["location"])

    def test_error_renders_inline_on_exports_page(self) -> None:
        """After a validation failure, the redirect target renders a
        danger alert with the error text so an operator sees why
        nothing was created without opening dev tools."""
        r = self.client.post(
            "/admin/create_export",
            data={"name": "]bad", "src_url": "https://upstream.invalid/demo"},
            follow_redirects=True,
        )
        self.assertEqual(r.status_code, 200)
        # ``flash`` context var renders as a Bootstrap alert.
        self.assertIn("alert-danger", r.text)
        self.assertIn("name", r.text.lower())


class DeleteExportFormTests(_AdminFormsBase):
    def test_delete_removes_row_and_redirects(self) -> None:
        # Seed with a form-created row.
        self.client.post(
            "/admin/create_export",
            data={
                "name": "to-delete",
                "src_url": "https://upstream.invalid/x.img.gz",
            },
        )
        self.assertEqual(len(self.client.get("/exports").json()), 1)
        r = self.client.post("/admin/delete_export/to-delete", follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/exports")
        self.assertEqual(self.client.get("/exports").json(), [])

    def test_delete_unknown_still_303_and_no_error(self) -> None:
        """Idempotent from the operator's perspective: a repeat click
        on a row that already vanished still lands on /ui/exports
        without an error flash. Same "make sure this is gone" intent
        the JSON DELETE + client library share."""
        r = self.client.post("/admin/delete_export/never-existed", follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/exports")


class AuthGatedTests(_AdminFormsBase):
    ENABLE_AUTH = True

    def test_create_form_requires_session(self) -> None:
        """Auth on -> POST /admin/create_export without session 303s
        to /ui/login (same shape as any other /ui/* route)."""
        r = self.client.post(
            "/admin/create_export",
            data={"name": "demo", "src_url": "https://upstream.invalid/demo"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/login")

    def test_delete_form_requires_session(self) -> None:
        r = self.client.post("/admin/delete_export/demo", follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/login")

    def test_create_form_works_after_login(self) -> None:
        self._login()
        r = self.client.post(
            "/admin/create_export",
            data={"name": "demo", "src_url": "https://upstream.invalid/demo"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/exports")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
