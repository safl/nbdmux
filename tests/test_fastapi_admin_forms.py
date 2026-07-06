"""TestClient tests for the /admin/* form-encoded routes.

Pins the operator-UI create + delete flow: form POSTs land the
same rows the JSON /exports control plane does, validation errors
303 back to /ui/exports with ``?error=<msg>``, and the auth gate
mirrors the JSON API's semantics.

Written as unittest.TestCase to match the rest of the suite
(``make test`` = ``python3 -m unittest discover``).
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
    raise unittest.SkipTest("fastapi + httpx not installed") from None

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
    """Form-encoded src_url -> row lands as queued and the browser
    303s to /ui/exports so the dashboard reflects it. The export
    name is derived from the URL's basename (sanitised) so the
    operator doesn't have to pick one by hand."""

    def test_valid_form_creates_queued_row_and_redirects(self) -> None:
        r = self.client.post(
            "/admin/create_export",
            data={"src_url": "https://upstream.invalid/demo.img.gz"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/exports")
        # Row visible via the JSON API + on the Jinja-rendered page.
        # Name matches the URL's basename verbatim (already valid).
        listing = self.client.get("/exports").json()
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]["name"], "demo.img.gz")
        self.assertEqual(listing[0]["status"], "queued")
        self.assertEqual(listing[0]["src_url"], "https://upstream.invalid/demo.img.gz")
        body = self.client.get("/ui/exports").text
        self.assertIn("demo.img.gz", body)

    def test_url_with_non_allowlist_chars_is_sanitised(self) -> None:
        """Any character outside ``[A-Za-z0-9._-]`` folds to ``-`` so
        the derived name is INI-section-safe. Percent-encoded chars
        get decoded first so ``%20`` becomes ``-`` not ``-20-``."""
        r = self.client.post(
            "/admin/create_export",
            data={"src_url": "https://upstream.invalid/path/Ubuntu%2024.iso.zst"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        listing = self.client.get("/exports").json()
        self.assertEqual(listing[0]["name"], "Ubuntu-24.iso.zst")


class CreateExportFormValidationTests(_AdminFormsBase):
    """Every validation branch 303s back to /ui/exports with an
    ``?error=<msg>`` query so the render shows the reason inline
    -- no 400 / 500 stack traces bleeding to the operator."""

    def test_empty_src_url_redirects_with_error(self) -> None:
        r = self.client.post(
            "/admin/create_export",
            data={"src_url": "   "},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertTrue(r.headers["location"].startswith("/ui/exports?error="))
        self.assertIn("src_url", r.headers["location"])

    def test_url_without_basename_redirects_with_error(self) -> None:
        """A bare host without a path segment gives us nothing to
        derive from; refuse rather than mint a mystery ``xxx.img``."""
        for bad in ("https://upstream.invalid", "https://upstream.invalid/"):
            with self.subTest(url=bad):
                r = self.client.post(
                    "/admin/create_export",
                    data={"src_url": bad},
                    follow_redirects=False,
                )
                self.assertEqual(r.status_code, 303)
                self.assertIn("error=", r.headers["location"])

    def test_missing_withcache_url_redirects_with_error(self) -> None:
        os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        r = self.client.post(
            "/admin/create_export",
            data={"src_url": "https://upstream.invalid/demo.img.gz"},
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
            data={"src_url": "https://upstream.invalid"},
            follow_redirects=True,
        )
        self.assertEqual(r.status_code, 200)
        # ``flash`` context var renders as a Bootstrap alert.
        self.assertIn("alert-danger", r.text)
        self.assertIn("basename", r.text.lower())


class DeleteExportFormTests(_AdminFormsBase):
    def test_delete_removes_row_and_redirects(self) -> None:
        # Seed with a form-created row; the derived export name
        # matches the URL basename.
        self.client.post(
            "/admin/create_export",
            data={"src_url": "https://upstream.invalid/to-delete.img.gz"},
        )
        self.assertEqual(len(self.client.get("/exports").json()), 1)
        r = self.client.post(
            "/admin/delete_export/to-delete.img.gz", follow_redirects=False
        )
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
            data={"src_url": "https://upstream.invalid/demo.img.gz"},
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
            data={"src_url": "https://upstream.invalid/demo.img.gz"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/exports")


class CatalogPickerRenderTests(_AdminFormsBase):
    """The /ui/exports subnav offers a catalog picker populated
    from ``<NBDMUX_WITHCACHE_URL>/catalog``. On success the
    template renders a ``<select>`` with an ``<option>`` per
    entry; on failure the subnav shows an inline error. Both are
    render-time only -- the catalog fetcher is a stdlib
    ``urllib.request.urlopen`` call, so the test monkeypatches at
    that boundary."""

    def _patch_catalog(self, entries: list[dict[str, object]]) -> None:
        import io
        import json as _json
        import urllib.request as _urlreq

        payload = _json.dumps({"entries": entries}).encode("utf-8")

        def _fake_urlopen(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            return io.BytesIO(payload)

        self._orig_urlopen = _urlreq.urlopen
        _urlreq.urlopen = _fake_urlopen  # type: ignore[assignment]

    def _restore_catalog(self) -> None:
        import urllib.request as _urlreq

        _urlreq.urlopen = self._orig_urlopen  # type: ignore[assignment]

    def test_picker_lists_catalog_entries(self) -> None:
        self._patch_catalog(
            [
                {
                    "name": "ubuntu-24.04",
                    "src": "https://upstream.invalid/ubuntu-24.04.img.gz",
                    "format": "img.gz",
                },
                {"name": "no-src-drops"},  # dropped by the filter
            ]
        )
        try:
            body = self.client.get("/ui/exports").text
        finally:
            self._restore_catalog()
        self.assertIn('name="src_url"', body)
        self.assertIn("https://upstream.invalid/ubuntu-24.04.img.gz", body)
        self.assertIn("ubuntu-24.04", body)
        # And the URL text input is gone.
        self.assertNotIn('type="url"', body)

    def test_picker_shows_empty_hint_when_catalog_is_empty(self) -> None:
        self._patch_catalog([])
        try:
            body = self.client.get("/ui/exports").text
        finally:
            self._restore_catalog()
        self.assertIn("withcache catalog is empty", body)

    def test_picker_shows_unreachable_hint_on_transport_error(self) -> None:
        import urllib.error as _urlerr
        import urllib.request as _urlreq

        def _boom(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            raise _urlerr.URLError("connection refused")

        orig = _urlreq.urlopen
        _urlreq.urlopen = _boom  # type: ignore[assignment]
        try:
            body = self.client.get("/ui/exports").text
        finally:
            _urlreq.urlopen = orig  # type: ignore[assignment]
        self.assertIn("catalog unreachable", body)


class CatalogPickerWithoutWithcacheTests(_AdminFormsBase):
    WITHCACHE_URL = None

    def test_picker_shows_configure_hint(self) -> None:
        body = self.client.get("/ui/exports").text
        self.assertIn("NBDMUX_WITHCACHE_URL", body)
        # No src_url field at all when unconfigured.
        self.assertNotIn('name="src_url"', body)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
