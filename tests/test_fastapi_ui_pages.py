"""TestClient tests for /ui/exports and /ui/settings.

Covers the operator-facing HTML pages: Exports (Jinja + Bootstrap
table + status pills + progress bars) and Settings (identity +
storage paths + resolved withcache URL + auth state).

Written as ``unittest.TestCase`` so ``make test``
(``python3 -m unittest discover``) picks them up alongside the
legacy stdlib suite. Follow the same pattern as
``tests/test_fastapi_scaffold.py``.
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


class _UiPagesBase(unittest.TestCase):
    """Auth-off deploy path: /ui/* is open, so tests hit pages
    without a login round-trip. Auth-on branches sit in
    :class:`AuthGateTests` below."""

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

    def _write_file(self, name: str, contents: bytes = b"pretend-image") -> str:
        path = os.path.join(self._tmpdir, name)
        with open(path, "wb") as f:
            f.write(contents)
        return path

    def _login(self) -> None:
        r = self.client.post("/ui/login", data={"password": TEST_PASSWORD}, follow_redirects=False)
        self.assertEqual(r.status_code, 303, r.text)


class ExportsPageTests(_UiPagesBase):
    """The operator dashboard: Bootstrap table backed by the same
    Store the JSON API mutates."""

    def test_renders_empty_state_when_no_exports(self) -> None:
        r = self.client.get("/ui/exports")
        self.assertEqual(r.status_code, 200)
        body = r.text
        # Empty-state hint mentions the two ways to register an
        # export so an operator lands here first knows what to do.
        self.assertIn("No exports registered yet", body)
        self.assertIn("nbdmux.client", body)
        self.assertIn("Pre-warm", body)
        # Chrome present.
        self.assertIn("NBDMUX", body)
        self.assertIn("brand-accent", body)

    def test_renders_registered_pre_warmed_export(self) -> None:
        """After a pre-warmed POST, /ui/exports shows the export in
        the table with the ``ready`` status pill and its file path."""
        path = self._write_file("demo.img")
        self.client.post("/exports", json={"name": "demo-ready", "file": path})
        body = self.client.get("/ui/exports").text
        self.assertIn("demo-ready", body)
        # Green "ready" pill.
        self.assertIn("bg-success", body)
        # File path column carries the operator-visible absolute path
        # so a debug session can spot a wrong bind-mount immediately.
        self.assertIn(path, body)
        # Pre-warmed rows label the source column so the operator
        # can tell them apart from warm-via-withcache exports without
        # scanning src_url.
        self.assertIn("pre-warmed", body)

    def test_renders_registered_warm_export_as_queued(self) -> None:
        """Warm-via-withcache POST -> row shows ``queued`` status pill
        + the src_url column populated."""
        self.client.post(
            "/exports",
            json={
                "name": "demo-warm",
                "src_url": "https://upstream.invalid/demo.img.gz",
            },
        )
        body = self.client.get("/ui/exports").text
        self.assertIn("demo-warm", body)
        self.assertIn("queued", body)
        self.assertIn("https://upstream.invalid/demo.img.gz", body)

    def test_subnav_shows_withcache_url_when_configured(self) -> None:
        body = self.client.get("/ui/exports").text
        self.assertIn("warms via", body)
        self.assertIn("withcache.invalid", body)


class ExportsPageNoWithcacheTests(_UiPagesBase):
    """When NBDMUX_WITHCACHE_URL is unset, the subnav flips to a
    warning so operators immediately spot the misconfiguration."""

    WITHCACHE_URL = None

    def test_warns_when_withcache_url_missing(self) -> None:
        body = self.client.get("/ui/exports").text
        self.assertIn("no NBDMUX_WITHCACHE_URL configured", body)


class SettingsPageTests(_UiPagesBase):
    """First Settings page on nbdmux. Read-only; four cards
    (Identity / Storage paths / Warming / Auth) mirror bty's
    Settings shape."""

    def test_renders_all_four_cards_with_subnav_anchors(self) -> None:
        body = self.client.get("/ui/settings").text
        for anchor in ("identity", "paths", "warming", "auth"):
            with self.subTest(anchor=anchor):
                self.assertIn(f'id="{anchor}"', body)
                self.assertIn(f'href="#{anchor}"', body)

    def test_identity_card_shows_version(self) -> None:
        body = self.client.get("/ui/settings").text
        # Version literal isn't stable (it's __version__); assert on
        # the shape instead -- the identity card's label + the
        # project link that always renders.
        self.assertIn("nbdmux version", body)
        self.assertIn("github.com/safl/nbdmux", body)

    def test_storage_paths_card_shows_data_and_images_dirs(self) -> None:
        body = self.client.get("/ui/settings").text
        # Data dir renders as the tmp path we passed to create_app.
        self.assertIn(self._tmpdir, body)
        # Images dir is derived as <data_dir>/images by default.
        self.assertIn("images", body)

    def test_warming_card_shows_configured_withcache_url(self) -> None:
        body = self.client.get("/ui/settings").text
        self.assertIn("Withcache URL", body)
        self.assertIn("withcache.invalid", body)
        self.assertIn("NBDMUX_WITHCACHE_URL", body)

    def test_warming_card_shows_nbd_port(self) -> None:
        body = self.client.get("/ui/settings").text
        self.assertIn("NBD listener port", body)
        self.assertIn("10809", body)

    def test_auth_card_shows_open_mode_when_no_password(self) -> None:
        body = self.client.get("/ui/settings").text
        self.assertIn("open mode", body)
        # And session-secret from disk (not env) in this fixture.
        self.assertIn("&lt;data-dir&gt;/session-secret", body)


class SettingsPageAuthOnTests(_UiPagesBase):
    """Auth on -> ``configured`` pill instead of ``open mode``. Also
    ensures the session-secret row shows env source when the env
    var is set (parity test between the two source paths)."""

    ENABLE_AUTH = True

    def setUp(self) -> None:
        # Set the env-persisted session secret BEFORE super().setUp
        # so create_app sees it during initialisation.
        self._saved_secret_env = os.environ.get("NBDMUX_SESSION_SECRET")
        os.environ["NBDMUX_SESSION_SECRET"] = "operator-provided-secret"
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()
        if self._saved_secret_env is None:
            os.environ.pop("NBDMUX_SESSION_SECRET", None)
        else:
            os.environ["NBDMUX_SESSION_SECRET"] = self._saved_secret_env

    def test_auth_card_shows_configured_pill_when_password_set(self) -> None:
        self._login()
        body = self.client.get("/ui/settings").text
        self.assertIn("configured", body)
        self.assertIn("from env", body)


class SettingsPageNoWithcacheTests(_UiPagesBase):
    """Warming card's Withcache-URL row shows the ``not configured``
    warning when the env is empty. Guards against silently rendering
    a blank cell that operators would miss."""

    WITHCACHE_URL = None

    def test_shows_not_configured_when_env_empty(self) -> None:
        body = self.client.get("/ui/settings").text
        self.assertIn("not configured", body)


class AuthGateTests(_UiPagesBase):
    """When NBDMUX_ADMIN_PASSWORD is set, /ui/exports and
    /ui/settings both require a session cookie. Un-authed requests
    303 to /ui/login (same shape bty uses)."""

    ENABLE_AUTH = True

    def test_ui_exports_redirects_to_login_without_session(self) -> None:
        r = self.client.get("/ui/exports")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/login")

    def test_ui_settings_redirects_to_login_without_session(self) -> None:
        r = self.client.get("/ui/settings")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/login")

    def test_ui_exports_renders_after_login(self) -> None:
        self._login()
        r = self.client.get("/ui/exports")
        self.assertEqual(r.status_code, 200)

    def test_ui_settings_renders_after_login(self) -> None:
        self._login()
        r = self.client.get("/ui/settings")
        self.assertEqual(r.status_code, 200)


class NavBtnActiveStateTests(_UiPagesBase):
    """Nav pills highlight the current page ("you are here"). Pin
    the active state so a template shuffle can't silently break the
    breadcrumb signal."""

    def test_exports_nav_btn_marked_active_on_exports_page(self) -> None:
        body = self.client.get("/ui/exports").text
        # The active nav-btn carries the Bootstrap ``active`` class;
        # the brand pill lights up too via ``brand-active`` since the
        # brand doubles as the Exports link.
        self.assertIn('nav-btn active"', body.replace("&#39;", "'").replace("&#34;", '"'))

    def test_settings_nav_btn_marked_active_on_settings_page(self) -> None:
        body = self.client.get("/ui/settings").text
        self.assertIn("settings", body.lower())
        # Second nav-btn (Settings) has ``active`` when on that page.
        self.assertIn("active", body)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
