"""TestClient tests for Settings persistence (withcache URL + log level).

Sixth checkpoint of the v0.3.0 port. Pins the persistent-override
half of the Warming card so a Settings save writes to the DB, the
next render reflects it, and the process env stays in sync for the
Warmer thread (which reads env directly).

Split across the settings-store unit tests + the /admin/settings/
warming form tests + the /ui/settings render coverage. Runs under
``make test`` alongside the legacy suite.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from fastapi.testclient import TestClient  # noqa: E402
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("fastapi + httpx not available (port scaffolding deps)") from None

from nbdmux import _settings_store  # noqa: E402
from nbdmux._app import create_app  # noqa: E402

TEST_PASSWORD = "test-admin-pw"
TEST_SECRET = b"test-secret-not-for-prod-use-32b_"


class SettingsStoreUnitTests(unittest.TestCase):
    """Direct coverage of :mod:`_settings_store`: get / set / clear +
    resolve_withcache_url + resolve_log_level. Runs against an
    in-memory DB so no fixture / teardown needed."""

    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        _settings_store.init(self.conn)
        self._saved_wc = os.environ.get("NBDMUX_WITHCACHE_URL")
        self._saved_ll = os.environ.get("NBDMUX_LOG_LEVEL")
        os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        os.environ.pop("NBDMUX_LOG_LEVEL", None)

    def tearDown(self) -> None:
        self.conn.close()
        for key, saved in (
            ("NBDMUX_WITHCACHE_URL", self._saved_wc),
            ("NBDMUX_LOG_LEVEL", self._saved_ll),
        ):
            if saved is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = saved

    def test_init_creates_settings_table(self) -> None:
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='settings'"
        ).fetchall()
        self.assertEqual(len(rows), 1)

    def test_get_returns_none_when_unset(self) -> None:
        self.assertIsNone(_settings_store.get(self.conn, _settings_store.KEY_WITHCACHE_URL))

    def test_set_then_get_round_trip(self) -> None:
        _settings_store.set_value(
            self.conn, _settings_store.KEY_WITHCACHE_URL, "http://withcache:8081"
        )
        self.assertEqual(
            _settings_store.get(self.conn, _settings_store.KEY_WITHCACHE_URL),
            "http://withcache:8081",
        )

    def test_set_upserts_existing_row(self) -> None:
        _settings_store.set_value(self.conn, _settings_store.KEY_WITHCACHE_URL, "http://a")
        _settings_store.set_value(self.conn, _settings_store.KEY_WITHCACHE_URL, "http://b")
        self.assertEqual(
            _settings_store.get(self.conn, _settings_store.KEY_WITHCACHE_URL), "http://b"
        )

    def test_clear_removes_row(self) -> None:
        _settings_store.set_value(self.conn, _settings_store.KEY_WITHCACHE_URL, "http://a")
        _settings_store.clear(self.conn, _settings_store.KEY_WITHCACHE_URL)
        self.assertIsNone(_settings_store.get(self.conn, _settings_store.KEY_WITHCACHE_URL))

    def test_resolve_withcache_url_none_when_unset(self) -> None:
        self.assertIsNone(_settings_store.resolve_withcache_url(self.conn))

    def test_resolve_withcache_url_env_when_no_override(self) -> None:
        os.environ["NBDMUX_WITHCACHE_URL"] = "http://env:8081"
        self.assertEqual(_settings_store.resolve_withcache_url(self.conn), "http://env:8081")

    def test_resolve_withcache_url_override_beats_env(self) -> None:
        os.environ["NBDMUX_WITHCACHE_URL"] = "http://env:8081"
        _settings_store.set_value(self.conn, _settings_store.KEY_WITHCACHE_URL, "http://db:8081")
        self.assertEqual(_settings_store.resolve_withcache_url(self.conn), "http://db:8081")

    def test_resolve_log_level_default_when_unset(self) -> None:
        self.assertEqual(
            _settings_store.resolve_log_level(self.conn), _settings_store.DEFAULT_LOG_LEVEL
        )

    def test_resolve_log_level_env_when_no_override(self) -> None:
        os.environ["NBDMUX_LOG_LEVEL"] = "debug"
        self.assertEqual(_settings_store.resolve_log_level(self.conn), "debug")

    def test_resolve_log_level_override_beats_env(self) -> None:
        os.environ["NBDMUX_LOG_LEVEL"] = "info"
        _settings_store.set_value(self.conn, _settings_store.KEY_LOG_LEVEL, "trace")
        self.assertEqual(_settings_store.resolve_log_level(self.conn), "trace")

    def test_resolve_log_level_raises_on_invalid(self) -> None:
        _settings_store.set_value(self.conn, _settings_store.KEY_LOG_LEVEL, "chatty")
        with self.assertRaises(_settings_store.SettingValueError):
            _settings_store.resolve_log_level(self.conn)


class _SettingsFormBase(unittest.TestCase):
    ENABLE_AUTH = False

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._saved_pw = os.environ.get("NBDMUX_ADMIN_PASSWORD")
        self._saved_wc = os.environ.get("NBDMUX_WITHCACHE_URL")
        self._saved_ll = os.environ.get("NBDMUX_LOG_LEVEL")
        if self.ENABLE_AUTH:
            os.environ["NBDMUX_ADMIN_PASSWORD"] = TEST_PASSWORD
        else:
            os.environ.pop("NBDMUX_ADMIN_PASSWORD", None)
        os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        os.environ.pop("NBDMUX_LOG_LEVEL", None)
        app = create_app(data_dir=self._tmpdir, secret_key=TEST_SECRET)
        self.client = TestClient(app, follow_redirects=False)

    def tearDown(self) -> None:
        self.client.close()
        for key, saved in (
            ("NBDMUX_ADMIN_PASSWORD", self._saved_pw),
            ("NBDMUX_WITHCACHE_URL", self._saved_wc),
            ("NBDMUX_LOG_LEVEL", self._saved_ll),
        ):
            if saved is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = saved
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _login(self) -> None:
        r = self.client.post("/ui/login", data={"password": TEST_PASSWORD}, follow_redirects=False)
        self.assertEqual(r.status_code, 303, r.text)


class SettingsFormRenderTests(_SettingsFormBase):
    """The Settings page's Warming card now renders as an editable
    form with the Override / Effective / Default three-column
    pattern bty uses."""

    def test_renders_form_with_action_target(self) -> None:
        body = self.client.get("/ui/settings").text
        self.assertIn('action="/admin/settings/warming"', body)
        self.assertIn('name="withcache_url"', body)
        self.assertIn('name="log_level"', body)

    def test_effective_shows_env_when_no_override(self) -> None:
        os.environ["NBDMUX_WITHCACHE_URL"] = "http://env-only:8081"
        body = self.client.get("/ui/settings").text
        self.assertIn("http://env-only:8081", body)

    def test_effective_shows_override_when_persisted(self) -> None:
        # Save via the form; render should surface the override in
        # both the input (as ``value=``) and the Effective column.
        self.client.post(
            "/admin/settings/warming",
            data={"withcache_url": "http://db-override:8081", "log_level": ""},
        )
        body = self.client.get("/ui/settings").text
        self.assertIn('value="http://db-override:8081"', body)
        self.assertIn("http://db-override:8081", body)


class SettingsFormPersistTests(_SettingsFormBase):
    def test_valid_form_saves_and_redirects_with_flash(self) -> None:
        r = self.client.post(
            "/admin/settings/warming",
            data={"withcache_url": "http://withcache:8081", "log_level": "debug"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/settings?saved=warming#warming")
        # Next render carries the ``saved=warming`` flash banner.
        body = self.client.get("/ui/settings?saved=warming").text
        self.assertIn("Warming settings saved", body)
        # And the values persisted.
        self.assertIn("http://withcache:8081", body)

    def test_saving_withcache_url_syncs_env_immediately(self) -> None:
        """The Warmer + JSON POST /exports validator read
        ``NBDMUX_WITHCACHE_URL`` from env; a form save syncs the
        env at write time so the change takes effect without a
        restart."""
        self.assertNotIn("NBDMUX_WITHCACHE_URL", os.environ)
        self.client.post(
            "/admin/settings/warming",
            data={"withcache_url": "http://withcache:8081", "log_level": ""},
        )
        self.assertEqual(os.environ.get("NBDMUX_WITHCACHE_URL"), "http://withcache:8081")

    def test_empty_override_clears_row_and_env(self) -> None:
        # Seed with a saved override + env sync.
        self.client.post(
            "/admin/settings/warming",
            data={"withcache_url": "http://withcache:8081", "log_level": ""},
        )
        self.assertEqual(os.environ.get("NBDMUX_WITHCACHE_URL"), "http://withcache:8081")
        # Now clear via an empty submit.
        self.client.post(
            "/admin/settings/warming",
            data={"withcache_url": "", "log_level": ""},
        )
        self.assertNotIn("NBDMUX_WITHCACHE_URL", os.environ)

    def test_invalid_log_level_303s_with_error_and_no_persist(self) -> None:
        """A submit with an invalid log level 303s back with
        ``?error=<msg>`` and does NOT persist either field. Guards
        the resolver from having to raise on the next render."""
        r = self.client.post(
            "/admin/settings/warming",
            data={"withcache_url": "http://valid:8081", "log_level": "chatty"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertIn("error=", r.headers["location"])
        # And the withcache row didn't persist either -- reject
        # atomically so a partial save isn't a footgun.
        self.assertNotIn("NBDMUX_WITHCACHE_URL", os.environ)


class SettingsFormAuthTests(_SettingsFormBase):
    ENABLE_AUTH = True

    def test_save_requires_session(self) -> None:
        r = self.client.post(
            "/admin/settings/warming",
            data={"withcache_url": "http://x", "log_level": ""},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/login")

    def test_save_works_after_login(self) -> None:
        self._login()
        r = self.client.post(
            "/admin/settings/warming",
            data={"withcache_url": "http://x", "log_level": ""},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/settings?saved=warming#warming")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
