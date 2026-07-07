"""Tests for the nbdmux events log + /ui/events page."""

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
    raise unittest.SkipTest("fastapi not installed") from None

from nbdmux import _events_log  # noqa: E402
from nbdmux._app import _NoopNbdServer, _NoopWarmer, create_app  # noqa: E402

TEST_SECRET = b"test-secret-not-for-prod-use-32b_"


class _EventsBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._saved_pw = os.environ.get("NBDMUX_ADMIN_PASSWORD")
        self._saved_wc = os.environ.get("NBDMUX_WITHCACHE_URL")
        os.environ.pop("NBDMUX_ADMIN_PASSWORD", None)
        os.environ["NBDMUX_WITHCACHE_URL"] = "http://withcache.invalid:8081"
        self.app = create_app(
            data_dir=self._tmpdir,
            secret_key=TEST_SECRET,
            warmer=_NoopWarmer(),
            nbd=_NoopNbdServer(),
            images_dir=self._tmpdir,
        )
        self.client = TestClient(self.app, follow_redirects=False)

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

    def _events(self):
        with self.app.state.store.conn() as conn:
            return _events_log.search_events(conn, limit=200)


class EmitterTests(_EventsBase):
    def test_create_export_emits_event(self) -> None:
        self.client.post(
            "/admin/create_export",
            data={"src_url": "https://example.invalid/vm.img.zst"},
            follow_redirects=False,
        )
        kinds = [e.kind for e in self._events()]
        self.assertIn("export.created", kinds)

    def test_delete_export_emits_event(self) -> None:
        self.app.state.store.upsert_export(
            "vm",
            os.path.join(self._tmpdir, "vm.img"),
            readonly=True,
            status="ready",
            src_url="https://example.invalid/vm.img.zst",
        )
        self.client.post("/admin/delete_export/vm", follow_redirects=False)
        kinds = [e.kind for e in self._events()]
        self.assertIn("export.deleted", kinds)

    def test_settings_warming_emits_events(self) -> None:
        self.client.post(
            "/admin/settings/warming",
            data={
                "withcache_url": "http://new.invalid:8081",
                "withcache_browser_url": "",
                "log_level": "info",
            },
            follow_redirects=False,
        )
        kinds = [e.kind for e in self._events()]
        self.assertIn("settings.withcache.updated", kinds)
        self.assertIn("settings.logging.updated", kinds)


class EventsPageTests(_EventsBase):
    def _seed_events(self, count: int = 3) -> None:
        with self.app.state.store.conn() as conn:
            for i in range(count):
                _events_log.record(
                    conn,
                    kind="export.warm.completed",
                    summary=f"warm done {i}",
                    subject_kind="export",
                    subject_id=f"vm-{i}",
                    actor="system",
                )
            conn.commit()

    def test_events_page_renders_empty_state(self) -> None:
        r = self.client.get("/ui/events")
        self.assertEqual(r.status_code, 200)
        self.assertIn("No events recorded yet", r.text)

    def test_events_page_renders_row(self) -> None:
        self._seed_events(1)
        r = self.client.get("/ui/events")
        self.assertIn("warm done 0", r.text)
        self.assertIn("export.warm.completed", r.text)

    def test_ack_endpoint_marks_event(self) -> None:
        with self.app.state.store.conn() as conn:
            ev_id = _events_log.record(
                conn,
                kind="export.warm.failed",
                summary="warm broke",
                subject_kind="export",
                actor="system",
            )
            conn.commit()
        r = self.client.post(f"/admin/events/{ev_id}/ack", follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        with self.app.state.store.conn() as conn:
            rows = _events_log.search_events(conn, limit=10)
            found = next(e for e in rows if e.id == ev_id)
            self.assertTrue(found.acknowledged)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
