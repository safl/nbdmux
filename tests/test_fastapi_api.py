"""FastAPI JSON control-plane wire-contract tests.

Pins the ``/exports`` verbs so a regression in field names, status
codes, or auth semantics can't land quietly. Bty consumes this
surface from a sibling container via :mod:`nbdmux.client`; keep
the shape stable.

Covers:

- ``GET /exports`` open + record shape (name, status, file,
  readonly, src_url, format, bytes_total, bytes_done, progress,
  enqueued_at, started_at, completed_at, updated_at, error).
- ``GET /export/{name}`` 200 + 404.
- ``POST /exports`` pre-warmed shape (``{name, file, readonly?}``)
  -> 200 + record with ``status='ready'``.
- ``POST /exports`` warm-via-withcache shape
  (``{name, src_url, readonly?, format?}``) -> 200 + record with
  ``status='queued'``.
- ``POST /exports`` validation errors: 400 on missing name, bad
  name shape, missing/both {file, src_url}, missing withcache URL,
  file not found, non-absolute path.
- ``DELETE /exports/{name}`` 204 on delete, 404 on unknown.
- Auth: control-plane routes open when
  ``NBDMUX_ADMIN_PASSWORD`` is unset; 401 without session when
  set. GET /exports stays open regardless (bty needs it).

Written as unittest.TestCase to run under ``make test``
alongside the legacy stdlib suite.
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

# Full set of keys the wire contract promises on a GET /exports
# record. The legacy stdlib server + bty's client library key on
# ``name`` and ``status`` today; the rest are documented in the
# record schema and any consumer wire-scraping them (a fleet
# dashboard, an operator-side script) MUST keep working.
_EXPECTED_RECORD_KEYS = {
    "name",
    "status",
    "file",
    "readonly",
    "src_url",
    "format",
    "bytes_total",
    "bytes_done",
    "progress",
    "enqueued_at",
    "started_at",
    "completed_at",
    "updated_at",
    "error",
    # Added in v0.8.1 -- the port the per-export nbdkit is listening
    # on. Null when the process isn't currently running.
    "nbd_port",
    # Added in v0.9.0 -- the sibling catalog entry that carries the
    # matching nosi netboot bundle (kernel + initrd + manifest). Null
    # when the export's src catalog entry has no netboot pairing.
    "netboot_ref",
    # Added in v0.9.0 -- filesystem-derived boolean: True iff the
    # Warmer's post-ready stage has extracted the netboot bundle
    # under ``<artifacts_dir>/<name>/`` (manifest.json existence is
    # the truth marker).
    "netboot_ready",
}


class _ApiBase(unittest.TestCase):
    """Shared setup: temp data dir + FastAPI TestClient + optional
    admin password. Subclasses toggle ``ENABLE_AUTH`` to exercise
    the auth-on vs auth-off branches."""

    ENABLE_AUTH = False

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._saved_pw = os.environ.get("NBDMUX_ADMIN_PASSWORD")
        self._saved_withcache = os.environ.get("NBDMUX_WITHCACHE_URL")
        if self.ENABLE_AUTH:
            os.environ["NBDMUX_ADMIN_PASSWORD"] = TEST_PASSWORD
        else:
            os.environ.pop("NBDMUX_ADMIN_PASSWORD", None)
        os.environ["NBDMUX_WITHCACHE_URL"] = "http://withcache.invalid:8081"
        app = create_app(data_dir=self._tmpdir, secret_key=TEST_SECRET)
        self.client = TestClient(app, follow_redirects=False)

    def tearDown(self) -> None:
        self.client.close()
        for key, saved in (
            ("NBDMUX_ADMIN_PASSWORD", self._saved_pw),
            ("NBDMUX_WITHCACHE_URL", self._saved_withcache),
        ):
            if saved is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = saved
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_file(self, name: str, contents: bytes = b"pretend-image") -> str:
        """Drop a byte string into the temp dir under an absolute path
        so the ``{name, file}`` POST shape's is-file check passes."""
        path = os.path.join(self._tmpdir, name)
        with open(path, "wb") as f:
            f.write(contents)
        return path

    def _login(self) -> None:
        r = self.client.post("/ui/login", data={"password": TEST_PASSWORD}, follow_redirects=False)
        self.assertEqual(r.status_code, 303, r.text)


class GetExportsTests(_ApiBase):
    """Shape of ``GET /exports`` -- open route, returns list; each
    record carries the full key set."""

    def test_get_exports_is_open_returns_empty_list_initially(self) -> None:
        r = self.client.get("/exports")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), [])

    def test_get_exports_returns_records_with_all_wire_keys(self) -> None:
        """After a pre-warmed POST, GET /exports has one record and it
        carries every key the wire contract promises."""
        path = self._write_file("dummy.img")
        r = self.client.post("/exports", json={"name": "demo", "file": path})
        self.assertEqual(r.status_code, 200, r.text)
        listing = self.client.get("/exports").json()
        self.assertEqual(len(listing), 1)
        self.assertEqual(set(listing[0].keys()), _EXPECTED_RECORD_KEYS)
        self.assertEqual(listing[0]["name"], "demo")
        self.assertEqual(listing[0]["status"], "ready")


class GetExportByNameTests(_ApiBase):
    def test_get_export_404_when_unknown(self) -> None:
        r = self.client.get("/export/does-not-exist")
        self.assertEqual(r.status_code, 404)
        self.assertIn("detail", r.json())

    def test_get_export_200_when_known(self) -> None:
        path = self._write_file("dummy.img")
        self.client.post("/exports", json={"name": "demo", "file": path})
        r = self.client.get("/export/demo")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["name"], "demo")


class PostExportPrewarmedShapeTests(_ApiBase):
    """``{name, file, readonly?}`` -> status='ready'. Pre-warmed
    exports are the common bty flow when the ramboot init has
    already written the .img to a shared bind mount."""

    def test_prewarmed_happy_path(self) -> None:
        path = self._write_file("demo.img")
        r = self.client.post("/exports", json={"name": "demo", "file": path})
        self.assertEqual(r.status_code, 200)
        record = r.json()
        self.assertEqual(record["name"], "demo")
        self.assertEqual(record["status"], "ready")
        self.assertEqual(record["file"], path)
        self.assertIsNone(record["src_url"])
        # Bty polls list_exports at plan-emit time -- the row must be
        # visible immediately, not just via the returned record.
        self.assertEqual(len(self.client.get("/exports").json()), 1)

    def test_prewarmed_readonly_default_true(self) -> None:
        path = self._write_file("demo.img")
        r = self.client.post("/exports", json={"name": "demo", "file": path})
        self.assertTrue(r.json()["readonly"])

    def test_prewarmed_readonly_can_be_disabled(self) -> None:
        path = self._write_file("demo.img")
        r = self.client.post("/exports", json={"name": "demo", "file": path, "readonly": False})
        self.assertFalse(r.json()["readonly"])


class PostExportWarmShapeTests(_ApiBase):
    """``{name, src_url, readonly?, format?}`` -> status='queued'.
    Warm-via-withcache is the ramboot pre-warm entry point bty
    just wired into its Settings > Ramboot page."""

    def test_warm_happy_path(self) -> None:
        r = self.client.post(
            "/exports",
            json={
                "name": "demo",
                "src_url": "https://upstream.invalid/demo.img.gz",
            },
        )
        self.assertEqual(r.status_code, 200)
        record = r.json()
        self.assertEqual(record["name"], "demo")
        self.assertEqual(record["status"], "queued")
        self.assertEqual(record["src_url"], "https://upstream.invalid/demo.img.gz")
        # Format hint auto-derived from the URL extension when not
        # explicit; ``.img.gz`` -> ``img.gz``.
        self.assertEqual(record["format"], "img.gz")

    def test_warm_explicit_format_wins_over_url_extension(self) -> None:
        r = self.client.post(
            "/exports",
            json={
                "name": "demo",
                "src_url": "https://upstream.invalid/demo",
                "format": "img.zst",
            },
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["format"], "img.zst")

    def test_warm_400_when_withcache_url_missing(self) -> None:
        """Nbdmux only warms via withcache. Without the env var, the
        POST 400s with a message that names the missing configuration
        so the operator can fix it fast."""
        os.environ.pop("NBDMUX_WITHCACHE_URL", None)
        r = self.client.post(
            "/exports", json={"name": "demo", "src_url": "https://upstream.invalid/demo.img.gz"}
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("NBDMUX_WITHCACHE_URL", r.json()["detail"])


class PostExportValidationTests(_ApiBase):
    def test_missing_name_400(self) -> None:
        path = self._write_file("demo.img")
        r = self.client.post("/exports", json={"file": path})
        self.assertEqual(r.status_code, 400)
        self.assertIn("name", r.json()["detail"])

    def test_bad_name_shape_400(self) -> None:
        """Names get injected as ``[<name>]`` section headers in
        nbd-server.conf; ``]`` / ``/`` / spaces would corrupt the
        INI. Validator rejects them at the boundary."""
        for bad in ("with space", "with/slash", "]bracket", "-leading-dash"):
            with self.subTest(name=bad):
                path = self._write_file("demo.img")
                r = self.client.post("/exports", json={"name": bad, "file": path})
                self.assertEqual(r.status_code, 400)
                self.assertIn("name", r.json()["detail"])

    def test_neither_file_nor_src_url_400(self) -> None:
        r = self.client.post("/exports", json={"name": "demo"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("file", r.json()["detail"])
        self.assertIn("src_url", r.json()["detail"])

    def test_both_file_and_src_url_400(self) -> None:
        path = self._write_file("demo.img")
        r = self.client.post(
            "/exports",
            json={"name": "demo", "file": path, "src_url": "https://upstream.invalid/demo"},
        )
        self.assertEqual(r.status_code, 400)

    def test_file_not_absolute_400(self) -> None:
        r = self.client.post("/exports", json={"name": "demo", "file": "demo.img"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("absolute", r.json()["detail"])

    def test_file_missing_on_disk_400(self) -> None:
        r = self.client.post("/exports", json={"name": "demo", "file": "/nonexistent/file.img"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("not found", r.json()["detail"])


class DeleteExportTests(_ApiBase):
    def test_delete_known_returns_204(self) -> None:
        path = self._write_file("demo.img")
        self.client.post("/exports", json={"name": "demo", "file": path})
        r = self.client.delete("/exports/demo")
        self.assertEqual(r.status_code, 204)
        # And the row is gone.
        self.assertEqual(self.client.get("/exports").json(), [])

    def test_delete_unknown_returns_404(self) -> None:
        """Client-side ``nbdmux.client.remove_export`` swallows 404
        as no-op for the operator's "make sure this is gone" intent;
        the server-side must still emit 404 so the swallow is
        deterministic."""
        r = self.client.delete("/exports/never-existed")
        self.assertEqual(r.status_code, 404)

    def test_delete_cleans_up_artifacts_dir(self) -> None:
        """Extracted netboot bundles must be dropped in lockstep with
        the export they belong to -- a re-warmed export must not
        inherit stale kernel/initrd files from a previous run."""
        path = self._write_file("demo.img")
        self.client.post("/exports", json={"name": "demo", "file": path})
        artifacts_root = os.path.join(self._tmpdir, "artifacts", "demo")
        os.makedirs(artifacts_root, exist_ok=True)
        for filename in ("vmlinuz", "initrd", "manifest.json"):
            with open(os.path.join(artifacts_root, filename), "wb") as f:
                f.write(b"x")
        self.assertTrue(os.path.exists(artifacts_root))
        r = self.client.delete("/exports/demo")
        self.assertEqual(r.status_code, 204)
        self.assertFalse(os.path.exists(artifacts_root))


class ArtifactRouteTests(_ApiBase):
    """The ``GET /artifacts/{name}/{vmlinuz,initrd,manifest.json}``
    routes serve bytes out of ``<artifacts_dir>/<name>/``. Bty's
    ipxe_ramboot chain uses them directly, so their status codes +
    content-types are wire contract."""

    def _seed_artifacts(self, name: str, files: dict[str, bytes]) -> None:
        target = os.path.join(self._tmpdir, "artifacts", name)
        os.makedirs(target, exist_ok=True)
        for filename, content in files.items():
            with open(os.path.join(target, filename), "wb") as f:
                f.write(content)

    def test_artifact_vmlinuz_served_when_present(self) -> None:
        self._seed_artifacts("demo", {"vmlinuz": b"kernel-bytes"})
        r = self.client.get("/artifacts/demo/vmlinuz")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, b"kernel-bytes")
        self.assertEqual(r.headers["content-type"], "application/octet-stream")

    def test_artifact_missing_returns_404(self) -> None:
        r = self.client.get("/artifacts/demo/vmlinuz")
        self.assertEqual(r.status_code, 404)

    def test_artifact_invalid_export_name_returns_404(self) -> None:
        """The export-name validator refuses ``../`` etc.; the artifact
        route MUST refuse the same so path-traversal probes are 404,
        not 200 leaking bytes outside the artifacts dir."""
        r = self.client.get("/artifacts/..%2fetc%2fpasswd/vmlinuz")
        self.assertEqual(r.status_code, 404)

    def test_netboot_ready_flip_when_manifest_lands(self) -> None:
        """GET /exports advertises ``netboot_ready`` as True iff the
        manifest.json exists under ``<artifacts_dir>/<name>/``."""
        path = self._write_file("demo.img")
        self.client.post("/exports", json={"name": "demo", "file": path})
        before = self.client.get("/exports").json()[0]
        self.assertFalse(before["netboot_ready"])
        self._seed_artifacts("demo", {"manifest.json": b'{"framework":"initramfs-tools"}'})
        after = self.client.get("/exports").json()[0]
        self.assertTrue(after["netboot_ready"])


class AuthOffOpenModeTests(_ApiBase):
    ENABLE_AUTH = False

    def test_post_export_open_without_session(self) -> None:
        """LAN-only deploy path: no admin password set -> POST works
        without any session cookie. Pre-port behaviour preserved
        byte-identically."""
        path = self._write_file("demo.img")
        r = self.client.post("/exports", json={"name": "demo", "file": path})
        self.assertEqual(r.status_code, 200)


class AuthOnGatedTests(_ApiBase):
    ENABLE_AUTH = True

    def test_get_exports_stays_open_even_with_auth_enabled(self) -> None:
        """bty polls this from a sibling container without a session;
        the read path stays open regardless of admin-password
        configuration."""
        r = self.client.get("/exports")
        self.assertEqual(r.status_code, 200)

    def test_post_export_401_without_session(self) -> None:
        path = self._write_file("demo.img")
        r = self.client.post("/exports", json={"name": "demo", "file": path})
        self.assertEqual(r.status_code, 401)
        self.assertIn("auth required", r.json()["detail"])

    def test_delete_export_401_without_session(self) -> None:
        r = self.client.delete("/exports/demo")
        self.assertEqual(r.status_code, 401)

    def test_post_export_200_with_session(self) -> None:
        self._login()
        path = self._write_file("demo.img")
        r = self.client.post("/exports", json={"name": "demo", "file": path})
        self.assertEqual(r.status_code, 200)

    def test_post_export_200_with_bearer_matching_admin_password(self) -> None:
        """Service-to-service path: bty-web reads NBDMUX_ADMIN_PASSWORD
        from env and sends it as ``Authorization: Bearer <pw>``. The
        control-plane accepts that as equivalent to a session cookie
        so cross-container callers don't have to POST /ui/login."""
        path = self._write_file("demo.img")
        r = self.client.post(
            "/exports",
            json={"name": "demo", "file": path},
            headers={"Authorization": f"Bearer {TEST_PASSWORD}"},
        )
        self.assertEqual(r.status_code, 200)

    def test_post_export_401_with_bearer_mismatch(self) -> None:
        """A wrong Bearer must still 401 -- constant-time compare
        against the configured admin password."""
        path = self._write_file("demo.img")
        r = self.client.post(
            "/exports",
            json={"name": "demo", "file": path},
            headers={"Authorization": "Bearer wrong-pw"},
        )
        self.assertEqual(r.status_code, 401)

    def test_delete_export_204_with_bearer(self) -> None:
        """DELETE mirrors POST: Bearer works for the write path."""
        # Seed a row via a session so we have something to delete.
        self._login()
        path = self._write_file("demo.img")
        self.client.post("/exports", json={"name": "demo", "file": path})
        # New client to drop the session cookie; use Bearer instead.
        self.client.cookies.clear()
        r = self.client.delete(
            "/exports/demo",
            headers={"Authorization": f"Bearer {TEST_PASSWORD}"},
        )
        self.assertEqual(r.status_code, 204)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
