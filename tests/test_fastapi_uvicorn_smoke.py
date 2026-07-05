"""Uvicorn boot smoke test for the v0.3.0 runtime cut-over.

The TestClient tests exercise the FastAPI app in-process. This
test proves the runtime path actually works: boot the app under
uvicorn in a subprocess (matching what ``server.main`` does),
verify /healthz returns 200 + expected JSON, verify /exports
returns an empty list, then send SIGTERM and confirm the process
exits cleanly.

Skipped when the ``nbd-server`` binary is absent -- the Warmer
lifecycle enqueues but does no real work in a fresh state.db, and
NbdServer only fires the subprocess when there's at least one
ready export; the smoke test's happy path doesn't need it. The
Warmer thread still starts.

This test replaces the fear-driven "did we break the daemon?"
gap the earlier port checkpoints had. Written as
unittest.TestCase so ``make test`` picks it up alongside the
legacy suite.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# The lifespan starts NbdServer, which spawns the real nbd-server
# binary. Skip the smoke test when the binary isn't installed --
# this test's purpose is proving uvicorn boots the daemon end to
# end, and the pre-port stdlib main() had the same requirement
# (it also spawned nbd-server unconditionally). CI installs
# nbd-server via ``apt-get install nbd-server`` in the runner setup.
_NBD_SERVER_BIN = shutil.which("nbd-server")


def _find_free_port() -> int:
    """Ask the kernel for an unused TCP port. Small race between
    close and the subprocess bind is acceptable at test scope."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_http(url: str, *, timeout: float = 10.0) -> None:
    """Poll ``url`` until it 200s or the timeout runs out. Raises
    :class:`TimeoutError` on give-up. Uvicorn's boot takes ~200 ms
    on a laptop; the generous window here gives CI headroom."""
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:  # noqa: S310
                if resp.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = exc
        time.sleep(0.1)
    raise TimeoutError(f"{url!r} did not respond 200 within {timeout}s: {last_err}")


@unittest.skipIf(_NBD_SERVER_BIN is None, "nbd-server binary not available on this runner")
class UvicornRuntimeSmokeTests(unittest.TestCase):
    """Boot the daemon exactly like ``server.main`` does + poke
    the wire from an external client."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._port = _find_free_port()
        # Guarantee an unset admin password so the /exports GET
        # doesn't need a session cookie, and set a stable secret
        # so cookie signing works across the subprocess boundary.
        env = os.environ.copy()
        env.pop("NBDMUX_ADMIN_PASSWORD", None)
        env["NBDMUX_DATA_DIR"] = self._tmpdir
        # A withcache URL isn't required for /healthz; skip.
        env.pop("NBDMUX_WITHCACHE_URL", None)
        self._env = env

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _spawn(self) -> subprocess.Popen[bytes]:
        """Launch ``nbdmux-server`` (the pyproject.toml script that
        points at ``server:main``) with the temp data-dir + a free
        port. The Warmer thread starts inside the lifespan; we
        don't need nbd-server to fire since the test's happy path
        doesn't register a ready export."""
        return subprocess.Popen(
            [
                sys.executable,
                "-m",
                "nbdmux.server",
                "--data-dir",
                self._tmpdir,
                "--port",
                str(self._port),
                # An unused NBD port so a second concurrent test on
                # the same runner doesn't collide.
                "--nbd-port",
                str(_find_free_port()),
                # Point at the real binary found by shutil.which so
                # NbdServer's Popen succeeds; the empty ready list
                # + free NBD port keep nbd-server harmless (no NBD
                # clients connect, no data flows).
                "--nbd-server-bin",
                _NBD_SERVER_BIN or "nbd-server",
            ],
            env=self._env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_uvicorn_boot_healthz_and_exports_then_sigterm(self) -> None:
        """Full runtime lifecycle: boot -> serve /healthz + /exports ->
        SIGTERM -> clean exit. Proves the FastAPI lifespan hook wires
        Warmer + NbdServer start / stop correctly, uvicorn is
        actually being launched (not just TestClient), and the routes
        registered under create_app are reachable from an out-of-
        process client."""
        proc = self._spawn()
        try:
            _wait_for_http(f"http://127.0.0.1:{self._port}/healthz", timeout=15.0)
            # /healthz JSON shape parity with the pre-port stdlib server.
            with urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{self._port}/healthz", timeout=2.0
            ) as resp:
                body = json.loads(resp.read())
            self.assertEqual(body["status"], "ok")
            self.assertEqual(body["service"], "nbdmux")
            self.assertIn("version", body)
            # /exports open route -- bty polls this from a sibling
            # container. A fresh state.db carries only the probe
            # export ``_ensure_probe_export`` seeds (so nbd-server has
            # something to serve at bootstrap even before an operator
            # POSTs anything). Assert on the record shape, not the
            # exact list length.
            with urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{self._port}/exports", timeout=2.0
            ) as resp:
                exports = json.loads(resp.read())
            self.assertIsInstance(exports, list)
            for e in exports:
                self.assertIn("name", e)
                self.assertIn("status", e)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)
        # SIGTERM -> uvicorn's graceful shutdown -> lifespan
        # ``finally:`` runs -> Warmer.stop() + NbdServer.stop().
        # Uvicorn's exit code depends on how far the graceful path
        # got before the signal fired: 0 on a clean shutdown,
        # ``-signal.SIGTERM`` (-15) when the signal fires before the
        # handler installs. Both mean "process exited in response
        # to SIGTERM"; what we're asserting is that it exited at
        # all (didn't hang, didn't crash with an unexpected code).
        self.assertIn(proc.returncode, (0, -15))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
