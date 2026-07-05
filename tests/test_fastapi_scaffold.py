"""FastAPI-port scaffolding smoke tests.

Pins the first-checkpoint behaviour of the v0.3.0 port:

- /healthz returns 200 + a JSON body naming service + version.
- /ui/login renders on GET without auth.
- Un-authed /ui/exports 303s to /ui/login.
- Login with the right password mints the session; /ui/exports
  then renders (200) rather than redirecting.
- Login with the wrong password stays on the form + reports
  "Invalid password" so the operator gets a clear signal.

Uses FastAPI TestClient rather than the unittest-based
stdlib-server tests. The pre-port ``tests/test_nbdmux.py``
suite stays green during the port because ``server.py`` and
its stdlib http.server handler are unchanged.

Written pytest-style (matches the other trio siblings'
tests) rather than unittest so the port lands on the
framework it's targeting.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nbdmux._app import create_app

TEST_PASSWORD = "test-admin-pw"
TEST_SECRET = b"test-secret-not-for-prod-use-32b_"  # 33 bytes; length not enforced


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("NBDMUX_ADMIN_PASSWORD", TEST_PASSWORD)
    app = create_app(data_dir=tmp_path, secret_key=TEST_SECRET)
    with TestClient(app, follow_redirects=False) as c:
        yield c


def _login(c: TestClient, password: str = TEST_PASSWORD) -> None:
    r = c.post("/ui/login", data={"password": password}, follow_redirects=False)
    assert r.status_code in (200, 303), r.text


# ---------- /healthz --------------------------------------------------------


def test_healthz_returns_200_json(client: TestClient) -> None:
    """The pre-port stdlib server's /healthz returned 200 + a
    single-line JSON body naming the service. The FastAPI port
    preserves that shape byte-identically so container probes and
    bty-web's reachability pill don't need to change."""
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "nbdmux"
    assert "version" in body


# ---------- login flow ------------------------------------------------------


def test_ui_login_form_renders_without_auth(client: TestClient) -> None:
    r = client.get("/ui/login")
    assert r.status_code == 200
    body = r.text
    assert "Log in" in body
    assert 'name="password"' in body
    # Points operators at the env var the daemon reads.
    assert "NBDMUX_ADMIN_PASSWORD" in body


def test_ui_exports_without_auth_redirects_to_login(client: TestClient) -> None:
    """Auth gate: an un-authed request to a UI page 303s to the
    login form. Same shape as bty's require_ui_auth dependency."""
    r = client.get("/ui/exports")
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/login"


def test_root_redirects_to_exports(client: TestClient) -> None:
    """``GET /`` is the operator's landing route; pre-port it
    served the Exports view directly. Post-port it 303s to
    ``/ui/exports`` so the auth-gate covers the entry point."""
    r = client.get("/")
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/exports"


def test_ui_login_wrong_password_re_renders_with_error(client: TestClient) -> None:
    r = client.post("/ui/login", data={"password": "not-the-password"})
    assert r.status_code == 200
    assert "Invalid password" in r.text


def test_ui_login_valid_password_sets_session_and_reaches_exports(client: TestClient) -> None:
    """Happy path: correct password mints the session cookie; a
    subsequent GET /ui/exports renders (200) rather than
    redirecting. Pins the session-flow end-to-end so a middleware
    regression can't leave the operator stuck on the login page."""
    r = client.post(
        "/ui/login", data={"password": TEST_PASSWORD}, follow_redirects=False
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/exports"
    # Same client carries the session cookie through the next
    # request via the TestClient's cookie jar.
    r2 = client.get("/ui/exports")
    assert r2.status_code == 200
    # Basic layout markers present so the render actually ran.
    assert "NBDMUX" in r2.text
    assert "brand-accent" in r2.text


def test_ui_logout_clears_session_and_redirects(client: TestClient) -> None:
    _login(client)
    r = client.post("/ui/logout", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/login"
    # After logout the exports page 303s back to login again.
    r2 = client.get("/ui/exports")
    assert r2.status_code == 303
    assert r2.headers["location"] == "/ui/login"
