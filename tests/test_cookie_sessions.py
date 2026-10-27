"""TDD: persistent browser sessions without JavaScript-readable credentials."""

import hashlib
import pytest
from fastapi.testclient import TestClient
from app import auth, db
from app.main import app

pytestmark = [pytest.mark.integration, pytest.mark.security]
BASE = "/api/v1"
BODY = {"email": "browser@example.com", "password": "browser-test-password-123!"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SECUREFLOW_PUBLIC_ORIGIN", raising=False)
    monkeypatch.setenv("SECUREFLOW_COOKIE_SECURE", "false")
    monkeypatch.setenv("SECUREFLOW_DB", str(tmp_path / "cookies.db"))
    with TestClient(app) as client:
        yield client


def register(client):
    response = client.post(BASE + "/auth/register", json=BODY)
    assert response.status_code == 201
    return response


def test_registration_sets_persistent_httponly_cookie_and_restores_user(client):
    response = register(client)
    cookie = response.headers.get("set-cookie", "").lower()
    assert "sentinelx_session=" in cookie
    assert "httponly" in cookie and "samesite=lax" in cookie and "max-age=28800" in cookie
    assert "path=/" in cookie and "domain=" not in cookie
    assert client.get(BASE + "/auth/me").json()["email"] == BODY["email"]
    with db.connect() as c:
        raw = client.cookies["sentinelx_session"]
        assert (
            c.execute("SELECT token_hash FROM sessions WHERE token_hash=?", (raw,)).fetchone()
            is None
        )
        assert (
            c.execute(
                "SELECT token_hash FROM sessions WHERE token_hash=?",
                (hashlib.sha256(raw.encode()).hexdigest(),),
            ).fetchone()
            is not None
        )


def test_login_cookie_survives_new_browser_context(client):
    register(client)
    client.cookies.clear()
    response = client.post(BASE + "/auth/login", json=BODY)
    assert "sentinelx_session=" in response.headers.get("set-cookie", "")
    with TestClient(app) as reopened:
        reopened.cookies.update(client.cookies)
        assert reopened.get(BASE + "/auth/me").status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Origin": "https://attacker.example"},
        {"Origin": "null"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Origin": "http://testserver", "Sec-Fetch-Site": "cross-site"},
    ],
)
def test_cookie_mutation_rejects_csrf(client, headers):
    register(client)
    response = client.post(BASE + "/projects", json={"name": "Forged"}, headers=headers)
    assert response.status_code == 403
    assert client.get(BASE + "/projects").json() == []


def test_same_origin_cookie_write_and_logout_revoke(client):
    response = register(client)
    token = response.json()["access_token"]
    headers = {"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"}
    assert (
        client.post(
            BASE + "/projects", headers=headers, json={"name": "Browser project"}
        ).status_code
        == 201
    )
    response = client.post(BASE + "/auth/logout", headers=headers)
    assert response.status_code == 204
    assert "max-age=0" in response.headers["set-cookie"].lower()
    assert client.get(BASE + "/auth/me").status_code == 401
    assert (
        client.get(BASE + "/auth/me", headers={"Authorization": "Bearer " + token}).status_code
        == 401
    )


def test_secure_cookie_for_https_and_expired_cookie_rejected(client, monkeypatch):
    monkeypatch.setenv("SECUREFLOW_COOKIE_SECURE", "true")
    response = register(client)
    assert "; secure" in response.headers["set-cookie"].lower()
    with db.connect() as c:
        c.execute("UPDATE sessions SET expires=0")
    assert (
        client.get(
            BASE + "/auth/me",
            headers={"Authorization": "Bearer " + response.json()["access_token"]},
        ).status_code
        == 401
    )


def test_bearer_auth_still_supports_nonbrowser_clients(client):
    response = register(client)
    headers = {
        "Authorization": "Bearer " + response.json()["access_token"],
        "Origin": "https://external-api-client.example",
    }
    assert (
        client.post(BASE + "/projects", headers=headers, json={"name": "API project"}).status_code
        == 201
    )
    assert (
        client.get(
            BASE + "/auth/me", headers={"Authorization": "Bearer definitely-invalid"}
        ).status_code
        == 401
    )


def test_cross_origin_login_is_rejected_without_replacing_browser_session(client):
    original = register(client)
    response = client.post(
        BASE + "/auth/login", json=BODY, headers={"Origin": "https://attacker.example"}
    )
    assert response.status_code == 403
    assert client.cookies["sentinelx_session"] == original.json()["access_token"]


def test_admin_login_uses_separate_persistent_cookie(client):
    response = register(client)
    with db.connect() as c:
        c.execute("INSERT INTO platform_admins(user_id) VALUES(?)", (response.json()["id"],))
    client.cookies.clear()
    response = client.post(BASE + "/admin/auth/login", json=BODY)
    assert response.status_code == 200
    assert "httponly" in response.headers.get("set-cookie", "").lower()
    assert client.get(BASE + "/admin/me").json()["platform_admin"] is True


def test_admin_and_user_sessions_do_not_replace_each_other(client):
    response = register(client)
    workspace_token = client.cookies["sentinelx_session"]
    with db.connect() as c:
        c.execute("INSERT INTO platform_admins(user_id) VALUES(?)", (response.json()["id"],))
    assert client.get(BASE + "/admin/me").status_code == 401
    assert client.post(BASE + "/admin/auth/login", json=BODY).status_code == 200
    assert client.cookies["sentinelx_session"] == workspace_token
    assert client.cookies["sentinelx_admin_session"] != workspace_token
    assert client.get(BASE + "/auth/me").status_code == 200
    assert client.get(BASE + "/admin/me").status_code == 200
    assert (
        client.post(
            BASE + "/admin/auth/logout", headers={"Origin": "http://testserver"}
        ).status_code
        == 204
    )
    assert client.get(BASE + "/admin/me").status_code == 401
    assert client.get(BASE + "/auth/me").status_code == 200


def test_explicit_public_origin_supports_https_termination(client, monkeypatch):
    monkeypatch.setenv("SECUREFLOW_PUBLIC_ORIGIN", "https://sentinel.example")
    register(client)
    assert (
        client.post(
            BASE + "/projects",
            json={"name": "HTTPS"},
            headers={"Origin": "https://sentinel.example"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            BASE + "/projects", json={"name": "Spoofed"}, headers={"Origin": "http://testserver"}
        ).status_code
        == 403
    )


def test_malformed_authorization_never_falls_back_to_valid_cookie(client):
    register(client)
    assert (
        client.get(BASE + "/auth/me", headers={"Authorization": "Basic ignored"}).status_code == 401
    )
