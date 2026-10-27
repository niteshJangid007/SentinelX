"""TDD: platform administration is independent from workspace ownership."""

import pytest
from fastapi.testclient import TestClient
from app import auth, db
from app.main import app

pytestmark = [pytest.mark.integration, pytest.mark.security]
BASE = "/api/v1"
PASSWORD = "admin-test-password-123!"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SECUREFLOW_DB", str(tmp_path / "admin.db"))
    with TestClient(app) as client:
        yield client


def register(client, email):
    response = client.post(BASE + "/auth/register", json={"email": email, "password": PASSWORD})
    assert response.status_code == 201, response.text
    data = response.json()
    return data, {"Authorization": "Bearer " + data["access_token"]}


def platform(client):
    data, headers = register(client, "operator@example.com")
    with db.connect() as c:
        c.execute("INSERT INTO platform_admins(user_id) VALUES(?)", (data["id"],))
    return data, headers


def test_workspace_admin_cannot_use_platform_portal(client):
    _, headers = register(client, "owner@example.com")
    assert client.get(BASE + "/admin/users", headers=headers).status_code == 403
    assert client.get(BASE + "/admin/users").status_code == 401
    response = client.post(
        BASE + "/admin/auth/login", json={"email": "owner@example.com", "password": PASSWORD}
    )
    assert response.status_code == 401


def test_admin_login_and_safe_user_listing(client):
    user, _ = platform(client)
    response = client.post(
        BASE + "/admin/auth/login", json={"email": user["email"], "password": PASSWORD}
    )
    assert response.status_code == 200
    headers = {"Authorization": "Bearer " + response.json()["access_token"]}
    assert client.get(BASE + "/admin/me", headers=headers).json()["platform_admin"] is True
    rows = client.get(BASE + "/admin/users", headers=headers).json()
    assert rows[0]["email"] == user["email"]
    assert set(rows[0]) == {"id", "email", "role", "disabled", "platform_admin"}
    assert "password" not in str(rows)


def test_admin_cross_account_visibility_and_audit(client):
    _, admin_headers = platform(client)
    user, user_headers = register(client, "developer@example.com")
    project = client.post(
        BASE + "/projects", headers=user_headers, json={"name": "Private Payments"}
    ).json()
    assert client.get(BASE + "/projects", headers=admin_headers).json() == []
    rows = client.get(BASE + "/admin/projects", headers=admin_headers).json()
    assert rows[0]["id"] == project["id"] and rows[0]["owner_id"] == user["id"]
    assert (
        client.get(BASE + "/admin/projects/" + project["id"], headers=admin_headers).status_code
        == 200
    )
    overview = client.get(BASE + "/admin/overview", headers=admin_headers).json()
    assert overview["users"] == 2 and overview["projects"] == 1
    logs = client.get(BASE + "/admin/audit-logs", headers=admin_headers).json()
    assert any(log["action"] == "admin.resource.read" for log in logs)


def test_disable_revokes_live_sessions_and_login(client):
    _, headers = platform(client)
    user, live = register(client, "disabled@example.com")
    response = client.patch(
        BASE + "/admin/users/" + user["id"], headers=headers, json={"disabled": True}
    )
    assert response.status_code == 200
    assert response.json()["disabled"] is True
    assert client.get(BASE + "/auth/me", headers=live).status_code == 401
    assert (
        client.post(
            BASE + "/auth/login", json={"email": user["email"], "password": PASSWORD}
        ).status_code
        == 401
    )
    assert (
        client.patch(
            BASE + "/admin/users/" + user["id"], headers=headers, json={"disabled": False}
        ).status_code
        == 200
    )
    assert (
        client.get(BASE + "/auth/me", headers=live).status_code == 401
    )  # Revocation survives re-enable.


def test_role_updates_cannot_grant_platform_membership(client):
    _, headers = platform(client)
    user, user_headers = register(client, "viewer@example.com")
    target = BASE + "/admin/users/" + user["id"]
    assert client.patch(target, headers=headers, json={"role": "viewer"}).status_code == 200
    assert (
        client.post(
            BASE + "/projects", headers=user_headers, json={"name": "Forbidden"}
        ).status_code
        == 403
    )
    for body in ({"role": "platform_admin"}, {"platform_admin": True}, {"id": "forged"}, {}):
        assert client.patch(target, headers=headers, json=body).status_code == 422
    assert client.get(BASE + "/admin/users", headers=user_headers).status_code == 403


def test_admin_accounts_cannot_be_disabled_or_demoted_via_api(client):
    admin, headers = platform(client)
    response = client.patch(
        BASE + "/admin/users/" + admin["id"],
        headers=headers,
        json={"disabled": True, "role": "viewer"},
    )
    assert response.status_code == 409
    assert client.get(BASE + "/admin/me", headers=headers).status_code == 200


def test_admin_login_shares_auth_throttle(client):
    client.app.state.auth_limiter = auth.RateLimiter(limit=1)
    assert (
        client.post(
            BASE + "/admin/auth/login", json={"email": "absent@example.com", "password": PASSWORD}
        ).status_code
        == 401
    )
    assert (
        client.post(
            BASE + "/auth/login", json={"email": "absent@example.com", "password": PASSWORD}
        ).status_code
        == 429
    )


def test_admin_report_and_nonexistent_resources(client):
    _, headers = platform(client)
    user, _ = register(client, "reports@example.com")
    project = db.create("project", user["id"], {"name": "Reports"})
    scan = db.create(
        "scan",
        user["id"],
        {"project_id": project["id"], "status": "completed", "decision": "BLOCK", "findings": []},
    )
    report = client.get(BASE + "/admin/scans/" + scan["id"] + "/report", headers=headers)
    assert report.status_code == 200
    assert report.json()["scan"]["decision"] == "BLOCK"
    assert report.json()["deployment_allowed"] is False
    rows = client.get(BASE + "/admin/reports", headers=headers).json()
    assert rows[0]["scan_id"] == scan["id"]
    assert client.get(BASE + "/admin/projects/not-present", headers=headers).status_code == 404
    assert client.get(BASE + "/admin/users?limit=100000", headers=headers).status_code == 422


def test_cli_bootstrap_creates_hashed_password_and_explicit_membership(client):
    from app.manage import create_admin

    ident = create_admin("local-operator@example.com", PASSWORD)
    with db.connect() as c:
        row = c.execute("SELECT password FROM users WHERE id=?", (ident,)).fetchone()
        member = c.execute(
            "SELECT user_id FROM platform_admins WHERE user_id=?", (ident,)
        ).fetchone()
    assert row["password"] != PASSWORD
    assert auth.verify_password(PASSWORD, row["password"])
    assert member["user_id"] == ident
    assert (
        client.post(
            BASE + "/admin/auth/login",
            json={"email": "local-operator@example.com", "password": PASSWORD},
        ).status_code
        == 200
    )
    with pytest.raises(ValueError):
        create_admin("local-operator@example.com", PASSWORD)


def test_cli_requires_explicit_existing_account_grant_and_keeps_password(client):
    from app.manage import create_admin

    user, _ = register(client, "existing@example.com")
    with db.connect() as c:
        before = c.execute("SELECT password FROM users WHERE id=?", (user["id"],)).fetchone()[
            "password"
        ]
    with pytest.raises(ValueError):
        create_admin("existing@example.com", PASSWORD)
    assert create_admin("existing@example.com", grant_existing=True) == user["id"]
    with db.connect() as c:
        assert (
            c.execute("SELECT password FROM users WHERE id=?", (user["id"],)).fetchone()["password"]
            == before
        )
    with pytest.raises(ValueError):
        create_admin("not-existing@example.com", grant_existing=True)


def test_cli_never_echoes_password_on_validation_error(client, monkeypatch, capsys):
    from app import manage

    secret = "weak-secret"
    monkeypatch.setattr(manage.getpass, "getpass", lambda _: secret)
    assert manage.main(["create-admin", "--email", "invalid-email"]) == 1
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err


def test_revoked_platform_membership_rejects_existing_session(client):
    user, headers = platform(client)
    with db.connect() as c:
        c.execute("DELETE FROM platform_admins WHERE user_id=?", (user["id"],))
    assert client.get(BASE + "/admin/me", headers=headers).status_code == 403
    assert client.get(BASE + "/admin/scans", headers=headers).status_code == 403
    assert client.get(BASE + "/auth/me", headers=headers).status_code == 200


@pytest.mark.parametrize(
    "endpoint",
    ["overview", "users", "projects", "repositories", "scans", "reports", "audit-logs", "findings"],
)
def test_all_admin_collections_reject_regular_account(client, endpoint):
    _, headers = register(client, "tenant@example.com")
    assert client.get(BASE + "/admin/" + endpoint, headers=headers).status_code == 403
