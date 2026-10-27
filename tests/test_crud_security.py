"""Local adversarial CRUD regressions using synthetic accounts and databases."""

import pytest
from fastapi.testclient import TestClient
from app import db
from app.main import app

pytestmark = [pytest.mark.integration, pytest.mark.security]
P = "/api/v1"


@pytest.fixture
def session(tmp_path, monkeypatch):
    for name in ("DATABASE_URL", "SECUREFLOW_ENV", "SENTINELX_ENV", "SECUREFLOW_PUBLIC_ORIGIN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SECUREFLOW_COOKIE_SECURE", "false")
    monkeypatch.setenv("SECUREFLOW_DB", str(tmp_path / "crud-security.db"))
    with TestClient(app) as client:
        user = client.post(
            P + "/auth/register",
            json={"email": "owner@example.test", "password": "owner-security-password"},
        ).json()
        headers = {"Authorization": "Bearer " + user["access_token"]}
        project = client.post(
            P + "/projects", headers=headers, json={"name": "Private Project"}
        ).json()
        yield client, user, headers, project


def test_cookie_delete_requires_csrf_evidence_even_with_confirmation(session):
    client, user, headers, project = session
    url = P + "/projects/" + project["id"] + "?confirm=true"
    assert client.delete(url, headers={"Origin": "https://attacker.example"}).status_code == 403
    assert client.delete(url).status_code == 403
    assert db.get("project", user["id"], project["id"]) is not None
    assert client.delete(url, headers={"Origin": "http://testserver"}).status_code == 204


def test_viewer_cannot_delete_or_edit_with_forged_role_headers(session):
    client, user, headers, project = session
    with db.connect() as c:
        c.execute("UPDATE users SET role='viewer' WHERE id=?", (user["id"],))
    forged = {**headers, "X-Role": "admin", "X-User-ID": user["id"]}
    assert (
        client.delete(
            P + "/projects/" + project["id"] + "?confirm=true", headers=forged
        ).status_code
        == 403
    )
    assert (
        client.put(
            P + "/projects/" + project["id"], headers=forged, json={"name": "Takeover"}
        ).status_code
        == 403
    )
    assert db.get("project", user["id"], project["id"])["name"] == "Private Project"


def test_project_cascade_never_deletes_other_owner_rows_with_poisoned_links(session):
    client, user, headers, project = session
    # A corrupted/imported child must not widen deletion beyond the authenticated
    # owner, even when its project_id points to the target account's project.
    outsider = "synthetic-other-owner"
    child = db.create(
        "finding", outsider, {"project_id": project["id"], "title": "Other account finding"}
    )
    own = db.create("finding", user["id"], {"project_id": project["id"], "title": "Own finding"})
    assert (
        client.delete(
            P + "/projects/" + project["id"] + "?confirm=true", headers=headers
        ).status_code
        == 204
    )
    assert db.get("finding", user["id"], own["id"]) is None
    assert db.get("finding", outsider, child["id"]) is not None


def test_delete_rolls_back_if_atomic_audit_write_fails(session):
    client, user, headers, project = session
    child = db.create(
        "repository",
        user["id"],
        {"project_id": project["id"], "url": "https://github.com/example/project"},
    )
    with db.connect() as c:
        c.executescript("""CREATE TRIGGER reject_audit BEFORE INSERT ON resources
        WHEN NEW.kind='audit' BEGIN SELECT RAISE(ABORT,'synthetic-secret-must-not-leak'); END;""")
    response = client.delete(P + "/projects/" + project["id"] + "?confirm=true", headers=headers)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "database_conflict"
    assert "synthetic-secret-must-not-leak" not in response.text
    assert db.get("project", user["id"], project["id"]) is not None
    assert db.get("repository", user["id"], child["id"]) is not None
