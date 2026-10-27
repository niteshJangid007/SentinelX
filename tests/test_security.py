"""Regression checks for authorization and conservative release decisions."""

import pytest

pytestmark = pytest.mark.security

from fastapi.testclient import TestClient
from app import db
from app.main import app

BASE = "/api/v1"


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREFLOW_DB", str(tmp_path / "security.db"))
    with TestClient(app) as client:
        response = client.post(
            BASE + "/auth/register",
            json={"email": "security@example.com", "password": "security-test-password-123!"},
        )
        assert response.status_code == 201
        headers = {"Authorization": "Bearer " + response.json()["access_token"]}
        yield client, headers


def test_registration_rejects_role_injection(session):
    client, _ = session
    response = client.post(
        BASE + "/auth/register",
        json={
            "email": "injected@example.com",
            "password": "security-test-password-123!",
            "role": "admin",
            "id": "' OR 1=1 --",
        },
    )
    assert response.status_code == 422
    with db.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_logout_revokes_token(session):
    client, headers = session
    assert client.post(BASE + "/auth/logout", headers=headers).status_code == 204
    assert client.get(BASE + "/auth/me", headers=headers).status_code == 401


def test_unknown_bearer_cannot_read_data(session):
    client, _ = session
    response = client.get(BASE + "/projects", headers={"Authorization": "Bearer ' OR 1=1 --"})
    assert response.status_code == 401


@pytest.mark.parametrize(
    "gates",
    [
        [],
        [{"scanner": "sast"}],
        [{"scanner": "sast", "status": "UNRECOGNIZED"}],
        [{"scanner": "sast", "status": "SKIPPED"}],
    ],
)
def test_incomplete_or_malformed_coverage_blocks_release(session, monkeypatch, gates):
    from app import scanner

    client, headers = session
    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda *args, **kwargs: {
            "status": "completed",
            "decision": "PASS",
            "risk_score": 0,
            "findings": [],
            "gates": gates,
        },
    )
    project = client.post(BASE + "/projects", headers=headers, json={"name": "Release"}).json()
    repository = client.post(
        BASE + "/repositories",
        headers=headers,
        json={"project_id": project["id"], "url": "https://github.com/example/release"},
    ).json()
    scan = client.post(
        BASE + "/scans", headers=headers, json={"repository_id": repository["id"]}
    ).json()
    report = client.get(BASE + "/scans/" + scan["id"] + "/report", headers=headers).json()
    assert report["scan"]["decision"] == "BLOCK"
    assert report["deployment_allowed"] is False
    deployment = client.post(
        BASE + "/deployments", headers=headers, json={"scan_id": scan["id"], "version": "v1"}
    ).json()
    assert deployment["status"] == "blocked"


@pytest.mark.parametrize("coverage", [None, {"complete": False}])
def test_incomplete_coverage_blocks_even_when_gates_pass(session, monkeypatch, coverage):
    from app import scanner

    client, headers = session
    result = {
        "status": "completed",
        "decision": "PASS",
        "findings": [],
        "gates": [{"scanner": "sast", "status": "PASS"}],
    }
    if coverage is not None:
        result["coverage"] = coverage
    monkeypatch.setattr(scanner, "scan_repository", lambda *args, **kwargs: result)
    project = client.post(BASE + "/projects", headers=headers, json={"name": "Coverage"}).json()
    repository = client.post(
        BASE + "/repositories",
        headers=headers,
        json={"project_id": project["id"], "url": "https://github.com/example/coverage"},
    ).json()
    scan = client.post(
        BASE + "/scans", headers=headers, json={"repository_id": repository["id"]}
    ).json()
    report = client.get(BASE + "/scans/" + scan["id"] + "/report", headers=headers).json()
    assert report["deployment_allowed"] is False
    assert report["scan"]["decision"] == "BLOCK"
