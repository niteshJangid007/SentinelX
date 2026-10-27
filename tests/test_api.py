"""Exercise the complete authenticated control-plane workflow without network dependencies."""

import hashlib
import time

import pytest

pytestmark = pytest.mark.integration

from fastapi.testclient import TestClient

from app import db
from app.main import app

BASE = "/api/v1"
PASSWORD = "secure-test-password-123!"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREFLOW_DB", str(tmp_path / "test.db"))
    with TestClient(app) as client:
        yield client


def account(client, email="owner@example.com"):
    response = client.post(BASE + "/auth/register", json={"email": email, "password": PASSWORD})
    assert response.status_code in (200, 201), response.text
    response = client.post(BASE + "/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def resource(client, path, headers, body):
    response = client.post(BASE + path, headers=headers, json=body)
    assert response.status_code in (200, 201, 202), response.text
    return response.json()


def project_and_repository(client, headers):
    project = resource(client, "/projects", headers, {"name": "Payments"})
    repository = resource(
        client,
        "/repositories",
        headers,
        {
            "project_id": project["id"],
            "url": "https://github.com/example/payments",
            "branch": "main",
        },
    )
    return project, repository


def test_authentication_validation_and_session_storage(client):
    assert client.get(BASE + "/projects").status_code == 401
    assert (
        client.post(BASE + "/auth/register", json={"email": "bad", "password": "tiny"}).status_code
        == 422
    )
    headers = account(client)
    assert client.get(BASE + "/projects", headers=headers).status_code == 200
    assert (
        client.post(
            BASE + "/auth/login",
            json={"email": "owner@example.com", "password": "incorrect-password"},
        ).status_code
        == 401
    )
    assert (
        client.post(
            BASE + "/auth/register", json={"email": "owner@example.com", "password": PASSWORD}
        ).status_code
        == 409
    )
    token = headers["Authorization"].split()[1]
    with db.connect() as c:
        row = c.execute(
            "SELECT token_hash FROM sessions WHERE token_hash=?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        user = c.execute("SELECT password FROM users").fetchone()
    assert row is not None
    assert user["password"] != PASSWORD
    assert token != row["token_hash"]


def test_cross_user_resource_isolation(client):
    owner = account(client)
    outsider = account(client, "outsider@example.com")
    project, repository = project_and_repository(client, owner)
    assert client.get(BASE + "/projects", headers=outsider).json() == []
    assert client.get(BASE + "/projects/" + project["id"], headers=outsider).status_code == 404
    response = client.post(
        BASE + "/repositories",
        headers=outsider,
        json={"project_id": project["id"], "url": "https://github.com/example/private"},
    )
    assert response.status_code == 404
    assert (
        client.post(
            BASE + "/scans", headers=outsider, json={"repository_id": repository["id"]}
        ).status_code
        == 404
    )


def test_expired_sessions_and_viewer_permissions(client):
    headers = account(client)
    with db.connect() as c:
        c.execute("UPDATE users SET role='viewer'")
    assert client.get(BASE + "/projects", headers=headers).status_code == 200
    assert (
        client.post(BASE + "/projects", headers=headers, json={"name": "Unauthorized"}).status_code
        == 403
    )
    assert (
        client.post(BASE + "/policies", headers=headers, json={"name": "Unauthorized"}).status_code
        == 403
    )
    with db.connect() as c:
        c.execute("UPDATE sessions SET expires=?", (time.time() - 10,))
    assert client.get(BASE + "/projects", headers=headers).status_code == 401


def test_repository_url_rejects_untrusted_destinations(client):
    headers = account(client)
    project = resource(client, "/projects", headers, {"name": "Security"})
    for url in [
        "http://169.254.169.254/latest/meta-data",
        "https://github.com.evil.test/a/b",
        "file:///etc/passwd",
        "https://user:pass@github.com/a/b",
    ]:
        response = client.post(
            BASE + "/repositories", headers=headers, json={"project_id": project["id"], "url": url}
        )
        assert response.status_code in (400, 422), (url, response.text)


def test_scan_report_policy_and_deployment_gate(client, monkeypatch):
    from app.main import scanner

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda *args, **kwargs: {
            "commit": "a" * 40,
            "status": "completed",
            "decision": "BLOCK",
            "risk_score": 25,
            "findings": [
                {
                    "title": "Unsafe evaluation",
                    "severity": "high",
                    "scanner": "sast",
                    "path": "app.py",
                    "line": 3,
                    "description": "Dynamic evaluation of input.",
                    "remediation": "Parse structured input instead.",
                }
            ],
            "gates": [{"scanner": "sast", "status": "PASS"}],
        },
    )
    headers = account(client)
    _, repository = project_and_repository(client, headers)
    scan = resource(client, "/scans", headers, {"repository_id": repository["id"]})
    completed = client.get(BASE + "/scans/" + scan["id"], headers=headers).json()
    assert completed["status"] == "completed", completed
    assert completed["decision"] == "BLOCK", completed
    report_response = client.get(BASE + "/scans/" + scan["id"] + "/report", headers=headers)
    assert report_response.status_code == 200
    assert "Unsafe evaluation" in report_response.text
    findings = client.get(BASE + "/findings", headers=headers).json()
    assert len(findings) == 1
    finding = findings[0]
    response = client.patch(
        BASE + "/findings/" + finding["id"],
        headers=headers,
        json={"status": "resolved", "reason": "Removed dynamic execution"},
    )
    assert response.status_code == 200
    deployment = resource(
        client,
        "/deployments",
        headers,
        {"scan_id": scan["id"], "version": "v1.0", "environment": "production"},
    )
    assert deployment["status"] == "blocked", deployment
    outsider = account(client, "report-outsider@example.com")
    assert (
        client.get(BASE + "/scans/" + scan["id"] + "/report", headers=outsider).status_code == 404
    )
    assert (
        client.patch(
            BASE + "/findings/" + finding["id"],
            headers=outsider,
            json={"status": "ignored", "reason": "Unauthorized change"},
        ).status_code
        == 404
    )


def test_scanner_failure_blocks_release(client, monkeypatch):
    from app.main import scanner

    def broken(*args, **kwargs):
        raise RuntimeError("Scanner unavailable")

    monkeypatch.setattr(scanner, "scan_repository", broken)
    headers = account(client)
    _, repository = project_and_repository(client, headers)
    scan = resource(client, "/scans", headers, {"repository_id": repository["id"]})
    result = client.get(BASE + "/scans/" + scan["id"], headers=headers).json()
    assert result["status"] == "failed", result
    assert result["decision"] == "BLOCK", result
    deployment = resource(
        client,
        "/deployments",
        headers,
        {"scan_id": scan["id"], "version": "v2", "environment": "production"},
    )
    assert deployment["status"] == "blocked", deployment


def test_logout_revokes_current_session_only(client):
    headers = account(client)
    second = client.post(
        BASE + "/auth/login", json={"email": "owner@example.com", "password": PASSWORD}
    )
    other_headers = {"Authorization": "Bearer " + second.json()["access_token"]}
    assert client.post(BASE + "/auth/logout", headers=headers).status_code == 204
    assert client.get(BASE + "/auth/me", headers=headers).status_code == 401
    assert client.get(BASE + "/auth/me", headers=other_headers).status_code == 200


def test_policy_owner_isolation_and_invalid_actions(client):
    headers = account(client)
    outsider = account(client, "policy-outsider@example.com")
    policy = resource(client, "/policies", headers, {"name": "Production", "medium": "BLOCK"})
    response = client.put(
        BASE + "/policies/" + policy["id"],
        headers=outsider,
        json={"name": "Weakened", "high": "ALLOW"},
    )
    assert response.status_code == 404
    response = client.post(
        BASE + "/policies", headers=headers, json={"name": "Bad", "critical": "IGNORE"}
    )
    assert response.status_code == 422
    response = client.put(
        BASE + "/policies/" + policy["id"],
        headers=headers,
        json={"name": "Production strict", "medium": "BLOCK"},
    )
    assert response.status_code == 200
    assert response.json()["medium"] == "BLOCK"


def test_incomplete_scanner_coverage_cannot_pass(client, monkeypatch):
    from app.main import scanner

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda *args, **kwargs: {
            "status": "completed",
            "decision": "PASS",
            "findings": [],
            "gates": [{"scanner": "external-sca", "status": "UNAVAILABLE"}],
        },
    )
    headers = account(client)
    _, repository = project_and_repository(client, headers)
    scan = resource(client, "/scans", headers, {"repository_id": repository["id"]})
    result = client.get(BASE + "/scans/" + scan["id"], headers=headers).json()
    assert result["decision"] == "BLOCK"
    assert result["reasons"]
    assert (
        client.get(BASE + "/scans/" + scan["id"] + "/report", headers=headers).json()[
            "deployment_allowed"
        ]
        is False
    )


def test_zip_upload_validates_type_and_project_ownership(client):
    headers = account(client)
    outsider = account(client, "upload-outsider@example.com")
    project = resource(client, "/projects", headers, {"name": "ZIP project"})
    path = BASE + "/projects/" + project["id"] + "/upload"
    response = client.post(
        path, headers=headers, files={"file": ("source.zip", b"not a zip", "application/zip")}
    )
    assert response.status_code == 422
    response = client.post(
        path, headers=outsider, files={"file": ("source.zip", b"PKbad", "application/zip")}
    )
    assert response.status_code == 404


def test_complete_clean_scan_is_eligible_but_does_not_deploy(client, monkeypatch):
    from app.main import scanner

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda *args, **kwargs: {
            "status": "completed",
            "decision": "PASS",
            "findings": [],
            "coverage": {"complete": True},
            "gates": [{"scanner": "sast", "status": "PASS"}],
        },
    )
    headers = account(client)
    _, repository = project_and_repository(client, headers)
    scan = resource(client, "/scans", headers, {"repository_id": repository["id"]})
    result = client.get(BASE + "/scans/" + scan["id"], headers=headers).json()
    assert result["decision"] == "PASS"
    assert (
        client.get(BASE + "/scans/" + scan["id"] + "/report", headers=headers).json()[
            "deployment_allowed"
        ]
        is True
    )
    deployment = resource(
        client,
        "/deployments",
        headers,
        {"scan_id": scan["id"], "version": "v1.1", "environment": "production"},
    )
    assert deployment["status"] == "eligible"
    assert deployment["executed"] is False
