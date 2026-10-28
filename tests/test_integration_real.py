"""Real API -> scanner -> SQLite integration tests; no scanner or transport mocks."""

import io
import json
import stat
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import db
from app.main import app

pytestmark = pytest.mark.integration

BASE = "/api/v1"
SECRET = "ghp_" + "Q7w9R2t6Y4u8I1o3P5a0S9d7F2g6H4j8K1l3"


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "integration.db"
    monkeypatch.setenv("SECUREFLOW_DB", str(path))
    return path


@pytest.fixture
def client(database):
    with TestClient(app) as client:
        yield client


def register(client, email="real-integration@example.com"):
    response = client.post(
        BASE + "/auth/register", json={"email": email, "password": "Real-integration-password-72!"}
    )
    assert response.status_code == 201, response.text
    return response.json()["id"], {"Authorization": "Bearer " + response.json()["access_token"]}


def project(client, headers):
    response = client.post(
        BASE + "/projects", headers=headers, json={"name": "Real integration target"}
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def archive(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, contents in entries.items():
            zipped.writestr(name, contents)
    return stream.getvalue()


def upload(client, headers, project_id, data):
    response = client.post(
        BASE + "/projects/" + project_id + "/upload",
        headers=headers,
        files={"file": ("target.zip", data, "application/zip")},
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]
    result = client.get(BASE + "/scans/" + scan_id, headers=headers)
    assert result.status_code == 200, result.text
    return result.json()


def test_real_vulnerable_zip_findings_report_gate_audit_and_owner_isolation(client, caplog):
    owner, headers = register(client)
    project_id = project(client, headers)
    data = archive(
        {
            "app.py": 'import pickle\nTOKEN = "'
            + SECRET
            + '"\nvalue = eval(input())\npickle.loads(b"data")\n',
            "Dockerfile": "FROM python:3.12\nUSER root\n",
            "deployment.yaml": "securityContext:\n  privileged: true\n",
        }
    )
    scan = upload(client, headers, project_id, data)
    assert scan["status"] == "completed"
    assert scan["source"] == "zip"
    assert scan["decision"] == "BLOCK"
    assert scan["risk_score"] > 0
    assert scan["coverage"]["complete"] is False
    assert "Python" in scan["technologies"]
    assert "Docker" in scan["technologies"]
    assert {"secrets", "sast", "iac"} <= {f["scanner"] for f in scan["findings"]}
    assert any(f["title"] == "Dynamic code execution" for f in scan["findings"])
    assert any(f["title"] == "Unsafe deserialization" for f in scan["findings"])
    assert all(
        f["scan_id"] == scan["id"] and f["project_id"] == project_id for f in scan["findings"]
    )

    findings = client.get(BASE + "/findings", headers=headers).json()
    assert len(findings) == len(scan["findings"])
    report = client.get(BASE + "/scans/" + scan["id"] + "/report", headers=headers)
    assert report.status_code == 200
    assert report.json()["deployment_allowed"] is False
    assert report.json()["scan"]["findings"] == scan["findings"]
    deployment = client.post(
        BASE + "/deployments",
        headers=headers,
        json={"scan_id": scan["id"], "version": "v1-real", "environment": "production"},
    )
    assert deployment.status_code == 201
    assert deployment.json()["status"] == "blocked"
    assert deployment.json()["executed"] is False
    dashboard = client.get(BASE + "/dashboard", headers=headers).json()
    assert dashboard["total_scans"] == 1
    assert dashboard["open_findings"] == len(findings)
    assert dashboard["blocked_releases"] == 1
    audit = client.get(BASE + "/audit-logs", headers=headers).json()
    assert {
        "project.created",
        "scan.started",
        "scan.completed",
        "report.generated",
        "deployment.evaluated",
    } <= {e["action"] for e in audit}
    assert len(client.get(BASE + "/reports", headers=headers).json()) == 1

    # A live secret-like test string must never appear in persisted metadata or logs.
    with db.connect() as connection:
        stored = [
            row["data"]
            for row in connection.execute("SELECT data FROM resources WHERE owner=?", (owner,))
        ]
    assert SECRET not in "\n".join(stored)
    assert SECRET not in report.text
    assert SECRET not in caplog.text

    _, outsider = register(client, "real-outsider@example.com")
    for endpoint in [
        "/scans/" + scan["id"],
        "/scans/" + scan["id"] + "/report",
        "/findings/" + findings[0]["id"],
    ]:
        assert client.get(BASE + endpoint, headers=outsider).status_code == 404
    for endpoint in ["/findings", "/reports", "/scans", "/audit-logs"]:
        values = client.get(BASE + endpoint, headers=outsider).json()
        assert scan["id"] not in json.dumps(values)
        assert project_id not in json.dumps(values)
    assert (
        client.post(
            BASE + "/deployments",
            headers=outsider,
            json={"scan_id": scan["id"], "version": "stolen", "environment": "production"},
        ).status_code
        == 404
    )


@pytest.mark.parametrize("kind", ["traversal", "symlink", "oversized_file", "corrupt_zip"])
def test_malicious_zip_fails_closed_without_findings_or_secret_disclosure(client, caplog, kind):
    _, headers = register(client)
    project_id = project(client, headers)
    if kind == "traversal":
        data = archive({"../../outside.py": 'secret_key = "' + SECRET + '"'})
    elif kind == "symlink":
        stream = io.BytesIO()
        info = zipfile.ZipInfo("unsafe-link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(stream, "w") as zipped:
            zipped.writestr(info, "/etc/passwd")
        data = stream.getvalue()
    elif kind == "oversized_file":
        data = archive({"large.py": "#" * (1024 * 1024 + 1)})
    else:
        data = b"PK this is not a valid ZIP " + SECRET.encode()
    scan = upload(client, headers, project_id, data)
    assert scan["status"] == "failed"
    assert scan["decision"] == "BLOCK"
    assert scan["findings"] == []
    assert client.get(BASE + "/findings", headers=headers).json() == []
    report = client.get(BASE + "/scans/" + scan["id"] + "/report", headers=headers)
    assert report.status_code == 200
    assert report.json()["deployment_allowed"] is False
    assert SECRET not in report.text
    assert SECRET not in caplog.text
    audit = client.get(BASE + "/audit-logs", headers=headers).json()
    assert any(item["action"] == "scan.failed" for item in audit)


def test_restart_preserves_data_and_recovers_interrupted_scans(database):
    with TestClient(app) as first:
        owner, headers = register(first)
        project_id = project(first, headers)
        completed = upload(
            first, headers, project_id, archive({"main.py": 'print("safe baseline")\n'})
        )
        assert completed["status"] == "completed"
        interrupted = db.create(
            "scan",
            owner,
            {
                "project_id": project_id,
                "status": "running",
                "decision": "PASS",
                "findings": [],
                "gates": [],
            },
        )
    # Fresh lifespan against the same on-disk SQLite database simulates a worker restart.
    with TestClient(app) as restarted:
        assert restarted.get("/health").json()["status"] == "ok"
        assert restarted.get(BASE + "/projects/" + project_id, headers=headers).status_code == 200
        persisted = restarted.get(BASE + "/scans/" + completed["id"], headers=headers).json()
        assert persisted == completed
        recovered = restarted.get(BASE + "/scans/" + interrupted["id"], headers=headers).json()
        assert recovered["status"] == "failed"
        assert recovered["decision"] == "BLOCK"
        assert "interrupted" in recovered["error"].lower()
        report = restarted.get(BASE + "/scans/" + interrupted["id"] + "/report", headers=headers)
        assert report.status_code == 200
        assert report.json()["deployment_allowed"] is False


def test_real_python_parse_failure_does_not_report_clean_sast(client):
    _, headers = register(client)
    project_id = project(client, headers)
    result = upload(client, headers, project_id, archive({"broken.py": "def broken(:\n"}))
    assert result["status"] == "completed"
    assert result["decision"] == "BLOCK"
    sast = next(gate for gate in result["gates"] if gate["scanner"] == "sast")
    assert sast["status"] == "FAILED"
    assert result["coverage"]["analysis_errors"]


def test_uploaded_build_hooks_and_application_code_are_never_executed(client, tmp_path):
    _, headers = register(client)
    project_id = project(client, headers)
    marker = tmp_path / "untrusted-code-executed"
    payload = f'from pathlib import Path\nPath({str(marker)!r}).write_text("executed")\n'
    data = archive(
        {
            "setup.py": payload,
            "main.py": payload,
            "package.json": json.dumps({"scripts": {"postinstall": "touch " + str(marker)}}),
            "Dockerfile": "FROM scratch\nRUN touch " + str(marker) + "\n",
        }
    )
    result = upload(client, headers, project_id, data)
    assert result["status"] == "completed"
    assert result["decision"] == "BLOCK"
    assert marker.exists() is False
    assert any("No untrusted repository code" in item for item in result["coverage"]["limitations"])


def test_php_runtime_cves_survive_real_scan_persistence_and_report(client):
    _, headers = register(client, "php-runtime@example.test")
    project_id = project(client, headers)
    scan = upload(client, headers, project_id, archive({"Dockerfile": "FROM php:8.3.35-fpm\n"}))
    assert scan["status"] == "completed"
    report = client.get(BASE + "/scans/" + scan["id"] + "/report", headers=headers).json()
    cves = [f for f in report["scan"]["findings"] if f.get("cve")]
    assert {f["cve"] for f in cves} == {"CVE-2026-109618", "CVE-2026-109619"}
    assert all(f["fixed_version"] == "8.3.36" and f["line"] == 1 for f in cves)
    assert report["scan"]["coverage"]["php_runtime"]["evidence"][0]["status"] == "affected"
    assert report["deployment_allowed"] is False
    saved = client.get(BASE + "/findings", headers=headers).json()
    assert {f["cve"] for f in saved if f.get("cve")} == {f["cve"] for f in cves}
    _, other = register(client, "other-php@example.test")
    assert client.get(BASE + "/scans/" + scan["id"] + "/report", headers=other).status_code == 404


def test_inline_js_findings_saved_in_api_and_report(client):
    _, headers = register(client, "javascript-review@example.test")
    project_id = project(client, headers)
    source = "<script>\nconst allowed = !secure || viewer.id === target.id || viewer.role === 'admin';\nel.innerHTML = data;\n</script>"
    result = upload(client, headers, project_id, archive({"index.html": source}))
    report = client.get(BASE + "/scans/" + result["id"] + "/report", headers=headers).json()
    findings = report["scan"]["findings"]
    assert {f["rule_id"] for f in findings} == {"JS-CLIENT-AUTH", "JS-DYNAMIC-HTML"}
    assert {f["line"] for f in findings} == {2, 3}
    assert all(f["confidence"] == "low" and f["assessment"] == "review_required" for f in findings)
    assert next(g for g in report["scan"]["gates"] if g["scanner"] == "sast")["status"] == "WARN"
    assert client.get(BASE + "/findings", headers=headers).json()
