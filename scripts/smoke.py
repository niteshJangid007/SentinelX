"""Exercise a running API with a synthetic vulnerable ZIP, no external targets."""

import io
import json
import secrets
import sys
import time
import zipfile
import httpx

base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
with httpx.Client(base_url=base, timeout=30) as client:
    assert client.get("/health").json()["status"] == "ok"
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": f"smoke-{secrets.token_hex(6)}@example.test",
            "password": secrets.token_urlsafe(24),
        },
    )
    response.raise_for_status()
    client.headers["Authorization"] = "Bearer " + response.json()["access_token"]
    project = client.post("/api/v1/projects", json={"name": "Smoke fixture"})
    project.raise_for_status()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("app.py", 'import subprocess\nsubprocess.run("echo test", shell=True)\n')
        output.writestr("Dockerfile", "FROM python:latest\nUSER root\n")
    response = client.post(
        "/api/v1/projects/" + project.json()["id"] + "/upload",
        files={"file": ("fixture.zip", archive.getvalue(), "application/zip")},
    )
    response.raise_for_status()
    ident = response.json()["id"]
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        scan = client.get("/api/v1/scans/" + ident).json()
        if scan["status"] not in ("queued", "running"):
            break
        time.sleep(0.2)
    assert scan["status"] == "completed", scan
    assert scan["findings"], scan
    assert scan["decision"] == "BLOCK", scan
    report = client.get("/api/v1/scans/" + ident + "/report")
    report.raise_for_status()
    assert report.json()["deployment_allowed"] is False
    print(
        json.dumps(
            {
                "status": scan["status"],
                "findings": len(scan["findings"]),
                "decision": scan["decision"],
                "report_verified": True,
            }
        )
    )
