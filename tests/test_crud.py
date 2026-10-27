"""Project and repository CRUD, owner isolation and deletion safeguards."""

import os
import uuid
import pytest
from fastapi.testclient import TestClient
from app import db
from app.main import app

pytestmark = pytest.mark.integration


@pytest.fixture(params=["sqlite", "postgres"])
def session(tmp_path, monkeypatch, request):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SECUREFLOW_ENV", raising=False)
    monkeypatch.delenv("SENTINELX_ENV", raising=False)
    monkeypatch.setenv("SECUREFLOW_DB", str(tmp_path / "crud.db"))
    destination = os.getenv("TEST_DATABASE_URL")
    schema = None
    if request.param == "postgres":
        if not destination:
            pytest.skip("TEST_DATABASE_URL required for PostgreSQL CRUD parity")
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        schema = "secureflow_crud_" + uuid.uuid4().hex
        with psycopg.connect(destination, autocommit=True) as connection:
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        monkeypatch.setenv(
            "DATABASE_URL", make_conninfo(destination, options=f"-c search_path={schema}")
        )
    try:
        with TestClient(app) as client:
            created = client.post(
                "/api/v1/auth/register",
                json={"email": "crud@example.test", "password": "crud-test-password-123!"},
            ).json()
            yield client, {"Authorization": "Bearer " + created["access_token"]}, created["id"]
    finally:
        if schema:
            with psycopg.connect(destination, autocommit=True) as connection:
                connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def create_project(client, headers, name="Payments"):
    result = client.post("/api/v1/projects", headers=headers, json={"name": name})
    assert result.status_code == 201
    return result.json()


def create_repo(client, headers, project_id):
    result = client.post(
        "/api/v1/repositories",
        headers=headers,
        json={
            "project_id": project_id,
            "url": "https://github.com/acme/payments",
            "branch": "main",
        },
    )
    assert result.status_code == 201
    return result.json()


def test_project_full_crud_and_search(session):
    client, headers, owner = session
    project = create_project(client, headers)
    create_project(client, headers, "Inventory")
    assert (
        client.get("/api/v1/projects/" + project["id"], headers=headers).json()["name"]
        == "Payments"
    )
    updated = client.put(
        "/api/v1/projects/" + project["id"],
        headers=headers,
        json={"name": "  Payments API  ", "technology": "Python"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Payments API"
    assert [
        p["id"]
        for p in client.get("/api/v1/projects?q=PAYMENTS&limit=1&offset=0", headers=headers).json()
    ] == [project["id"]]
    assert client.get("/api/v1/projects", params={"q": "' OR 1=1 --"}, headers=headers).json() == []
    assert client.delete("/api/v1/projects/" + project["id"], headers=headers).status_code == 422
    assert (
        client.delete(
            "/api/v1/projects/" + project["id"] + "?confirm=true", headers=headers
        ).status_code
        == 204
    )
    assert db.get("project", owner, project["id"]) is None
    assert client.get("/api/v1/projects/" + project["id"], headers=headers).status_code == 404


def test_repository_full_crud_and_retained_scan_history(session):
    client, headers, owner = session
    project = create_project(client, headers)
    repo = create_repo(client, headers, project["id"])
    assert client.get("/api/v1/repositories/" + repo["id"], headers=headers).status_code == 200
    body = {
        "project_id": project["id"],
        "url": "https://github.com/acme/service",
        "branch": "develop",
    }
    changed = client.put("/api/v1/repositories/" + repo["id"], headers=headers, json=body)
    assert changed.status_code == 200
    assert changed.json()["branch"] == "develop"
    assert len(client.get("/api/v1/repositories?q=SERVICE", headers=headers).json()) == 1
    scan = db.create(
        "scan",
        owner,
        {"project_id": project["id"], "repository_id": repo["id"], "status": "completed"},
    )
    assert (
        client.delete(
            "/api/v1/repositories/" + repo["id"] + "?confirm=true", headers=headers
        ).status_code
        == 204
    )
    assert db.get("scan", owner, scan["id"]) is not None
    assert db.get("repository", owner, repo["id"]) is None


@pytest.mark.security
def test_cross_owner_crud_and_invalid_values_rejected(session):
    client, headers, owner = session
    project = create_project(client, headers)
    repo = create_repo(client, headers, project["id"])
    second = client.post(
        "/api/v1/auth/register",
        json={"email": "other@example.test", "password": "other-test-password-123!"},
    ).json()
    other = {"Authorization": "Bearer " + second["access_token"]}
    for resource, ident in [("projects", project["id"]), ("repositories", repo["id"])]:
        assert client.get("/api/v1/" + resource + "/" + ident, headers=other).status_code == 404
        assert (
            client.delete(
                "/api/v1/" + resource + "/" + ident + "?confirm=true", headers=other
            ).status_code
            == 404
        )
    assert (
        client.put(
            "/api/v1/projects/" + project["id"], headers=other, json={"name": "stolen"}
        ).status_code
        == 404
    )
    assert (
        client.put(
            "/api/v1/repositories/" + repo["id"],
            headers=other,
            json={
                "project_id": project["id"],
                "url": "https://github.com/acme/service",
                "branch": "main",
            },
        ).status_code
        == 404
    )
    assert client.post("/api/v1/projects", headers=headers, json={"name": "   "}).status_code == 422
    for url, branch in [
        ("http://127.0.0.1/x", "main"),
        ("https://github.com/acme/service", "--upload-pack=evil"),
        ("https://github.com/acme/service", "../main"),
    ]:
        assert (
            client.put(
                "/api/v1/repositories/" + repo["id"],
                headers=headers,
                json={"project_id": project["id"], "url": url, "branch": branch},
            ).status_code
            == 422
        )


def test_active_scan_conflicts_and_project_transactional_cascade(session):
    client, headers, owner = session
    project = create_project(client, headers)
    repo = create_repo(client, headers, project["id"])
    scan = db.create(
        "scan",
        owner,
        {"project_id": project["id"], "repository_id": repo["id"], "status": "running"},
    )
    finding = db.create("finding", owner, {"project_id": project["id"], "scan_id": scan["id"]})
    deployment = db.create(
        "deployment", owner, {"project_id": project["id"], "scan_id": scan["id"]}
    )
    unrelated = db.create("project", owner, {"name": "Keep"})
    audit = db.audit(owner, "scan.started", scan["id"])
    for resource, ident in [("projects", project["id"]), ("repositories", repo["id"])]:
        assert (
            client.delete(
                "/api/v1/" + resource + "/" + ident + "?confirm=true", headers=headers
            ).status_code
            == 409
        )
    db.update("scan", owner, scan["id"], {"status": "completed"})
    assert (
        client.delete(
            "/api/v1/projects/" + project["id"] + "?confirm=true", headers=headers
        ).status_code
        == 204
    )
    for kind, item in [
        ("project", project),
        ("repository", repo),
        ("scan", scan),
        ("finding", finding),
        ("deployment", deployment),
    ]:
        assert db.get(kind, owner, item["id"]) is None
    assert db.get("project", owner, unrelated["id"]) is not None
    assert db.get("audit", owner, audit["id"]) is not None
    assert any(a["action"] == "project.deleted" for a in db.listing("audit", owner))


@pytest.mark.security
def test_delete_false_confirmation_keeps_resource(session):
    client, headers, owner = session
    project = create_project(client, headers)
    assert (
        client.delete(
            "/api/v1/projects/" + project["id"] + "?confirm=false", headers=headers
        ).status_code
        == 400
    )
    assert db.get("project", owner, project["id"]) is not None


def test_stale_repository_cannot_queue_after_deletion(session):
    from fastapi import BackgroundTasks, HTTPException
    from app.main import queue_scan

    client, headers, owner = session
    project = create_project(client, headers)
    repository = create_repo(client, headers, project["id"])
    assert (
        client.delete(
            "/api/v1/repositories/" + repository["id"] + "?confirm=true", headers=headers
        ).status_code
        == 204
    )
    with pytest.raises(HTTPException) as exception:
        queue_scan({"id": owner}, repository, {}, BackgroundTasks())
    assert exception.value.status_code == 404
    assert db.listing("scan", owner) == []


def test_stale_repository_queues_current_project_after_edit(session):
    from fastapi import BackgroundTasks
    from app.main import queue_scan

    client, headers, owner = session
    first = create_project(client, headers)
    repository = create_repo(client, headers, first["id"])
    second = create_project(client, headers, "Moved repository owner project")
    changed = client.put(
        "/api/v1/repositories/" + repository["id"],
        headers=headers,
        json={"project_id": second["id"], "url": repository["url"], "branch": "develop"},
    )
    assert changed.status_code == 200
    queued = queue_scan({"id": owner}, repository, {}, BackgroundTasks())
    assert queued["project_id"] == second["id"]
    assert queued["branch"] == "develop"
