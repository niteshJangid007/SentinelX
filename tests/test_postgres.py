"""PostgreSQL parity checks use an isolated temporary schema, never public tables."""

import os
import uuid

import pytest

from app import db

pytestmark = pytest.mark.integration


@pytest.fixture
def postgres(monkeypatch):
    destination = os.getenv("TEST_DATABASE_URL")
    if not destination:
        pytest.skip("TEST_DATABASE_URL required for live PostgreSQL integration")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    schema = "secureflow_test_" + uuid.uuid4().hex
    with psycopg.connect(destination, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    monkeypatch.setenv(
        "DATABASE_URL", make_conninfo(destination, options=f"-c search_path={schema}")
    )
    try:
        yield
    finally:
        with psycopg.connect(destination, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def test_postgres_initialize_crud_and_admin_tables(postgres):
    db.initialize()
    db.initialize()
    with db.connect() as connection:
        connection.execute(
            "INSERT INTO users VALUES(?,?,?,?)", ("u1", "owner@example.com", "hash", "admin")
        )
        connection.execute("INSERT INTO platform_admins(user_id) VALUES(?)", ("u1",))
        connection.execute("INSERT INTO user_controls(user_id,disabled) VALUES(?,?)", ("u1", 0))
        row = connection.execute("SELECT email FROM users WHERE id=?", ("u1",)).fetchone()
        assert row["email"] == "owner@example.com"
        literals = connection.execute(
            "SELECT '?' AS question, '100%' AS percentage, ? AS supplied", ("safe value",)
        ).fetchone()
        assert literals == {"question": "?", "percentage": "100%", "supplied": "safe value"}
    first = db.create("project", "u1", {"name": "Owner's project ? %s"})
    second = db.create("project", "u1", {"name": "New project"})
    assert db.get("project", "u1", first["id"])["name"] == "Owner's project ? %s"
    assert db.get("project", "other", first["id"]) is None
    assert [p["id"] for p in db.listing("project", "u1")] == [second["id"], first["id"]]
    assert db.update("project", "u1", first["id"], {"name": "Updated"})["name"] == "Updated"
    db.audit("u1", "project.created", first["id"])
    assert len(db.listing("audit", "u1")) == 1


def test_postgres_transactions_rollback_and_integrity(postgres):
    db.initialize()
    with pytest.raises(RuntimeError):
        with db.connect() as connection:
            connection.execute(
                "INSERT INTO users VALUES(?,?,?,?)", ("u1", "rollback@example.com", "hash", "admin")
            )
            raise RuntimeError("rollback")
    with db.connect() as connection:
        assert connection.execute("SELECT id FROM users WHERE id=?", ("u1",)).fetchone() is None
        connection.execute(
            "INSERT INTO users VALUES(?,?,?,?)", ("u1", "owner@example.com", "hash", "admin")
        )
    with pytest.raises(db.IntegrityError):
        with db.connect() as connection:
            connection.execute(
                "INSERT INTO users VALUES(?,?,?,?)", ("u2", "owner@example.com", "hash", "admin")
            )


@pytest.mark.unit
def test_postgres_placeholder_translation_preserves_quoted_sql():
    assert (
        db.postgres_sql("SELECT '?' AS literal, id FROM users WHERE id=?")
        == "SELECT '?' AS literal, id FROM users WHERE id=%s"
    )


@pytest.mark.unit
def test_database_url_rejects_other_database_protocols(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "mysql://localhost/secureflow")
    with pytest.raises(ValueError, match="PostgreSQL"):
        db.connect()


def test_postgres_authenticated_control_plane(postgres):
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        registered = client.post(
            "/api/v1/auth/register",
            json={"email": "pg-owner@example.com", "password": "postgres-test-password-123!"},
        )
        assert registered.status_code == 201
        headers = {"Authorization": "Bearer " + registered.json()["access_token"]}
        created = client.post(
            "/api/v1/projects", headers=headers, json={"name": "PostgreSQL project"}
        )
        assert created.status_code == 201
        assert (
            client.get("/api/v1/projects", headers=headers).json()[0]["id"] == created.json()["id"]
        )
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
        assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
        assert client.get("/api/v1/projects", headers=headers).status_code == 401


@pytest.mark.unit
@pytest.mark.parametrize("environment_name", ["SENTINELX_ENV", "SECUREFLOW_ENV"])
def test_production_without_database_url_fails_before_sqlite_creation(
    tmp_path, monkeypatch, environment_name
):
    monkeypatch.setenv(environment_name, "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    target = tmp_path / "unwanted.db"
    monkeypatch.setenv("SECUREFLOW_DB", str(target))
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        db.connect()
    assert not target.exists()


def test_postgres_project_and_platform_admin_survive_app_restart(postgres):
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as first:
        result = first.post(
            "/api/v1/auth/register",
            json={"email": "persist@example.test", "password": "persistence-test-password-123!"},
        )
        assert result.status_code == 201
        account = result.json()
        headers = {"Authorization": "Bearer " + account["access_token"]}
        project = first.post(
            "/api/v1/projects", headers=headers, json={"name": "Persistent application"}
        ).json()
        with db.connect() as connection:
            connection.execute("INSERT INTO platform_admins(user_id) VALUES(?)", (account["id"],))
        assert first.get("/api/v1/admin/me", headers=headers).status_code == 200
    # Re-entering lifespan models a new API instance reconnecting to retained PG data.
    with TestClient(app) as reopened:
        projects = reopened.get("/api/v1/projects", headers=headers)
        assert projects.status_code == 200
        assert any(row["id"] == project["id"] for row in projects.json())
        assert reopened.get("/api/v1/admin/me", headers=headers).status_code == 200
        overview = reopened.get("/api/v1/admin/overview", headers=headers)
        assert overview.status_code == 200
        assert overview.json()["projects"] == 1


@pytest.mark.unit
def test_postgres_connection_failure_never_falls_back_to_sqlite(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://configured.test/database")
    target = tmp_path / "unwanted.db"
    monkeypatch.setenv("SECUREFLOW_DB", str(target))

    def unavailable(_destination):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(db, "PostgreSQLConnection", unavailable)
    with pytest.raises(RuntimeError, match="database unavailable"):
        db.connect()
    assert not target.exists()
