"""Migration must preserve source and refuse ambiguous targets."""

import sqlite3
import pytest

pytestmark = pytest.mark.unit


def test_migration_requires_postgresql(tmp_path, monkeypatch):
    from app.migrate import migrate_sqlite

    monkeypatch.delenv("DATABASE_URL", raising=False)
    path = tmp_path / "source.db"
    path.write_bytes(b"original database")
    with pytest.raises(ValueError, match="PostgreSQL"):
        migrate_sqlite(path)
    assert path.read_bytes() == b"original database"


def test_migration_refuses_invalid_source_without_writing(tmp_path, monkeypatch):
    from app.migrate import migrate_sqlite

    monkeypatch.setenv("DATABASE_URL", "postgresql://unreachable.invalid/test")
    path = tmp_path / "source.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unrelated(id TEXT)")
    original = path.read_bytes()
    with pytest.raises(ValueError, match="source"):
        migrate_sqlite(path)
    assert path.read_bytes() == original


@pytest.mark.integration
def test_migration_preserves_source_and_refuses_second_import(tmp_path, monkeypatch):
    import os
    import uuid
    import hashlib
    from urllib.parse import quote
    from app import auth, db
    from app.migrate import migrate_sqlite

    destination = os.getenv("TEST_DATABASE_URL")
    if not destination:
        pytest.skip("TEST_DATABASE_URL required for PostgreSQL migration integration")
    import psycopg
    from psycopg import sql

    schema = "sentinelx_migration_" + uuid.uuid4().hex
    with psycopg.connect(destination, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    try:
        source = tmp_path / "old.db"
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("SECUREFLOW_DB", str(source))
        db.initialize()
        stored = auth.password_hash("migration-test-password")
        with db.connect() as connection:
            connection.execute(
                "INSERT INTO users VALUES(?,?,?,?)",
                ("user-1", "migrated@example.test", stored, "developer"),
            )
        resource = db.create("project", "user-1", {"name": "Preserved project"})
        auth.issue_session("user-1")
        original_hash = hashlib.sha256(source.read_bytes()).digest()
        target = (
            destination
            + ("&" if "?" in destination else "?")
            + "options="
            + quote("-csearch_path=" + schema, safe="")
        )
        monkeypatch.setenv("DATABASE_URL", target)
        result = migrate_sqlite(source)
        assert result == {
            "users": 1,
            "resources": 1,
            "sessions_imported": 0,
            "source_preserved": True,
        }
        assert hashlib.sha256(source.read_bytes()).digest() == original_hash
        assert db.get("project", "user-1", resource["id"])["name"] == "Preserved project"
        with db.connect() as connection:
            assert auth.verify_password(
                "migration-test-password",
                connection.execute("SELECT password FROM users").fetchone()["password"],
            )
            assert connection.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"] == 0
        with pytest.raises(ValueError, match="not empty"):
            migrate_sqlite(source)
        assert len(db.listing("project", "user-1")) == 1
    finally:
        with psycopg.connect(destination, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
