"""A developer's inherited database must never become a fixture database."""

import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import pytest

pytestmark = pytest.mark.integration


def test_nested_api_test_cannot_mutate_inherited_postgres(monkeypatch):
    destination = os.getenv("TEST_DATABASE_URL")
    if not destination:
        pytest.skip("TEST_DATABASE_URL required for disposable PostgreSQL isolation regression")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from app import db

    schema = "sentinelx_safety_" + uuid.uuid4().hex
    with psycopg.connect(destination, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    inherited = make_conninfo(destination, options=f"-c search_path={schema}")
    try:
        monkeypatch.setenv("DATABASE_URL", inherited)
        db.initialize()
        with db.connect() as connection:
            connection.execute(
                "INSERT INTO users VALUES(?,?,?,?)",
                ("sentinel", "sentinel@example.test", "unused-hash", "admin"),
            )
            connection.execute(
                "INSERT INTO sessions VALUES(?,?,?)",
                ("sentinel-session", "sentinel", time.time() + 86400),
            )
            before_users = connection.execute("SELECT * FROM users ORDER BY id").fetchall()
            before_sessions = connection.execute(
                "SELECT * FROM sessions ORDER BY token_hash"
            ).fetchall()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/test_api.py::test_expired_sessions_and_viewer_permissions",
                "-q",
            ],
            cwd=Path(__file__).resolve().parents[1],
            env={
                **os.environ,
                "DATABASE_URL": inherited,
                "SENTINELX_ENV": "production",
                "SECUREFLOW_ENV": "production",
            },
            capture_output=True,
            text=True,
            timeout=60,
        )
        # Never include subprocess output or connection details in failures.
        assert result.returncode == 0, "Nested API test did not complete successfully"
        with db.connect() as connection:
            assert connection.execute("SELECT * FROM users ORDER BY id").fetchall() == before_users
            assert (
                connection.execute("SELECT * FROM sessions ORDER BY token_hash").fetchall()
                == before_sessions
            )
            assert (
                connection.execute("SELECT COUNT(*) AS count FROM resources").fetchone()["count"]
                == 0
            )
    finally:
        with psycopg.connect(destination, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def test_smoke_runner_ignores_inherited_live_database_settings():
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "check.sh").read_text(encoding="utf-8")
    # Exercise the real smoke-server section without recursively running pytest.
    runner = script.split("\"$PYTHON_BIN\" - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    result = subprocess.run(
        [sys.executable, "-c", runner],
        cwd=root,
        env={
            **os.environ,
            "DATABASE_URL": "postgresql://invalid.invalid/do-not-use",
            "SENTINELX_ENV": "production",
            "SECUREFLOW_ENV": "production",
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, "Smoke runner did not use its isolated temporary SQLite database"
