"""TDD: database errors must be useful without exposing statements or credentials."""

import logging
import sqlite3
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

pytestmark = [pytest.mark.unit, pytest.mark.security]
SENSITIVE = "synthetic-password-should-not-appear"


def error_client(error):
    from app.errors import install_error_handlers

    app = FastAPI()
    install_error_handlers(app)

    @app.get("/database")
    def broken():
        raise error

    return TestClient(app)


@pytest.mark.parametrize(
    "error,status,code",
    [
        (sqlite3.IntegrityError("UNIQUE failed " + SENSITIVE), 409, "database_conflict"),
        (sqlite3.OperationalError("database locked " + SENSITIVE), 503, "database_unavailable"),
        (sqlite3.InterfaceError("connection broken " + SENSITIVE), 503, "database_unavailable"),
        (
            sqlite3.ProgrammingError("SELECT password FROM users " + SENSITIVE),
            500,
            "database_error",
        ),
    ],
)
def test_sqlite_failures_are_structured_and_redacted(error, status, code, caplog):
    with caplog.at_level(logging.WARNING):
        response = error_client(error).get("/database")
    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert isinstance(response.json()["detail"], str)
    assert SENSITIVE not in response.text + caplog.text
    assert "SELECT" not in response.text + caplog.text
    assert "Traceback" not in caplog.text
    assert "database_request_failed" in caplog.text
    if status == 503:
        assert response.headers["Retry-After"] == "5"


def test_psycopg_errors_are_handled_without_connection_or_dsn(caplog):
    psycopg = pytest.importorskip("psycopg")
    errors = [
        (psycopg.IntegrityError(SENSITIVE), 409, "database_conflict"),
        (psycopg.OperationalError(SENSITIVE), 503, "database_unavailable"),
        (psycopg.InterfaceError(SENSITIVE), 503, "database_unavailable"),
        (psycopg.ProgrammingError(SENSITIVE), 500, "database_error"),
    ]
    with caplog.at_level(logging.WARNING):
        for error, status, code in errors:
            response = error_client(error).get("/database")
            assert response.status_code == status
            assert response.json()["error"]["code"] == code
            assert SENSITIVE not in response.text
    assert SENSITIVE not in caplog.text


def test_installer_does_not_mask_application_defects():
    from app.errors import install_error_handlers

    app = FastAPI()
    install_error_handlers(app)

    @app.get("/application")
    def broken():
        raise RuntimeError("Application coding defect")

    with TestClient(app) as client:
        with pytest.raises(RuntimeError, match="Application coding defect"):
            client.get("/application")


@pytest.mark.integration
def test_main_api_installs_safe_database_boundary(tmp_path, monkeypatch, caplog):
    from app import db
    from app.main import app

    for name in ("DATABASE_URL", "SECUREFLOW_ENV", "SENTINELX_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SECUREFLOW_DB", str(tmp_path / "errors-api.db"))
    with TestClient(app) as client:

        def unavailable():
            raise sqlite3.OperationalError("dsn=synthetic-user:" + SENSITIVE)

        monkeypatch.setattr(db, "connect", unavailable)
        with caplog.at_level(logging.WARNING):
            response = client.get("/health")
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "database_unavailable"
        assert SENSITIVE not in response.text + caplog.text
