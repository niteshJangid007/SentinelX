"""Tests opt into databases explicitly; inherited application settings are unsafe."""

import pytest


@pytest.fixture(autouse=True)
def isolated_database_environment(monkeypatch, tmp_path):
    # Live PostgreSQL tests retain TEST_DATABASE_URL and explicitly bind a fresh
    # randomly named schema after this fixture. Never use an inherited live DSN.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SENTINELX_ENV", raising=False)
    monkeypatch.delenv("SECUREFLOW_ENV", raising=False)
    monkeypatch.setenv("SECUREFLOW_DB", str(tmp_path / "isolated-default.db"))
