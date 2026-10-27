"""Launcher settings must keep using the configured PostgreSQL database."""

import pytest
from scripts import local_config

pytestmark = pytest.mark.unit


def test_existing_database_url_in_dotenv_is_used_without_regeneration(tmp_path, monkeypatch):
    monkeypatch.setattr(local_config, "ROOT", tmp_path)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    configured = "postgresql://example.test/existing_database"
    content = f"DATABASE_URL={configured}\n"
    (tmp_path / ".env").write_text(content)
    assert local_config.database_url(create=True) == configured
    assert (tmp_path / ".env").read_text() == content


def test_process_database_url_takes_precedence(tmp_path, monkeypatch):
    monkeypatch.setattr(local_config, "ROOT", tmp_path)
    (tmp_path / ".env").write_text("DATABASE_URL=postgresql://file.test/database\n")
    monkeypatch.setenv("DATABASE_URL", "postgresql://process.test/database")
    assert local_config.database_url() == "postgresql://process.test/database"


def test_launcher_treats_dotenv_database_as_external(monkeypatch):
    import sys
    from pathlib import Path

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    from scripts import start

    monkeypatch.delenv("DATABASE_URL", raising=False)
    destination = "postgresql://configured.test/retained_data"
    monkeypatch.setattr(
        start,
        "load_settings",
        lambda: {"DATABASE_URL": destination, "SECUREFLOW_ENV": "production"},
    )
    monkeypatch.setattr(start, "database_url", lambda create=False: destination)
    monkeypatch.setattr(
        start.shutil, "which", lambda _: pytest.fail("External database must not require Docker")
    )
    monkeypatch.setattr(
        start.subprocess,
        "run",
        lambda *_a, **_k: pytest.fail("External database must not start local Docker"),
    )
    commands = []
    monkeypatch.setattr(
        start.subprocess, "call", lambda command, **kwargs: commands.append(kwargs["env"]) or 0
    )
    monkeypatch.setattr(sys, "argv", ["scripts/start.py"])
    assert start.main() == 0
    assert commands[0]["DATABASE_URL"] == destination
    assert commands[0]["SECUREFLOW_ENV"] == "production"
