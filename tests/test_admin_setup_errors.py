import pytest
from app import db, manage

pytestmark = [pytest.mark.integration, pytest.mark.security]


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SECUREFLOW_DB", str(tmp_path / "setup.db"))
    db.initialize()


def test_existing_email_explained_without_password(database, monkeypatch, capsys):
    password = "private-test-password-123"
    manage.create_admin("existing@example.test", password)
    monkeypatch.setattr(manage.getpass, "getpass", lambda _: password)
    assert manage.main(["create-admin", "--email", "existing@example.test"]) == 1
    output = capsys.readouterr().err
    assert "already exists" in output
    assert "--grant-existing" in output
    assert password not in output


def test_mismatched_passwords_explained(database, monkeypatch, capsys):
    entries = iter(["private-test-password-123", "other-test-password-123"])
    monkeypatch.setattr(manage.getpass, "getpass", lambda _: next(entries))
    assert manage.main(["create-admin", "--email", "new@example.test"]) == 1
    output = capsys.readouterr().err
    assert "do not match" in output
    assert "private-test" not in output


def test_short_password_explained_without_value(database, monkeypatch, capsys):
    monkeypatch.setattr(manage.getpass, "getpass", lambda _: "tiny")
    assert manage.main(["create-admin", "--email", "new@example.test"]) == 1
    output = capsys.readouterr().err
    assert "12" in output
    assert "tiny" not in output


def test_launcher_forwards_only_explicit_existing_account_flag(monkeypatch):
    import sys
    from pathlib import Path

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    from scripts import start

    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/not-used")
    monkeypatch.setattr(sys, "argv", ["scripts/start.py", "create-admin", "--grant-existing"])
    commands = []
    monkeypatch.setattr(
        start.subprocess, "call", lambda command, **kwargs: commands.append(command) or 0
    )
    assert start.main() == 0
    assert commands[0][-2:] == ["create-admin", "--grant-existing"]
