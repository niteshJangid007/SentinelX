"""Local password repair must not expose credentials or remove preserved data."""

import subprocess
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def repair(tmp_path, monkeypatch):
    from scripts import repair_postgres

    monkeypatch.setattr(repair_postgres, "ROOT", tmp_path)
    (tmp_path / ".env").write_text(
        "POSTGRES_USER=sentinelx\nPOSTGRES_DB=sentinelx\nPOSTGRES_PASSWORD=private-test-password\n"
    )
    values = {
        "POSTGRES_USER": "sentinelx",
        "POSTGRES_DB": "sentinelx",
        "POSTGRES_PASSWORD": "private-test-password",
    }
    monkeypatch.setattr(repair_postgres, "load_settings", lambda create=False: values.copy())
    monkeypatch.setattr(
        repair_postgres, "database_url", lambda create=False: "postgresql://local-test-unused"
    )
    monkeypatch.setattr(repair_postgres.shutil, "which", lambda _: "docker")
    for key in ("DATABASE_URL", "SENTINELX_ENV", "SECUREFLOW_ENV"):
        monkeypatch.delenv(key, raising=False)
    return repair_postgres, values


def test_password_repair_uses_stdin_and_preserves_env(repair, monkeypatch, capsys):
    module, values = repair
    before = (module.ROOT / ".env").read_bytes()
    calls = []
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs))
        or subprocess.CompletedProcess(command, 0, stdout="ALTER ROLE\n", stderr=""),
    )
    connect = MagicMock()
    monkeypatch.setattr(module.psycopg, "connect", connect)
    assert module.main([]) == 0
    command, kwargs = calls[0]
    assert command[:5] == ["docker", "compose", "exec", "-T", "db"]
    assert "private-test-password" not in repr(command)
    assert "private-test-password" in kwargs["input"]
    assert kwargs["capture_output"] is True
    assert "ALTER ROLE" in kwargs["input"]
    assert not any(token in command for token in ("down", "rm", "--volumes", "-v"))
    connect.assert_called_once()
    assert (module.ROOT / ".env").read_bytes() == before
    output = capsys.readouterr()
    assert "Password synchronized; data preserved" in output.out
    assert "private-test-password" not in output.out + output.err


@pytest.mark.parametrize(
    "field,value",
    [
        ("DATABASE_URL", "postgresql://external.test/data"),
        ("SENTINELX_ENV", "production"),
        ("SECUREFLOW_ENV", "production"),
        ("POSTGRES_PASSWORD", ""),
    ],
)
def test_unsafe_or_missing_configuration_refused(repair, monkeypatch, capsys, field, value):
    module, values = repair
    values[field] = value
    monkeypatch.setattr(
        module.subprocess, "run", lambda *_a, **_k: pytest.fail("Must not modify database")
    )
    assert module.main([]) == 1
    output = capsys.readouterr()
    assert "private-test-password" not in output.out + output.err


def test_missing_env_never_generated(repair):
    module, _ = repair
    (module.ROOT / ".env").unlink()
    assert module.main([]) == 1
    assert not (module.ROOT / ".env").exists()


def test_database_failure_does_not_echo_driver_secret(repair, monkeypatch, capsys):
    module, _ = repair

    def fail(*args, **kwargs):
        raise RuntimeError("private-test-password DATABASE_URL=private")

    monkeypatch.setattr(module.subprocess, "run", fail)
    assert module.main([]) == 1
    output = capsys.readouterr()
    assert "private-test-password" not in output.out + output.err
    assert "Traceback" not in output.err


def test_password_sql_quotes_role_and_secret(repair, monkeypatch):
    module, values = repair
    values["POSTGRES_USER"] = 'role"; DROP DATABASE important;--'
    values["POSTGRES_PASSWORD"] = "secret'; DROP DATABASE important;--"
    captured = []
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda command, **kwargs: captured.append(kwargs["input"])
        or subprocess.CompletedProcess(command, 0),
    )
    monkeypatch.setattr(module.psycopg, "connect", MagicMock())
    assert module.main([]) == 0
    assert captured[0].startswith('ALTER ROLE "role""; DROP DATABASE important;--" PASSWORD ')
    assert "secret''; DROP DATABASE important;--" in captured[0]
