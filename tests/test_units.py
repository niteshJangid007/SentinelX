"""Isolated unit contracts for identity, input boundaries and SQLite persistence.

These characterize existing behavior. New feature work must add a failing test
first; this module does not claim existing code was originally developed by TDD.
"""

import hashlib
import sqlite3
import time

import pytest
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import ValidationError

from app import auth, db, schemas

pytestmark = pytest.mark.unit


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "unit.db"
    monkeypatch.setenv("SECUREFLOW_DB", str(path))
    db.initialize()
    return path


def test_password_hash_uses_unique_salts_and_verifies_exact_password():
    password = "unit-test-password-!123"
    first, second = auth.password_hash(password), auth.password_hash(password)
    assert first != second
    assert password not in first
    salt, digest = first.split(":")
    assert len(bytes.fromhex(salt)) == 16
    assert len(bytes.fromhex(digest)) == 32
    assert auth.verify_password(password, first)
    assert not auth.verify_password(password + "x", first)
    assert not auth.verify_password(password.upper(), first)


def test_password_verification_supports_unicode():
    password = "a-secure-密碼-🔐-123"
    stored = auth.password_hash(password)
    assert auth.verify_password(password, stored)
    assert not auth.verify_password("a-secure-password-123", stored)


def test_session_stores_digest_and_enforces_expiration(database):
    with db.connect() as connection:
        connection.execute(
            "INSERT INTO users VALUES(?,?,?,?)",
            ("owner", "owner@example.com", "unused", "developer"),
        )
    session = auth.issue_session("owner")
    token = session["access_token"]
    with db.connect() as connection:
        row = connection.execute("SELECT * FROM sessions").fetchone()
        assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
        assert row["token_hash"] != token
        assert time.time() + 28000 < row["expires"] < time.time() + 29000
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/auth/me",
            "headers": [],
            "scheme": "http",
            "server": ("testserver", 80),
        }
    )
    assert auth.current_user(request, credentials=credentials) == {
        "id": "owner",
        "email": "owner@example.com",
        "role": "developer",
    }
    with db.connect() as connection:
        connection.execute("UPDATE sessions SET expires=0")
    with pytest.raises(HTTPException) as error:
        auth.current_user(request, credentials=credentials)
    assert error.value.status_code == 401


@pytest.mark.parametrize("role", ["viewer", "unknown"])
def test_read_only_role_cannot_write(role):
    with pytest.raises(HTTPException) as error:
        auth.writer({"id": "owner", "role": role})
    assert error.value.status_code == 403


@pytest.mark.parametrize("role", ["developer", "viewer"])
def test_policy_write_requires_security_role(role):
    with pytest.raises(HTTPException) as error:
        auth.policy_writer({"id": "owner", "role": role})
    assert error.value.status_code == 403


@pytest.mark.parametrize("role", ["security_analyst", "admin"])
def test_security_roles_can_manage_policy(role):
    user = {"id": "owner", "role": role}
    assert auth.policy_writer(user) == user


def test_credentials_normalize_email_and_forbid_role_escalation():
    credentials = schemas.Credentials(email="  Owner@Example.COM ", password="secure-password-123")
    assert credentials.email == "owner@example.com"
    with pytest.raises(ValidationError):
        schemas.Credentials(email="owner@example.com", password="secure-password-123", role="admin")


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "bad-email", "password": "secure-password-123"},
        {"email": "owner@example.com", "password": "short"},
        {"email": "owner@example.com", "password": "x" * 257},
        {"email": "owner @example.com", "password": "secure-password-123"},
    ],
)
def test_credentials_reject_invalid_boundaries(payload):
    with pytest.raises(ValidationError):
        schemas.Credentials(**payload)


@pytest.mark.parametrize(
    "schema,payload",
    [
        (schemas.Project, {"name": ""}),
        (schemas.Project, {"name": "x" * 121}),
        (schemas.Project, {"name": "Valid", "environment": "unknown"}),
        (schemas.Policy, {"name": "Valid", "critical": "IGNORE"}),
        (schemas.Policy, {"name": "Valid", "scanner_failure": "ALLOW"}),
        (schemas.FindingUpdate, {"status": "resolved", "reason": ""}),
        (schemas.FindingUpdate, {"status": "invented", "reason": "reviewed"}),
        (schemas.Deployment, {"scan_id": "scan", "version": "v1", "deploy_anyway": True}),
        (schemas.Scan, {"repository_id": "repository", "owner": "someone-else"}),
    ],
)
def test_resource_input_rejects_invalid_or_privileged_fields(schema, payload):
    with pytest.raises(ValidationError):
        schema(**payload)


def test_default_policy_blocks_critical_and_failed_scanners():
    policy = schemas.Policy(name="default")
    assert policy.critical == policy.high == policy.scanner_failure == "BLOCK"
    assert policy.medium == "WARN"


def test_database_preserves_data_across_connections(database):
    created = db.create(
        "project", "owner-a", {"name": "Payments", "settings": {"tags": ["finance"]}}
    )
    # The create connection has closed; a separate connection must see committed data.
    assert db.get("project", "owner-a", created["id"]) == created
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM resources").fetchone()[0] == 1
    assert created["created_at"] and created["updated_at"]


def test_database_cannot_read_or_update_another_owners_resource(database):
    created = db.create("project", "owner-a", {"name": "Payments"})
    assert db.get("project", "owner-b", created["id"]) is None
    assert db.listing("project", "owner-b") == []
    assert db.update("project", "owner-b", created["id"], {"name": "stolen"}) is None
    assert db.get("project", "owner-a", created["id"])["name"] == "Payments"
    assert db.get("scan", "owner-a", created["id"]) is None


def test_database_queries_parameterize_untrusted_identifiers(database):
    created = db.create("project", "owner-a", {"name": "Payments"})
    injection = "' OR 1=1 --"
    assert db.get("project", injection, created["id"]) is None
    assert db.get("project", "owner-a", injection) is None
    assert db.listing(injection, "owner-a") == []
    assert db.get("project", "owner-a", created["id"])["name"] == "Payments"


def test_database_update_and_audit_are_persisted_and_scoped(database):
    created = db.create("project", "owner-a", {"name": "Payments", "description": "original"})
    updated = db.update("project", "owner-a", created["id"], {"name": "Billing"})
    assert updated["id"] == created["id"]
    assert updated["description"] == "original"
    assert db.get("project", "owner-a", created["id"])["name"] == "Billing"
    audit = db.audit("owner-a", "project.updated", created["id"])
    assert audit in db.listing("audit", "owner-a")
    assert db.listing("audit", "owner-b") == []
