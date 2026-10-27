"""SQLite and PostgreSQL persistence. All resource lookups are scoped to the authenticated owner."""

import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # SQLite remains available in minimal/offline installations.
    psycopg = None

IntegrityError = (sqlite3.IntegrityError,) + ((psycopg.IntegrityError,) if psycopg else ())


def now():
    return datetime.now(timezone.utc).isoformat()


class Connection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def postgres_sql(query):
    """Convert our parameterized SQLite-style SQL; preserve quoted literals/comments."""
    tokens = re.split(r"('(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|--[^\n]*|/\*.*?\*/)", query, flags=re.S)
    return "".join(
        token if index % 2 else token.replace("?", "%s") for index, token in enumerate(tokens)
    )


class PostgreSQLConnection:
    def __init__(self, destination):
        if psycopg is None:
            raise RuntimeError("PostgreSQL requires the psycopg[binary] dependency")
        self.connection = psycopg.connect(destination, row_factory=dict_row, connect_timeout=10)

    def execute(self, query, parameters=None):
        if parameters is None:
            return self.connection.execute(query)
        # Psycopg reserves % placeholders; literal percents must remain literal.
        return self.connection.execute(postgres_sql(query.replace("%", "%%")), parameters)

    def executescript(self, script):
        # Initialization scripts contain plain DDL, without procedural SQL bodies.
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)

    def __enter__(self):
        self.connection.__enter__()
        return self

    def __exit__(self, *args):
        return self.connection.__exit__(*args)

    def close(self):
        self.connection.close()

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()


def connect():
    destination = os.getenv("DATABASE_URL", "").strip()
    if destination:
        if "://" in destination and not destination.startswith(("postgresql://", "postgres://")):
            raise ValueError("DATABASE_URL must identify a PostgreSQL database")
        return PostgreSQLConnection(destination)
    if any(
        os.getenv(name, "").strip().lower() == "production"
        for name in ("SENTINELX_ENV", "SECUREFLOW_ENV")
    ):
        raise RuntimeError("DATABASE_URL is required in production; SQLite fallback is disabled")
    path = os.getenv("SECUREFLOW_DB", "/workspace/secureflow-data/secureflow.db")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30, factory=Connection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def initialize():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires DOUBLE PRECISION NOT NULL);
        CREATE TABLE IF NOT EXISTS resources(id TEXT PRIMARY KEY,kind TEXT NOT NULL,owner TEXT NOT NULL,data TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS resources_owner_kind ON resources(owner,kind);
        CREATE TABLE IF NOT EXISTS platform_admins(user_id TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS user_controls(user_id TEXT PRIMARY KEY,disabled INTEGER NOT NULL DEFAULT 0);
        """)


def create(kind, owner, data):
    data = {**data, "id": str(uuid.uuid4()), "created_at": now(), "updated_at": now()}
    with connect() as c:
        c.execute(
            "INSERT INTO resources VALUES(?,?,?,?)", (data["id"], kind, owner, json.dumps(data))
        )
    return data


def get(kind, owner, ident):
    with connect() as c:
        row = c.execute(
            "SELECT data FROM resources WHERE id=? AND kind=? AND owner=?", (ident, kind, owner)
        ).fetchone()
    return json.loads(row["data"]) if row else None


def listing(kind, owner):
    with connect() as c:
        rows = c.execute(
            "SELECT data FROM resources WHERE kind=? AND owner=?", (kind, owner)
        ).fetchall()
    items = [json.loads(row["data"]) for row in rows]
    return sorted(items, key=lambda item: (item.get("created_at", ""), item["id"]), reverse=True)


def update(kind, owner, ident, changes):
    data = get(kind, owner, ident)
    if data is None:
        return None
    data.update(changes)
    data["updated_at"] = now()
    with connect() as c:
        c.execute(
            "UPDATE resources SET data=? WHERE id=? AND owner=? AND kind=?",
            (json.dumps(data), ident, owner, kind),
        )
    return data


def audit(owner, action, resource, result="success"):
    return create("audit", owner, {"action": action, "resource": resource, "result": result})
