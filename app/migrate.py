"""One-way, non-destructive import into an empty PostgreSQL installation."""

import argparse
import json
import os
from pathlib import Path
import sqlite3
from urllib.parse import quote

from . import db


def migrate_sqlite(source):
    if not os.getenv("DATABASE_URL", "").startswith(("postgresql://", "postgres://")):
        raise ValueError("Set DATABASE_URL to a PostgreSQL target before migration.")
    path = Path(source).resolve()
    if not path.is_file():
        raise ValueError("SQLite source file does not exist.")
    uri = "file:" + quote(path.as_posix(), safe="/:") + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as original:
        original.row_factory = sqlite3.Row
        tables = {
            row["name"]
            for row in original.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if not {"users", "resources"}.issubset(tables):
            raise ValueError("SQLite source does not contain the expected Sentinelx schema.")
        # Snapshot all retained data from one source read transaction.
        original.execute("BEGIN")
        users = [dict(row) for row in original.execute("SELECT id,email,password,role FROM users")]
        resources = [
            dict(row) for row in original.execute("SELECT id,kind,owner,data FROM resources")
        ]
        for row in resources:
            json.loads(row["data"])  # Reject corrupt JSON before touching destination.
        admins = (
            [dict(row) for row in original.execute("SELECT user_id FROM platform_admins")]
            if "platform_admins" in tables
            else []
        )
        controls = (
            [dict(row) for row in original.execute("SELECT user_id,disabled FROM user_controls")]
            if "user_controls" in tables
            else []
        )
    db.initialize()
    with db.connect() as target:
        # Serialize imports and account writes; never merge identities implicitly.
        target.execute(
            "LOCK TABLE users, resources, sessions, platform_admins, user_controls IN ACCESS EXCLUSIVE MODE"
        )
        if any(
            target.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
            for table in ("users", "resources", "sessions", "platform_admins", "user_controls")
        ):
            raise ValueError(
                "PostgreSQL target is not empty. Migration cancelled without importing data."
            )
        for row in users:
            target.execute(
                "INSERT INTO users(id,email,password,role) VALUES(?,?,?,?)",
                tuple(row[k] for k in ("id", "email", "password", "role")),
            )
        for row in resources:
            target.execute(
                "INSERT INTO resources(id,kind,owner,data) VALUES(?,?,?,?)",
                tuple(row[k] for k in ("id", "kind", "owner", "data")),
            )
        for row in admins:
            target.execute("INSERT INTO platform_admins(user_id) VALUES(?)", (row["user_id"],))
        for row in controls:
            target.execute(
                "INSERT INTO user_controls(user_id,disabled) VALUES(?,?)",
                (row["user_id"], row["disabled"]),
            )
    return {
        "users": len(users),
        "resources": len(resources),
        "sessions_imported": 0,
        "source_preserved": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite", required=True, help="Existing SQLite file (read-only source)")
    args = parser.parse_args()
    try:
        result = migrate_sqlite(args.sqlite)
    except (ValueError, sqlite3.Error) as error:
        print(str(error))
        return 1
    except Exception:
        print(
            "Migration failed; no data was imported. Check PostgreSQL connectivity and schema. Credentials are not displayed."
        )
        return 1
    print(
        f"Imported {result['users']} users and {result['resources']} resources. SQLite source is unchanged. Sign in again; sessions were not copied."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
