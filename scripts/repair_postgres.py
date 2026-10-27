"""Repair only this checkout's local Compose PostgreSQL password mismatch.

Run explicitly after restoring an older local database volume or changing .env.
The existing .env and named database volume remain untouched. Never use this
helper for production or an externally configured database. The ALTER ROLE
statement travels over stdin, not process arguments, and captured driver output
is never printed because PostgreSQL errors can contain submitted credentials.
"""

import os
import shutil
import subprocess
import sys

import psycopg
from psycopg import sql

if __package__:
    from .local_config import ROOT, database_url, load_settings
else:
    from local_config import ROOT, database_url, load_settings


def protected_file_settings(path):
    """Inspect safety flags even when an empty process variable shadows .env."""
    settings = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            settings[key.strip()] = value.strip().strip("\"'")
    return settings


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        print("Usage: repair_postgres.py (local development only)", file=sys.stderr)
        return 1
    try:
        path = ROOT / ".env"
        if not path.is_file():
            raise RuntimeError("Local configuration is missing")
        values = load_settings(create=False)
        file_values = protected_file_settings(path)
        for source in (values, file_values, os.environ):
            if source.get("DATABASE_URL", "").strip():
                raise RuntimeError("External database configuration is not eligible")
            if any(
                source.get(key, "").strip().lower() == "production"
                for key in ("SENTINELX_ENV", "SECUREFLOW_ENV")
            ):
                raise RuntimeError("Production database repair is not supported")
        password = values.get("POSTGRES_PASSWORD", "")
        if not password or not shutil.which("docker"):
            raise RuntimeError("Local password and Docker are required")
        user = values.get("POSTGRES_USER", "sentinelx")
        name = values.get("POSTGRES_DB", "sentinelx")
        if not user or not name:
            raise RuntimeError("Local database user and name are required")
        # Validate the local TCP configuration before making any change.
        destination = database_url(create=False)
        statement = (
            sql.SQL("ALTER ROLE {} PASSWORD {};\n")
            .format(sql.Identifier(user), sql.Literal(password))
            .as_string(None)
        )
        command = [
            "docker",
            "compose",
            "exec",
            "-T",
            "db",
            "psql",
            "--no-psqlrc",
            "--no-password",
            "--host=/var/run/postgresql",
            "--username=" + user,
            "--dbname=" + name,
            "--set=ON_ERROR_STOP=1",
        ]
        subprocess.run(
            command,
            input=statement,
            text=True,
            capture_output=True,
            check=True,
            timeout=30,
            cwd=ROOT,
        )
        with psycopg.connect(destination, connect_timeout=10) as connection:
            connection.execute("SELECT 1")
        print("Password synchronized; data preserved. Start Sentinelx again.")
        return 0
    except Exception:
        # Neither exception text nor stderr is safe: either can contain the SQL.
        print(
            "Local PostgreSQL password repair could not complete. Check Docker Desktop, the running local db service, and existing .env settings. External and production databases are not supported. No database volume or configuration file was removed.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
