"""Local PostgreSQL configuration. Credentials never appear in command output."""

from pathlib import Path
import os
import secrets
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def load_settings(create=False):
    path = ROOT / ".env"
    if create and not path.exists():
        # Exclusive creation protects existing user configuration.
        with path.open("x", encoding="utf-8") as stream:
            stream.write(
                "POSTGRES_USER=sentinelx\nPOSTGRES_DB=sentinelx\n"
                f"POSTGRES_PASSWORD={secrets.token_hex(32)}\n"
                "SENTINELX_POSTGRES_PORT=55432\n"
            )
        if os.name != "nt":
            path.chmod(0o600)
    values = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("\"'")
    for key in (
        "DATABASE_URL",
        "POSTGRES_USER",
        "POSTGRES_DB",
        "POSTGRES_PASSWORD",
        "SENTINELX_POSTGRES_PORT",
        "SENTINELX_ENV",
        "SECUREFLOW_ENV",
    ):
        if key in os.environ:
            values[key] = os.environ[key]
    return values


def database_url(create=False):
    if os.getenv("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    values = load_settings(create=create)
    if values.get("DATABASE_URL", "").strip():
        return values["DATABASE_URL"].strip()
    if not values.get("POSTGRES_PASSWORD"):
        raise RuntimeError(
            "Set POSTGRES_PASSWORD securely in the local .env file before continuing."
        )
    user = quote(values.get("POSTGRES_USER", "sentinelx"), safe="")
    password = quote(values["POSTGRES_PASSWORD"], safe="")
    name = quote(values.get("POSTGRES_DB", "sentinelx"), safe="")
    port = int(values.get("SENTINELX_POSTGRES_PORT", "55432"))
    if not 1 <= port <= 65535:
        raise RuntimeError("Invalid local PostgreSQL port.")
    return f"postgresql://{user}:{password}@127.0.0.1:{port}/{name}"
