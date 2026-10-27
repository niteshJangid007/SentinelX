"""Run admin browser checks against an isolated temporary PostgreSQL schema."""

import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    destination = os.getenv("TEST_DATABASE_URL")
    if not destination:
        raise SystemExit("Set TEST_DATABASE_URL for an isolated PostgreSQL browser check.")
    schema = "sentinelx_browser_" + uuid.uuid4().hex
    with psycopg.connect(destination, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    original_url = os.environ.get("DATABASE_URL")
    process = None
    try:
        target = make_conninfo(destination, options="-c search_path=" + schema)
        os.environ["DATABASE_URL"] = target
        from app.manage import create_admin

        email = "admin-" + secrets.token_hex(6) + "@example.test"
        password = secrets.token_urlsafe(30)
        create_admin(email, password)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        environment = {
            **os.environ,
            "SECUREFLOW_TEST_ADMIN_EMAIL": email,
            "SECUREFLOW_TEST_ADMIN_PASSWORD": password,
            "SECUREFLOW_TEST_ADMIN_BASE_URL": origin,
        }
        with tempfile.TemporaryDirectory(prefix="sentinelx-admin-check-") as directory:
            with open(Path(directory) / "server.log", "w+") as log:
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "uvicorn",
                        "app.main:app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                        "--no-proxy-headers",
                    ],
                    cwd=ROOT,
                    env=environment,
                    stdout=log,
                    stderr=log,
                )
                for attempt in range(200):
                    try:
                        urllib.request.urlopen(origin + "/health", timeout=1).close()
                        break
                    except OSError:
                        if process.poll() is not None:
                            raise RuntimeError(
                                "Isolated administrator test server failed to start."
                            )
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Isolated administrator test server timed out.")
                result = subprocess.call(
                    [sys.executable, "scripts/admin_browser_test.py"], cwd=ROOT, env=environment
                )
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                process = None
                return result
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if original_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = original_url
        with psycopg.connect(destination, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


if __name__ == "__main__":
    raise SystemExit(main())
