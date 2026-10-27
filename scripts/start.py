"""Start local PostgreSQL and the dashboard, or run a database management command."""

import os
from pathlib import Path
import shutil
import subprocess
import sys

from local_config import ROOT, database_url, load_settings


def main():
    os.chdir(ROOT)
    settings = load_settings()
    external = bool(settings.get("DATABASE_URL", "").strip())
    try:
        destination = database_url(create=not external)
        if not external:
            if not shutil.which("docker"):
                raise RuntimeError(
                    "Install and start Docker Desktop first, or configure DATABASE_URL for an existing PostgreSQL server."
                )
            subprocess.run(["docker", "compose", "up", "-d", "--wait", "db"], check=True)
        environment = {
            **{
                key: settings[key] for key in ("SENTINELX_ENV", "SECUREFLOW_ENV") if key in settings
            },
            **os.environ,
            "DATABASE_URL": destination,
        }
        if len(sys.argv) > 1:
            # Only explicit management modules; no arbitrary command forwarding.
            if sys.argv[1] == "create-admin" and (
                len(sys.argv) == 2 or sys.argv[2:] == ["--grant-existing"]
            ):
                command = [sys.executable, "-m", "app.manage", "create-admin", *sys.argv[2:]]
            elif sys.argv[1] == "migrate" and len(sys.argv) == 3:
                command = [sys.executable, "-m", "app.migrate", "--sqlite", sys.argv[2]]
            else:
                raise RuntimeError(
                    "Usage: start.py [create-admin [--grant-existing] | migrate PATH_TO_SQLITE]"
                )
        else:
            print("Sentinelx dashboard: http://127.0.0.1:8000")
            print("Administrator portal: http://127.0.0.1:8000/admin")
            print("Keep this terminal open. Press Ctrl+C to stop.")
            command = [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8000",
                "--workers",
                "1",
                "--no-proxy-headers",
            ]
        return subprocess.call(command, env=environment)
    except (RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    except subprocess.CalledProcessError:
        print(
            "PostgreSQL startup failed. Check that Docker Desktop is running and the local database port is available.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
