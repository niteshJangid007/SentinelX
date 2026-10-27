# PostgreSQL and the administrator portal

Sentinelx has two distinct interfaces. The application dashboard is for each user's projects, repositories, scans, findings and reports. The administrator portal at `/admin` is for explicitly provisioned platform administrators to inspect platform-wide activity and manage users. Registering a normal account does not grant platform administrator access.

## Local prerequisites

Install Python 3.12 or later and Docker Desktop (Windows/macOS), or Docker Engine with the Compose plugin (Linux). Start Docker before using the launcher. PostgreSQL runs as a container; no separate PostgreSQL installation is needed. If Docker reports that it cannot connect to the daemon, open Docker Desktop and wait for it to become ready.

The local startup helper prepares an ignored `.env` file with a securely generated, URL-safe database password, starts the `db` service, waits for its healthcheck, and starts the API against PostgreSQL. Preserve an existing `.env`; it contains the password for the initialized database. Never commit it or send its contents in chat.

Compose creates a **new** `sentinelx-postgres` named volume for PostgreSQL. It retains the earlier `secureflow-data` volume and SQLite mount for migration. Existing SQLite accounts and scans do not automatically appear in the new PostgreSQL database.

## Container deployment

When using the full Compose stack instead of the host API launcher, first ensure the local helper has generated `.env`. Then:

```sh
docker compose up --build -d --wait
```

The API is bound to host loopback port 8000. PostgreSQL is bound to host loopback port 55432 by default. Set `SENTINELX_POSTGRES_PORT` in `.env` if that local port is occupied. API containers connect to `db:5432` on the Compose network; host API processes use the configured loopback port. The `DATABASE_URL` passed to the API is a credential and must not be printed in logs or committed.

For manual setup, copy `.env.example` to `.env`, generate a long random URL-safe `POSTGRES_PASSWORD`, and set `POSTGRES_USER` and `POSTGRES_DB` (both default to `sentinelx`). Compose intentionally refuses to start without a password. Changing the password in `.env` after PostgreSQL has initialized its volume does **not** update the database role's actual password; coordinate a PostgreSQL password change before updating configuration.

Use `docker compose up -d --wait db` to start only the database. Stop services using `docker compose down`; do not add `--volumes` when preserving data. Neither old SQLite storage nor PostgreSQL volumes should be deleted as a troubleshooting shortcut.

## Safe migration

Before migration, stop the API and any scanner processes so new records cannot be written. Back up the SQLite database with SQLite's backup API, including any committed WAL state, and retain the original database and named volume. Back up PostgreSQL before importing into an existing installation.

`DATABASE_URL` takes precedence when set. `SECUREFLOW_DB` is retained only as the SQLite fallback and does not trigger migration. Schema initialization is idempotent and does not copy SQLite records.

Migration is an explicit operator action. It copies users and resource records (sessions are deliberately not imported) into an empty PostgreSQL application database, preserve IDs and ownership, and compare source and destination counts. Do not point a new application at PostgreSQL and assume the SQLite history has already moved. Do not remove the legacy volume until login, ownership isolation, projects, scan history and reports have been independently checked against PostgreSQL.

## Administrator access

Platform administrator privileges are separate from the workspace administrator role returned by normal registration. With the API's database configuration active, run:

```sh
python -m app.manage create-admin --email operator@example.com
```

The CLI prompts twice for a password of at least 12 characters; input is hidden. No password argument or default is supported. To grant platform access to an existing, verified account while retaining its password and workspace role, use `python -m app.manage create-admin --email operator@example.com --grant-existing`. This is an explicit privileged local action. Do not add a public role-selection field or modify a browser token. Avoid putting passwords in shell commands or process arguments.

For a running API container, use `docker compose exec api python -m app.manage create-admin --email operator@example.com`. Host CLI commands need the same `DATABASE_URL` as the API or they may target the SQLite fallback instead.

The administrator portal has its own login entry and checks platform privileges on the server. Its cross-user visibility is intentional and privileged. Keep it bound to loopback for local use; add HTTPS and trusted administrative access controls before making it remotely reachable. Platform administrator accounts cannot be edited or disabled through the user-management API; their membership requires local operator access. Disabling an ordinary account rejects login and existing sessions and revokes all its sessions; re-enabling does not restore them. Administrative actions are audited. The portal does not make local audit records tamper-proof and does not replace operational database backups.

## Deployment boundaries

This setup prepares a local PostgreSQL-backed application. It does not provision a hosted database, create a public URL, configure TLS ingress, or publish a cloud deployment. Docker engine network restrictions may still prevent the image builder or scanner from reaching external services. The offline wheel build procedure in [architecture](architecture.md) remains available for a restricted builder, using a fresh context and the latest application files.

## One-time SQLite import

Before creating any account in a fresh PostgreSQL database, back up your SQLite file and run from the project directory:

```powershell
.\.venv\Scripts\python.exe scripts\start.py migrate data\secureflow.db
```

The helper starts PostgreSQL and imports users, password hashes, projects/scans/reports/audits and existing access controls. It never modifies the SQLite source, does not copy sessions, and refuses a nonempty target instead of merging accounts. Then create your administrator with `scripts\start.py create-admin` and start the dashboard. The importer is transactional; source validation occurs before destination data writes.
