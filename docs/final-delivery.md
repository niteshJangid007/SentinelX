# Sentinelx final source delivery

Sentinelx is a working PostgreSQL-backed repository security application with a browser workspace, a separate platform administrator portal, source scanning, policy evaluation and downloadable reports. The source includes launchers, database initialization/migration, automated tests and deployment templates. GitHub stores the source; publishing a repository does not start the application or create a live website.

## What is implemented

- Account registration, login/logout and eight-hour HttpOnly browser sessions; password hashing, session revocation, server-side role checks, same-origin cookie-write protection and bounded authentication throttling.
- Owner-isolated project/repository workflows, public GitHub source connection, bounded ZIP uploads, scan execution/history, normalized findings, policy evaluation and JSON reports.
- Source-only baseline checks for potential secrets, selected Python security issues and infrastructure/container-file issues. Findings include severity, location, remediation and scanner attribution; detected secret values are not returned.
- A separate `/admin` portal for explicitly provisioned platform administrators, with cross-account activity review, workspace role changes, account disabling/re-enabling and audit events.
- PostgreSQL persistence for users and resources, plus a retained SQLite compatibility path and explicit one-way migration into an empty PostgreSQL target.
- The approved black/blue/red interface, responsive navigation, actual-data severity distribution, scan activity and release summary. Fonts and icons are bundled locally with their licenses.

Project CRUD acceptance steps and response codes are in [CRUD demonstration](crud-demo.md). The UI is a client of the API and database; it does not simulate a browser-side scanner.

## Run on Windows

1. Install Python 3.12 or later, Docker Desktop and Git if cloning the repository. Start Docker Desktop and wait until its engine is ready.
2. Clone/download the final source into a writable folder. If updating an existing installation, stop its old terminal/server first. Preserve the existing `.env`, database volumes and any legacy `data/` database.
3. Double-click `Start-Sentinelx.cmd`. The launcher prepares the Python environment, installs pinned dependencies, generates a local database password only when needed, starts PostgreSQL and starts the API. Keep its terminal open.
4. Open the local app address shown by the launcher, normally `http://127.0.0.1:8000`. Create an account or sign in with the existing account.
5. For platform administration, run `Create-Admin.cmd`, enter the designated email and password through its hidden prompt, then open `/admin`. Normal public registration does not grant this privilege.

No Node installation, separate frontend build, manual SQL creation or plaintext default administrator password is required. Package installation and public GitHub scanning need network access. Native Windows execution must be checked on the target Windows machine; Linux automated tests and simulated Windows archive-path regressions do not establish a native Windows result.

If importing an old SQLite installation, run the documented migration **before** creating accounts in the empty PostgreSQL destination. The import preserves ownership and hashes, refuses a nonempty target, leaves the source untouched and intentionally does not copy sessions. See [administrator/PostgreSQL guide](admin-postgres.md).

## Code and database organization

| Module | Responsibility |
| --- | --- |
| `app/main.py` | Application lifecycle and project/repository/scan/report API orchestration. |
| `app/schemas.py` | Typed request schemas, lengths/enums and rejected unexpected fields. |
| `app/resource_validation.py` | Shared nonblank project-name and repository URL/branch validation. |
| `app/auth.py` | Password hashing, sessions, cookies, CSRF/origin checks, role guards and throttling. |
| `app/db.py` | PostgreSQL/SQLite connection adapter, schema initialization and owner-scoped persistence. |
| `app/scanner.py` | GitHub/archive acquisition, bounded source inspection, normalization and policy evaluation. |
| `app/admin.py` | Platform administrator authorization and management endpoints. |
| `app/manage.py` | Private administrator provisioning with hidden password prompts. |
| `app/migrate.py` | Non-destructive SQLite import into an empty PostgreSQL target. |
| `app/web.py` | Dashboard/static hosting, content security policy and asset versioning. |
| `app/static/` | User/admin HTML, CSS and JavaScript; local fonts/icons and their licenses. |
| `scripts/local_config.py`, `scripts/start.py` | Local database configuration and application/management launch workflows. |
| `tests/`, `scripts/check.sh` | Unit, integration, security and real HTTP workflow checks. |
| `scripts/browser_test.py`, `scripts/check_admin_browser.py` | Browser acceptance checks against real application behavior. |

PostgreSQL stores users, hashed sessions, platform memberships, account controls and owner-scoped JSON resources. Project, repository, scan, finding, policy and audit records retain their IDs and ownership in resource rows. Schema initialization is automatic and idempotent. UI state is loaded from these persisted records; refreshing a page does not recreate the account or reset its projects.

Validation is applied on the server, not only in HTML fields. API errors distinguish invalid inputs, expired sessions, denied permissions, missing resources and conflicting active work. The source includes comments around trust boundaries, recovery and intentionally constrained behavior. Secrets belong in local ignored configuration or hosting secret settings, never in GitHub source or reports.

## Verification and submission evidence

Run `bash scripts/check.sh` after installing `requirements.lock`. PostgreSQL-specific checks use an isolated test database selected by `TEST_DATABASE_URL`; do not point this at a production database. Browser checks require `requirements-browser.txt` and Playwright Chromium. Follow [testing evidence](testing.md) for exact coverage, recorded test-first changes and known limits. Test-result files and screenshots demonstrate the run that created them; configured GitHub Actions are not a claim that remote CI has already executed.

For review, demonstrate account creation, project creation/listing/editing/deletion, an invalid input, a denied cross-account request, actual ZIP/GitHub scan completion, findings, downloaded report, reload persistence and the separate administrator boundary. Use synthetic sample code that you own; do not scan arbitrary live applications.

## Deployment and limits

A local app address and a GitHub repository URL are different from a hosted application URL. [Deployment instructions](deployment.md) cover the standalone Docker/Caddy HTTPS stack and an optional Render blueprint with managed PostgreSQL. Applying those templates still requires a hosting account, private database settings and an HTTPS origin; no public endpoint is implied by this source delivery.

The current application uses one API worker/instance and in-process scan jobs. Process restarts interrupt work and mark unfinished scans failed/blocked; it is not a durable job queue. Authentication throttling is local to a process, and proxy traffic can share a peer budget. Broad production use needs durable isolated workers, quotas, monitoring, backups and trusted ingress rate controls.

Private GitHub OAuth/App authorization, the full Gitleaks/Semgrep/CodeQL/dependency-CVE/Checkov/Trivy/ZAP integrations, active DAST and automated deployment execution are not complete. Unconfigured required engines stay visible and block release approval. A clean baseline scan is not a security certification. Deployment records evaluate eligibility and do not deploy source code.

## Final validation evidence

The final integrated suite passed186 tests with a live PostgreSQL service; both browser suites passed, including the full CRUD demonstration and existing scan/report pipeline. Python source is consistently formatted by Ruff and correctness lint passes. CI installs requirements-dev.txt and enforces format/lint checks alongside database and browser tests. Install developer tools with `python -m pip install -r requirements-dev.txt`; run `python -m ruff format --check app scripts tests` and `python -m ruff check app scripts tests`.
