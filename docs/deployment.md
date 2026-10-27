# Deploying Sentinelx

The repository includes deployment configurations; no hosting account, DNS record, public site, or hosted database has been provisioned. Pick one persistent Python/Docker host. The API serves the dashboard and administrator portal as well as the backend. Keep one API instance and one Uvicorn worker while scans and authentication throttling remain in-process.

## Database and session settings

Set `SENTINELX_ENV=production` and a PostgreSQL `DATABASE_URL` in your hosting platform's secret settings. Production startup requires PostgreSQL; a missing URL must not quietly create SQLite. A database connection failure must remain a startup failure. Use the provider's verified TLS connection settings for external databases; never disable certificate verification to bypass a connection error.

For HTTPS, set `SECUREFLOW_COOKIE_SECURE=true` and `SECUREFLOW_PUBLIC_ORIGIN` to the exact public origin, such as `https://security.example.com`, without a trailing slash. This is needed because TLS terminates at the proxy and the API deliberately does not trust forwarded headers. Browser sessions use HttpOnly cookies. Keep the application and frontend on the same origin. Do not put database URLs or session values into frontend files.

Normal public registration creates a workspace account, not a platform administrator. Bootstrap the administrator through the host's private shell with the same database configuration as the running API:

```sh
python -m app.manage create-admin --email operator@example.com
```

Use its hidden password prompts. Refer to [administrator setup](admin-postgres.md) when importing legacy SQLite data; migrate before creating accounts in an empty destination database.

## Docker server with automatic HTTPS

Prerequisites: a Linux server with Docker/Compose, a public DNS hostname pointing at the server, and inbound TCP 80/443 (UDP 443 optional). Place privately completed settings from `deploy/production.env.example` in `.env.production`. Generate a long URL-safe database password; no password is supplied in the template.

Run from the repository checkout:

```sh
docker compose --env-file .env.production -f compose.production.yaml config --quiet
docker compose --env-file .env.production -f compose.production.yaml up --build -d --wait
docker compose --env-file .env.production -f compose.production.yaml logs --tail=50 api
```

`compose.production.yaml` is a **standalone** stack. Do not combine it with the local Compose file: local settings publish ports for development. The production stack publishes only Caddy ports 80/443. PostgreSQL is on a private internal network; the API has no published port. Caddy obtains certificates for the configured hostname and persists them in `caddy-data`. PostgreSQL data remains in `sentinelx-postgres`. Existing volume names depend on the Compose project name; keep that name stable between starts. Back up an existing database before changing stacks, credentials, image versions or project names.

Provision the administrator with:

```sh
docker compose --env-file .env.production -f compose.production.yaml exec api python -m app.manage create-admin --email operator@example.com
```

The Docker command keeps `--no-proxy-headers`. Caddy is the sole exposed HTTP entry, and incoming forwarding headers are not used for application authorization or rate-limit identity. Consequently the application sees the proxy as a shared peer for its default 30 authentication requests per minute. This is a conservative shared budget, not a per-user production ingress limiter. Add a separately configured, trusted edge limiter before increasing traffic. Do not use `--forwarded-allow-ips='*'` or enable arbitrary proxy headers to work around that limit.

Caddy can request certificates only when public DNS and network access are correct. Local `caddy validate` checks syntax; it does not establish DNS ownership or certificate issuance. This stack enables HSTS for the configured HTTPS hostname. Do not use a production hostname until HTTPS works and you intend browsers to retain that requirement.

## Render blueprint

`render.yaml` describes one always-on Docker web service and a managed PostgreSQL database with external database access disabled. It uses paid instance/database plans; review current provider availability and charges before applying it. The blueprint is prepared for review and has not been applied to any account.

Import this repository using Render's Blueprint workflow. Set the requested `SECUREFLOW_PUBLIC_ORIGIN` secret-setting field to the final HTTPS service/custom-domain origin, and retain the managed `DATABASE_URL` binding. The service uses port 8000, health endpoint `/health`, secure cookies and production PostgreSQL requirements. Automatic deploys are disabled in the template. The Docker image includes the static dashboard, so no separate frontend build or hosting service is necessary.

After provisioning, use the provider's private service shell for administrator bootstrap. Confirm persistence by creating a project, restarting/redeploying the service, signing in again, and verifying the same project remains. Run `scripts/smoke.py` only against your own prepared environment; it creates a test account, project and report. Check `/health`, dashboard login, administrator access controls, repository scan/report completion, and PostgreSQL backup configuration before wider access.

Render's ingress also remains untrusted by Uvicorn, so the application authentication throttle can be shared across visitors. Use provider/edge rate controls and an explicit trusted-proxy design if per-client limiting is required. Do not trust arbitrary forwarded identity headers.

## Why not a Vercel-only deployment?

The current backend executes scans in its API process and expects PostgreSQL connections and bounded temporary archive storage. Serverless invocation lifetimes and ephemeral process state do not provide a durable worker. Host this backend on a persistent container/Python service. Vercel can host a future separately built frontend, but that requires an explicit origin, cookie/CORS design, and a separately deployed API. The included same-origin dashboard avoids that extra setup.

## Operations and known limits

Keep encrypted PostgreSQL backups outside the host and test restoration. Never run `docker compose down --volumes` to fix a startup issue: it deletes persistent data. Changing `.env.production` credentials does not rotate an existing PostgreSQL role automatically. Migrations and deployments must stop or drain in-process scans; interrupted scans are marked failed and blocked on restart.

The platform currently runs source-only baseline checks, not the full external scanner suite. Missing required engines stay visible and block releases. It does not execute target code or perform deployments. Before adding active tools or broad public access, use isolated durable workers, job/tenant quotas, monitoring, log retention, a shared authentication limiter, and verified scanner supply chains. A generated deployment manifest does not establish those capabilities.
