# Sentinelx architecture

```text
Browser workspace / administrator portal
  -> local Gold/Street presentation preference and accessible scene motion
  -> same-origin FastAPI API with separate HttpOnly cookie sessions
  -> role and ownership authorization
  -> PostgreSQL users, sessions and owner-scoped resources
  -> in-process source scan task
     -> public GitHub branch archive or uploaded ZIP
     -> bounded in-memory archive validation (no extraction or source execution)
     -> secret patterns, selected Python AST checks, JS/inline-HTML review patterns,
        PHP runtime advisory snapshot and IaC/configuration rules
     -> normalized findings and explicit unavailable engine states
  -> weighted severity score and policy evaluation
  -> persisted findings, reports, audit events and deployment eligibility record
```

## Modules and boundaries

- `app/auth.py`: PBKDF2 password hashing, opaque hashed sessions, independent user/admin cookies, CSRF/origin checks and bounded single-process authentication throttling.
- `app/projects.py` and `resource_validation.py`: project/repository CRUD/search, owner checks, explicit deletion confirmation, active-scan conflicts and transactional deletion/auditing.
- `app/db.py`: parameterized SQLite compatibility/PostgreSQL adapter. PostgreSQL is the normal deployment; production cannot silently fall back to SQLite. Domain resources currently use JSON text records, not normalized relational domain tables.
- `app/scanner.py`: archive/URL restrictions and baseline heuristics. Submitted source, dependency installers and build hooks are never executed. Detected secret values are omitted from reports.
- `app/main.py`: scan orchestration, reports, findings, policy, dashboard and eligibility APIs. FastAPI background tasks run inside one API process; they are not a durable worker queue. Restart marks interrupted jobs failed.
- `app/admin.py` and `manage.py`: explicit platform membership, operator bootstrap with hidden password prompts, cross-account review, guarded role/access updates and audit events. Public registration grants no platform-admin membership.
- `app/web.py`: same-origin HTML/assets, content-hash CSS/JS URLs, no-store responses and restrictive browser security headers.
- `app/static/app.js`, `admin.js` and `theme.js`: actual API-backed user/admin views. Theme choice alone uses local storage; credentials remain in HttpOnly cookies. Gold/Street styling spans all pages and dialogs; motion ignores polling/filter rebuilds and respects reduced-motion preferences.

## Current limits

The scanning engines are limited heuristics, not Gitleaks/Semgrep/Trivy/ZAP integrations. SCA, image scanning and DAST remain unconfigured; incomplete required coverage blocks releases. The observed risk score is a weighted count, not CVSS. Scans fetch branch archives without immutable commit attribution. Repeated detections are currently stored as separate finding occurrences; unique vulnerability lifecycle/deduplication needs additional work. Deployment records do not execute deployments. Audit events are local database records, not an immutable external audit service.

The supported runtime is one API worker. Multi-instance scaling needs a durable job queue, cross-process state/locks, shared ingress rate limiting, connection pooling and resource quotas. PostgreSQL schema migrations, normalized/indexed domain querying, GitHub App/private access, organization collaboration, calibrated detection benchmarks and actual CI/deployment orchestration remain future work.

Tests use temporary SQLite databases by default and explicitly created disposable PostgreSQL schemas for live integration. Inherited DATABASE_URL and production environment settings are cleared before ordinary tests. The smoke child process also overrides these settings, preventing accidental operations against the caller's real database.

## Restricted Docker builder fallback

The cloud machine's Docker builder could fetch the Python base image, but could not resolve the package registry even with host networking. The API image was validated using wheels downloaded by the host's verified pip connection. To reproduce this workaround on the same Python 3.12/Linux architecture, from the checkout:

```sh
mkdir -p /tmp/secureflow-docker-offline/wheels
.venv/bin/python -m pip download --only-binary=:all: --dest /tmp/secureflow-docker-offline/wheels -r requirements.lock
python3 - <<'PY'
from pathlib import Path
import shutil
context = Path('/tmp/secureflow-docker-offline')
shutil.copytree('app', context / 'app', dirs_exist_ok=True,
                ignore=shutil.ignore_patterns('__pycache__'))
shutil.copy('requirements.lock', context / 'requirements.lock')
dockerfile = Path('Dockerfile').read_text().replace(
    'RUN pip install --no-cache-dir -r requirements.lock',
    'COPY wheels /wheels\nRUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.lock')
(context / 'Dockerfile').write_text(dockerfile)
PY
DOCKER_CONFIG=/tmp/secureflow-docker-config docker build -t sentinelx-api /tmp/secureflow-docker-offline
DOCKER_CONFIG=/tmp/secureflow-docker-config docker compose up --no-build -d --wait
.venv/bin/python scripts/smoke.py http://127.0.0.1:8000
```

Use a fresh temporary context when repeating this after source deletions. This workaround copies no proxy credentials and does not disable TLS verification. It verifies the same pinned dependencies and application code; the standard network-based Dockerfile build remains unverified in this restricted builder network. GitHub network scans from the container require separately configured outbound DNS/network access; local ZIP scan readiness does not establish GitHub reachability from Docker.
