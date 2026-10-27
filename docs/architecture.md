# Backend architecture

```text
Authenticated API
  -> owner-scoped SQLite resources and audit events
  -> source scan task
     -> GitHub source archive
     -> bounded, validated extraction
     -> source-only heuristic engines
     -> normalized findings and explicit engine results
  -> risk and policy evaluation
  -> report and deployment decision record
```

Authentication uses salted PBKDF2 password hashes and expiring opaque bearer sessions stored by token hash. Resource queries include the authenticated owner. Write and policy operations enforce role checks on the server. Audit events record security-relevant API actions; this local database audit trail is not a tamper-resistant external logging service.

GitHub repository URLs and refs are validated before retrieval. Archive members must not escape the temporary scan directory, introduce symlinks, or exceed processing limits. The API must never run a repository's setup/build commands. Reports redact detected secret material at the scanner boundary.

The frontend is a future consumer of the OpenAPI contract. It should show source acquisition, individual scanner states, findings, score, policy reasons, and deployment decisions separately. It must not imply that the browser performs scans or that a policy decision deploys software.

## Production follow-up

- GitHub App authorization with per-installation scope, webhook verification and delivery deduplication.
- Durable task broker and workers with per-job isolation, cancellation, resource limits, and recovery.
- Versioned security-tool images and trusted, updated vulnerability databases.
- Organization membership, invitation-based role administration, quotas and retention.
- Database migrations, centralized immutable audit export, authentication throttling and operational monitoring.
- Explicit approval workflow for exceptions; deployment credentials and actual deployment integration.
- DAST target ownership verification and network restrictions before enabling active scans.

These are implementation boundaries, not existing capabilities.

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
