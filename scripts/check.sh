#!/usr/bin/env bash
# Local/CI checks against isolated fixture state; no external attack targets.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON_BIN="${PYTHON_BIN:-.venv/bin/python}"
mkdir -p test-results
"$PYTHON_BIN" -m pytest -m unit -q --junitxml=test-results/unit.xml
"$PYTHON_BIN" -m pytest -m integration -q --junitxml=test-results/integration.xml
"$PYTHON_BIN" -m pytest -m security -q --junitxml=test-results/security.xml
"$PYTHON_BIN" - <<'PY'
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

with tempfile.TemporaryDirectory(prefix='secureflow-check-') as directory:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    environment = {
        **os.environ,
        'DATABASE_URL': '',
        'SENTINELX_ENV': 'test',
        'SECUREFLOW_ENV': 'test',
        'SECUREFLOW_DB': str(Path(directory) / 'smoke.db'),
    }
    with open(Path(directory) / 'server.log', 'w+') as log:
        process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', str(port), '--no-proxy-headers'], env=environment, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 20
            while True:
                try:
                    with urllib.request.urlopen(origin + '/health', timeout=1) as response:
                        assert response.status == 200
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        log.seek(0)
                        raise RuntimeError('Smoke server did not become ready: ' + log.read())
                    time.sleep(.1)
            subprocess.run([sys.executable, 'scripts/smoke.py', origin], check=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
PY
