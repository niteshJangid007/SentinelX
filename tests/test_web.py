"""Same-origin browser UI hosting regression checks."""

import pytest

pytestmark = pytest.mark.integration

from fastapi import FastAPI
from fastapi.testclient import TestClient


def make_client(tmp_path):
    from app.web import mount_web

    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<!doctype html><title>SecureFlow</title>", encoding="utf-8")
    (static / "app.js").write_text('console.log("ready");', encoding="utf-8")
    (static / "styles.css").write_text("body { color: white; }", encoding="utf-8")
    (tmp_path / "private.txt").write_text("private server data", encoding="utf-8")
    app = FastAPI()
    mount_web(app, static)
    return TestClient(app)


def test_homepage_and_assets_are_same_origin(tmp_path):
    with make_client(tmp_path) as client:
        home = client.get("/")
        assert home.status_code == 200
        assert "SecureFlow" in home.text
        assert home.headers["content-type"].startswith("text/html")
        assert client.get("/assets/app.js").status_code == 200
        assert client.get("/assets/styles.css").status_code == 200


@pytest.mark.security
def test_browser_security_headers_and_fresh_index(tmp_path):
    with make_client(tmp_path) as client:
        response = client.get("/")
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        csp = response.headers["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp
        asset = client.get("/assets/app.js")
        assert asset.headers["x-content-type-options"] == "nosniff"


@pytest.mark.security
def test_static_paths_cannot_read_outside_directory(tmp_path):
    with make_client(tmp_path) as client:
        for path in (
            "/assets/../private.txt",
            "/assets/%2e%2e/private.txt",
            "/assets/%2e%2e%2fprivate.txt",
            "/assets/nonexistent",
        ):
            response = client.get(path)
            assert response.status_code == 404
            assert "private server data" not in response.text


@pytest.mark.security
def test_static_symlink_cannot_escape_directory(tmp_path):
    with make_client(tmp_path) as client:
        try:
            (tmp_path / "static" / "escape.txt").symlink_to(tmp_path / "private.txt")
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"Symlink creation unsupported or not permitted: {exc}")
        response = client.get("/assets/escape.txt")
        assert response.status_code == 404
        assert "private server data" not in response.text


def test_application_uses_sentinelx_brand():
    from pathlib import Path
    from app.main import app

    assert app.title == "Sentinelx API"
    static = Path(__file__).resolve().parents[1] / "app" / "static"
    html = (static / "index.html").read_text(encoding="utf-8")
    js = (static / "app.js").read_text(encoding="utf-8")
    assert "<title>Sentinelx" in html
    assert "SecureFlow" not in html
    assert "SecureFlow" not in js
    assert "sentinelx-report-" in js
