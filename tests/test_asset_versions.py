import hashlib
import re
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.web import mount_web

pytestmark = pytest.mark.integration


def test_html_versions_assets_and_changes_version_after_update(tmp_path):
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text(
        '<link href="/assets/styles.css"><script src="/assets/app.js"></script>'
    )
    (static / "styles.css").write_text("body{color:blue}")
    script = static / "app.js"
    script.write_text('console.log("new theme")')
    app = FastAPI()
    mount_web(app, static)
    with TestClient(app) as c:
        first = c.get("/").text
        digest = hashlib.sha256(script.read_bytes()).hexdigest()[:16]
        assert "/assets/app.js?v=" + digest in first
        assert c.get("/assets/styles.css").headers["cache-control"] == "no-store"
        script.write_text('console.log("updated theme")')
        second = c.get("/").text
        assert first != second
        assert "/assets/app.js?v=" + hashlib.sha256(script.read_bytes()).hexdigest()[:16] in second
