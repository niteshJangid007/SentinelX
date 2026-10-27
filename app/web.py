"""Serve the control panel beside the API, without a separate frontend server."""

from pathlib import Path
import hashlib
import re

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

STATIC_DIRECTORY = Path(__file__).resolve().parent / "static"
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


def mount_web(app: FastAPI, static_directory: Path = STATIC_DIRECTORY) -> None:
    directory = Path(static_directory).resolve()

    @app.middleware("http")
    async def web_security_headers(request: Request, call_next):
        response = await call_next(request)
        if request.url.path in ("/", "/admin", "/admin/") or request.url.path.startswith(
            "/assets/"
        ):
            response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Cache-Control"] = "no-store"
        return response

    def render_page(index):
        html = index.read_text(encoding="utf-8")

        def version(match):
            asset = directory / match.group(1).removeprefix("/assets/")
            if not asset.is_file() or not asset.resolve().is_relative_to(directory):
                return match.group(0)
            digest = hashlib.sha256(asset.read_bytes()).hexdigest()[:16]
            return match.group(1) + "?v=" + digest

        html = re.sub(r'(/assets/[^"\s?]+\.(?:js|css))(?:\?v=[^"\s]*)?', version, html)
        return HTMLResponse(html)

    @app.get("/", include_in_schema=False)
    def homepage():
        index = directory / "index.html"
        if not index.is_file():
            raise HTTPException(404, "Control panel assets are unavailable")
        return render_page(index)

    @app.get("/admin", include_in_schema=False)
    @app.get("/admin/", include_in_schema=False)
    def admin_homepage():
        index = directory / "admin.html"
        if not index.is_file():
            raise HTTPException(404, "Administration assets are unavailable")
        return render_page(index)

    app.mount(
        "/assets",
        StaticFiles(directory=directory, check_dir=False, follow_symlink=False),
        name="assets",
    )
