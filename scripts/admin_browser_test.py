"""Real administrator browser acceptance test against a running isolated server.

Required SECUREFLOW_TEST_ADMIN_EMAIL and SECUREFLOW_TEST_ADMIN_PASSWORD identify a
platform administrator bootstrapped separately with python -m app.manage.
Optional SECUREFLOW_TEST_ADMIN_BASE_URL defaults to http://127.0.0.1:8002.
BROWSER_EXECUTABLE can select a system Chromium. No HTTP/scanner mocks are used.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import secrets
import time
import zipfile
from urllib.parse import urlparse, parse_qs

import httpx
from playwright.sync_api import expect, sync_playwright
from browser_theme import (
    assert_no_overflow,
    first_visit_editions,
    assert_safe_storage,
    exercise_portal_editions,
)

ROOT = Path(__file__).resolve().parents[1]
BASE = os.getenv("SECUREFLOW_TEST_ADMIN_BASE_URL", "http://127.0.0.1:8002")
PREFIX = "/api/v1"


def run():
    # Feature-first security assertion also yields a meaningful RED before admin exists.
    with httpx.Client(base_url=BASE, timeout=30) as api:
        denied = api.get(PREFIX + "/admin/users")
        assert denied.status_code == 401, "Unauthenticated admin users endpoint must return 401"
        admin_email = os.environ["SECUREFLOW_TEST_ADMIN_EMAIL"]
        admin_password = os.environ["SECUREFLOW_TEST_ADMIN_PASSWORD"]
        member_email = "admin-e2e-" + secrets.token_hex(6) + "@example.test"
        member_password = secrets.token_urlsafe(24)
        created = api.post(
            PREFIX + "/auth/register", json={"email": member_email, "password": member_password}
        )
        assert created.status_code == 201, created.text
        member_id = created.json()["id"]
        member_token = created.json()["access_token"]
        member_headers = {"Authorization": "Bearer " + member_token}
        assert api.get(PREFIX + "/admin/users", headers=member_headers).status_code == 403
        assert (
            api.post(
                PREFIX + "/admin/auth/login",
                json={"email": member_email, "password": member_password},
            ).status_code
            == 401
        )
        hostile_name = '<img src=x onerror="window.__adminXss=true">'
        project = api.post(
            PREFIX + "/projects", headers=member_headers, json={"name": hostile_name}
        )
        assert project.status_code == 201, project.text
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("main.py", "result = eval(input())\n")
        uploaded = api.post(
            PREFIX + "/projects/" + project.json()["id"] + "/upload",
            headers=member_headers,
            files={"file": ("admin-fixture.zip", stream.getvalue(), "application/zip")},
        )
        assert uploaded.status_code == 202, uploaded.text
        scan_id = uploaded.json()["id"]
        deadline = time.monotonic() + 30
        while True:
            scan = api.get(PREFIX + "/scans/" + scan_id, headers=member_headers).json()
            if scan["status"] not in ("queued", "running"):
                break
            assert time.monotonic() < deadline, "Fixture scan timed out"
            time.sleep(0.1)
        assert scan["status"] == "completed"
        assert scan["decision"] == "BLOCK"

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.getenv("BROWSER_EXECUTABLE"))
            page = browser.new_page(viewport={"width": 1364, "height": 686}, accept_downloads=True)
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on(
                "response",
                lambda response: errors.append(
                    "Asset HTTP " + str(response.status) + ": " + response.url
                )
                if response.status >= 400
                and response.request.resource_type in ("image", "font", "stylesheet", "script")
                else None,
            )
            page.on(
                "console",
                lambda message: errors.append(message.text)
                if message.type == "error"
                and any(
                    term in message.text
                    for term in ("Content Security Policy", "Refused to load", "Refused to execute")
                )
                else None,
            )
            page.goto(BASE + "/admin")
            first_visit_editions(
                page, browser, BASE + "/admin", ROOT / "docs" / "screenshots", "admin"
            )
            asset_urls = page.locator("script[src], link[rel=stylesheet]").evaluate_all(
                "elements => elements.map(element => element.src || element.href)"
            )
            assert asset_urls
            for asset_url in asset_urls:
                assert parse_qs(urlparse(asset_url).query).get("v"), (
                    "Unversioned stylesheet or script URL"
                )
                asset_response = page.request.get(asset_url)
                assert asset_response.status == 200
                assert "no-store" in asset_response.headers.get("cache-control", ""), (
                    "Assets must reject stale cache reuse"
                )
            page.get_by_label("Administrator email", exact=True).fill(member_email)
            page.get_by_label("Password", exact=True).fill(member_password)
            page.locator("#adm-auth-submit").click()
            expect(page.locator("#adm-auth-error")).not_to_be_empty()
            expect(page.locator("#adm-shell")).to_be_hidden()
            page.get_by_label("Administrator email", exact=True).fill(admin_email)
            page.get_by_label("Password", exact=True).fill(admin_password)
            page.locator("#adm-auth-submit").click()
            expect(page.locator("#adm-shell")).to_be_visible()
            page.reload()
            expect(page.locator("#adm-shell")).to_be_visible()
            auth_cookies = [cookie for cookie in page.context.cookies() if cookie["httpOnly"]]
            assert auth_cookies, "HttpOnly administrator session cookie missing"
            assert all(cookie["sameSite"] in ("Lax", "Strict") for cookie in auth_cookies)
            assert all(
                cookie["value"] not in page.evaluate("document.cookie") for cookie in auth_cookies
            )
            restored_context = browser.new_context(storage_state=page.context.storage_state())
            reopened = restored_context.new_page()
            reopened.goto(BASE + "/admin")
            expect(reopened.locator("#adm-shell")).to_be_visible()
            restored_context.close()

            page.locator("[data-admin-view=users]").first.click()
            member_row = page.locator("tr").filter(has_text=member_email)
            expect(member_row).to_be_visible()
            member_row.get_by_role("button", name="Manage user", exact=True).click()
            page.locator("#adm-disabled").check()
            page.locator("#adm-confirm").check()
            page.get_by_role("button", name="Save account changes", exact=True).click()
            expect(page.locator("#adm-dialog")).to_have_count(0)
            assert api.get(PREFIX + "/auth/me", headers=member_headers).status_code == 401, (
                "Disabling must revoke existing member session"
            )
            assert (
                api.post(
                    PREFIX + "/auth/login",
                    json={"email": member_email, "password": member_password},
                ).status_code
                == 401
            )

            member_row = page.locator("tr").filter(has_text=member_email)
            member_row.get_by_role("button", name="Manage user", exact=True).click()
            page.locator("#adm-disabled").uncheck()
            page.locator("#adm-role").select_option("viewer")
            page.locator("#adm-confirm").check()
            page.get_by_role("button", name="Save account changes", exact=True).click()
            expect(page.locator("#adm-dialog")).to_have_count(0)
            relogin = api.post(
                PREFIX + "/auth/login", json={"email": member_email, "password": member_password}
            )
            assert relogin.status_code == 200, relogin.text
            refreshed_headers = {"Authorization": "Bearer " + relogin.json()["access_token"]}
            assert (
                api.get(PREFIX + "/auth/me", headers=refreshed_headers).json()["role"] == "viewer"
            )
            assert (
                api.post(
                    PREFIX + "/projects", headers=refreshed_headers, json={"name": "Denied write"}
                ).status_code
                == 403
            )
            assert api.get(PREFIX + "/admin/users", headers=refreshed_headers).status_code == 403

            page.locator("[data-admin-view=reports]").first.click()
            row = page.locator("tr").filter(has_text=scan_id[:8])
            if row.count() == 0:
                row = page.locator("tr").filter(has_text=hostile_name)
            row.get_by_role("button", name="View report", exact=True).click()
            expect(page.locator("#adm-dialog")).to_be_visible()
            assert page.evaluate("window.__adminXss") is None
            assert page.locator("img[onerror]").count() == 0
            with page.expect_download() as download:
                page.get_by_role("button", name="Download JSON", exact=True).click()
            report = json.loads(Path(download.value.path()).read_text())
            assert report["scan"]["id"] == scan_id
            assert report["scan"]["decision"] == "BLOCK"
            assert report["project"]["name"] == hostile_name
            page.locator("#adm-dialog").get_by_role("button", name="Close", exact=True).click()
            assert_safe_storage(page)
            assert page.evaluate("Object.keys(sessionStorage).length") == 0
            assert page.evaluate("Object.keys(sessionStorage).length") == 0
            assert page.locator("script:not([src])").count() == 0
            page.locator("[data-admin-view=audit]").first.click()
            expect(page.get_by_text("admin.user.updated", exact=True).first).to_be_visible()
            screenshots = ROOT / "docs" / "screenshots"
            screenshots.mkdir(parents=True, exist_ok=True)
            exercise_portal_editions(page, BASE + "/admin", screenshots, "admin")
            page.set_viewport_size({"width": 1364, "height": 686})
            page.locator("[data-admin-view=overview]").first.click()
            page.screenshot(
                animations="disabled", path=str(screenshots / "admin-overview.png"), full_page=False
            )
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (
                page.evaluate(
                    "() => Array.from(document.querySelectorAll('body *')).filter(e => e.getBoundingClientRect().right > innerWidth + 1).slice(0,12).map(e => ({tag:e.tagName,id:e.id,class:e.className,right:e.getBoundingClientRect().right,width:e.getBoundingClientRect().width}))"
                )
            )
            page.locator("[data-admin-view=users]").first.click()
            expect(page.locator("tr").filter(has_text=member_email)).to_be_visible()
            page.screenshot(
                animations="disabled",
                path=str(screenshots / "admin-mobile-users.png"),
                full_page=True,
            )
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (
                "Admin users mobile overflow"
            )
            for view in ["overview", "users", "repositories", "scans", "reports", "audit"]:
                page.locator(f"[data-admin-view={view}]").first.click()
                expect(page.locator("#adm-main h1")).to_be_visible()
                assert_no_overflow(page, f"Admin final mobile {view}")
            page.locator("#adm-logout").click()
            expect(page.locator("#adm-auth-section")).to_be_visible()
            page.reload()
            expect(page.locator("#adm-auth-section")).to_be_visible()
            expect(page.locator("#adm-shell")).to_be_hidden()
            assert page.request.get(BASE + PREFIX + "/admin/me").status == 401
            assert not errors, errors
            browser.close()
    print(
        json.dumps(
            {
                "passed": True,
                "checks": [
                    "admin unauthenticated rejection",
                    "member admin rejection",
                    "real admin browser login",
                    "cross-account user review",
                    "disable revokes sessions",
                    "reenable and role update",
                    "viewer write denial",
                    "cross-account report download",
                    "XSS escaping",
                    "audit evidence",
                    "mobile navigation",
                    "no tokens in web storage",
                    "HttpOnly session cookie",
                    "reload restores admin data",
                    "logout survives reload",
                    "no JavaScript errors",
                ],
            }
        )
    )


if __name__ == "__main__":
    run()
