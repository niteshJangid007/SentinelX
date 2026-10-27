"""Real browser acceptance test against the running, same-origin SecureFlow app.

Run: PLAYWRIGHT_BROWSERS_PATH=/workspace/playwright .venv/bin/python scripts/browser_test.py
Optional: SECUREFLOW_TEST_BASE_URL=http://127.0.0.1:8001
Set SECUREFLOW_TEST_GITHUB=1 to additionally exercise an actual public GitHub scan.
Set BROWSER_EXECUTABLE to use a system browser instead of Playwright Chromium.
Exercises real API and scanner; it does not mock network responses.
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

from playwright.sync_api import expect, sync_playwright
from browser_theme import (
    assert_no_overflow,
    first_visit_editions,
    assert_safe_storage,
    exercise_portal_editions,
)

BASE_URL = os.getenv("SECUREFLOW_TEST_BASE_URL", "http://127.0.0.1:8001")
ROOT = Path(__file__).resolve().parents[1]


def vulnerable_zip():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("main.py", "value = eval(input())\n")
        archive.writestr("Dockerfile", "FROM python:3.12\nUSER root\n")
    return stream.getvalue()


def exercise_crud(page):
    """Create, inspect, edit, search and remove real owned resources through the UI."""
    demo_name = "CRUD demo " + secrets.token_hex(4)
    updated_name = demo_name + " edited"
    page.locator("[data-view=repositories]").first.click()
    page.locator("#new-project-name").fill(demo_name)
    with page.expect_response(
        lambda response: response.request.method == "POST"
        and response.url.endswith("/api/v1/projects")
    ) as created_event:
        page.get_by_role("button", name="Create project", exact=True).click()
    assert created_event.value.status == 201
    project_id = created_event.value.json()["id"]
    project_row = page.locator("tr").filter(has_text=demo_name)
    expect(project_row).to_be_visible()
    project_row.get_by_role("button", name="View project", exact=True).click()
    expect(page.locator("#detail-dialog")).to_contain_text(demo_name)
    page.locator("#detail-dialog").get_by_role("button", name="Close", exact=True).click()
    project_row.get_by_role("button", name="Edit project", exact=True).click()
    edit = page.locator("#edit-project-form")
    edit.get_by_label("Project name", exact=True).fill(updated_name)
    edit.get_by_label("Description", exact=True).fill(
        "Updated through the real browser CRUD workflow."
    )
    edit.get_by_label("Technology", exact=True).fill("Python")
    edit.locator("#edit-project-environment").select_option("staging")
    edit.get_by_role("button", name="Save project", exact=True).click()
    expect(page.locator("#detail-dialog")).to_have_count(0)
    persisted = page.request.get(BASE_URL + "/api/v1/projects/" + project_id).json()
    assert persisted["name"] == updated_name
    assert persisted["description"] == "Updated through the real browser CRUD workflow."
    assert persisted["technology"] == "Python"
    assert persisted["environment"] == "staging"
    results = page.request.get(BASE_URL + "/api/v1/projects", params={"q": updated_name}).json()
    assert [item["id"] for item in results] == [project_id]
    assert (
        page.request.get(
            BASE_URL + "/api/v1/projects", params={"q": "definitely-absent-" + demo_name}
        ).json()
        == []
    )
    page.evaluate(
        "() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))"
    )
    scene_before_search = page.locator("html").get_attribute("data-scene-sequence")
    page.locator("#global-search").fill(updated_name)
    expect(page.locator("tr").filter(has_text=updated_name)).to_be_visible()
    page.locator("#global-search").fill("definitely-absent-" + demo_name)
    expect(page.locator("tr").filter(has_text=updated_name)).to_have_count(0)
    page.locator("#global-search").fill("")
    page.evaluate(
        "() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))"
    )
    assert page.locator("html").get_attribute("data-scene-sequence") == scene_before_search, (
        "Search replays scene entrance animation"
    )

    page.locator("#project-name").fill(updated_name)
    page.locator("#repo-url").fill("https://github.com/octocat/Hello-World")
    page.locator("#repo-branch").fill("master")
    page.locator("#scan-on-connect").uncheck()
    with page.expect_response(
        lambda response: response.request.method == "POST"
        and response.url.endswith("/api/v1/repositories")
    ) as connected_event:
        page.get_by_role("button", name="Connect repository", exact=True).click()
    assert connected_event.value.status == 201
    repository_id = connected_event.value.json()["id"]
    repo_row = (
        page.locator("tr")
        .filter(has_text="https://github.com/octocat/Hello-World")
        .filter(has_text=updated_name)
    )
    expect(repo_row).to_be_visible()
    repo_row.get_by_role("button", name="View repository", exact=True).click()
    expect(page.locator("#detail-dialog")).to_contain_text("octocat/Hello-World")
    page.locator("#detail-dialog").get_by_role("button", name="Close", exact=True).click()
    repo_row.get_by_role("button", name="Edit repository", exact=True).click()
    repo_edit = page.locator("#edit-repository-form")
    repo_edit.get_by_label("Branch", exact=True).fill("feature/crud-demo")
    repo_edit.get_by_role("button", name="Save repository", exact=True).click()
    expect(page.locator("#detail-dialog")).to_have_count(0)
    repo = page.request.get(BASE_URL + "/api/v1/repositories/" + repository_id).json()
    assert repo["branch"] == "feature/crud-demo"
    assert repo["project_id"] == project_id
    matches = page.request.get(
        BASE_URL + "/api/v1/repositories", params={"q": "feature/crud-demo"}
    ).json()
    assert [item["id"] for item in matches] == [repository_id]
    assert (
        page.request.get(
            BASE_URL + "/api/v1/repositories", params={"q": "definitely-absent-" + demo_name}
        ).json()
        == []
    )
    page.screenshot(
        animations="disabled",
        path=str(ROOT / "docs" / "screenshots" / "crud-demo.png"),
        full_page=True,
    )
    repo_row.get_by_role("button", name="Disconnect repository", exact=True).click()
    disconnect = page.locator("#disconnect-repository-form")
    expect(
        disconnect.get_by_role("button", name="Disconnect repository", exact=True)
    ).to_be_visible()
    expect(
        disconnect.get_by_role("button", name="Disconnect repository", exact=True)
    ).to_be_disabled()
    expect(page.locator("#detail-dialog")).to_be_visible()
    assert page.request.get(BASE_URL + "/api/v1/repositories/" + repository_id).status == 200
    disconnect.locator("#confirm-delete").check()
    disconnect.get_by_role("button", name="Disconnect repository", exact=True).click()
    expect(page.locator("#detail-dialog")).to_have_count(0)
    assert page.request.get(BASE_URL + "/api/v1/repositories/" + repository_id).status == 404
    project_row = page.locator("tr").filter(has_text=updated_name)
    project_row.get_by_role("button", name="Delete project", exact=True).click()
    deletion = page.locator("#delete-project-form")
    expect(deletion.get_by_role("button", name="Delete project", exact=True)).to_be_visible()
    expect(deletion.get_by_role("button", name="Delete project", exact=True)).to_be_disabled()
    expect(page.locator("#detail-dialog")).to_be_visible()
    assert page.request.get(BASE_URL + "/api/v1/projects/" + project_id).status == 200
    deletion.locator("#confirm-delete").check()
    deletion.get_by_role("button", name="Delete project", exact=True).click()
    expect(page.locator("#detail-dialog")).to_have_count(0)
    assert page.request.get(BASE_URL + "/api/v1/projects/" + project_id).status == 404
    assert page.request.get(BASE_URL + "/api/v1/projects", params={"q": demo_name}).json() == []
    assert (
        page.request.get(
            BASE_URL + "/api/v1/repositories", params={"q": "feature/crud-demo"}
        ).json()
        == []
    )


def run():
    screenshots = ROOT / "docs" / "screenshots"
    screenshots.mkdir(parents=True, exist_ok=True)
    failures = []
    with sync_playwright() as playwright:
        executable = os.getenv("BROWSER_EXECUTABLE")
        browser = playwright.chromium.launch(executable_path=executable)
        page = browser.new_page(viewport={"width": 1364, "height": 686}, accept_downloads=True)
        page.on("pageerror", lambda error: failures.append(str(error)))
        page.on(
            "response",
            lambda response: failures.append(
                "Asset HTTP " + str(response.status) + ": " + response.url
            )
            if response.status >= 400
            and response.request.resource_type in ("image", "font", "stylesheet", "script")
            else None,
        )
        page.on(
            "console",
            lambda message: failures.append(message.text)
            if message.type == "error"
            and any(
                term in message.text
                for term in ("Content Security Policy", "Refused to load", "Refused to execute")
            )
            else None,
        )
        page.goto(BASE_URL)
        first_visit_editions(page, browser, BASE_URL, screenshots, "user")
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
        expect(page.locator("#auth-title")).to_be_visible()
        page.locator("#auth-mode").click()
        expect(page.locator("#auth-submit")).to_have_text("Create account")
        page.get_by_label("Email address", exact=True).fill(
            f"browser-{secrets.token_hex(6)}@example.test"
        )
        page.get_by_label("Password", exact=True).fill("Browser-test-password-42!")
        page.get_by_role("button", name="Create account", exact=True).click()
        expect(page.locator("#app-shell")).to_be_visible()
        expect(page.locator("#main-content h1")).to_be_visible()
        page.reload()
        expect(page.locator("#app-shell")).to_be_visible()

        exercise_crud(page)

        page.locator("[data-view=repositories]").first.click()
        hostile_name = '<img src=x onerror="window.__xss=true">'
        page.locator("#new-project-name").fill(hostile_name)
        page.get_by_role("button", name="Create project", exact=True).click()
        expect(page.locator("#upload-project option").filter(has_text=hostile_name)).to_have_count(
            1
        )
        assert page.evaluate("window.__xss") is None, "Hostile project name executed script"
        assert page.locator("img[onerror]").count() == 0

        page.locator("[data-view=repositories]").first.click()
        page.locator("#project-name").fill("Browser GitHub integration")
        page.get_by_label("Repository URL", exact=True).fill(
            "https://github.com/octocat/Hello-World"
        )
        page.get_by_label("Branch", exact=True).fill("master")
        github_enabled = os.getenv("SECUREFLOW_TEST_GITHUB") == "1"
        page.locator("#scan-on-connect").set_checked(github_enabled)
        if github_enabled:
            with page.expect_response(
                lambda response: response.request.method == "POST"
                and response.url.endswith("/api/v1/scans")
            ) as github_started:
                page.get_by_role("button", name="Connect repository", exact=True).click()
            assert github_started.value.status == 202
            expect(page.get_by_text("completed", exact=True).first).to_be_visible(timeout=120000)
            page.get_by_role("button", name="View report", exact=True).first.click()
            with page.expect_download() as github_download_event:
                page.get_by_role("button", name="Download JSON", exact=True).click()
            github_report = json.loads(Path(github_download_event.value.path()).read_text())
            assert github_report["scan"]["source"] == "github"
            assert github_report["scan"]["status"] == "completed"
            assert github_report["scan"]["coverage"]["files_analyzed"] > 0
            assert github_report["scan"]["decision"] == "BLOCK"
            page.locator("#detail-dialog").get_by_role("button", name="Close", exact=True).click()
        else:
            page.get_by_role("button", name="Connect repository", exact=True).click()
            expect(
                page.get_by_text("https://github.com/octocat/Hello-World", exact=True).first
            ).to_be_visible()

        page.locator("[data-view=repositories]").first.click()
        page.locator("#upload-project").select_option(label=hostile_name)
        page.get_by_label("Project ZIP", exact=True).set_input_files(
            {"name": "vulnerable.zip", "mimeType": "application/zip", "buffer": vulnerable_zip()}
        )
        page.get_by_role("button", name="Upload and scan", exact=True).click()
        zip_row = page.locator("tr").filter(has_text=hostile_name).first
        expect(zip_row.get_by_text("completed", exact=True)).to_be_visible(timeout=30000)
        expect(zip_row.get_by_text("BLOCK", exact=True)).to_be_visible()
        zip_row.get_by_role("button", name="View report", exact=True).click()
        page.locator("#detail-dialog summary").filter(has_text="Dynamic code execution").click()
        expect(
            page.get_by_role("heading", name="Dynamic code execution", exact=True)
        ).to_be_visible()
        with page.expect_download() as download_event:
            page.get_by_role("button", name="Download JSON", exact=True).click()
        report_download = download_event.value
        downloaded_report = json.loads(Path(report_download.path()).read_text())
        assert downloaded_report["scan"]["decision"] == "BLOCK"
        assert downloaded_report["deployment_allowed"] is False
        assert downloaded_report["scan"]["findings"]
        assert hostile_name == downloaded_report["project"]["name"]
        assert page.evaluate("window.__xss") is None
        assert_safe_storage(page)
        assert page.evaluate("Object.keys(sessionStorage).length") == 0
        assert page.evaluate("Object.keys(sessionStorage).length") == 0, (
            "Authentication persisted in sessionStorage"
        )
        assert page.locator("script:not([src])").count() == 0, "Inline scripts found"
        page.locator("#detail-dialog").get_by_role("button", name="Close", exact=True).click()

        # Populate the visual review with real persisted projects and actual scan outputs.
        origin_headers = {"Origin": BASE_URL}
        renamed = page.request.put(
            BASE_URL + "/api/v1/projects/" + downloaded_report["project"]["id"],
            data={"name": "payment-service"},
            headers=origin_headers,
        )
        assert renamed.ok
        expected_findings = len(downloaded_report["scan"]["findings"])
        for name, source_name, source in [
            ("customer-dashboard", "main.py", 'print("customer dashboard")\n'),
            ("infrastructure", "deployment.yaml", "securityContext:\n  privileged: true\n"),
            ("public-api", "app.py", 'import hashlib\nhashlib.md5(b"integrity")\n'),
        ]:
            created = page.request.post(
                BASE_URL + "/api/v1/projects", data={"name": name}, headers=origin_headers
            )
            assert created.ok
            project_id = created.json()["id"]
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr(source_name, source)
            queued = page.request.post(
                BASE_URL + "/api/v1/projects/" + project_id + "/upload",
                headers=origin_headers,
                multipart={
                    "file": {
                        "name": name + ".zip",
                        "mimeType": "application/zip",
                        "buffer": stream.getvalue(),
                    }
                },
            )
            assert queued.status == 202
            fixture_id = queued.json()["id"]
            deadline = time.monotonic() + 30
            while True:
                fixture = page.request.get(BASE_URL + "/api/v1/scans/" + fixture_id).json()
                if fixture["status"] not in ("queued", "running"):
                    break
                assert time.monotonic() < deadline, "Visual fixture scan timed out"
                page.wait_for_timeout(100)
            assert fixture["status"] == "completed"
            expected_findings += len(fixture["findings"])
        page.locator("[data-view=overview]").first.click()
        page.reload()
        expect(page.locator("#app-shell")).to_be_visible()
        dashboard = page.evaluate("async () => (await fetch('/api/v1/dashboard')).json()")
        assert dashboard["open_findings"] == expected_findings
        assert dashboard["total_scans"] >= 4
        expect(page.locator(".severity-distribution")).to_be_visible()
        levels = ["critical", "high", "medium", "low", "informational"]
        label = "Open finding severity: " + ", ".join(
            f"{dashboard['severity_counts'][level]} {level}" for level in levels
        )
        expect(page.locator("#severity-distribution svg")).to_have_attribute("aria-label", label)
        for level in levels:
            expect(
                page.locator(".severity-legend-item")
                .filter(has_text=level.capitalize())
                .locator("strong")
            ).to_have_text(str(dashboard["severity_counts"][level]))
        restored_context = browser.new_context(storage_state=page.context.storage_state())
        reopened = restored_context.new_page()
        reopened.goto(BASE_URL)
        expect(reopened.locator("#app-shell")).to_be_visible()
        restored_dashboard = reopened.evaluate(
            "async () => (await fetch('/api/v1/dashboard')).json()"
        )
        assert restored_dashboard["open_findings"] == dashboard["open_findings"]
        restored_context.close()
        expect(
            page.locator(".metric-card").filter(has_text="Open findings").locator(".metric-value")
        ).to_have_text(str(dashboard["open_findings"]))
        auth_cookies = [cookie for cookie in page.context.cookies() if cookie["httpOnly"]]
        assert auth_cookies, "HttpOnly authentication cookie missing"
        assert all(cookie["sameSite"] in ("Lax", "Strict") for cookie in auth_cookies)
        assert all(
            cookie["value"] not in page.evaluate("document.cookie") for cookie in auth_cookies
        )
        exercise_portal_editions(page, BASE_URL, screenshots, "user")
        page.set_viewport_size({"width": 1364, "height": 686})
        page.locator("[data-view=overview]:visible").first.click()
        page.screenshot(
            animations="disabled", path=str(screenshots / "dashboard.png"), full_page=False
        )
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (
            page.evaluate(
                "() => Array.from(document.querySelectorAll('body *')).filter(e => e.getBoundingClientRect().right > innerWidth + 1).slice(0,12).map(e => ({tag:e.tagName,id:e.id,class:e.className,right:e.getBoundingClientRect().right,width:e.getBoundingClientRect().width}))"
            )
        )
        page.locator("[data-view=findings]").first.click()
        expect(page.get_by_text("Dynamic code execution", exact=True).first).to_be_visible()
        page.screenshot(
            animations="disabled", path=str(screenshots / "mobile-findings.png"), full_page=True
        )
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (
            "Mobile findings overflow horizontally"
        )
        for view in [
            "overview",
            "repositories",
            "scans",
            "findings",
            "reports",
            "policies",
            "audit",
        ]:
            page.locator(f"[data-view={view}]").first.click()
            expect(page.locator("#main-content h1")).to_be_visible()
            assert_no_overflow(page, f"User final mobile {view}")
        page.locator("#logout-button").click()
        expect(page.locator("#auth-section")).to_be_visible()
        page.reload()
        expect(page.locator("#auth-section")).to_be_visible()
        expect(page.locator("#app-shell")).to_be_hidden()
        assert page.request.get(BASE_URL + "/api/v1/auth/me").status == 401
        assert not failures, failures
        browser.close()
    print(
        json.dumps(
            {
                "passed": True,
                "checks": [
                    "browser registration",
                    "project and repository CRUD",
                    "positive and negative search",
                    "confirmed deletion with no leftovers",
                    "project creation",
                    "XSS escaping",
                    "GitHub repository connection",
                    "real ZIP scan",
                    "report rendering",
                    "JSON download",
                    "mobile navigation",
                    "mobile overflow",
                    "reload restores real dashboard data",
                    "severity distribution counts",
                    "HttpOnly session cookie",
                    "logout survives reload",
                    "no JavaScript errors",
                ],
                "github_scan_verified": github_enabled,
                "screenshots": str(screenshots),
            }
        )
    )


if __name__ == "__main__":
    run()
