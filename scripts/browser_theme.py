"""Shared real-browser edition, responsive and preference acceptance checks."""

from pathlib import Path
from playwright.sync_api import expect

EDITION_KEY = "sentinelx.edition"
VIEWPORTS = {
    "desktop": {"width": 1364, "height": 686},
    "tablet": {"width": 768, "height": 1024},
    "mobile": {"width": 390, "height": 844},
}


def assert_safe_storage(page):
    values = page.evaluate("Object.fromEntries(Object.entries(localStorage))")
    assert set(values) <= {EDITION_KEY}, "Unexpected data stored in localStorage"
    assert values.get(EDITION_KEY) in ("gold", "street")
    assert page.evaluate("Object.keys(sessionStorage).length") == 0, (
        "Unexpected sessionStorage data"
    )
    cookies = page.context.cookies()
    assert all(cookie["value"] not in values.values() for cookie in cookies if cookie["httpOnly"])


def assert_no_overflow(page, description):
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (
        description,
        page.evaluate(
            "({scroll:document.documentElement.scrollWidth,inner:innerWidth,client:document.documentElement.clientWidth})"
        ),
        page.evaluate("""() => Array.from(document.querySelectorAll('body *'))
        .filter(e => e.getBoundingClientRect().right > innerWidth)
        .slice(0,8).map(e => ({tag:e.tagName,id:e.id,class:String(e.className),
        right:e.getBoundingClientRect().right,width:e.getBoundingClientRect().width}))"""),
    )


def assert_resting_layout_and_table_scroll(page, description):
    page.evaluate("""async () => {
        await Promise.all(document.getAnimations().filter(animation => animation.effect &&
            animation.effect.getComputedTiming().iterations !== Infinity)
            .map(animation => animation.finished.catch(() => {})));
    }""")
    assert_no_overflow(page, description + " at rest")
    offenders = page.evaluate("""() => Array.from(document.querySelectorAll(
        'input,textarea,select,button,h1,h2,h3')).filter(element => {
        if (!element.getClientRects().length || element.closest('.table-wrap,.top-tabs')) return false;
        const style = getComputedStyle(element);
        if (style.display === 'none' || style.visibility === 'hidden') return false;
        const rect = element.getBoundingClientRect();
        return rect.right > innerWidth + 1 || rect.left < -1;
    }).map(element => ({tag:element.tagName,id:element.id,text:element.textContent.slice(0,60)}))""")
    assert not offenders, (description + " clipped static controls or headings", offenders)
    scrolling = page.evaluate("""() => Array.from(document.querySelectorAll('.table-wrap'))
        .filter(element => element.getClientRects().length && element.scrollWidth > element.clientWidth + 1)
        .map(element => {
            const previous = element.scrollLeft;
            element.scrollLeft = element.scrollWidth;
            const works = element.scrollLeft > 0 && ['auto','scroll'].includes(getComputedStyle(element).overflowX);
            element.scrollLeft = previous;
            return works;
        })""")
    assert all(scrolling), description + " horizontal data tables no longer scroll"


def switch_edition(page, edition):
    if (
        page.locator("html").get_attribute("data-edition") == edition
        and not page.locator("#edition-dialog").is_visible()
    ):
        assert_safe_storage(page)
        return
    direct = page.locator(f'[data-edition-choice="{edition}"]:visible')
    if not direct.count():
        page.locator("[data-open-editions]:visible").first.click()
        expect(page.locator("#edition-dialog")).to_be_visible()
        direct = page.locator(f'[data-edition-choice="{edition}"]:visible')
    direct.first.focus()
    page.keyboard.press("Enter")
    expect(page.locator("html")).to_have_attribute("data-edition", edition)
    expect(page.locator("#edition-dialog")).not_to_be_visible()
    assert_safe_storage(page)


def assert_display_fonts_loaded(page):
    """A computed family string alone can conceal a system-font fallback."""
    for descriptor in [
        '400 16px "Instrument Serif"',
        'italic 400 16px "Instrument Serif"',
        '400 16px "Permanent Marker"',
        '400 16px "Bebas Neue"',
    ]:
        faces = page.evaluate(
            "async descriptor => (await document.fonts.load(descriptor)).map(face => ({family:face.family,status:face.status}))",
            descriptor,
        )
        assert faces and all(face["status"] == "loaded" for face in faces), (
            f"Display font falls back: {descriptor}"
        )


def first_visit_editions(page, browser, url, screenshots, portal):
    screenshots = Path(screenshots)
    screenshots.mkdir(parents=True, exist_ok=True)
    expect(page.locator("#edition-dialog")).to_be_visible()
    assert_display_fonts_loaded(page)
    page.screenshot(animations="disabled", path=str(screenshots / f"{portal}-edition-chooser.png"))
    page.locator("#choose-gold").focus()
    page.keyboard.press("Tab")
    assert page.locator("#edition-dialog").evaluate(
        "(dialog) => dialog.contains(document.activeElement)"
    ), "Edition chooser loses keyboard focus"
    page.locator("#choose-gold").focus()
    page.keyboard.press("Enter")
    expect(page.locator("html")).to_have_attribute("data-edition", "gold")
    expect(page.locator("#edition-dialog")).not_to_be_visible()
    signatures = {}
    for edition in ("gold", "street"):
        switch_edition(page, edition)
        page.reload()
        expect(page.locator("html")).to_have_attribute("data-edition", edition)
        expect(page.locator("#edition-dialog")).not_to_be_visible()
        assert_display_fonts_loaded(page)
        page.evaluate("() => document.fonts.ready")
        signatures[edition] = page.locator("h1").first.evaluate(
            "element => ({font:getComputedStyle(element).fontFamily,color:getComputedStyle(element).color,background:getComputedStyle(document.body).backgroundColor})"
        )
        for size in ("desktop", "tablet", "mobile"):
            page.set_viewport_size(VIEWPORTS[size])
            assert_no_overflow(page, f"{portal} {edition} auth {size}")
            page.screenshot(
                animations="disabled", path=str(screenshots / f"{portal}-{edition}-auth-{size}.png")
            )
    assert signatures["gold"] != signatures["street"], (
        "Edition attribute changes without a rendered visual change"
    )
    page.set_viewport_size(VIEWPORTS["desktop"])
    switch_edition(page, "gold")
    # Separate first-time contexts verify both documented default-entry routes.
    for action in ("escape", "skip"):
        context = browser.new_context(viewport=VIEWPORTS["desktop"], reduced_motion="reduce")
        temporary = context.new_page()
        temporary.goto(url)
        expect(temporary.locator("#edition-dialog")).to_be_visible()
        expect(temporary.locator("html")).to_have_attribute("data-motion", "reduced")
        if action == "escape":
            temporary.keyboard.press("Escape")
        else:
            temporary.locator("[data-edition-skip]").click()
        expect(temporary.locator("#edition-dialog")).not_to_be_visible()
        expect(temporary.locator("html")).to_have_attribute("data-edition", "gold")
        assert_safe_storage(temporary)
        assert temporary.locator("#edition-cursor").count() == 0
        assert temporary.locator("[data-reveal]").count() == 0
        temporary.reload()
        expect(temporary.locator("#edition-dialog")).not_to_be_visible()
        context.close()


def exercise_portal_editions(page, url, screenshots, portal):
    screenshots = Path(screenshots)
    admin = portal == "admin"
    nav = "data-admin-view" if admin else "data-view"
    main = "#adm-main" if admin else "#main-content"
    shell = "#adm-shell" if admin else "#app-shell"
    dialog = "#adm-dialog" if admin else "#detail-dialog"
    views = (
        ["overview", "users", "repositories", "scans", "reports", "audit"]
        if admin
        else ["overview", "repositories", "scans", "findings", "reports", "policies", "audit"]
    )
    for edition in ("gold", "street"):
        page.set_viewport_size(VIEWPORTS["desktop"])
        switch_edition(page, edition)
        page.reload()
        try:
            expect(page.locator(shell)).to_be_visible()
        except AssertionError:
            print("RESTORE DIAGNOSTIC", page.locator("body").inner_text()[:1600], flush=True)
            raise
        expect(page.locator("html")).to_have_attribute("data-edition", edition)
        expect(page.locator("#edition-dialog")).not_to_be_visible()
        page.evaluate(
            "() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))"
        )
        sequence = page.locator("html").get_attribute("data-scene-sequence")
        search = "#adm-search" if admin else "#global-search"
        page.locator(search).fill("theme-search-no-match")
        page.locator(search).fill("")
        page.evaluate(
            "() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))"
        )
        assert page.locator("html").get_attribute("data-scene-sequence") == sequence, (
            "Same-view search replays scene entrance"
        )
        refresh = "#adm-refresh" if admin else "#refresh-button"
        endpoint = "/api/v1/admin/overview" if admin else "/api/v1/dashboard"
        with page.expect_response(lambda response: response.url.endswith(endpoint)):
            page.locator(refresh).click()
        page.evaluate(
            "() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))"
        )
        assert page.locator("html").get_attribute("data-scene-sequence") == sequence, (
            "Same-view refresh replays scene entrance"
        )
        for size, viewport in VIEWPORTS.items():
            page.set_viewport_size(viewport)
            for view in views:
                scene = page.locator("html").get_attribute("data-scene")
                sequence = int(page.locator("html").get_attribute("data-scene-sequence") or "0")
                page.locator(f'[{nav}="{view}"]:visible').first.click()
                expect(page.locator(main + " h1")).to_be_visible()
                page.evaluate(
                    "() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))"
                )
                if page.locator("html").get_attribute("data-scene") != scene:
                    assert (
                        int(page.locator("html").get_attribute("data-scene-sequence") or "0")
                        > sequence
                    ), "Navigation failed to enter a new scene"
                assert_no_overflow(page, f"{portal} {edition} {size} {view}")
                assert_resting_layout_and_table_scroll(page, f"{portal} {edition} {size} {view}")
                if view == "overview":
                    page.screenshot(
                        animations="disabled",
                        path=str(screenshots / f"{portal}-{edition}-dashboard-{size}.png"),
                    )
            page.locator(f"[{nav}=reports]:visible").first.click()
            page.locator(main).get_by_role("button", name="View report", exact=True).first.click()
            expect(page.locator(dialog)).to_be_visible()
            assert_no_overflow(page, f"{portal} {edition} {size} report dialog")
            assert_resting_layout_and_table_scroll(page, f"{portal} {edition} {size} report dialog")
            page.screenshot(
                animations="disabled",
                path=str(screenshots / f"{portal}-{edition}-report-{size}.png"),
            )
            page.keyboard.press("Escape")
            expect(page.locator(dialog)).not_to_be_visible()
            form_view = "users" if admin else "repositories"
            page.locator(f'[{nav}="{form_view}"]:visible').first.click()
            form_button = "Manage user" if admin else "Edit project"
            page.locator(main).get_by_role("button", name=form_button, exact=True).first.click()
            expect(page.locator(dialog)).to_be_visible()
            page.keyboard.press("Tab")
            assert page.locator(dialog).evaluate(
                "element => element.contains(document.activeElement)"
            ), "Modal loses keyboard focus"
            assert_no_overflow(page, f"{portal} {edition} {size} edit dialog")
            assert_resting_layout_and_table_scroll(page, f"{portal} {edition} {size} edit dialog")
            page.screenshot(
                animations="disabled", path=str(screenshots / f"{portal}-{edition}-edit-{size}.png")
            )
            page.keyboard.press("Escape")
            expect(page.locator(dialog)).not_to_be_visible()
            assert_safe_storage(page)
    page.emulate_media(reduced_motion="reduce")
    expect(page.locator("html")).to_have_attribute("data-motion", "reduced")
    page.emulate_media(reduced_motion="no-preference")
    page.set_viewport_size(VIEWPORTS["mobile"])
