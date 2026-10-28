"""Behavior tests for bounded JS/HTML review heuristics, not exploit proofs."""

import pytest

from app import scanner
from tests.test_scanner import archive

pytestmark = pytest.mark.unit


def scan(source, path="index.html"):
    return scanner.scan_zip(archive({path: source}))


def test_inline_access_decision_and_dynamic_html_are_reported_with_lines():
    source = """<html><script>
const allowed = !secure || viewer.id === target.id || viewer.role === 'admin';
document.getElementById('profile').innerHTML = allowed ? rows.map(x => `<b>${x.name}</b>`).join('') : '';
</script></html>"""
    result = scan(source)
    findings = result["findings"]
    assert {f["rule_id"] for f in findings} == {"JS-CLIENT-AUTH", "JS-DYNAMIC-HTML"}
    assert {f["line"] for f in findings} == {2, 3}
    assert all(f["scanner"] == "sast" and f["confidence"] == "low" for f in findings)
    assert all("review" in f["description"].lower() for f in findings)
    assert next(g for g in result["gates"] if g["scanner"] == "sast")["status"] == "WARN"
    assert "JavaScript/TypeScript" in result["technologies"]


def test_standalone_js_and_multiline_sink():
    result = scan(
        "const canAccess = current.role === 'admin';\nel.innerHTML\n = userInput;", "app.js"
    )
    assert {f["rule_id"] for f in result["findings"]} == {"JS-CLIENT-AUTH", "JS-DYNAMIC-HTML"}


@pytest.mark.parametrize(
    "source",
    [
        "el.textContent = userInput;",
        "el.innerHTML = '<b>Static title</b>';",
        "el.innerHTML = `<b>Static title</b>`;",
        "// el.innerHTML = input;\n/* const allowed = viewer.role; */",
        'const example = "el.innerHTML = input; const allowed = viewer.role;";',
    ],
)
def test_safe_static_comments_and_documentation_strings_not_reported(source):
    assert scan(source, "app.js")["findings"] == []


def test_html_prose_and_non_executable_json_scripts_not_javascript():
    source = """<pre>el.innerHTML = input;</pre><script type="application/ld+json">{"example":"el.innerHTML = input;"}</script>"""
    assert scan(source)["findings"] == []


def test_template_interpolation_and_concatenation_remain_review_findings():
    result = scan(
        "a.innerHTML = `<b>${user.name}</b>`;\nb.innerHTML = '<p>' + value + '</p>';", "app.ts"
    )
    assert len(result["findings"]) == 2
    assert all(f["cwe"] == "CWE-79" for f in result["findings"])


@pytest.mark.security
def test_source_is_never_executed_and_payload_not_echoed(tmp_path):
    marker = tmp_path / "ran"
    source = f"require('fs').writeFileSync('{marker}', 'x');\nel.innerHTML = '<img onerror=payload>' + input;"
    result = scan(source, "evil.js")
    assert not marker.exists()
    assert "onerror=payload" not in str(result)
    assert result["decision"] == "BLOCK"


def test_unclosed_inline_script_does_not_silently_pass():
    result = scan("<script>el.innerHTML = input;")
    assert result["findings"]
    assert result["coverage"]["analysis_errors"]
    assert next(g for g in result["gates"] if g["scanner"] == "sast")["status"] == "FAILED"


def test_plain_server_permission_check_not_labelled_browser_authorization():
    result = scan(
        "const allowed = req.user.role === 'admin';\nif (!allowed) res.sendStatus(403);",
        "server.js",
    )
    assert not result["findings"]


@pytest.mark.security
def test_inline_script_count_is_bounded_and_fails_closed():
    result = scan("<script>el.innerHTML = input;</script>" * 2001)
    assert result["coverage"]["analysis_errors"]
    assert next(g for g in result["gates"] if g["scanner"] == "sast")["status"] == "FAILED"


@pytest.mark.security
def test_unterminated_escaped_string_reports_incomplete_instead_of_passing():
    result = scan("'" + "\\'a" * 2000, "malformed.js")
    assert result["coverage"]["analysis_errors"]
    assert next(g for g in result["gates"] if g["scanner"] == "sast")["status"] == "FAILED"


@pytest.mark.parametrize(
    "start", ["<script/>", '<script type="text/javascript" type="application/json">']
)
def test_html_executable_script_semantics(start):
    result = scan(start + "el.innerHTML = input;</script>")
    assert any(f.get("rule_id") == "JS-DYNAMIC-HTML" for f in result["findings"])
