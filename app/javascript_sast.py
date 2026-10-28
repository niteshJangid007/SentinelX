"""Bounded JS/inline-HTML review patterns. No parsing, execution or exploit claims."""

import bisect
from html.parser import HTMLParser
import re

LIMITATION = (
    "JavaScript/TypeScript and executable inline HTML scripts receive limited pattern checks "
    "for client-side permission decisions and dynamic HTML writes. No JS AST, taint analysis, "
    "backend authorization verification or exploit confirmation is performed. Findings require review."
)
SINK = re.compile(r"\.(?:innerHTML|outerHTML)\s*=(?!=)")
DECISION = re.compile(
    r"\b(?:const|let|var)\s+(?:allowed|authorized|permitted|canAccess|canView|isAdmin|isOwner)\s*=\s*([^;\n]{1,1000})",
    re.I,
)
IDENTITY = re.compile(r"\.(?:role|permissions?|owner_?id|user_?id)\b|\.id\s*={2,3}\s*\w+\.id", re.I)
LITERAL = re.compile(
    r"\s*(?:'(?:\\[\s\S]|[^'\\])*'|\"(?:\\[\s\S]|[^\"\\])*\"|`(?:\\[\s\S]|[^`\\])*`)\s*(?:;|$)"
)


def _mask(source):
    """Single forward pass: malformed quotes must not cause regex restart attacks."""
    output = list(source)
    index, incomplete = 0, False
    while index < len(source):
        start = index
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = len(source) if end < 0 else end
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            incomplete |= end < 0
            index = len(source) if end < 0 else end + 2
        elif source[index] in ("'", '"', "`"):
            quote = source[index]
            index += 1
            closed = False
            while index < len(source):
                if source[index] == "\\":
                    index = min(index + 2, len(source))
                elif source[index] == quote:
                    index += 1
                    closed = True
                    break
                else:
                    index += 1
            incomplete |= not closed
        else:
            index += 1
            continue
        for position in range(start, index):
            if source[position] != "\n":
                output[position] = " "
    return "".join(output), incomplete


class InlineScripts(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]
        self.open_script = None
        self.chunks = []
        self.incomplete = False

    def source_offset(self):
        line, column = self.getpos()
        return self.starts[line - 1] + column

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        attributes = dict(reversed(attrs))
        kind = (attributes.get("type") or "").strip().lower()
        executable = (
            kind
            in (
                "",
                "module",
                "text/javascript",
                "application/javascript",
                "text/ecmascript",
                "application/ecmascript",
            )
            and "src" not in attributes
        )
        self.open_script = (self.source_offset() + len(self.get_starttag_text()), executable)

    def handle_startendtag(self, tag, attrs):
        if tag == "script":
            # In HTML a slash does not close the non-void script element.
            self.handle_starttag(tag, attrs)
            self.set_cdata_mode(tag)

    def handle_endtag(self, tag):
        if tag == "script" and self.open_script is not None:
            start, executable = self.open_script
            if executable:
                self.append(start, self.source_offset())
            self.open_script = None

    def append(self, start, end):
        if len(self.chunks) >= 2000:
            raise ValueError("Inline script limit exceeded")
        self.chunks.append((self.text[start:end], bisect.bisect_right(self.starts, start) - 1))

    def finish(self):
        self.feed(self.text)
        self.close()
        if self.open_script and self.open_script[1]:
            self.append(self.open_script[0], len(self.text))
            self.incomplete = True
        return self.chunks, self.incomplete


def scan(path, text, finding_factory):
    html = path.lower().endswith((".html", ".htm"))
    chunks, incomplete = InlineScripts(text).finish() if html else ([(text, 0)], False)
    findings = []
    seen = set()
    for code, base_line in chunks:
        masked, lexical_incomplete = _mask(code)
        incomplete |= lexical_incomplete
        browser_context = (
            html
            or SINK.search(masked)
            or re.search(r"\b(?:document|window|localStorage|sessionStorage)\b", masked)
        )
        newlines = [m.start() for m in re.finditer("\n", code)]
        matches = [(m, "JS-DYNAMIC-HTML") for m in SINK.finditer(masked)]
        matches.extend(
            (m, "JS-CLIENT-AUTH")
            for m in DECISION.finditer(masked)
            if IDENTITY.search(m[1]) and browser_context
        )
        for match, rule in matches:
            if rule == "JS-DYNAMIC-HTML":
                literal = LITERAL.match(code, match.end())
                if literal and "${" not in literal[0]:
                    continue
                title, cwe = "Dynamic HTML write requires injection review", "CWE-79"
                description = (
                    "A dynamic expression is assigned to innerHTML/outerHTML. Review whether any "
                    "value can be controlled by an attacker and whether it is sanitized. This is "
                    "a low-confidence sink detection, not confirmed XSS; hardcoded data or a "
                    "correct sanitizer may make the write safe."
                )
                remediation = "Prefer DOM creation and textContent. If HTML is necessary, use a reviewed sanitizer and verify source-to-sink data flow; never trust raw user input."
            else:
                title, cwe = (
                    "Client-side permission decision requires server-side verification",
                    "CWE-602",
                )
                description = (
                    "Browser code computes a permission-like decision using identity or role "
                    "fields. Review the backend: client-side state can be changed and must not "
                    "be the authorization boundary. This low-confidence pattern may be harmless "
                    "presentation logic or an intentional simulation; it does not prove missing "
                    "server authorization or an exploitable access-control bypass."
                )
                remediation = "Derive identity from a trusted server session and enforce ownership/permissions on every backend request. Do not ship unauthorized private records to the browser. Test horizontal and vertical access with separate accounts."
            line = base_line + bisect.bisect_left(newlines, match.start()) + 1
            finding = finding_factory(
                title, "medium", "sast", path, line, description, remediation, cwe
            )
            finding.update(rule_id=rule, confidence="low", assessment="review_required")
            # Existing finding keys are line-based: emit one finding per rule/line.
            if finding["fingerprint"] not in seen:
                findings.append(finding)
                seen.add(finding["fingerprint"])
            if len(findings) > 2000:
                raise ValueError("JavaScript finding limit exceeded")
    return findings, bool(chunks), incomplete
