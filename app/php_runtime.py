"""Offline PHP runtime advisory matching from declarations, never source execution.

This deliberately small, reviewed catalog is not general SCA or container scanning.
Untrusted repository input cannot change advisories or trigger network requests.
"""

import json
import re
import shlex
from pathlib import PurePosixPath

CATALOG_DATE = "2026-10-28"
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
ADVISORIES = (
    ("CVE-2026-109618", "GHSA-w8hw-w9fx-j79w", "Out-of-memory cleanup corruption", "CWE-908"),
    ("CVE-2026-109619", "GHSA-6wmf-4rv5-p3rp", "Cross-request use-after-free", "CWE-416"),
)
LIMITATION = (
    "PHP runtime checks match source declarations against only CVE-2026-109618 and "
    "CVE-2026-109619 (catalog reviewed 2026-10-28). No installed runtime, image digest, "
    "server configuration or exploitability is verified. No catalog match does not mean safe."
)
# Only known official image names. Custom registries and package names are not proof.
IMAGE = re.compile(r"^(?:docker\.io/)?(?:library/)?php(?::([^@]+))?(?:@sha256:[a-fA-F0-9]{64})?$")
VERSION = re.compile(
    r"^(8)\.(\d{1,2})\.(\d{1,5})(?:-(?:fpm|apache|cli|zts|alpine|bookworm|bullseye|trixie)(?:[A-Za-z0-9_.-]*))?$"
)


def _append(evidence, item):
    if len(evidence) >= 2000:
        raise ValueError("PHP runtime evidence exceeds 2000 result limit")
    evidence.append(item)


def _evidence(path, line, kind, value=None):
    match = VERSION.fullmatch(value or "")
    version = tuple(map(int, match.groups())) if match else None
    known = version and version[:2] in FIXED
    return {
        "path": path,
        "line": line,
        "kind": kind,
        "detected_version": ".".join(map(str, version)) if version else None,
        "status": ("affected" if version < FIXED[version[:2]] else "no_catalog_match")
        if known
        else "unknown",
        "confidence": "medium",
        "basis": "Repository declaration; deployed runtime and configuration unverified.",
    }


def inspect_file(path, text):
    """Return bounded metadata only; never persist raw configuration or image credentials."""
    name = PurePosixPath(path).name.lower()
    evidence = []
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        for number, line in enumerate(text.splitlines(), 1):
            if not re.match(r"^\s*FROM\s", line, re.I):
                continue
            try:
                parts = shlex.split(line, comments=True)
            except ValueError:
                continue
            parts = parts[1:]
            while parts and parts[0].startswith("--"):
                parts.pop(0)
            if parts and (match := IMAGE.fullmatch(parts[0])):
                _append(evidence, _evidence(path, number, "docker_base_image", match[1]))
    elif name.endswith((".yml", ".yaml")):
        # A conservative scalar subset, not a YAML interpreter. Dynamic/complex values
        # remain unknown; anchors/templates are not expanded or evaluated.
        scalar_indent = None
        for number, line in enumerate(text.splitlines(), 1):
            indent = len(line) - len(line.lstrip(" "))
            if scalar_indent is not None:
                if not line.strip() or indent > scalar_indent:
                    continue
                scalar_indent = None
            if re.search(r"(?:^|:\s*|^-\s+)[|>][1-9+-]{0,2}\s*(?:#.*)?$", line.strip()):
                scalar_indent = indent
                continue
            match = re.match(r"^\s*(?:-\s+)?image\s*:\s*(.*?)\s*$", line)
            if not match:
                continue
            try:
                parts = shlex.split(match[1], comments=True)
            except ValueError:
                continue
            if len(parts) == 1 and (image := IMAGE.fullmatch(parts[0])):
                _append(evidence, _evidence(path, number, "deployment_image", image[1]))
    elif name == ".php-version":
        _append(evidence, _evidence(path, 1, "runtime_version_file", text.strip()))
    elif name == "composer.json":
        # Composer require.php and config.platform.php are constraints/emulated
        # platform values. Even an exact value is not an installed PHP version.
        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError("Expected object")
        except (ValueError, RecursionError):
            _append(evidence, _evidence(path, 1, "unreadable_composer_manifest"))
        else:
            _append(evidence, _evidence(path, 1, "composer_requirement_not_runtime"))
    return evidence


def assess(evidence, finding_factory):
    findings = []
    for item in evidence:
        path, line = item["path"], item["line"]
        version = item["detected_version"]
        if item["status"] == "unknown":
            finding = finding_factory(
                "PHP deployed runtime version unknown",
                "informational",
                "runtime",
                path,
                line,
                "PHP usage was detected, but this evidence cannot establish a catalogued runtime "
                "version. Composer requirements and virtual platform values are not installed "
                "versions. Unsupported branches, floating tags and dynamic values require review. "
                "Confidence: medium for PHP usage; deployment exposure is unverified.",
                "Collect the actual deployed PHP version through authenticated inventory, then "
                "compare it with current PHP security advisories. Pin a supported patched runtime "
                "and rebuild/redeploy. Do not interpret unknown as safe.",
            )
            finding.update(confidence="medium", runtime_status="unknown")
            findings.append(finding)
        elif item["status"] == "affected":
            fixed = ".".join(map(str, FIXED[tuple(map(int, version.split(".")[:2]))]))
            for cve, ghsa, title, cwe in ADVISORIES:
                url = "https://github.com/php/php-src/security/advisories/" + ghsa
                finding = finding_factory(
                    f"{cve}: PHP {title}",
                    "critical",
                    "runtime",
                    path,
                    line,
                    f"Declared PHP {version} matches the affected range for {cve}. "
                    "Confidence: medium; this is source-declared version evidence, not confirmation "
                    "of deployment runtime or exploitability. Exposure depends on server, "
                    f"application and worker configuration. Advisory: {url}",
                    f"Upgrade this branch to PHP {fixed} or a later supported patched release. "
                    "Rebuild/redeploy and restart every PHP worker. Verify the actual running "
                    f"version and follow both linked PHP advisories. Source: {url}",
                    cwe,
                )
                finding.update(
                    cve=cve,
                    detected_version=version,
                    fixed_version=fixed,
                    confidence="medium",
                    runtime_status="affected",
                    references=[url],
                    catalog_reviewed_at=CATALOG_DATE,
                )
                findings.append(finding)
    return findings
