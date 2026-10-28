"""Known PHP runtime advisory matching, not exploit verification."""

import json

import pytest

from app import scanner
from tests.test_scanner import archive

pytestmark = pytest.mark.unit


def scan(files):
    return scanner.scan_zip(archive(files))


@pytest.mark.parametrize(
    "version,fixed",
    [("8.2.34", "8.2.35"), ("8.3.35", "8.3.36"), ("8.4.26", "8.4.27"), ("8.5.11", "8.5.12")],
)
def test_pinned_affected_runtime_has_both_cves_and_evidence(version, fixed):
    result = scan({"repo/Dockerfile": f"# deployment\nFROM php:{version}-fpm\n"})
    findings = [f for f in result["findings"] if f["scanner"] == "runtime"]
    assert {f["cve"] for f in findings} == {"CVE-2026-109618", "CVE-2026-109619"}
    assert all(f["severity"] == "critical" and f["line"] == 2 for f in findings)
    assert all(f["fixed_version"] == fixed and f["detected_version"] == version for f in findings)
    assert all("deployment" in f["description"].lower() for f in findings)
    assert result["decision"] == "BLOCK"
    assert next(g for g in result["gates"] if g["scanner"] == "runtime")["status"] == "BLOCK"


@pytest.mark.parametrize("version", ["8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.5.13"])
def test_patched_version_only_clears_catalogued_advisories(version):
    result = scan({"Dockerfile": f"FROM php:{version}-apache"})
    assert not [f for f in result["findings"] if f["scanner"] == "runtime"]
    assert result["coverage"]["php_runtime"]["evidence"][0]["status"] == "no_catalog_match"
    assert result["coverage"]["complete"] is False
    assert result["decision"] == "BLOCK"


@pytest.mark.parametrize(
    "tag", ["8.3-fpm", "latest", "8.5.12RC1-fpm", "${PHP_VERSION}-fpm", "8.1.33-fpm"]
)
def test_ambiguous_or_uncatalogued_image_is_unknown_not_safe(tag):
    result = scan({"Dockerfile": f"FROM php:{tag}"})
    evidence = result["coverage"]["php_runtime"]["evidence"]
    assert evidence[0]["status"] == "unknown"
    findings = [f for f in result["findings"] if f["scanner"] == "runtime"]
    assert len(findings) == 1 and findings[0]["severity"] == "informational"
    assert "cve" not in findings[0]
    assert next(g for g in result["gates"] if g["scanner"] == "runtime")["status"] == "UNKNOWN"


def test_composer_requirement_and_virtual_platform_are_not_installed_version():
    result = scan(
        {
            "composer.json": json.dumps(
                {"require": {"php": ">=8.2"}, "config": {"platform": {"php": "8.3.35"}}}
            )
        }
    )
    assert "PHP" in result["technologies"]
    assert all(e["status"] == "unknown" for e in result["coverage"]["php_runtime"]["evidence"])
    assert not any(f.get("cve") for f in result["findings"])


def test_compose_official_image_and_php_version_file():
    result = scan(
        {
            "compose.yaml": 'services:\n  app:\n    image: "docker.io/library/php:8.3.35-fpm"\n',
            ".php-version": "8.4.26\n",
        }
    )
    findings = [f for f in result["findings"] if f.get("cve")]
    assert len(findings) == 4
    assert {f["path"] for f in findings} == {"compose.yaml", ".php-version"}


@pytest.mark.security
def test_comments_custom_images_and_shell_commands_are_not_trusted_runtime_evidence():
    result = scan(
        {
            "Dockerfile": "# FROM php:8.3.35\nFROM evil.test/php:8.3.35\nRUN echo php:8.3.35\n",
            "README.md": "FROM php:8.3.35",
        }
    )
    assert not any(f.get("cve") for f in result["findings"])


@pytest.mark.security
def test_dynamic_docker_args_are_never_executed(tmp_path):
    marker = tmp_path / "executed"
    result = scan(
        {"Dockerfile": f"ARG PHP_VERSION=$(touch {marker})\nFROM php:${{PHP_VERSION}}-fpm"}
    )
    assert not marker.exists()
    assert result["coverage"]["php_runtime"]["evidence"][0]["status"] == "unknown"
    assert "touch" not in str(result["coverage"]["php_runtime"])


def test_php_source_without_version_and_malformed_composer_are_visible_unknowns():
    result = scan({"index.php": "<?php echo 1;", "composer.json": "{broken"})
    assert "PHP" in result["technologies"]
    assert result["coverage"]["php_runtime"]["evidence"]
    assert all(e["status"] == "unknown" for e in result["coverage"]["php_runtime"]["evidence"])


@pytest.mark.security
def test_runtime_evidence_is_bounded():
    result = scan({"Dockerfile": "FROM php:8.3.36-fpm\n" * 2001})
    assert result["status"] == "failed"
    assert result["decision"] == "BLOCK"


def test_unknown_runtime_gate_cannot_be_allowed_by_policy():
    assert (
        scanner.evaluate_policy([], [{"status": "UNKNOWN"}], {"scanner_failure": "ALLOW"})[
            "decision"
        ]
        == "BLOCK"
    )


@pytest.mark.security
@pytest.mark.parametrize(
    "header", ["script: |", "script: >-", "script: |2 # literal", "- script: |+"]
)
def test_yaml_block_scalar_script_is_not_deployment_evidence(header):
    result = scan({"ci.yml": header + "\n  image: php:8.3.35-fpm\n"})
    assert not any(f.get("cve") for f in result["findings"])


def test_yaml_image_after_script_block_is_still_detected():
    result = scan({"compose.yml": "command: |\n  echo hello\nimage: php:8.3.35-fpm\n"})
    assert len([f for f in result["findings"] if f.get("cve")]) == 2


def test_unknown_runtime_gate_preserves_unknown_under_warning_policy():
    result = scanner.scan_zip(
        archive({"Dockerfile": "FROM php:8.3-fpm"}), policy={"informational": "WARN"}
    )
    assert next(g for g in result["gates"] if g["scanner"] == "runtime")["status"] == "UNKNOWN"
