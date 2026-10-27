"""Bounded, non-executing repository analysis.

These rules are a baseline heuristic engine, not Semgrep/Gitleaks or a complete
vulnerability assessment. Archives are inspected in memory, never extracted or run.
"""

from __future__ import annotations

import ast
import hashlib
import io
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 5000
MAX_FINDINGS = 2000
DEFAULT_POLICY = {
    "critical": "BLOCK",
    "high": "BLOCK",
    "medium": "WARN",
    "low": "ALLOW",
    "informational": "ALLOW",
    "scanner_failure": "BLOCK",
}
BASELINE = "Sentinelx baseline heuristics v1"
SCANNERS = ("secrets", "sast", "iac")


def validate_repository(url: str) -> dict:
    """Accept only canonical GitHub HTTPS repositories, never arbitrary hosts."""
    if not isinstance(url, str) or len(url) > 512:
        raise ValueError("A GitHub HTTPS repository URL is required")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid repository URL") from None
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Use https://github.com/owner/repository without credentials or query parameters"
        )
    parts = parsed.path.rstrip("/").split("/")
    if len(parts) != 3 or parts[0] != "":
        raise ValueError("Repository URL must contain exactly owner/repository")
    owner, name = parts[1:]
    if name.endswith(".git"):
        name = name[:-4]
    if (
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", owner)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name)
        or name in (".", "..")
    ):
        raise ValueError("Invalid GitHub owner or repository name")
    return {"owner": owner, "name": name, "url": f"https://github.com/{owner}/{name}"}


def validate_repository_url(url: str) -> str:
    return validate_repository(url)["url"]


def validate_branch(branch: str) -> str:
    if (
        not isinstance(branch, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", branch)
        or any(part in branch for part in ("..", "//", "@{", "\\"))
        or branch.endswith(("/", ".", ".lock"))
        or any(p.startswith(".") for p in branch.split("/"))
    ):
        raise ValueError("Invalid Git branch name")
    return branch


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Unexpected GitHub archive redirect")


def _download_archive(repository: dict, branch: str) -> bytes:
    # Fixed destination and scheme. No user supplied URL is ever fetched directly.
    url = f"https://codeload.github.com/{repository['owner']}/{repository['name']}/zip/refs/heads/{urllib.parse.quote(branch, safe='')}"
    request = urllib.request.Request(
        url, headers={"User-Agent": "Sentinelx/0.1", "Accept": "application/zip"}
    )
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(request, timeout=30) as response:
        length = response.headers.get("Content-Length")
        if length and int(length) > MAX_ARCHIVE_BYTES:
            raise ValueError("Repository archive exceeds 20 MiB compressed size limit")
        chunks, total = [], 0
        started = time.monotonic()
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES or time.monotonic() - started > 90:
                raise ValueError("Repository download exceeded size or time limit")
            chunks.append(chunk)
    return b"".join(chunks)


def _finding(title, severity, scanner, path, line, description, remediation, cwe=None):
    fingerprint = hashlib.sha256(f"{title}:{path}:{line}".encode()).hexdigest()
    return {
        "id": fingerprint[:24],
        "fingerprint": fingerprint,
        "title": title,
        "severity": severity,
        "scanner": scanner,
        "category": scanner,
        "path": path,
        "line": line,
        "description": description,
        "remediation": remediation,
        "cwe": cwe,
        "status": "open",
    }


SECRET_PATTERNS = [
    (
        "Private key material",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    ("Potential AWS access key", "high", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "Potential GitHub access token",
        "high",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b"),
    ),
    (
        "Potential hardcoded credential",
        "high",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|secret[_-]?key|password|client[_-]?secret)\s*[:=]\s*["']([^"'\r\n]{12,200})["']"""
        ),
    ),
]


def _scan_secrets(path: str, text: str) -> list:
    findings = []
    for title, severity, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            if match.lastindex:
                candidate = match.group(1).lower()
                if any(
                    p in candidate
                    for p in (
                        "example",
                        "placeholder",
                        "changeme",
                        "your_",
                        "${",
                        "os.environ",
                        "process.env",
                    )
                ):
                    continue
            findings.append(
                _finding(
                    title,
                    severity,
                    "secrets",
                    path,
                    text.count("\n", 0, match.start()) + 1,
                    "Credential-like material detected. Evidence is deliberately omitted to prevent disclosure.",
                    "Verify the credential, revoke and rotate it if real, remove it from source and history, and use a secret manager.",
                    "CWE-798",
                )
            )
    return findings


def _scan_python(path: str, text: str) -> list:
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError, RecursionError):
        raise ValueError("Python file could not be parsed by the installed interpreter") from None
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    def name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return name(node.value) + "." + node.attr
        return ""

    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = name(node.func)
        details = None
        if called in ("eval", "exec", "builtins.eval", "builtins.exec"):
            details = (
                "Dynamic code execution",
                "high",
                "Use of eval/exec can execute attacker-controlled code; review input provenance.",
                "Replace dynamic execution with explicit parsing and an allowlisted operation map.",
                "CWE-95",
            )
        elif called in ("pickle.load", "pickle.loads", "dill.load", "dill.loads"):
            details = (
                "Unsafe deserialization",
                "high",
                "Deserializing untrusted pickle data can execute arbitrary code.",
                "Use a data-only format and validate its schema; never unpickle untrusted data.",
                "CWE-502",
            )
        elif called == "os.system" or (
            called.startswith("subprocess.")
            and any(
                k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                for k in node.keywords
            )
        ):
            details = (
                "Shell command execution requires review",
                "high",
                "Shell execution may permit command injection if arguments include untrusted data.",
                "Use subprocess with an argument list and shell=False, and validate arguments.",
                "CWE-78",
            )
        elif called in ("hashlib.md5", "hashlib.sha1"):
            details = (
                "Weak cryptographic hash",
                "medium",
                "MD5/SHA-1 are unsuitable for security-sensitive hashing; intended use needs review.",
                "Use SHA-256 for integrity or Argon2/scrypt for passwords.",
                "CWE-327",
            )
        elif called == "yaml.load" and not any(
            k.arg == "Loader" and name(k.value).endswith(("SafeLoader", "CSafeLoader"))
            for k in node.keywords
        ):
            details = (
                "Potentially unsafe YAML loading",
                "high",
                "YAML loading without an explicit safe loader may permit object construction.",
                "Use yaml.safe_load for untrusted YAML input.",
                "CWE-502",
            )
        elif any(
            k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False
            for k in node.keywords
        ):
            details = (
                "TLS certificate verification disabled",
                "high",
                "The call disables TLS certificate verification.",
                "Enable verification and configure a trusted CA bundle.",
                "CWE-295",
            )
        if details:
            title, severity, description, remediation, cwe = details
            findings.append(
                _finding(title, severity, "sast", path, node.lineno, description, remediation, cwe)
            )
    return findings


def _scan_iac(path, text):
    checks = []
    lower = path.lower()
    if lower.endswith((".tf", ".yaml", ".yml", ".json")):
        checks = [
            (
                r"(?:0\.0\.0\.0/0|::/0)",
                "Public network access requires review",
                "medium",
                "A rule may expose infrastructure to all networks.",
                "Restrict ingress to necessary networks and ports.",
                "CWE-284",
            ),
            (
                r"(?im)\bprivileged\s*:\s*true\b",
                "Privileged container configuration",
                "high",
                "Privileged containers can gain broad host access.",
                "Disable privileged mode and grant only necessary capabilities.",
                "CWE-250",
            ),
            (
                r"(?im)\brunAsUser\s*:\s*0\b",
                "Container explicitly runs as root",
                "medium",
                "Root workloads increase impact of compromise.",
                "Run the workload as a non-root user.",
                "CWE-250",
            ),
        ]
    if PurePosixPath(path).name.lower().startswith("dockerfile"):
        checks += [
            (
                r"(?im)^\s*USER\s+(?:root|0)\s*$",
                "Docker image runs as root",
                "medium",
                "The image explicitly selects the root user.",
                "Create and select a non-root runtime user.",
                "CWE-250",
            )
        ]
    result = []
    for pattern, title, severity, desc, remediation, cwe in checks:
        for match in re.finditer(pattern, text):
            result.append(
                _finding(
                    title,
                    severity,
                    "iac",
                    path,
                    text.count("\n", 0, match.start()) + 1,
                    desc,
                    remediation,
                    cwe,
                )
            )
    return result


def evaluate_policy(findings: list, gates: list, policy: dict | None = None) -> dict:
    selected = {**DEFAULT_POLICY, **(policy or {})}
    if "info" in selected:
        selected["informational"] = selected["info"]
    decision, reasons = "PASS", []
    risk = min(
        100,
        sum(
            {"critical": 35, "high": 20, "medium": 8, "low": 2}.get(f["severity"].lower(), 0)
            for f in findings
        ),
    )
    for finding in findings:
        action = selected.get(finding["severity"].lower(), "BLOCK")
        if action not in ("ALLOW", "PASS", "WARN", "BLOCK"):
            action = "BLOCK"
        if action == "BLOCK":
            decision = "BLOCK"
        elif action == "WARN" and decision != "BLOCK":
            decision = "WARN"
        if action in ("BLOCK", "WARN"):
            reason = f"{finding['severity'].upper()} finding: {finding['title']}"
            if reason not in reasons:
                reasons.append(reason)
    if any(g["status"] in ("FAILED", "NOT_CONFIGURED") for g in gates):
        # Execution failures always fail closed regardless of configurable severity rules.
        decision = "BLOCK"
        reasons.append("A required scanner failed, is not configured, or coverage was truncated")
    return {"risk_score": risk, "decision": decision, "reasons": reasons}


def _archive_files(data: bytes) -> list[tuple[str, bytes]]:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("Archive exceeds 20 MiB compressed size limit")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError("Archive exceeds 5000 entry limit")
        total = 0
        paths = set()
        files = []
        for info in infos:
            # Validate original ZIP names before platform normalization or NUL truncation.
            raw_name = info.orig_filename
            if "\\" in raw_name or "\x00" in raw_name:
                raise ValueError("Unsafe archive path")
            path = PurePosixPath(info.filename)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in info.filename
                or "\x00" in info.filename
                or re.match(r"^[A-Za-z]:", info.filename)
            ):
                raise ValueError("Unsafe archive path")
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError("Symlinks are not supported in uploaded repositories")
            if info.flag_bits & 1:
                raise ValueError("Encrypted archives are not supported")
            normalized = str(path)
            if normalized in paths:
                raise ValueError("Duplicate archive path")
            paths.add(normalized)
            if info.is_dir():
                continue
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("Archive exceeds 50 MiB expanded size limit")
            if info.file_size > MAX_FILE_BYTES:
                raise ValueError("Archive contains file larger than 1 MiB scan limit")
            if info.file_size > 1024 * 1024 and info.file_size > max(1, info.compress_size) * 200:
                raise ValueError("Suspicious archive compression ratio")
            # Reading by ZipInfo validates CRC and keeps memory bounded by preflight limits.
            files.append((normalized, archive.read(info)))
        if not files:
            raise ValueError("Repository archive contains no files")
        return files


def _scan_archive(data: bytes, policy: dict | None = None) -> dict:
    start = time.monotonic()
    files = _archive_files(data)
    findings, technologies, binary_count, text_count = [], set(), 0, 0
    analysis_errors = []
    for path, content in files:
        if "\x00" in content.decode("latin1"):
            binary_count += 1
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            binary_count += 1
            continue
        text_count += 1
        findings.extend(_scan_secrets(path, text))
        if path.endswith(".py"):
            technologies.add("Python")
            try:
                findings.extend(_scan_python(path, text))
            except ValueError:
                analysis_errors.append(
                    {"path": path, "reason": "Python parsing failed; SAST coverage incomplete"}
                )
        if path.endswith((".js", ".jsx", ".ts", ".tsx")) or path.endswith("package.json"):
            technologies.add("JavaScript/TypeScript")
        if path.endswith("go.mod"):
            technologies.add("Go")
        if path.endswith("Cargo.toml"):
            technologies.add("Rust")
        if path.endswith("pom.xml"):
            technologies.add("Java")
        if path.endswith(".tf"):
            technologies.add("Terraform")
        if PurePosixPath(path).name.lower().startswith("dockerfile"):
            technologies.add("Docker")
        findings.extend(_scan_iac(path, text))
        if len(findings) > MAX_FINDINGS:
            raise ValueError(
                "Findings exceed 2000 result limit; split the repository into smaller scans"
            )
    if not text_count:
        raise ValueError("Archive contains no supported UTF-8 text files")
    elapsed = round((time.monotonic() - start) * 1000)
    gates = [
        {
            "scanner": scanner,
            "name": scanner,
            "tool": BASELINE,
            "status": "PASS" if not any(f["scanner"] == scanner for f in findings) else "WARN",
            "findings": sum(f["scanner"] == scanner for f in findings),
            "duration_ms": elapsed,
            "coverage": "heuristic",
        }
        for scanner in SCANNERS
    ]
    for gate in gates:
        subset = [f for f in findings if f["scanner"] == gate["scanner"]]
        gate["status"] = evaluate_policy(subset, [], policy)["decision"]
        if gate["scanner"] == "sast" and analysis_errors:
            gate["status"] = "FAILED"
    for scanner, tool in (
        ("sca", "Dependency vulnerability engine"),
        ("container", "Container image scanner"),
        ("dast", "Dynamic application scanner"),
    ):
        gates.append(
            {
                "scanner": scanner,
                "name": scanner,
                "tool": tool,
                "status": "NOT_CONFIGURED",
                "findings": 0,
                "duration_ms": 0,
                "coverage": "none",
            }
        )
    coverage = {
        "level": "baseline",
        "complete": False,
        "files_analyzed": text_count,
        "binary_files_skipped": binary_count,
        "engines": list(SCANNERS),
        "analysis_errors": analysis_errors,
        "limitations": [
            "Heuristic secret patterns; not a comprehensive secrets audit.",
            "SAST rules cover selected Python calls only, without data-flow analysis.",
            "IaC and Docker checks use a small set of configuration patterns.",
            "Dependency CVEs, container images, live applications and CI execution are not scanned.",
            "No untrusted repository code or build hooks are executed.",
        ],
    }
    return {
        "status": "completed",
        "commit": None,
        "findings": findings,
        "gates": gates,
        "technologies": sorted(technologies),
        "coverage": coverage,
        **evaluate_policy(findings, gates, policy),
    }


def _failed(message: str) -> dict:
    return {
        "status": "failed",
        "commit": None,
        "error": message,
        "findings": [],
        "gates": [
            {
                "scanner": "checkout",
                "name": "checkout",
                "tool": BASELINE,
                "status": "FAILED",
                "findings": 0,
            }
        ],
        "technologies": [],
        "risk_score": 0,
        "decision": "BLOCK",
        "reasons": [message],
        "coverage": {"level": "none", "complete": False, "limitations": [message]},
    }


def scan_zip(archive: bytes | str | Path, policy: dict | None = None) -> dict:
    try:
        if isinstance(archive, (str, Path)):
            path = Path(archive)
            if path.stat().st_size > MAX_ARCHIVE_BYTES:
                return _failed("Archive exceeds 20 MiB compressed size limit")
            archive = path.read_bytes()
        result = _scan_archive(archive, policy)
        return {"source": "zip", **result}
    except ValueError as exc:
        return {"source": "zip", **_failed("Archive scan failed: " + str(exc)[:200])}
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError, RecursionError):
        return {
            "source": "zip",
            **_failed("Archive scan failed: invalid, unsupported, or unreadable ZIP archive"),
        }


def scan_repository(repository_url: str, branch: str = "main", policy: dict | None = None) -> dict:
    repository = validate_repository(repository_url)
    validate_branch(branch)
    try:
        archive = _download_archive(repository, branch)
        result = _scan_archive(archive, policy)
        return {"source": "github", "repository_url": repository["url"], "branch": branch, **result}
    except urllib.error.HTTPError as exc:
        return _failed(
            f"GitHub archive request failed (HTTP {exc.code}); verify public repository and branch access"
        )
    except (urllib.error.URLError, TimeoutError, OSError):
        return _failed("GitHub archive download failed; check network access and retry")
    except ValueError as exc:
        return _failed("Repository scan failed: " + str(exc)[:200])
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, RecursionError):
        return _failed("Repository scan failed: invalid or unsupported archive")


scan_github = scan_repository
