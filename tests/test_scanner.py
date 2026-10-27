import io
import stat
import zipfile

import pytest

pytestmark = pytest.mark.unit


from app import scanner


def archive(files):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as z:
        for path, value in files.items():
            info = zipfile.ZipInfo()
            info.filename = path  # Preserve raw attack paths on Windows too.
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, value)
    return data.getvalue()


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo",
        "https://github.com.evil.test/a/b",
        "https://github.com@127.0.0.1/a/b",
        "https://user:password@github.com/a/b",
        "https://github.com:443/a/b",
        "https://github.com/a/b?redirect=evil",
        "https://github.com/a/../b",
        "https://github.com/a/%2e%2e",
        "https://127.0.0.1/a/b",
        "file:///etc/passwd",
        "https://github.com/a/b/tree/main",
    ],
)
def test_repository_url_rejects_unsafe(url):
    with pytest.raises(ValueError):
        scanner.validate_repository_url(url)


def test_url_normalization():
    assert (
        scanner.validate_repository_url("https://github.com/owner/repository.git/")
        == "https://github.com/owner/repository"
    )


@pytest.mark.parametrize(
    "branch",
    [
        "../main",
        "main..bad",
        "-option",
        "main?foo",
        "feature//x",
        "feature/.hidden",
        "foo.lock",
        "main\n",
    ],
)
def test_branch_rejects_unsafe(branch):
    with pytest.raises(ValueError):
        scanner.validate_branch(branch)


def test_real_findings_and_redaction():
    token = "ghp_" + "X" * 36
    source = f'token = "{token}"\nimport pickle\npickle.loads(payload)\n'
    result = scanner.scan_zip(
        archive({"repo/server.py": source, "repo/deploy.yaml": "privileged: true\n"})
    )
    assert result["status"] == "completed"
    assert result["decision"] == "BLOCK"
    assert result["risk_score"] > 0
    assert {f["scanner"] for f in result["findings"]} == {"secrets", "sast", "iac"}
    assert token not in str(result)
    assert result["coverage"]["complete"] is False
    assert "Python" in result["technologies"]


def test_clean_baseline_is_not_comprehensive():
    result = scanner.scan_zip(archive({"repo/hello.py": "print('hello')\n"}))
    assert result["status"] == "completed"
    assert result["findings"] == []
    assert result["decision"] == "BLOCK"
    assert any(g["status"] == "NOT_CONFIGURED" for g in result["gates"])
    assert not result["coverage"]["complete"]
    assert result["coverage"]["limitations"]


@pytest.mark.parametrize(
    "path",
    ["../../escape.py", "/absolute.py", "repo/../escape.py", "C:/escape.py", "repo\\escape.py"],
)
def test_zip_traversal_blocked(path):
    result = scanner.scan_zip(archive({path: "print('hi')"}))
    assert result["status"] == "failed"
    assert result["decision"] == "BLOCK"


def test_zip_symlink_blocked():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as z:
        info = zipfile.ZipInfo("repo/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, "/etc/passwd")
    assert scanner.scan_zip(data.getvalue())["decision"] == "BLOCK"


def test_zip_bomb_limit():
    result = scanner.scan_zip(archive({"repo/large.py": b"x" * (scanner.MAX_FILE_BYTES + 1)}))
    assert result["status"] == "failed"
    assert result["decision"] == "BLOCK"


def test_invalid_and_empty_zip_fail_closed():
    for value in (b"not zip", archive({})):
        result = scanner.scan_zip(value)
        assert result["status"] == "failed"
        assert result["decision"] == "BLOCK"


def test_python_aliases_and_safe_yaml():
    source = "from pickle import loads as read\nimport yaml\nread(data)\nyaml.load(data, Loader=yaml.SafeLoader)\n"
    result = scanner.scan_zip(archive({"repo/app.py": source}))
    assert [f["title"] for f in result["findings"]] == ["Unsafe deserialization"]


def test_policy_and_scanner_fail_closed():
    finding = {"title": "example", "severity": "high"}
    assert scanner.evaluate_policy([finding], [], {"high": "WARN"})["decision"] == "WARN"
    assert (
        scanner.evaluate_policy([], [{"status": "FAILED"}], {"scanner_failure": "ALLOW"})[
            "decision"
        ]
        == "BLOCK"
    )


def test_network_failure_not_success(monkeypatch):
    def failure(*args):
        raise OSError("offline")

    monkeypatch.setattr(scanner, "_download_archive", failure)
    result = scanner.scan_repository("https://github.com/owner/repo", "main")
    assert result["status"] == "failed"
    assert result["decision"] == "BLOCK"
    assert "offline" not in str(result)


def test_no_source_execution(tmp_path):
    marker = tmp_path / "executed"
    source = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
    result = scanner.scan_zip(archive({"repo/setup.py": source}))
    assert result["status"] == "completed"
    assert not marker.exists()


def test_python_parse_error_is_not_a_passing_scan():
    result = scanner.scan_zip(archive({"repo/broken.py": "def broken(:\n"}))
    assert result["status"] == "completed"
    assert result["decision"] == "BLOCK"
    assert result["coverage"]["analysis_errors"]
    assert next(g for g in result["gates"] if g["scanner"] == "sast")["status"] == "FAILED"


def test_missing_required_engines_block_even_permissive_policy():
    policy = {key: "ALLOW" for key in scanner.DEFAULT_POLICY}
    result = scanner.scan_zip(archive({"repo/hello.py": "print('hello')\n"}), policy=policy)
    assert result["decision"] == "BLOCK"
    assert {g["scanner"] for g in result["gates"] if g["status"] == "NOT_CONFIGURED"} == {
        "sca",
        "container",
        "dast",
    }


def test_archive_fixture_preserves_malicious_backslash_on_windows(monkeypatch):
    # ZipInfo normally converts native Windows separators before writing.
    # The attack fixture must retain the raw name that the scanner must reject.
    monkeypatch.setattr(zipfile.os, "sep", "\\")
    path = "repo\\escape.py"
    payload = archive({path: "print('hi')"})
    with zipfile.ZipFile(io.BytesIO(payload)) as zipped:
        assert [info.orig_filename for info in zipped.infolist()] == [path]
    assert scanner.scan_zip(payload)["status"] == "failed"
