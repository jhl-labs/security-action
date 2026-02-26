"""NativeAuditScanner 테스트"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanners.native_audit_scanner import NativeAuditScanner


def _pip_audit_output() -> str:
    return json.dumps(
        [
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [
                    {
                        "id": "PYSEC-2024-1",
                        "description": "test vulnerability",
                        "aliases": ["CVE-2024-0001"],
                        "fix_versions": ["2.32.0"],
                    }
                ],
            }
        ]
    )


def _pip_audit_output_v2() -> str:
    return json.dumps(
        {
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.25.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2024-1",
                            "description": "test vulnerability",
                            "aliases": ["CVE-2024-0001"],
                            "fix_versions": ["2.32.0"],
                        }
                    ],
                }
            ],
            "fixes": [],
        }
    )


def test_run_pip_audit_uses_requirements_files(tmp_path, monkeypatch):
    service_a = tmp_path / "service-a"
    service_a.mkdir()
    (service_a / "requirements.txt").write_text("requests==2.25.0\n")

    service_b = tmp_path / "service-b"
    service_b.mkdir()
    (service_b / "requirements-dev.txt").write_text("requests==2.25.0\n")

    scanner = NativeAuditScanner(str(tmp_path), tools=["pip"])
    calls = []

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):
        calls.append({"cmd": cmd, "cwd": cwd})
        return SimpleNamespace(stdout=_pip_audit_output(), stderr="", returncode=1)

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    findings = scanner._run_pip_audit()

    assert len(calls) == 2
    called_requirements = {tuple(call["cmd"][-2:]) for call in calls}
    assert called_requirements == {
        ("-r", "service-a/requirements.txt"),
        ("-r", "service-b/requirements-dev.txt"),
    }
    assert all(call["cwd"] == str(tmp_path) for call in calls)

    assert len(findings) == 2
    assert {f.file_path for f in findings} == {
        "service-a/requirements.txt",
        "service-b/requirements-dev.txt",
    }


def test_run_pip_audit_falls_back_to_lock_file_directories(tmp_path, monkeypatch):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "Pipfile.lock").write_text("{}")

    scanner = NativeAuditScanner(str(tmp_path), tools=["pip"])
    calls = []

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):
        calls.append({"cmd": cmd, "cwd": cwd})
        return SimpleNamespace(stdout=_pip_audit_output(), stderr="", returncode=1)

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    findings = scanner._run_pip_audit()

    assert len(calls) == 1
    assert "-r" not in calls[0]["cmd"]
    assert calls[0]["cwd"] == str(app_dir)

    assert len(findings) == 1
    assert findings[0].file_path == "app/Pipfile.lock"


def test_run_pip_audit_parses_v2_dependencies_format(tmp_path, monkeypatch):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "requirements.txt").write_text("requests==2.25.0\n")

    scanner = NativeAuditScanner(str(tmp_path), tools=["pip"])

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):
        return SimpleNamespace(stdout=_pip_audit_output_v2(), stderr="", returncode=1)

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    findings = scanner._run_pip_audit()

    assert len(findings) == 1
    assert findings[0].rule_id == "PYSEC-2024-1"
    assert findings[0].file_path == "app/requirements.txt"


def test_run_scan_returns_failure_when_audit_raises(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}")

    scanner = NativeAuditScanner(str(tmp_path), tools=["npm"])
    monkeypatch.setattr(scanner, "_is_tool_available", lambda manager: True)

    def fake_run_audit(manager):
        raise RuntimeError("npm execution failed")

    monkeypatch.setattr(scanner, "_run_audit", fake_run_audit)

    success, findings, error = scanner._run_scan()

    assert success is False
    assert findings == []
    assert error is not None
    assert "npm audit failed" in error


def test_run_scan_returns_failure_when_detected_tool_is_unavailable(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}")

    scanner = NativeAuditScanner(str(tmp_path), tools=["npm"])
    monkeypatch.setattr(scanner, "_is_tool_available", lambda manager: False)

    success, findings, error = scanner._run_scan()

    assert success is False
    assert findings == []
    assert error is not None
    assert "npm tool not available" in error


def test_run_npm_audit_generates_lock_without_running_scripts(tmp_path, monkeypatch):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "package.json").write_text('{"name":"demo","version":"1.0.0"}')

    scanner = NativeAuditScanner(str(tmp_path), tools=["npm"])
    calls = []

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        calls.append({"cmd": cmd, "cwd": cwd})

        if cmd[:2] == ["npm", "install"]:
            (Path(cwd) / "package-lock.json").write_text("{}", encoding="utf-8")
            return SimpleNamespace(stdout="", stderr="", returncode=0)

        if cmd[:2] == ["npm", "audit"]:
            return SimpleNamespace(
                stdout=json.dumps({"vulnerabilities": {}}), stderr="", returncode=0
            )

        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    findings = scanner._run_npm_audit()

    assert findings == []
    install_calls = [call for call in calls if call["cmd"][:2] == ["npm", "install"]]
    assert len(install_calls) == 1
    install_cmd = install_calls[0]["cmd"]
    assert "--package-lock-only" in install_cmd
    assert "--ignore-scripts" in install_cmd
    assert "--no-audit" in install_cmd
    assert "--no-fund" in install_cmd


def test_is_tool_available_ignores_workspace_path_hijack(tmp_path, monkeypatch):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    fake_bin = workspace / "bin"
    fake_bin.mkdir()

    scanner = NativeAuditScanner(str(workspace), tools=["npm"])
    monkeypatch.setenv("PATH", f"{fake_bin}")

    # workspace 내 binary만 PATH에 있을 때는 안전 경로에서 npm을 찾지 못해야 함
    assert scanner._is_tool_available("npm") is False


def test_detect_package_managers_ignores_vendor_like_directories(tmp_path):
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "vendor" / "lib").mkdir(parents=True)
    (tmp_path / "vendor" / "lib" / "composer.lock").write_text("{}", encoding="utf-8")

    scanner = NativeAuditScanner(str(tmp_path), tools=["auto"])

    detected = scanner._detect_package_managers()
    assert detected == []


def test_run_npm_audit_skips_node_modules_nested_package_json(tmp_path, monkeypatch):
    app_dir = tmp_path / "app"
    app_dir.mkdir(parents=True)
    (app_dir / "package.json").write_text('{"name":"demo","version":"1.0.0"}', encoding="utf-8")
    (app_dir / "node_modules" / "leftpad").mkdir(parents=True)
    (app_dir / "node_modules" / "leftpad" / "package.json").write_text("{}", encoding="utf-8")

    scanner = NativeAuditScanner(str(tmp_path), tools=["npm"])
    calls: list[dict] = []

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        calls.append({"cmd": cmd, "cwd": cwd})
        if cmd[:2] == ["npm", "install"]:
            (Path(cwd) / "package-lock.json").write_text("{}", encoding="utf-8")
            return SimpleNamespace(stdout="", stderr="", returncode=0)
        if cmd[:2] == ["npm", "audit"]:
            return SimpleNamespace(
                stdout=json.dumps({"vulnerabilities": {}}), stderr="", returncode=0
            )
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    findings = scanner._run_npm_audit()

    assert findings == []
    assert len(calls) == 2
    assert all("node_modules" not in str(call.get("cwd", "")) for call in calls)


def test_run_npm_audit_fails_when_lock_generation_fails(tmp_path, monkeypatch):
    app_dir = tmp_path / "app"
    app_dir.mkdir(parents=True)
    (app_dir / "package.json").write_text('{"name":"demo","version":"1.0.0"}', encoding="utf-8")

    scanner = NativeAuditScanner(str(tmp_path), tools=["npm"])

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        if cmd[:2] == ["npm", "install"]:
            return SimpleNamespace(stdout="", stderr="network unavailable", returncode=1)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    with pytest.raises(RuntimeError, match="package-lock.json generation failed"):
        scanner._run_npm_audit()


def test_parse_npm_audit_handles_via_string_only():
    scanner = NativeAuditScanner("/tmp", tools=["npm"])
    data = {
        "vulnerabilities": {
            "lodash": {
                "severity": "high",
                "via": ["dep-a", "dep-b"],
                "effects": ["app"],
                "fixAvailable": False,
            }
        }
    }

    findings = scanner._parse_npm_audit(data, ".")

    assert len(findings) == 1
    assert findings[0].rule_id == "lodash"
    assert "dependency chain" in findings[0].message
    assert findings[0].metadata["via"] == ["dep-a", "dep-b"]


def test_parse_cargo_audit_treats_cvss_vector_as_high():
    scanner = NativeAuditScanner("/tmp", tools=["cargo"])
    data = {
        "vulnerabilities": {
            "list": [
                {
                    "advisory": {
                        "id": "RUSTSEC-2024-0001",
                        "title": "Critical memory safety issue",
                        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "url": "https://example.com/advisory",
                    },
                    "package": {"name": "foo", "version": "1.0.0"},
                }
            ]
        }
    }

    findings = scanner._parse_cargo_audit(data, ".")

    assert len(findings) == 1
    assert findings[0].severity.value == "high"


def test_parse_cargo_audit_parses_numeric_cvss_prefix():
    scanner = NativeAuditScanner("/tmp", tools=["cargo"])
    data = {
        "vulnerabilities": {
            "list": [
                {
                    "advisory": {
                        "id": "RUSTSEC-2024-0002",
                        "title": "Remote code execution",
                        "cvss": "9.8/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "url": "https://example.com/advisory",
                    },
                    "package": {"name": "bar", "version": "2.0.0"},
                }
            ]
        }
    }

    findings = scanner._parse_cargo_audit(data, ".")

    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_parse_composer_audit_handles_string_cvss_score():
    scanner = NativeAuditScanner("/tmp", tools=["composer"])
    data = {
        "advisories": {
            "laravel/framework": [
                {
                    "advisoryId": "PKSA-123",
                    "title": "Sample advisory",
                    "cvss": {"score": "8.2"},
                    "link": "https://example.com",
                }
            ]
        }
    }

    findings = scanner._parse_composer_audit(data, ".")

    assert len(findings) == 1
    assert findings[0].severity.value == "high"


def test_parse_composer_audit_ignores_unexpected_shape():
    scanner = NativeAuditScanner("/tmp", tools=["composer"])
    data = {"advisories": ["unexpected"]}

    findings = scanner._parse_composer_audit(data, ".")

    assert findings == []


def test_run_scan_marks_failure_when_pip_audit_command_fails_without_output(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")

    scanner = NativeAuditScanner(str(tmp_path), tools=["pip"])
    monkeypatch.setattr(scanner, "_is_tool_available", lambda manager: True)

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        return SimpleNamespace(stdout="", stderr="resolver failed", returncode=2)

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is False
    assert findings == []
    assert error is not None
    assert "pip-audit command failed" in error


def test_run_scan_marks_failure_when_npm_audit_nonzero_output_is_not_json(tmp_path, monkeypatch):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "package-lock.json").write_text("{}")

    scanner = NativeAuditScanner(str(tmp_path), tools=["npm"])
    monkeypatch.setattr(scanner, "_is_tool_available", lambda manager: True)

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        return SimpleNamespace(stdout="not-json", stderr="", returncode=1)

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is False
    assert findings == []
    assert error is not None
    assert "Failed to parse npm audit JSON" in error
