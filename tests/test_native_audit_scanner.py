"""NativeAuditScanner 테스트"""

import json
from types import SimpleNamespace

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
