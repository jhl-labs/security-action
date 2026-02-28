"""DependencyScanner 단위 테스트"""

import json
from pathlib import Path
from types import SimpleNamespace

from scanners.dependency_scanner import DependencyScanner


def test_dependency_scanner_fails_on_nonzero_exit(monkeypatch, tmp_path):
    scanner = DependencyScanner(str(tmp_path))

    def fake_run_command(*args, **kwargs):
        return SimpleNamespace(returncode=2, stdout="", stderr="network timeout")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is False
    assert findings == []
    assert error is not None
    assert "exit code 2" in error
    assert "network timeout" in error


def test_dependency_scanner_parses_trivy_json_output(monkeypatch, tmp_path):
    scanner = DependencyScanner(str(tmp_path))

    def fake_run_command(cmd, timeout=None, **kwargs):  # noqa: ANN001, ANN202, ARG001
        output_index = cmd.index("--output") + 1
        report_path = Path(cmd[output_index])
        report_path.write_text(
            json.dumps(
                {
                    "Results": [
                        {
                            "Target": str(tmp_path / "requirements.txt"),
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2024-0001",
                                    "Severity": "HIGH",
                                    "PkgName": "requests",
                                    "InstalledVersion": "2.19.0",
                                    "FixedVersion": "2.32.0",
                                    "Title": "Test vulnerability",
                                    "References": ["https://example.com/advisory"],
                                    "CweIDs": ["CWE-79"],
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is True
    assert error is None
    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner == "Trivy"
    assert finding.rule_id == "CVE-2024-0001"
    assert finding.metadata["package"] == "requests"
    assert finding.metadata["fixed_version"] == "2.32.0"
