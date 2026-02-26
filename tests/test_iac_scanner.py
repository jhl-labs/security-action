"""IaC scanner tests."""

import subprocess

from scanners.iac_scanner import IaCScanner


def test_convert_check_handles_empty_file_line_range():
    scanner = IaCScanner("/tmp/repo", frameworks=[])
    finding = scanner._convert_check(
        {
            "check_id": "CKV_TEST_1",
            "check_name": "Test check",
            "file_path": "infra/main.tf",
            "file_line_range": [],
        }
    )

    assert finding is not None
    assert finding.line_start == 1
    assert finding.line_end is None


def test_convert_check_normalizes_non_numeric_line_range():
    scanner = IaCScanner("/tmp/repo", frameworks=[])
    finding = scanner._convert_check(
        {
            "check_id": "CKV_TEST_2",
            "check_name": "Test check",
            "file_path": "infra/main.tf",
            "file_line_range": ["NaN", "invalid"],
        }
    )

    assert finding is not None
    assert finding.line_start == 1
    assert finding.line_end == 1


def test_convert_check_normalizes_reversed_line_range():
    scanner = IaCScanner("/tmp/repo", frameworks=[])
    finding = scanner._convert_check(
        {
            "check_id": "CKV_TEST_3",
            "check_name": "Test check",
            "file_path": "infra/main.tf",
            "file_line_range": [20, 10],
        }
    )

    assert finding is not None
    assert finding.line_start == 20
    assert finding.line_end == 20


def test_iac_scanner_resolves_relative_external_checks_dir(tmp_path, monkeypatch):
    checks_dir = tmp_path / "custom-checks"
    checks_dir.mkdir()
    monkeypatch.setenv("INPUT_IAC_CUSTOM_CHECKS", "custom-checks")

    scanner = IaCScanner(str(tmp_path), frameworks=[])

    assert scanner.external_checks_dir == str(checks_dir.resolve())


def test_iac_scanner_rejects_external_checks_dir_escape_in_github_actions(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("INPUT_IAC_CUSTOM_CHECKS", "../outside-checks")

    scanner = IaCScanner(str(tmp_path), frameworks=[])

    assert scanner.external_checks_dir is None


def test_iac_scanner_detect_frameworks_ignores_vendor_like_directories(tmp_path):
    excluded_tf = tmp_path / "node_modules" / "terraform"
    excluded_tf.mkdir(parents=True)
    (excluded_tf / "main.tf").write_text('resource "x" "y" {}', encoding="utf-8")

    excluded_yaml = tmp_path / "vendor" / "k8s"
    excluded_yaml.mkdir(parents=True)
    (excluded_yaml / "deployment.yaml").write_text("apiVersion: v1\nkind: Pod\n", encoding="utf-8")

    scanner = IaCScanner(str(tmp_path))

    assert scanner.frameworks == []


def test_iac_scanner_adds_default_skip_path_to_checkov_command(tmp_path, monkeypatch):
    scanner = IaCScanner(str(tmp_path), frameworks=["terraform"])
    captured: dict[str, list[str]] = {}

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is True
    assert findings == []
    assert error is None
    assert "--skip-path" in captured["cmd"]
    skip_idx = captured["cmd"].index("--skip-path")
    assert captured["cmd"][skip_idx + 1] == scanner.DEFAULT_SKIP_PATH_REGEX


def test_iac_scanner_does_not_detect_cloudformation_from_generic_json(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"demo"}', encoding="utf-8")

    scanner = IaCScanner(str(tmp_path))

    assert "cloudformation" not in scanner.frameworks


def test_iac_scanner_detects_cloudformation_from_json_signature(tmp_path):
    (tmp_path / "infra-template.json").write_text(
        """
        {
          "AWSTemplateFormatVersion": "2010-09-09",
          "Resources": {
            "MyBucket": {
              "Type": "AWS::S3::Bucket"
            }
          }
        }
        """,
        encoding="utf-8",
    )

    scanner = IaCScanner(str(tmp_path))

    assert "cloudformation" in scanner.frameworks


def test_iac_scanner_detects_cloudformation_from_yaml_signature(tmp_path):
    (tmp_path / "template.yaml").write_text(
        """
        AWSTemplateFormatVersion: "2010-09-09"
        Resources:
          MyQueue:
            Type: AWS::SQS::Queue
        """,
        encoding="utf-8",
    )

    scanner = IaCScanner(str(tmp_path))

    assert "cloudformation" in scanner.frameworks
