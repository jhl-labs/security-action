"""main 모듈 테스트"""

import builtins
import json
import logging
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import main as main_module
from main import Config, Severity, generate_reports, should_fail


def _base_config() -> Config:
    return Config(
        secret_scan=False,
        code_scan=False,
        dependency_scan=False,
        severity_threshold=Severity.HIGH,
        fail_on_findings=True,
        sarif_output="security-results.sarif",
    )


def test_config_from_env_parses_usage_tracking(monkeypatch):
    monkeypatch.delenv("INPUT_USAGE_TRACKING", raising=False)
    monkeypatch.delenv("INPUT_UPLOAD_SARIF", raising=False)
    monkeypatch.setenv("INPUT_USAGE_TRACKING", "true")
    monkeypatch.setenv("INPUT_UPLOAD_SARIF", "false")

    cfg = Config.from_env()

    assert cfg.usage_tracking is True
    assert cfg.upload_sarif is False


def test_config_from_env_sarif_defaults(monkeypatch):
    monkeypatch.delenv("INPUT_UPLOAD_SARIF", raising=False)
    monkeypatch.delenv("INPUT_FAIL_ON_SARIF_UPLOAD_ERROR", raising=False)
    monkeypatch.delenv("INPUT_SARIF_CATEGORY", raising=False)

    cfg = Config.from_env()

    assert cfg.upload_sarif is False
    assert cfg.fail_on_sarif_upload_error is False
    assert cfg.sarif_category == "security-action"


def test_config_from_env_falls_back_to_global_ai_env(monkeypatch):
    monkeypatch.delenv("INPUT_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("INPUT_ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "openai-global")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-global")

    cfg = Config.from_env()

    assert cfg.openai_api_key == "openai-global"
    assert cfg.anthropic_api_key == "anthropic-global"


def test_config_from_env_invalid_severity_falls_back_to_high(monkeypatch):
    monkeypatch.setenv("INPUT_SEVERITY_THRESHOLD", "invalid-level")

    cfg = Config.from_env()

    assert cfg.severity_threshold == Severity.HIGH


def test_config_from_env_parses_json_output(monkeypatch):
    monkeypatch.setenv("INPUT_JSON_OUTPUT", "reports/security.json")
    cfg = Config.from_env()
    assert cfg.json_output == "reports/security.json"


def test_config_from_env_sanitizes_blank_output_related_values(monkeypatch):
    monkeypatch.setenv("INPUT_SBOM_OUTPUT", "   ")
    monkeypatch.setenv("INPUT_SARIF_OUTPUT", "")
    monkeypatch.setenv("INPUT_JSON_OUTPUT", "   ")
    monkeypatch.setenv("INPUT_SARIF_CATEGORY", " ")
    monkeypatch.setenv("INPUT_CONFIG_PATH", " ")

    cfg = Config.from_env()

    assert cfg.sbom_output == "sbom.json"
    assert cfg.sarif_output == "security-results.sarif"
    assert cfg.json_output is None
    assert cfg.sarif_category == "security-action"
    assert cfg.config_path is None


def test_config_from_env_parses_parallel(monkeypatch):
    monkeypatch.setenv("INPUT_PARALLEL", "true")

    cfg = Config.from_env()

    assert cfg.parallel is True


def test_config_from_env_bool_parser_handles_spaces_and_on(monkeypatch):
    monkeypatch.setenv("INPUT_SECRET_SCAN", " On ")
    monkeypatch.setenv("INPUT_CODE_SCAN", " 1 ")
    monkeypatch.setenv("INPUT_DEPENDENCY_SCAN", " no ")
    monkeypatch.setenv("INPUT_UPLOAD_SARIF", " YES ")

    cfg = Config.from_env()

    assert cfg.secret_scan is True
    assert cfg.code_scan is True
    assert cfg.dependency_scan is False
    assert cfg.upload_sarif is True


def test_configure_runtime_verbosity_applies_verbose(monkeypatch):
    monkeypatch.setenv("INPUT_VERBOSE", "true")
    monkeypatch.setenv("INPUT_QUIET", "false")

    original_root_level = logging.getLogger().level
    original_logger_level = main_module.logger.level
    original_quiet = main_module.console.quiet
    try:
        verbose, quiet = main_module._configure_runtime_verbosity()
        assert verbose is True
        assert quiet is False
        assert main_module.console.quiet is False
        assert logging.getLogger().level == logging.DEBUG
        assert main_module.logger.level == logging.DEBUG
    finally:
        logging.getLogger().setLevel(original_root_level)
        main_module.logger.setLevel(original_logger_level)
        main_module.console.quiet = original_quiet


def test_configure_runtime_verbosity_quiet_overrides_verbose(monkeypatch):
    monkeypatch.setenv("INPUT_VERBOSE", "true")
    monkeypatch.setenv("INPUT_QUIET", "true")

    original_root_level = logging.getLogger().level
    original_logger_level = main_module.logger.level
    original_quiet = main_module.console.quiet
    try:
        verbose, quiet = main_module._configure_runtime_verbosity()
        assert verbose is True
        assert quiet is True
        assert main_module.console.quiet is True
        assert logging.getLogger().level == logging.WARNING
        assert main_module.logger.level == logging.WARNING
    finally:
        logging.getLogger().setLevel(original_root_level)
        main_module.logger.setLevel(original_logger_level)
        main_module.console.quiet = original_quiet


def test_get_workspace_falls_back_when_env_is_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_WORKSPACE", "   ")
    monkeypatch.chdir(tmp_path)

    workspace = main_module._get_workspace()

    assert workspace == str(tmp_path.resolve())


def test_set_github_output_writes_to_output_file(tmp_path, monkeypatch):
    output_file = tmp_path / "github-output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

    main_module.set_github_output("demo", "line1\nline2")
    content = output_file.read_text(encoding="utf-8")

    assert "demo<<" in content
    assert "line1\nline2" in content


def test_set_github_output_skips_when_output_path_missing(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)

    main_module.set_github_output("demo", "value")
    captured = capsys.readouterr()

    assert captured.out == ""
    assert captured.err == ""


def test_set_findings_count_outputs_uses_filtered_findings(monkeypatch):
    captured = {}

    def fake_set_output(name, value):
        captured[name] = value

    monkeypatch.setattr(main_module, "set_github_output", fake_set_output)

    findings = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "unknown"},
    ]

    main_module.set_findings_count_outputs(findings)

    assert captured["findings-count"] == "4"
    assert captured["critical-count"] == "1"
    assert captured["high-count"] == "1"


def test_apply_yaml_runtime_overrides_updates_config(tmp_path, monkeypatch):
    fake_env = {}
    monkeypatch.setattr(main_module.os, "environ", fake_env)

    cfg = _base_config()
    cfg.secret_scan = True
    cfg.code_scan = True
    cfg.dependency_scan = False
    cfg.sonar_scan = False
    cfg.ai_review = False
    cfg.fail_on_findings = True
    cfg.severity_threshold = Severity.HIGH

    yaml_config = SimpleNamespace(
        gitleaks=SimpleNamespace(
            enabled=False,
            config_path="configs/gitleaks.toml",
            baseline_path=".security-baseline.json",
        ),
        semgrep=SimpleNamespace(enabled=False),
        trivy=SimpleNamespace(enabled=True),
        sonarqube=SimpleNamespace(
            enabled=True,
            host_url="https://sonar.example.com",
            project_key="demo_project",
        ),
        ai_review=SimpleNamespace(enabled=True, provider="openai", model="gpt-4o-mini"),
        reporting=SimpleNamespace(
            sarif_output="custom-output.sarif",
            json_output="custom-output.json",
            fail_on_findings=False,
            fail_on_severity="medium",
        ),
    )

    main_module.apply_yaml_runtime_overrides(cfg, yaml_config, str(tmp_path))

    assert cfg.secret_scan is False
    assert cfg.code_scan is False
    assert cfg.dependency_scan is True
    assert cfg.sonar_scan is True
    assert cfg.ai_review is True
    assert cfg.fail_on_findings is False
    assert cfg.severity_threshold == Severity.MEDIUM
    assert cfg.sarif_output == "custom-output.sarif"
    assert cfg.json_output == "custom-output.json"
    assert fake_env["SONAR_HOST_URL"] == "https://sonar.example.com"
    assert fake_env["SONAR_PROJECT_KEY"] == "demo_project"
    assert fake_env["INPUT_AI_REVIEW"] == "true"
    assert fake_env["INPUT_AI_PROVIDER"] == "openai"
    assert fake_env["INPUT_AI_MODEL"] == "gpt-4o-mini"
    assert fake_env["INPUT_GITLEAKS_CONFIG"] == str(tmp_path / "configs/gitleaks.toml")
    assert fake_env["INPUT_GITLEAKS_BASELINE"] == str(tmp_path / ".security-baseline.json")


def test_apply_yaml_runtime_overrides_ignores_yaml_defaults_when_not_explicit(tmp_path):
    from config.loader import load_config

    config_file = tmp_path / ".security-action.yml"
    config_file.write_text(
        """
version: "1.0"
false_positives:
  - id: ignore-test
    pattern: "**/test/**"
    reason: "test"
""".strip()
    )

    cfg = _base_config()
    cfg.secret_scan = False
    cfg.code_scan = False
    cfg.dependency_scan = False
    cfg.ai_review = False
    cfg.sarif_output = "from-input.sarif"
    cfg.fail_on_findings = False
    cfg.severity_threshold = Severity.CRITICAL

    yaml_cfg = load_config(str(config_file), str(tmp_path))
    main_module.apply_yaml_runtime_overrides(cfg, yaml_cfg, str(tmp_path))

    assert cfg.secret_scan is False
    assert cfg.code_scan is False
    assert cfg.dependency_scan is False
    assert cfg.ai_review is False
    assert cfg.sarif_output == "from-input.sarif"
    assert cfg.fail_on_findings is False
    assert cfg.severity_threshold == Severity.CRITICAL


def test_apply_yaml_runtime_overrides_disables_json_output_when_null(tmp_path):
    from config.loader import load_config

    config_file = tmp_path / ".security-action.yml"
    config_file.write_text(
        """
version: "1.0"
reporting:
  json_output: null
""".strip()
    )

    cfg = _base_config()
    cfg.json_output = "from-input.json"

    yaml_cfg = load_config(str(config_file), str(tmp_path))
    main_module.apply_yaml_runtime_overrides(cfg, yaml_cfg, str(tmp_path))

    assert cfg.json_output is None


def test_apply_yaml_runtime_overrides_ignores_blank_sarif_output(tmp_path):
    cfg = _base_config()
    cfg.sarif_output = "from-input.sarif"

    yaml_cfg = SimpleNamespace(
        gitleaks=SimpleNamespace(model_fields_set=set()),
        semgrep=SimpleNamespace(model_fields_set=set()),
        trivy=SimpleNamespace(model_fields_set=set()),
        sonarqube=SimpleNamespace(model_fields_set=set()),
        ai_review=SimpleNamespace(model_fields_set=set()),
        reporting=SimpleNamespace(
            sarif_output="",
            model_fields_set={"sarif_output"},
        ),
        model_fields_set={"reporting"},
    )

    main_module.apply_yaml_runtime_overrides(cfg, yaml_cfg, str(tmp_path))

    assert cfg.sarif_output == "from-input.sarif"


def test_load_yaml_runtime_config_rejects_workspace_escape_path_in_actions(tmp_path, monkeypatch):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    outside_config = tmp_path / "outside.yml"
    outside_config.write_text("version: '1.0'\n")

    cfg = _base_config()
    cfg.config_path = "../outside.yml"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    yaml_cfg, loaded_path = main_module.load_yaml_runtime_config(cfg, str(workspace))

    assert yaml_cfg is None
    assert loaded_path == str(outside_config.resolve())


def test_load_yaml_runtime_config_rejects_symlink_escape_in_actions(tmp_path, monkeypatch):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    outside_config = tmp_path / "outside.yml"
    outside_config.write_text("version: '1.0'\n")

    (workspace / ".security-action.yml").symlink_to(outside_config)

    cfg = _base_config()
    cfg.config_path = None
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    yaml_cfg, loaded_path = main_module.load_yaml_runtime_config(cfg, str(workspace))

    assert yaml_cfg is None
    assert loaded_path == str(outside_config.resolve())


def test_is_within_workspace_windows_case_insensitive():
    assert main_module._is_within_workspace(
        Path("c:/repo/project/.security-action.yml"),
        Path("C:/Repo/Project"),
    )


def test_is_within_workspace_windows_outside_path():
    assert not main_module._is_within_workspace(
        Path("C:/Repo/Other/.security-action.yml"),
        Path("C:/Repo/Project"),
    )


def test_apply_yaml_runtime_overrides_ignores_workspace_escape_paths_in_actions(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("INPUT_GITLEAKS_CONFIG", raising=False)
    monkeypatch.delenv("INPUT_GITLEAKS_BASELINE", raising=False)

    cfg = _base_config()
    yaml_config = SimpleNamespace(
        gitleaks=SimpleNamespace(
            enabled=True,
            config_path="../configs/gitleaks.toml",
            baseline_path="../baseline.json",
        ),
        semgrep=SimpleNamespace(enabled=True),
        trivy=SimpleNamespace(enabled=True),
        sonarqube=SimpleNamespace(enabled=False, host_url=None, project_key=None),
        ai_review=SimpleNamespace(enabled=False, provider=None, model=None),
        reporting=SimpleNamespace(
            sarif_output="security-results.sarif",
            json_output=None,
            fail_on_findings=True,
            fail_on_severity="high",
        ),
    )

    main_module.apply_yaml_runtime_overrides(cfg, yaml_config, str(tmp_path))

    assert main_module.os.getenv("INPUT_GITLEAKS_CONFIG") is None
    assert main_module.os.getenv("INPUT_GITLEAKS_BASELINE") is None


def test_apply_global_excludes_filters_matching_findings():
    findings = [
        {"rule_id": "A", "file_path": "src/test/app.py"},
        {"rule_id": "B", "file_path": "src/app.py"},
    ]

    filtered, suppressed = main_module.apply_global_excludes(findings, ["**/test/**"])

    assert len(filtered) == 1
    assert filtered[0]["rule_id"] == "B"
    assert len(suppressed) == 1
    assert suppressed[0]["rule_id"] == "A"
    assert "Matched global_excludes pattern" in suppressed[0]["suppress_reason"]


def test_apply_global_excludes_matches_root_level_paths():
    findings = [
        {"rule_id": "A", "file_path": "test/app.py"},
        {"rule_id": "B", "file_path": "src/app.py"},
    ]

    filtered, suppressed = main_module.apply_global_excludes(findings, ["**/test/**"])

    assert len(filtered) == 1
    assert filtered[0]["rule_id"] == "B"
    assert len(suppressed) == 1
    assert suppressed[0]["rule_id"] == "A"


def test_generate_reports_marks_upload_failed_on_sarif_generation_error(monkeypatch):
    class FakeSarifReporter:
        def add_finding(self, **kwargs):
            pass

        def save(self, output_path):
            raise RuntimeError("save failed")

    fake_reporters = SimpleNamespace(SarifReporter=FakeSarifReporter)
    monkeypatch.setitem(sys.modules, "reporters", fake_reporters)

    cfg = _base_config()
    cfg.upload_sarif = True
    cfg.github_token = None

    failed = generate_reports([], [], cfg, None, None)
    assert failed is True


def test_generate_reports_marks_upload_failed_on_github_reporting_exception(monkeypatch, tmp_path):
    class FakeSarifReporter:
        def add_finding(self, **kwargs):
            pass

        def save(self, output_path):
            Path(output_path).write_text('{"version":"2.1.0","runs":[]}')

    class FakeGitHubReporter:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("github init failed")

    fake_reporters = SimpleNamespace(
        SarifReporter=FakeSarifReporter,
        FindingComment=object,
        GitHubReporter=FakeGitHubReporter,
    )
    monkeypatch.setitem(sys.modules, "reporters", fake_reporters)

    cfg = _base_config()
    cfg.upload_sarif = True
    cfg.github_token = "token"
    cfg.sarif_output = str(tmp_path / "result.sarif")

    failed = generate_reports([], [], cfg, None, None)
    assert failed is True


def test_generate_reports_resolves_relative_sarif_output_to_workspace(monkeypatch, tmp_path):
    class FakeSarifReporter:
        def add_finding(self, **kwargs):
            pass

        def save(self, output_path):
            Path(output_path).write_text('{"version":"2.1.0","runs":[]}')

    fake_reporters = SimpleNamespace(SarifReporter=FakeSarifReporter)
    monkeypatch.setitem(sys.modules, "reporters", fake_reporters)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    cfg = _base_config()
    cfg.sarif_output = "reports/result.sarif"

    failed = generate_reports([], [], cfg, None, None)
    assert failed is False
    assert (tmp_path / "reports" / "result.sarif").exists()


def test_generate_reports_rejects_workspace_escape_path_in_actions(monkeypatch, tmp_path):
    class FakeSarifReporter:
        def add_finding(self, **kwargs):
            pass

        def save(self, output_path):
            raise AssertionError("save should not be called for invalid path")

    fake_reporters = SimpleNamespace(SarifReporter=FakeSarifReporter)
    monkeypatch.setitem(sys.modules, "reporters", fake_reporters)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    cfg = _base_config()
    cfg.upload_sarif = True
    cfg.sarif_output = "../outside.sarif"
    cfg.github_token = None

    failed = generate_reports([], [], cfg, None, None)
    assert failed is True


def test_generate_reports_posts_scanner_runtime_error_comment(monkeypatch, tmp_path):
    class FakeSarifReporter:
        def add_finding(self, **kwargs):
            pass

        def save(self, output_path):
            Path(output_path).write_text('{"version":"2.1.0","runs":[]}')

    class FakeGitHubReporter:
        def __init__(self):
            self.comment_body = None

        def is_available(self):
            return True

        def post_summary(self, findings, scan_results, ai_summary=None):
            return "ok"

        def is_pr_context(self):
            return True

        def create_pr_review(self, findings, summary=None):
            return True

        def create_pr_comment(self, body):
            self.comment_body = body
            return True

    fake_reporters = SimpleNamespace(
        SarifReporter=FakeSarifReporter,
        FindingComment=object,
        GitHubReporter=object,
    )
    monkeypatch.setitem(sys.modules, "reporters", fake_reporters)

    cfg = _base_config()
    cfg.github_token = "token"
    cfg.sarif_output = str(tmp_path / "result.sarif")

    reporter = FakeGitHubReporter()
    failed = generate_reports(
        [],
        [],
        cfg,
        None,
        reporter,
        scanner_runtime_errors=[
            {"scanner": "Semgrep", "message": "semgrep not found"},
            {"scanner": "Trivy", "message": "timeout"},
        ],
    )

    assert failed is False
    assert reporter.comment_body is not None
    assert "Scanner Runtime Errors" in reporter.comment_body
    assert "Semgrep" in reporter.comment_body
    assert "Trivy" in reporter.comment_body


def test_generate_reports_writes_json_output(monkeypatch, tmp_path):
    class FakeSarifReporter:
        def add_finding(self, **kwargs):
            pass

        def save(self, output_path):
            Path(output_path).write_text('{"version":"2.1.0","runs":[]}')

    fake_reporters = SimpleNamespace(SarifReporter=FakeSarifReporter)
    monkeypatch.setitem(sys.modules, "reporters", fake_reporters)

    cfg = _base_config()
    cfg.sarif_output = str(tmp_path / "result.sarif")
    cfg.json_output = str(tmp_path / "result.json")

    findings = [
        {
            "scanner": "Semgrep",
            "rule_id": "SG-1",
            "severity": "high",
            "message": "test finding",
            "file_path": "app.py",
            "line_start": 10,
        }
    ]

    failed = generate_reports([], findings, cfg, None, None)
    assert failed is False

    report_path = Path(cfg.json_output)
    assert report_path.exists()
    payload = json.loads(report_path.read_text())
    assert payload["summary"]["total_findings"] == 1
    assert payload["summary"]["severity_counts"]["high"] == 1
    assert payload["findings"][0]["rule_id"] == "SG-1"


def test_should_fail_uses_filtered_findings():
    cfg = _base_config()
    cfg.fail_on_findings = True
    cfg.severity_threshold = Severity.HIGH

    assert should_fail([], cfg) is False
    assert should_fail([{"severity": "low"}], cfg) is False
    assert should_fail([{"severity": "high"}], cfg) is True


def test_should_fail_respects_fail_on_findings_flag():
    cfg = _base_config()
    cfg.fail_on_findings = False
    cfg.severity_threshold = Severity.LOW

    assert should_fail([{"severity": "critical"}], cfg) is False


def test_print_workflow_annotations_escapes_workflow_command(capsys):
    main_module.print_workflow_annotations(
        [
            {
                "severity": "high",
                "file_path": "src/a,b:c.py",
                "line_start": "NaN",
                "line_end": 0,
                "rule_id": "RULE,1:INJECT",
                "scanner": "TestScanner",
                "message": "first line\nsecond%line\r\nthird line",
            }
        ]
    )

    output = capsys.readouterr().out
    annotation_lines = [line for line in output.splitlines() if line.startswith("::")]

    assert len(annotation_lines) == 1
    annotation = annotation_lines[0]
    assert "file=src/a%2Cb%3Ac.py" in annotation
    assert "line=1,endLine=1" in annotation
    assert "title=[TestScanner] RULE%2C1%3AINJECT" in annotation
    assert "::first line%0Asecond%25line%0D%0Athird line" in annotation


def test_print_workflow_annotations_skips_empty_file_path(capsys):
    main_module.print_workflow_annotations(
        [
            {
                "severity": "high",
                "file_path": "",
                "line_start": 1,
                "rule_id": "RULE-1",
                "scanner": "TestScanner",
                "message": "message",
            },
            {
                "severity": "medium",
                "file_path": "src/app.py",
                "line_start": 2,
                "rule_id": "RULE-2",
                "scanner": "TestScanner",
                "message": "message",
            },
        ]
    )

    output = capsys.readouterr().out
    annotation_lines = [line for line in output.splitlines() if line.startswith("::")]
    assert len(annotation_lines) == 1
    assert "file=src/app.py" in annotation_lines[0]


def test_print_workflow_annotations_normalizes_workspace_absolute_path(monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_WORKSPACE", "/home/runner/work/repo/repo")

    main_module.print_workflow_annotations(
        [
            {
                "severity": "high",
                "file_path": "/home/runner/work/repo/repo/src/app.py",
                "line_start": 3,
                "rule_id": "RULE-1",
                "scanner": "TestScanner",
                "message": "message",
            }
        ]
    )

    output = capsys.readouterr().out
    annotation_lines = [line for line in output.splitlines() if line.startswith("::")]
    assert len(annotation_lines) == 1
    assert "file=src/app.py" in annotation_lines[0]


def test_print_workflow_annotations_normalizes_windows_workspace_path_case_insensitive(
    monkeypatch, capsys
):
    monkeypatch.setenv("GITHUB_WORKSPACE", "C:/Repo/Project")

    main_module.print_workflow_annotations(
        [
            {
                "severity": "high",
                "file_path": "c:/repo/project/src/app.py",
                "line_start": 3,
                "rule_id": "RULE-1",
                "scanner": "TestScanner",
                "message": "message",
            }
        ]
    )

    output = capsys.readouterr().out
    annotation_lines = [line for line in output.splitlines() if line.startswith("::")]
    assert len(annotation_lines) == 1
    assert "file=src/app.py" in annotation_lines[0]


def test_print_workflow_annotations_skips_path_traversal_and_external_absolute(capsys):
    main_module.print_workflow_annotations(
        [
            {
                "severity": "high",
                "file_path": "../../etc/passwd",
                "line_start": 1,
                "rule_id": "RULE-1",
                "scanner": "TestScanner",
                "message": "message",
            },
            {
                "severity": "high",
                "file_path": "/etc/passwd",
                "line_start": 1,
                "rule_id": "RULE-2",
                "scanner": "TestScanner",
                "message": "message",
            },
            {
                "severity": "medium",
                "file_path": "src/safe.py",
                "line_start": 2,
                "rule_id": "RULE-3",
                "scanner": "TestScanner",
                "message": "message",
            },
        ]
    )

    output = capsys.readouterr().out
    annotation_lines = [line for line in output.splitlines() if line.startswith("::")]
    assert len(annotation_lines) == 1
    assert "file=src/safe.py" in annotation_lines[0]


def test_print_workflow_annotations_truncates_long_message(capsys):
    long_message = "A" * (main_module.MAX_WORKFLOW_ANNOTATION_MESSAGE_LENGTH + 100)
    main_module.print_workflow_annotations(
        [
            {
                "severity": "high",
                "file_path": "src/app.py",
                "line_start": 1,
                "rule_id": "RULE-1",
                "scanner": "TestScanner",
                "message": long_message,
            }
        ]
    )

    output = capsys.readouterr().out
    annotation_line = next(line for line in output.splitlines() if line.startswith("::"))
    encoded_message = annotation_line.split("::", 2)[2]
    assert len(encoded_message) <= main_module.MAX_WORKFLOW_ANNOTATION_MESSAGE_LENGTH
    assert encoded_message.endswith("...")


def test_print_workflow_annotations_redacts_sensitive_tokens(capsys):
    main_module.print_workflow_annotations(
        [
            {
                "severity": "high",
                "file_path": "src/app.py",
                "line_start": 1,
                "rule_id": "RULE-1",
                "scanner": "TestScanner",
                "message": "Authorization: Bearer supersecrettoken token=my-secret",
            }
        ]
    )

    output = capsys.readouterr().out
    annotation_line = next(line for line in output.splitlines() if line.startswith("::"))
    message = annotation_line.split("::", 2)[2]
    assert "supersecrettoken" not in message
    assert "my-secret" not in message
    assert "Bearer ***" in message
    assert "token=***" in message


def test_collect_scanner_runtime_errors_extracts_failed_results():
    results = [
        main_module.ScanResult(scanner="Gitleaks", success=True, findings=[]),
        main_module.ScanResult(scanner="Semgrep", success=False, findings=[], error="tool missing"),
    ]

    errors = main_module.collect_scanner_runtime_errors(results)
    assert len(errors) == 1
    assert errors[0]["scanner"] == "Semgrep"
    assert errors[0]["message"] == "tool missing"


def test_collect_scanner_runtime_errors_redacts_sensitive_tokens():
    results = [
        main_module.ScanResult(
            scanner="Semgrep",
            success=False,
            findings=[],
            error=(
                "Authorization: Bearer abcdefghijklmnop\n"
                "token=my-secret-token\n"
                "ghp_1234567890ABCDEFGHIJ"
            ),
        )
    ]

    errors = main_module.collect_scanner_runtime_errors(results)
    assert len(errors) == 1
    message = errors[0]["message"]
    assert "Bearer ***" in message
    assert "token=***" in message
    assert "ghp_1234567890ABCDEFGHIJ" not in message


def test_collect_scanner_runtime_errors_redacts_modern_token_formats():
    results = [
        main_module.ScanResult(
            scanner="Semgrep",
            success=False,
            findings=[],
            error=(
                "github_pat_1234567890ABCDEFGHIJ1234567890\n"
                "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"
            ),
        )
    ]

    errors = main_module.collect_scanner_runtime_errors(results)
    assert len(errors) == 1
    message = errors[0]["message"]
    assert "github_pat_" not in message
    assert "sk-proj-" not in message
    assert "***" in message


def test_collect_scanner_runtime_errors_redacts_private_key_blocks():
    private_key_block = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC\n"
        "-----END PRIVATE KEY-----"
    )
    results = [
        main_module.ScanResult(
            scanner="Semgrep",
            success=False,
            findings=[],
            error=private_key_block,
        )
    ]

    errors = main_module.collect_scanner_runtime_errors(results)
    assert len(errors) == 1
    message = errors[0]["message"]
    assert "BEGIN PRIVATE KEY" not in message
    assert "***REDACTED_PRIVATE_KEY***" in message


def test_collect_scanner_runtime_errors_redacts_aws_access_key_format():
    results = [
        main_module.ScanResult(
            scanner="Semgrep",
            success=False,
            findings=[],
            error="Detected AKIA1234567890ABCDEF in logs",
        )
    ]

    errors = main_module.collect_scanner_runtime_errors(results)
    assert len(errors) == 1
    message = errors[0]["message"]
    assert "AKIA1234567890ABCDEF" not in message
    assert "***" in message


def test_collect_scanner_runtime_errors_truncates_long_message():
    long_error = "x" * (main_module.MAX_SCANNER_ERROR_MESSAGE_LENGTH + 100)
    results = [
        main_module.ScanResult(
            scanner="Semgrep",
            success=False,
            findings=[],
            error=long_error,
        )
    ]

    errors = main_module.collect_scanner_runtime_errors(results)
    assert len(errors) == 1
    message = errors[0]["message"]
    assert len(message) == main_module.MAX_SCANNER_ERROR_MESSAGE_LENGTH
    assert message.endswith("...")


def test_print_scanner_runtime_error_annotations_emits_error(capsys):
    main_module.print_scanner_runtime_error_annotations(
        [{"scanner": "Semgrep", "message": "first line\nsecond%line"}]
    )

    output = capsys.readouterr().out
    annotation_lines = [line for line in output.splitlines() if line.startswith("::error ")]
    assert len(annotation_lines) == 1
    annotation = annotation_lines[0]
    assert "title=Scanner Failure (Semgrep)" in annotation
    assert "::first line%0Asecond%25line" in annotation


def test_print_findings_detail_warns_when_scanner_failed_without_findings(capsys):
    cfg = _base_config()
    failed = main_module.ScanResult(scanner="Semgrep", success=False, findings=[], error="failed")

    main_module.print_findings_detail([failed], cfg)

    output = capsys.readouterr().out
    assert "Results may be incomplete" in output
    assert "Failed scanners: Semgrep" in output


def test_print_scan_summary_redacts_sensitive_error_message(capsys):
    cfg = _base_config()
    results = [
        main_module.ScanResult(
            scanner="Semgrep",
            success=False,
            findings=[],
            error="Authorization: Bearer supersecrettoken token=my-secret-token",
            execution_time=0.1,
        )
    ]

    main_module.print_scan_summary(results, cfg)

    output = capsys.readouterr().out
    assert "supersecrettoken" not in output
    assert "my-secret-token" not in output
    assert "Bearer ***" in output
    assert "token=***" in output


def test_build_scanner_runtime_error_findings_creates_critical_entries():
    findings = main_module.build_scanner_runtime_error_findings(
        [{"scanner": "Semgrep", "message": "tool missing"}]
    )
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SCANNER_RUNTIME_FAILURE"
    assert findings[0]["severity"] == "critical"
    assert "Semgrep failed to execute" in findings[0]["message"]


def test_run_scanners_records_failed_result_on_exception(monkeypatch):
    cfg = _base_config()
    cfg.secret_scan = True

    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "scanners.secret_scanner":
            raise RuntimeError("import failed")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    results = main_module.run_scanners(cfg, github_reporter=None)

    assert len(results) == 1
    assert results[0].scanner == "Gitleaks"
    assert results[0].success is False
    assert "import failed" in (results[0].error or "")


def test_run_scanners_parallel_preserves_order(monkeypatch, tmp_path):
    cfg = _base_config()
    cfg.secret_scan = True
    cfg.code_scan = True
    cfg.parallel = True

    class FakeSecretScanner:
        def __init__(self, workspace, **kwargs):
            self.workspace = workspace

        def scan(self):
            time.sleep(0.05)
            return main_module.ScanResult(scanner="Gitleaks", success=True, findings=[])

    class FakeCodeScanner:
        def __init__(self, workspace, **kwargs):
            self.workspace = workspace

        def scan(self):
            time.sleep(0.01)
            return main_module.ScanResult(scanner="Semgrep", success=True, findings=[])

    monkeypatch.setitem(
        sys.modules, "scanners.secret_scanner", SimpleNamespace(SecretScanner=FakeSecretScanner)
    )
    monkeypatch.setitem(
        sys.modules, "scanners.code_scanner", SimpleNamespace(CodeScanner=FakeCodeScanner)
    )
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    results = main_module.run_scanners(cfg, github_reporter=None)

    assert [result.scanner for result in results] == ["Gitleaks", "Semgrep"]


def test_run_scanners_uses_cwd_when_github_workspace_empty(monkeypatch, tmp_path):
    cfg = _base_config()
    cfg.secret_scan = True
    captured_workspaces: list[str] = []

    class FakeSecretScanner:
        def __init__(self, workspace, **kwargs):
            captured_workspaces.append(workspace)

        def scan(self):
            return main_module.ScanResult(scanner="Gitleaks", success=True, findings=[])

    monkeypatch.setitem(
        sys.modules, "scanners.secret_scanner", SimpleNamespace(SecretScanner=FakeSecretScanner)
    )
    monkeypatch.setenv("GITHUB_WORKSPACE", "")
    monkeypatch.chdir(tmp_path)

    results = main_module.run_scanners(cfg, github_reporter=None)

    assert len(results) == 1
    assert captured_workspaces == [str(tmp_path.resolve())]


def test_run_scanners_masks_error_before_check_run_update(monkeypatch, tmp_path):
    cfg = _base_config()
    cfg.secret_scan = True
    cfg.scanner_checks = True

    class FakeSecretScanner:
        def __init__(self, workspace, **kwargs):
            self.workspace = workspace

        def scan(self):
            return main_module.ScanResult(
                scanner="Gitleaks",
                success=False,
                findings=[],
                error="Authorization: Bearer supersecrettoken token=my-secret-token",
                execution_time=0.1,
            )

    class FakeReporter:
        def __init__(self):
            self.errors = []

        def is_available(self):
            return True

        def start_scanner_check(self, scanner):  # noqa: ARG002
            return True

        def complete_scanner_check(self, scanner, findings, execution_time=0.0, error=None):  # noqa: ARG002
            self.errors.append(error)
            return True

    monkeypatch.setitem(
        sys.modules, "scanners.secret_scanner", SimpleNamespace(SecretScanner=FakeSecretScanner)
    )
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    reporter = FakeReporter()
    results = main_module.run_scanners(cfg, github_reporter=reporter)

    assert len(results) == 1
    assert len(reporter.errors) == 1
    assert reporter.errors[0] is not None
    assert "supersecrettoken" not in reporter.errors[0]
    assert "my-secret-token" not in reporter.errors[0]
    assert "Bearer ***" in reporter.errors[0]
    assert "token=***" in reporter.errors[0]


def test_run_ai_review_masks_error_before_check_run_update(monkeypatch, tmp_path):
    cfg = _base_config()
    cfg.ai_review = True
    cfg.scanner_checks = True
    cfg.openai_api_key = "dummy-openai-key"

    class FakeReporter:
        def __init__(self):
            self.started = False
            self.errors = []

        def is_available(self):
            return True

        def start_ai_review_check(self):
            self.started = True
            return True

        def complete_ai_review_check(self, reviews, summary=None, execution_time=0.0, error=None):  # noqa: ARG002
            self.errors.append(error)
            return True

    def fake_run_security_review(findings, workspace_path):  # noqa: ARG001
        return SimpleNamespace(
            error="Authorization: Bearer supersecrettoken token=my-secret-token",
            summary=None,
            reviews=[],
        )

    monkeypatch.setitem(
        sys.modules,
        "agent",
        SimpleNamespace(run_security_review=fake_run_security_review),
    )
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    reporter = FakeReporter()
    run_result = main_module.run_ai_review(
        results=[],
        config=cfg,
        github_reporter=reporter,
        prefiltered_findings=[
            {
                "scanner": "Semgrep",
                "rule_id": "RULE-1",
                "severity": "high",
                "message": "Potential issue",
                "file_path": "src/app.py",
                "line_start": 1,
            }
        ],
    )

    assert run_result is None
    assert reporter.started is True
    assert len(reporter.errors) == 1
    assert reporter.errors[0] is not None
    assert "supersecrettoken" not in reporter.errors[0]
    assert "my-secret-token" not in reporter.errors[0]
    assert "Bearer ***" in reporter.errors[0]
    assert "token=***" in reporter.errors[0]


def test_main_required_check_includes_scanner_runtime_errors(monkeypatch):
    cfg = _base_config()
    cfg.github_token = "dummy-token"
    cfg.skip_check = False
    cfg.fail_on_findings = True

    class FakeGitHubReporter:
        instances = []

        def __init__(self, *args, **kwargs):
            self.check_name = kwargs.get("check_name", "Security scan results")
            self.required_findings = []
            self.overall_findings = []
            self.__class__.instances.append(self)

        def is_available(self):
            return True

        def start_required_check(self):
            return True

        def complete_required_check(self, all_findings, scan_results, execution_time=0.0):
            self.required_findings = list(all_findings)
            return True

        def create_overall_status(self, findings):
            self.overall_findings = list(findings)
            return True

    failed_scan_results = [
        main_module.ScanResult(
            scanner="Semgrep",
            success=False,
            findings=[],
            error="semgrep binary not found",
            execution_time=0.1,
        )
    ]

    monkeypatch.setattr(main_module, "print_banner", lambda: None)
    monkeypatch.setattr(main_module, "print_scan_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "print_findings_detail", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "print_workflow_annotations", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        main_module, "print_scanner_runtime_error_annotations", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(main_module, "set_github_output", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "run_scanners", lambda *args, **kwargs: failed_scan_results)
    monkeypatch.setattr(main_module, "generate_reports", lambda *args, **kwargs: False)
    monkeypatch.setattr(main_module.Config, "from_env", classmethod(lambda cls: cfg))
    monkeypatch.setitem(
        sys.modules, "reporters", SimpleNamespace(GitHubReporter=FakeGitHubReporter)
    )

    exit_code = main_module.main()

    assert exit_code == 1
    assert len(FakeGitHubReporter.instances) == 1
    reporter = FakeGitHubReporter.instances[0]
    assert any(f.get("rule_id") == "SCANNER_RUNTIME_FAILURE" for f in reporter.required_findings)
    assert any(f.get("rule_id") == "SCANNER_RUNTIME_FAILURE" for f in reporter.overall_findings)


def test_main_report_only_mode_keeps_success_on_scanner_runtime_errors(monkeypatch):
    cfg = _base_config()
    cfg.github_token = "dummy-token"
    cfg.skip_check = False
    cfg.fail_on_findings = False

    class FakeGitHubReporter:
        def __init__(self, *args, **kwargs):
            self.check_name = kwargs.get("check_name", "Security scan results")

        def is_available(self):
            return True

        def start_required_check(self):
            return True

        def complete_required_check(self, all_findings, scan_results, execution_time=0.0):
            return True

        def create_overall_status(self, findings):
            return True

    failed_scan_results = [
        main_module.ScanResult(
            scanner="Semgrep",
            success=False,
            findings=[],
            error="semgrep binary not found",
            execution_time=0.1,
        )
    ]

    monkeypatch.setattr(main_module, "print_banner", lambda: None)
    monkeypatch.setattr(main_module, "print_scan_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "print_findings_detail", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "print_workflow_annotations", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        main_module, "print_scanner_runtime_error_annotations", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(main_module, "set_github_output", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "run_scanners", lambda *args, **kwargs: failed_scan_results)
    monkeypatch.setattr(main_module, "generate_reports", lambda *args, **kwargs: False)
    monkeypatch.setattr(main_module.Config, "from_env", classmethod(lambda cls: cfg))
    monkeypatch.setitem(
        sys.modules, "reporters", SimpleNamespace(GitHubReporter=FakeGitHubReporter)
    )

    exit_code = main_module.main()

    assert exit_code == 0


def test_main_completes_required_check_before_sarif_upload_failure(monkeypatch):
    cfg = _base_config()
    cfg.github_token = "dummy-token"
    cfg.upload_sarif = True
    cfg.fail_on_sarif_upload_error = True
    cfg.skip_check = False

    class FakeGitHubReporter:
        instances = []

        def __init__(self, *args, **kwargs):
            self.check_name = kwargs.get("check_name", "Security scan results")
            self.required_completed = False
            self.overall_created = False
            self.required_findings = []
            self.overall_findings = []
            self.__class__.instances.append(self)

        def is_available(self):
            return True

        def start_required_check(self):
            return True

        def complete_required_check(self, all_findings, scan_results, execution_time=0.0):
            self.required_completed = True
            self.required_findings = list(all_findings)
            return True

        def create_overall_status(self, findings):
            self.overall_created = True
            self.overall_findings = list(findings)
            return True

    monkeypatch.setattr(main_module, "print_banner", lambda: None)
    monkeypatch.setattr(main_module, "print_scan_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "print_findings_detail", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "print_workflow_annotations", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "set_github_output", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "run_scanners", lambda *args, **kwargs: [])
    monkeypatch.setattr(main_module, "generate_reports", lambda *args, **kwargs: True)
    monkeypatch.setattr(main_module.Config, "from_env", classmethod(lambda cls: cfg))
    monkeypatch.setitem(
        sys.modules, "reporters", SimpleNamespace(GitHubReporter=FakeGitHubReporter)
    )

    exit_code = main_module.main()

    assert exit_code == 1
    assert len(FakeGitHubReporter.instances) == 1

    reporter = FakeGitHubReporter.instances[0]
    assert reporter.required_completed is True
    assert reporter.overall_created is True
    assert any(f.get("rule_id") == "SARIF_UPLOAD_FAILED" for f in reporter.required_findings)
    assert any(f.get("rule_id") == "SARIF_UPLOAD_FAILED" for f in reporter.overall_findings)


def test_main_ai_review_receives_filtered_findings(monkeypatch):
    cfg = _base_config()
    cfg.ai_review = True
    cfg.fail_on_findings = False

    suppressed_path = "src/secrets/example.py"
    finding_obj = main_module.Finding(
        scanner="Semgrep",
        rule_id="SG-SECRET",
        severity=main_module.Severity.HIGH,
        message="hardcoded secret",
        file_path=suppressed_path,
        line_start=10,
    )
    scan_result = main_module.ScanResult(
        scanner="Semgrep",
        success=True,
        findings=[finding_obj],
        execution_time=0.1,
    )

    yaml_cfg = SimpleNamespace(
        global_excludes=["**/secrets/**"],
        false_positives=[],
    )

    captured = {}

    def fake_run_ai_review(results, config, github_reporter=None, prefiltered_findings=None):
        captured["prefiltered_findings"] = list(prefiltered_findings or [])
        return None

    monkeypatch.setattr(main_module, "print_banner", lambda: None)
    monkeypatch.setattr(main_module, "print_scan_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "print_findings_detail", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "print_workflow_annotations", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        main_module, "print_scanner_runtime_error_annotations", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(main_module, "set_github_output", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "run_scanners", lambda *args, **kwargs: [scan_result])
    monkeypatch.setattr(main_module, "run_ai_review", fake_run_ai_review)
    monkeypatch.setattr(main_module, "generate_reports", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        main_module, "load_yaml_runtime_config", lambda *args, **kwargs: (yaml_cfg, "mock.yml")
    )
    monkeypatch.setattr(main_module.Config, "from_env", classmethod(lambda cls: cfg))

    exit_code = main_module.main()

    assert exit_code == 0
    assert captured["prefiltered_findings"] == []


def test_main_sets_github_workspace_when_missing(monkeypatch, tmp_path):
    cfg = _base_config()
    cfg.fail_on_findings = False

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
    monkeypatch.setattr(main_module, "print_banner", lambda: None)
    monkeypatch.setattr(main_module, "print_scan_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "print_findings_detail", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "print_workflow_annotations", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        main_module, "print_scanner_runtime_error_annotations", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(main_module, "set_github_output", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module, "run_scanners", lambda *args, **kwargs: [])
    monkeypatch.setattr(main_module, "generate_reports", lambda *args, **kwargs: False)
    monkeypatch.setattr(main_module.Config, "from_env", classmethod(lambda cls: cfg))

    exit_code = main_module.main()

    assert exit_code == 0
    assert os.environ["GITHUB_WORKSPACE"] == str(tmp_path)
