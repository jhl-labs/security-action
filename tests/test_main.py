"""main 모듈 테스트"""

import builtins
import sys
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
    monkeypatch.setitem(sys.modules, "reporters", SimpleNamespace(GitHubReporter=FakeGitHubReporter))

    exit_code = main_module.main()

    assert exit_code == 1
    assert len(FakeGitHubReporter.instances) == 1

    reporter = FakeGitHubReporter.instances[0]
    assert reporter.required_completed is True
    assert reporter.overall_created is True
    assert any(f.get("rule_id") == "SARIF_UPLOAD_FAILED" for f in reporter.required_findings)
    assert any(f.get("rule_id") == "SARIF_UPLOAD_FAILED" for f in reporter.overall_findings)
