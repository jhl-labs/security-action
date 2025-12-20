"""리포터 테스트"""

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from reporters.sarif_reporter import SarifReporter
from reporters.github_reporter import GitHubReporter, FindingComment


class TestSarifReporter:
    """SARIF 리포터 테스트"""

    def test_create_reporter(self):
        reporter = SarifReporter()
        assert reporter.rules == {}
        assert reporter.results == []

    def test_add_finding(self):
        reporter = SarifReporter()
        reporter.add_finding(
            scanner="Gitleaks",
            rule_id="aws-access-key",
            severity="high",
            message="AWS Access Key detected",
            file_path="config.py",
            line_start=10,
        )

        assert len(reporter.results) == 1
        assert len(reporter.rules) == 1
        assert "Gitleaks/aws-access-key" in reporter.rules

    def test_severity_to_level(self):
        reporter = SarifReporter()
        assert reporter.SEVERITY_TO_LEVEL["critical"] == "error"
        assert reporter.SEVERITY_TO_LEVEL["high"] == "error"
        assert reporter.SEVERITY_TO_LEVEL["medium"] == "warning"
        assert reporter.SEVERITY_TO_LEVEL["low"] == "note"

    def test_generate_report(self):
        reporter = SarifReporter()
        reporter.add_finding(
            scanner="Semgrep",
            rule_id="sql-injection",
            severity="critical",
            message="SQL Injection vulnerability",
            file_path="app.py",
            line_start=25,
            line_end=27,
        )

        report = reporter.generate_report()
        assert report.version == "2.1.0"
        assert len(report.runs) == 1
        assert len(report.runs[0].results) == 1

    def test_to_dict(self):
        reporter = SarifReporter()
        reporter.add_finding(
            scanner="Trivy",
            rule_id="CVE-2021-1234",
            severity="medium",
            message="Vulnerable package",
            file_path="requirements.txt",
            line_start=1,
        )

        report = reporter.generate_report()
        data = report.to_dict()

        assert "$schema" in data
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1
        assert "tool" in data["runs"][0]
        assert "results" in data["runs"][0]

    def test_save_to_file(self, tmp_path):
        reporter = SarifReporter()
        reporter.add_finding(
            scanner="Test",
            rule_id="test-rule",
            severity="low",
            message="Test finding",
            file_path="test.py",
            line_start=1,
        )

        output_path = tmp_path / "report.sarif"
        reporter.save(str(output_path))

        assert output_path.exists()
        with open(output_path) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"

    def test_to_json(self):
        reporter = SarifReporter()
        reporter.add_finding(
            scanner="Test",
            rule_id="test-rule",
            severity="info",
            message="Info finding",
            file_path="readme.md",
            line_start=1,
        )

        json_str = reporter.to_json()
        data = json.loads(json_str)
        assert data["version"] == "2.1.0"


class TestGitHubReporter:
    """GitHub 리포터 테스트"""

    def test_create_reporter_no_token(self):
        reporter = GitHubReporter(token=None)
        assert reporter.github is None
        assert not reporter.is_available()

    def test_severity_emoji(self):
        assert GitHubReporter.SEVERITY_EMOJI["critical"] == "🔴"
        assert GitHubReporter.SEVERITY_EMOJI["high"] == "🟠"
        assert GitHubReporter.SEVERITY_EMOJI["medium"] == "🟡"

    def test_format_inline_comment(self):
        reporter = GitHubReporter()
        finding = FindingComment(
            file_path="app.py",
            line=10,
            severity="high",
            title="SQL Injection",
            message="User input in query",
            suggestion="Use parameterized queries",
        )

        comment = reporter._format_inline_comment(finding)
        assert "HIGH" in comment
        assert "SQL Injection" in comment
        assert "parameterized queries" in comment

    def test_format_inline_comment_with_code_fix(self):
        reporter = GitHubReporter()
        finding = FindingComment(
            file_path="app.py",
            line=10,
            severity="critical",
            title="Hardcoded Password",
            message="Password in source code",
            code_fix='password = os.getenv("DB_PASSWORD")',
        )

        comment = reporter._format_inline_comment(finding)
        assert "```suggestion" in comment
        assert "os.getenv" in comment

    def test_generate_review_summary(self):
        reporter = GitHubReporter()
        findings = [
            FindingComment("a.py", 1, "critical", "T1", "M1"),
            FindingComment("b.py", 2, "high", "T2", "M2"),
            FindingComment("c.py", 3, "high", "T3", "M3"),
            FindingComment("d.py", 4, "medium", "T4", "M4"),
        ]

        summary = reporter._generate_review_summary(findings)
        assert "Security Scan Results" in summary
        assert "4" in summary  # total
        assert "CRITICAL" in summary
        assert "HIGH" in summary

    def test_severity_to_annotation_level(self):
        reporter = GitHubReporter()
        assert reporter._severity_to_annotation_level("critical") == "failure"
        assert reporter._severity_to_annotation_level("high") == "failure"
        assert reporter._severity_to_annotation_level("medium") == "warning"
        assert reporter._severity_to_annotation_level("low") == "notice"

    def test_post_summary(self, tmp_path, monkeypatch):
        # GITHUB_STEP_SUMMARY 시뮬레이션
        summary_file = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

        reporter = GitHubReporter()
        findings = [
            {"rule_id": "test", "severity": "high", "file_path": "a.py", "line_start": 1, "message": "Test"},
        ]
        scan_results = [
            {"scanner": "Test", "success": True, "findings_count": 1, "time": "1.0s"},
        ]

        summary = reporter.post_summary(findings, scan_results, "AI Summary here")

        assert "Security Scan Report" in summary
        assert "AI Summary here" in summary
        assert summary_file.exists()


class TestFindingComment:
    """FindingComment 테스트"""

    def test_create_finding_comment(self):
        comment = FindingComment(
            file_path="test.py",
            line=10,
            severity="high",
            title="Test Issue",
            message="Test message",
        )
        assert comment.file_path == "test.py"
        assert comment.line == 10
        assert comment.suggestion is None
        assert comment.code_fix is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
