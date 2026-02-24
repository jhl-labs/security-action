"""리포터 테스트"""

import base64
import gzip
import json
import json as json_lib

import pytest

import reporters.github_reporter as gh_reporter_module
from reporters.github_reporter import FindingComment, GitHubReporter
from reporters.sarif_reporter import SarifReporter


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

    def test_create_annotations_normalizes_line_numbers_and_skips_empty_path(self):
        reporter = GitHubReporter()
        annotations = reporter._create_annotations(
            [
                {
                    "file_path": "requirements.txt",
                    "line_start": 0,
                    "line_end": 0,
                    "severity": "high",
                    "scanner": "Trivy",
                    "rule_id": "CVE-0000",
                    "message": "vuln",
                },
                {
                    "file_path": "",
                    "line_start": 1,
                    "severity": "medium",
                    "scanner": "Test",
                    "rule_id": "T-1",
                    "message": "msg",
                },
            ]
        )

        assert len(annotations) == 1
        assert annotations[0]["path"] == "requirements.txt"
        assert annotations[0]["start_line"] == 1
        assert annotations[0]["end_line"] == 1

    def test_create_annotations_handles_non_numeric_line_values(self):
        reporter = GitHubReporter()
        annotations = reporter._create_annotations(
            [
                {
                    "file_path": "src/app.py",
                    "line_start": "NaN",
                    "line_end": "invalid",
                    "severity": "medium",
                    "scanner": "Semgrep",
                    "rule_id": "SG-TEST",
                    "message": "test",
                }
            ]
        )

        assert len(annotations) == 1
        assert annotations[0]["start_line"] == 1
        assert annotations[0]["end_line"] == 1

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

    def test_uses_github_api_url(self, monkeypatch):
        monkeypatch.setenv("GITHUB_API_URL", "https://ghe.example.com/api/v3")
        reporter = GitHubReporter(token=None)
        assert reporter.api_url == "https://ghe.example.com/api/v3"

    def test_upload_sarif_without_token(self, tmp_path, monkeypatch):
        sarif_file = tmp_path / "test.sarif"
        sarif_file.write_text('{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}}}]}')
        monkeypatch.setenv("GITHUB_REPOSITORY", "octo/test")
        monkeypatch.setenv("GITHUB_SHA", "abc123")
        monkeypatch.setenv("GITHUB_REF", "refs/heads/main")

        reporter = GitHubReporter(token=None)
        result = reporter.upload_sarif(str(sarif_file))
        assert result.success is False
        assert "token" in (result.error or "").lower()

    def test_upload_sarif_success(self, tmp_path, monkeypatch):
        class FakeResponse:
            def __init__(self, status_code: int, payload: dict, text: str = ""):
                self.status_code = status_code
                self._payload = payload
                self.text = text

            def json(self):
                return self._payload

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def request(self, method, url, **kwargs):
                if method == "POST":
                    return self.post(url, kwargs.get("json"), kwargs.get("headers"))
                if method == "GET":
                    return self.get(url, kwargs.get("headers"))
                raise AssertionError(f"Unexpected method: {method}")

            def post(self, url, json, headers):
                assert url.endswith("/repos/octo/test/code-scanning/sarifs")
                assert "sarif" in json
                assert json["commit_sha"] == "abc123"
                assert json["ref"] == "refs/heads/main"
                assert json["tool_name"] == "security-action"
                decoded = gzip.decompress(base64.b64decode(json["sarif"])).decode("utf-8")
                sarif_payload = json_lib.loads(decoded)
                assert sarif_payload["runs"][0]["automationDetails"]["id"] == "security-action"
                return FakeResponse(202, {"id": "12345", "url": "https://api.example/sarifs/12345"})

            def get(self, url, headers):
                assert url.endswith("/repos/octo/test/code-scanning/sarifs/12345")
                return FakeResponse(200, {"processing_status": "complete"})

        monkeypatch.setattr(gh_reporter_module.httpx, "Client", FakeClient)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)

        reporter = GitHubReporter(token="dummy-token")

        monkeypatch.setenv("GITHUB_REPOSITORY", "octo/test")
        monkeypatch.setenv("GITHUB_SHA", "abc123")
        monkeypatch.setenv("GITHUB_REF", "refs/heads/main")

        sarif_file = tmp_path / "test.sarif"
        sarif_file.write_text('{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}}}]}')

        result = reporter.upload_sarif(str(sarif_file), category="security-action")
        assert result.success is True
        assert result.upload_id == "12345"
        assert result.processing_status == "complete"

    def test_upload_sarif_permission_error_hint(self, tmp_path, monkeypatch):
        class FakeResponse:
            def __init__(self):
                self.status_code = 403
                self.text = '{"message":"Resource not accessible by integration"}'

            def json(self):
                return {"message": "Resource not accessible by integration"}

        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def request(self, method, url, **kwargs):
                if method == "POST":
                    return self.post(url, kwargs.get("json"), kwargs.get("headers"))
                raise AssertionError(f"Unexpected method: {method}")

            def post(self, url, json, headers):
                return FakeResponse()

        monkeypatch.setattr(gh_reporter_module.httpx, "Client", FakeClient)
        monkeypatch.setenv("GITHUB_REPOSITORY", "octo/test")
        monkeypatch.setenv("GITHUB_SHA", "abc123")
        monkeypatch.setenv("GITHUB_REF", "refs/heads/main")

        reporter = GitHubReporter(token="dummy-token")
        sarif_file = tmp_path / "test.sarif"
        sarif_file.write_text('{"version":"2.1.0","runs":[]}')
        result = reporter.upload_sarif(str(sarif_file), category="security-action")
        assert result.success is False
        assert "security-events: write" in (result.error or "")

    def test_with_retry_retries_on_transient_errors(self, monkeypatch):
        reporter = GitHubReporter(token=None)
        calls = {"count": 0}

        monkeypatch.setattr(gh_reporter_module.time, "sleep", lambda *_args, **_kwargs: None)

        def flaky():
            calls["count"] += 1
            if calls["count"] < 3:
                raise RuntimeError("temporary")
            return "ok"

        result = reporter._with_retry("flaky-op", flaky)
        assert result == "ok"
        assert calls["count"] == 3

    def test_http_request_with_retry_on_503(self, monkeypatch):
        class FakeResponse:
            def __init__(self, status_code):
                self.status_code = status_code
                self.text = ""

            def json(self):
                return {}

        class FakeClient:
            def __init__(self):
                self.calls = 0

            def request(self, method, url, **kwargs):
                self.calls += 1
                if self.calls < 3:
                    return FakeResponse(503)
                return FakeResponse(200)

        reporter = GitHubReporter(token=None)
        client = FakeClient()
        monkeypatch.setattr(gh_reporter_module.time, "sleep", lambda *_args, **_kwargs: None)

        response = reporter._http_request_with_retry(client, "GET", "https://example.com")
        assert response.status_code == 200
        assert client.calls == 3


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
