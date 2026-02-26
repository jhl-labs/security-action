"""설정 및 오탐 관리 테스트"""

import json

import pytest

from config.false_positives import (
    FalsePositiveManager,
    FPRule,
    create_fp_rules_from_config,
)
from config.loader import (
    AIReviewConfig,
    GitleaksConfig,
    ReportingConfig,
    SecurityActionConfig,
    SemgrepConfig,
    SonarQubeConfig,
    TrivyConfig,
    find_config_file,
    load_config,
)


class TestSecurityActionConfig:
    """설정 테스트"""

    def test_default_config(self):
        config = SecurityActionConfig()
        assert config.version == "1.0"
        assert config.gitleaks.enabled is True
        assert config.semgrep.enabled is True
        assert config.trivy.enabled is True

    def test_gitleaks_config(self):
        config = GitleaksConfig(
            enabled=True,
            redact=False,
            exclude_patterns=["**/test/**"],
        )
        assert config.enabled is True
        assert config.redact is False
        assert "**/test/**" in config.exclude_patterns

    def test_semgrep_config(self):
        config = SemgrepConfig(
            rulesets=["auto", "p/security-audit"],
            exclude_rules=["generic.secrets.*"],
        )
        assert "auto" in config.rulesets
        assert "generic.secrets.*" in config.exclude_rules

    def test_trivy_config(self):
        config = TrivyConfig(
            ignore_unfixed=True,
            vuln_type=["library"],
        )
        assert config.ignore_unfixed is True
        assert "library" in config.vuln_type

    def test_sonarqube_config(self):
        config = SonarQubeConfig(
            enabled=True,
            host_url="https://sonar.example.com",
            project_key="acme_project",
        )
        assert config.enabled is True
        assert config.host_url == "https://sonar.example.com"
        assert config.project_key == "acme_project"

    def test_ai_review_config(self):
        config = AIReviewConfig(
            enabled=True,
            provider="anthropic",
            model="claude-3-5-sonnet",
        )
        assert config.enabled is True
        assert config.provider == "anthropic"

    def test_reporting_config(self):
        config = ReportingConfig(
            sarif_output="custom.sarif",
            fail_on_severity="critical",
        )
        assert config.sarif_output == "custom.sarif"
        assert config.fail_on_severity == "critical"


class TestLoadConfig:
    """설정 로드 테스트"""

    def test_load_default_config(self):
        config = load_config(config_path=None, workspace="/nonexistent")
        assert isinstance(config, SecurityActionConfig)

    def test_load_from_yaml(self, tmp_path):
        config_file = tmp_path / ".security-action.yml"
        config_file.write_text("""
version: "1.0"
gitleaks:
  enabled: false
semgrep:
  rulesets:
    - auto
ai_review:
  enabled: true
  provider: openai
sonarqube:
  enabled: true
  host_url: https://sonar.example.com
  project_key: demo_project
""")
        config = load_config(config_path=str(config_file))
        assert config.gitleaks.enabled is False
        assert config.ai_review.enabled is True
        assert config.sonarqube.enabled is True
        assert config.sonarqube.host_url == "https://sonar.example.com"
        assert config.sonarqube.project_key == "demo_project"

    def test_find_config_file(self, tmp_path):
        # 설정 파일 없음
        assert find_config_file(str(tmp_path)) is None

        # 설정 파일 생성
        (tmp_path / ".security-action.yml").write_text("version: '1.0'")
        found = find_config_file(str(tmp_path))
        assert found is not None
        assert found.name == ".security-action.yml"

    def test_merge_env_config_fail_on_findings(self, monkeypatch):
        from config.loader import merge_env_config

        cfg = SecurityActionConfig()
        monkeypatch.setenv("INPUT_FAIL_ON_FINDINGS", "false")
        merged = merge_env_config(cfg)
        assert merged.reporting.fail_on_findings is False

    def test_merge_env_config_parses_spaced_boolean_flags(self, monkeypatch):
        from config.loader import merge_env_config

        cfg = SecurityActionConfig()
        cfg.gitleaks.enabled = True
        cfg.semgrep.enabled = True
        cfg.trivy.enabled = True
        cfg.reporting.fail_on_findings = True

        monkeypatch.setenv("INPUT_AI_REVIEW", " On ")
        monkeypatch.setenv("INPUT_SECRET_SCAN", " 0 ")
        monkeypatch.setenv("INPUT_CODE_SCAN", " OFF ")
        monkeypatch.setenv("INPUT_DEPENDENCY_SCAN", " no ")
        monkeypatch.setenv("INPUT_FAIL_ON_FINDINGS", " 0 ")
        monkeypatch.setenv("INPUT_SARIF_OUTPUT", " reports/custom.sarif ")
        monkeypatch.setenv("INPUT_SEVERITY_THRESHOLD", " medium ")

        merged = merge_env_config(cfg)

        assert merged.ai_review.enabled is True
        assert merged.gitleaks.enabled is False
        assert merged.semgrep.enabled is False
        assert merged.trivy.enabled is False
        assert merged.reporting.fail_on_findings is False
        assert merged.reporting.sarif_output == "reports/custom.sarif"
        assert merged.reporting.fail_on_severity == "medium"


class TestFPRule:
    """오탐 규칙 테스트"""

    def test_create_rule(self):
        rule = FPRule(
            id="test-rule",
            pattern="**/test/**",
            reason="Test files",
        )
        assert rule.id == "test-rule"
        assert rule.pattern == "**/test/**"

    def test_expired_rule(self):
        rule = FPRule(
            id="expired",
            expires="2020-01-01",
        )
        assert rule.is_expired() is True

        rule2 = FPRule(
            id="not-expired",
            expires="2099-12-31",
        )
        assert rule2.is_expired() is False

    def test_no_expiry(self):
        rule = FPRule(id="no-expiry")
        assert rule.is_expired() is False


class TestFalsePositiveManager:
    """오탐 관리자 테스트"""

    def test_create_manager(self):
        manager = FalsePositiveManager()
        assert len(manager.rules) == 0

    def test_add_rule(self):
        manager = FalsePositiveManager()
        rule = FPRule(id="test", pattern="**/test/**")
        manager.add_rule(rule)
        assert len(manager.rules) == 1

    def test_is_false_positive_by_pattern(self):
        manager = FalsePositiveManager(
            [
                FPRule(id="test-fp", pattern="**/test/**", reason="Test file"),
            ]
        )

        finding = {
            "scanner": "Gitleaks",
            "rule_id": "aws-key",
            "file_path": "src/test/secrets.py",
        }

        is_fp, reason = manager.is_false_positive(finding)
        assert is_fp is True
        assert reason == "Test file"

    def test_is_false_positive_by_rule_id(self):
        manager = FalsePositiveManager(
            [
                FPRule(id="ignore-generic", rule_id="generic\\.secrets\\..*", reason="Too noisy"),
            ]
        )

        finding = {
            "scanner": "Semgrep",
            "rule_id": "generic.secrets.detected-secret",
            "file_path": "app.py",
        }

        is_fp, reason = manager.is_false_positive(finding)
        assert is_fp is True

    def test_is_false_positive_by_scanner(self):
        manager = FalsePositiveManager(
            [
                FPRule(id="ignore-trivy", scanner="Trivy", reason="Ignore all Trivy"),
            ]
        )

        finding = {"scanner": "Trivy", "rule_id": "CVE-123", "file_path": "req.txt"}
        is_fp, _ = manager.is_false_positive(finding)
        assert is_fp is True

        finding2 = {"scanner": "Gitleaks", "rule_id": "aws", "file_path": "x.py"}
        is_fp2, _ = manager.is_false_positive(finding2)
        assert is_fp2 is False

    def test_filter_findings(self):
        manager = FalsePositiveManager(
            [
                FPRule(id="test-fp", pattern="**/test/**"),
            ]
        )

        findings = [
            {"scanner": "A", "rule_id": "1", "file_path": "src/app.py"},
            {"scanner": "A", "rule_id": "2", "file_path": "test/test_app.py"},
            {"scanner": "A", "rule_id": "3", "file_path": "src/main.py"},
        ]

        valid, suppressed = manager.filter_findings(findings)
        assert len(valid) == 2
        assert len(suppressed) == 1
        assert suppressed[0]["file_path"] == "test/test_app.py"

    def test_expired_rule_not_applied(self):
        manager = FalsePositiveManager(
            [
                FPRule(id="expired", pattern="**/*", expires="2020-01-01"),
            ]
        )

        finding = {"scanner": "X", "rule_id": "Y", "file_path": "any.py"}
        is_fp, _ = manager.is_false_positive(finding)
        assert is_fp is False

    def test_filter_findings_does_not_mutate_input(self):
        manager = FalsePositiveManager([FPRule(id="test-fp", pattern="**/test/**")])
        findings = [
            {"scanner": "A", "rule_id": "1", "file_path": "src/app.py"},
            {"scanner": "A", "rule_id": "2", "file_path": "test/test_app.py"},
        ]
        original = [dict(item) for item in findings]

        valid, suppressed = manager.filter_findings(findings)

        assert findings == original
        assert len(valid) == 1
        assert len(suppressed) == 1
        assert suppressed[0]["suppressed"] is True
        assert "suppress_reason" in suppressed[0]

    def test_baseline_without_suppressed_field_is_applied(self, tmp_path):
        manager = FalsePositiveManager()
        finding = {
            "scanner": "Semgrep",
            "rule_id": "SG-001",
            "file_path": "src/app.py",
            "line_start": 12,
        }

        baseline_path = tmp_path / ".security-baseline.json"
        baseline_path.write_text(
            json.dumps(
                {
                    "version": "1.0",
                    "findings": [finding],  # legacy format: suppressed field omitted
                }
            ),
            encoding="utf-8",
        )

        manager.load_baseline(baseline_path)
        is_fp, reason = manager.is_false_positive(dict(finding))

        assert is_fp is True
        assert reason == "Baseline match"

    def test_save_baseline_persists_suppressed_metadata(self, tmp_path):
        manager = FalsePositiveManager()
        baseline_path = tmp_path / ".security-baseline.json"
        finding = {
            "scanner": "Trivy",
            "rule_id": "CVE-123",
            "file_path": "requirements.txt",
            "line_start": 1,
        }

        manager.save_baseline(baseline_path, [finding])

        saved = json.loads(baseline_path.read_text(encoding="utf-8"))
        assert saved["findings"][0]["suppressed"] is True
        assert saved["findings"][0]["suppress_reason"] == "Baseline match"

        reloaded = FalsePositiveManager()
        reloaded.load_baseline(baseline_path)
        is_fp, reason = reloaded.is_false_positive(dict(finding))
        assert is_fp is True
        assert reason == "Baseline match"


class TestCreateFPRulesFromConfig:
    """설정에서 규칙 생성 테스트"""

    def test_create_from_config(self):
        config_rules = [
            {
                "id": "rule1",
                "pattern": "**/test/**",
                "reason": "Test files",
            },
            {
                "id": "rule2",
                "scanner": "Semgrep",
                "rule_id": "generic.*",
            },
        ]

        rules = create_fp_rules_from_config(config_rules)
        assert len(rules) == 2
        assert rules[0].id == "rule1"
        assert rules[1].scanner == "Semgrep"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
