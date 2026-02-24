"""설정 파일 로더"""

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ScannerConfig(BaseModel):
    """개별 스캐너 설정"""

    enabled: bool = True
    severity_threshold: str = "low"
    custom_rules_path: str | None = None
    extra_args: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=list)
    include_patterns: list[str] = Field(default_factory=list)


class GitleaksConfig(ScannerConfig):
    """Gitleaks 설정"""

    config_path: str | None = None
    baseline_path: str | None = None
    redact: bool = True


class SemgrepConfig(ScannerConfig):
    """Semgrep 설정"""

    rulesets: list[str] = Field(default_factory=lambda: ["auto", "p/security-audit"])
    custom_rules_dir: str | None = None
    exclude_rules: list[str] = Field(default_factory=list)
    max_target_bytes: int = 1_000_000


class TrivyConfig(ScannerConfig):
    """Trivy 설정"""

    vuln_type: list[str] = Field(default_factory=lambda: ["os", "library"])
    ignore_unfixed: bool = False
    ignorefile_path: str | None = None


class AIReviewConfig(BaseModel):
    """AI 리뷰 설정"""

    enabled: bool = False
    provider: str = "openai"  # openai, anthropic
    model: str = "gpt-4o"
    max_findings: int = 20
    temperature: float = 0.1
    include_code_context: bool = True
    context_lines: int = 10


class FalsePositiveRule(BaseModel):
    """오탐 규칙"""

    id: str
    pattern: str | None = None  # 파일 경로 패턴
    rule_id: str | None = None  # 스캐너 규칙 ID
    scanner: str | None = None  # 특정 스캐너
    reason: str = ""
    expires: str | None = None  # YYYY-MM-DD


class ReportingConfig(BaseModel):
    """리포팅 설정"""

    sarif_output: str = "security-results.sarif"
    json_output: str | None = None
    html_output: str | None = None
    github_comment: bool = True
    github_check_run: bool = True
    fail_on_severity: str = "high"
    fail_on_findings: bool = True


class SecurityActionConfig(BaseModel):
    """전체 설정"""

    version: str = "1.0"
    gitleaks: GitleaksConfig = Field(default_factory=GitleaksConfig)
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    trivy: TrivyConfig = Field(default_factory=TrivyConfig)
    ai_review: AIReviewConfig = Field(default_factory=AIReviewConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    false_positives: list[FalsePositiveRule] = Field(default_factory=list)
    global_excludes: list[str] = Field(
        default_factory=lambda: [
            "**/node_modules/**",
            "**/vendor/**",
            "**/.git/**",
            "**/dist/**",
            "**/build/**",
            "**/__pycache__/**",
            "**/*.min.js",
            "**/*.min.css",
        ]
    )


def find_config_file(workspace: str) -> Path | None:
    """설정 파일 찾기"""
    config_names = [
        ".security-action.yml",
        ".security-action.yaml",
        "security-action.yml",
        "security-action.yaml",
        ".github/security-action.yml",
        ".github/security-action.yaml",
    ]

    workspace_path = Path(workspace)
    for name in config_names:
        config_path = workspace_path / name
        if config_path.exists():
            return config_path

    return None


def load_config(
    config_path: str | Path | None = None, workspace: str | None = None
) -> SecurityActionConfig:
    """설정 파일 로드"""
    # 설정 파일 경로 결정
    if config_path:
        path = Path(config_path)
    elif workspace:
        path = find_config_file(workspace)
    else:
        path = find_config_file(os.getcwd())

    # 기본 설정 반환
    if not path or not path.exists():
        return SecurityActionConfig()

    # YAML 로드
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        return SecurityActionConfig(**data)
    except Exception as e:
        print(f"Warning: Failed to load config from {path}: {e}")
        return SecurityActionConfig()


def merge_env_config(config: SecurityActionConfig) -> SecurityActionConfig:
    """환경 변수로 설정 오버라이드"""
    # AI 설정
    if os.getenv("INPUT_AI_REVIEW", "").lower() == "true":
        config.ai_review.enabled = True
    if os.getenv("INPUT_OPENAI_API_KEY"):
        config.ai_review.provider = "openai"
    elif os.getenv("INPUT_ANTHROPIC_API_KEY"):
        config.ai_review.provider = "anthropic"

    # 스캐너 활성화
    if os.getenv("INPUT_SECRET_SCAN", "").lower() == "false":
        config.gitleaks.enabled = False
    if os.getenv("INPUT_CODE_SCAN", "").lower() == "false":
        config.semgrep.enabled = False
    if os.getenv("INPUT_DEPENDENCY_SCAN", "").lower() == "false":
        config.trivy.enabled = False

    # 리포팅
    if os.getenv("INPUT_SARIF_OUTPUT"):
        config.reporting.sarif_output = os.getenv("INPUT_SARIF_OUTPUT")
    if os.getenv("INPUT_SEVERITY_THRESHOLD"):
        config.reporting.fail_on_severity = os.getenv("INPUT_SEVERITY_THRESHOLD")
    if os.getenv("INPUT_FAIL_ON_FINDINGS", "").lower() == "false":
        config.reporting.fail_on_findings = False

    return config
