#!/usr/bin/env python3
"""Security Scanner Action - 엔트리포인트"""

import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("security-action")

console = Console()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        return cls(value.lower())

    def __ge__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) >= order.index(other)


@dataclass
class Finding:
    """보안 취약점 발견 결과"""

    scanner: str
    rule_id: str
    severity: Severity
    message: str
    file_path: str
    line_start: int
    line_end: int | None = None
    code_snippet: str | None = None
    suggestion: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """스캔 결과"""

    scanner: str
    success: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    execution_time: float = 0.0


@dataclass
class Config:
    """액션 설정"""

    # 기본 스캐너
    secret_scan: bool = True
    secret_scan_history: bool = False
    code_scan: bool = True
    dependency_scan: bool = True
    # 추가 스캐너
    container_scan: bool = False
    container_image: str | None = None
    iac_scan: bool = False
    iac_frameworks: list[str] | None = None
    # 네이티브 의존성 스캔
    native_audit: bool = False
    native_audit_tools: list[str] | None = None
    # SBOM
    sbom_generate: bool = False
    sbom_format: str = "cyclonedx-json"
    sbom_output: str = "sbom.json"
    # SonarQube
    sonar_scan: bool = False
    # AI 리뷰
    ai_review: bool = False
    # 공통
    check_name: str = "🛡️ Security Report"
    skip_check: bool = False
    scanner_checks: bool = False  # 개별 스캐너 Check Run 생성 여부
    post_summary: bool = True  # Job Summary 생성 여부
    severity_threshold: Severity = Severity.HIGH
    fail_on_findings: bool = True
    sarif_output: str = "security-results.sarif"
    upload_sarif: bool = False
    sarif_category: str = "security-action"
    fail_on_sarif_upload_error: bool = False
    usage_tracking: bool = False
    github_token: str | None = None
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    config_path: str | None = None

    @classmethod
    def from_env(cls) -> "Config":
        """환경 변수에서 설정 로드"""

        def str_to_bool(value: str) -> bool:
            return value.lower() in ("true", "1", "yes")

        iac_frameworks_str = os.getenv("INPUT_IAC_FRAMEWORKS", "")
        iac_frameworks = [f.strip() for f in iac_frameworks_str.split(",") if f.strip()] or None

        native_audit_tools_str = os.getenv("INPUT_NATIVE_AUDIT_TOOLS", "auto")
        native_audit_tools = [
            t.strip() for t in native_audit_tools_str.split(",") if t.strip()
        ] or ["auto"]

        return cls(
            # 기본 스캐너
            secret_scan=str_to_bool(os.getenv("INPUT_SECRET_SCAN", "true")),
            secret_scan_history=str_to_bool(os.getenv("INPUT_SECRET_SCAN_HISTORY", "false")),
            code_scan=str_to_bool(os.getenv("INPUT_CODE_SCAN", "true")),
            dependency_scan=str_to_bool(os.getenv("INPUT_DEPENDENCY_SCAN", "true")),
            # 추가 스캐너
            container_scan=str_to_bool(os.getenv("INPUT_CONTAINER_SCAN", "false")),
            container_image=os.getenv("INPUT_CONTAINER_IMAGE"),
            iac_scan=str_to_bool(os.getenv("INPUT_IAC_SCAN", "false")),
            iac_frameworks=iac_frameworks,
            # 네이티브 의존성 스캔
            native_audit=str_to_bool(os.getenv("INPUT_NATIVE_AUDIT", "false")),
            native_audit_tools=native_audit_tools,
            # SBOM
            sbom_generate=str_to_bool(os.getenv("INPUT_SBOM_GENERATE", "false")),
            sbom_format=os.getenv("INPUT_SBOM_FORMAT", "cyclonedx-json"),
            sbom_output=os.getenv("INPUT_SBOM_OUTPUT", "sbom.json"),
            # SonarQube
            sonar_scan=str_to_bool(os.getenv("INPUT_SONAR_SCAN", "false")),
            # AI 리뷰
            ai_review=str_to_bool(os.getenv("INPUT_AI_REVIEW", "false")),
            # 공통
            check_name=os.getenv("INPUT_CHECK_NAME", "🛡️ Security Report"),
            skip_check=str_to_bool(os.getenv("INPUT_SKIP_CHECK", "false")),
            scanner_checks=str_to_bool(os.getenv("INPUT_SCANNER_CHECKS", "false")),
            post_summary=str_to_bool(os.getenv("INPUT_POST_SUMMARY", "true")),
            severity_threshold=Severity.from_string(os.getenv("INPUT_SEVERITY_THRESHOLD", "high")),
            fail_on_findings=str_to_bool(os.getenv("INPUT_FAIL_ON_FINDINGS", "true")),
            sarif_output=os.getenv("INPUT_SARIF_OUTPUT", "security-results.sarif"),
            upload_sarif=str_to_bool(os.getenv("INPUT_UPLOAD_SARIF", "false")),
            sarif_category=os.getenv("INPUT_SARIF_CATEGORY", "security-action"),
            fail_on_sarif_upload_error=str_to_bool(
                os.getenv("INPUT_FAIL_ON_SARIF_UPLOAD_ERROR", "false")
            ),
            usage_tracking=str_to_bool(os.getenv("INPUT_USAGE_TRACKING", "false")),
            github_token=os.getenv("INPUT_GITHUB_TOKEN"),
            openai_api_key=os.getenv("INPUT_OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("INPUT_ANTHROPIC_API_KEY"),
            config_path=os.getenv("INPUT_CONFIG_PATH"),
        )


def set_github_output(name: str, value: str) -> None:
    """GitHub Actions 출력 설정"""
    value_str = str(value)
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        delimiter = "EOF_SECURITY_ACTION"
        while delimiter in value_str:
            delimiter += "_X"

        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"{name}<<{delimiter}\n{value_str}\n{delimiter}\n")
    else:
        escaped_value = (
            value_str.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        )
        print(f"::set-output name={name}::{escaped_value}")


def _escape_workflow_command_data(value: str) -> str:
    """GitHub workflow command 데이터 이스케이프."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_workflow_command_property(value: str) -> str:
    """GitHub workflow command 속성값 이스케이프."""
    return _escape_workflow_command_data(value).replace(":", "%3A").replace(",", "%2C")


def _safe_positive_int(value: Any, default: int = 1) -> int:
    """양의 정수 파싱. 실패 시 기본값 반환."""
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return max(1, default)


def print_banner() -> None:
    """배너 출력"""
    console.print(
        """
[bold blue]╔═══════════════════════════════════════════════════════════╗
║             🛡️  Security Scanner Action                    ║
║       GitHub Advanced Security - Open Source Edition       ║
╚═══════════════════════════════════════════════════════════╝[/bold blue]
"""
    )


def print_scan_summary(results: list[ScanResult], config: Config) -> None:
    """스캔 결과 요약 출력"""
    all_findings: list[Finding] = []
    for result in results:
        all_findings.extend(result.findings)

    # 심각도별 카운트
    severity_counts = {s: 0 for s in Severity}
    for finding in all_findings:
        severity_counts[finding.severity] += 1

    # 테이블 출력
    table = Table(title="🔍 Scan Summary")
    table.add_column("Scanner", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Findings", justify="right")
    table.add_column("Time", justify="right")

    for result in results:
        status = "✅ Success" if result.success else f"❌ Failed: {result.error}"
        table.add_row(
            result.scanner,
            status,
            str(len(result.findings)),
            f"{result.execution_time:.2f}s",
        )

    console.print(table)
    console.print()

    # 심각도별 요약
    severity_table = Table(title="📊 Findings by Severity")
    severity_table.add_column("Severity", style="bold")
    severity_table.add_column("Count", justify="right")

    colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "orange1",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    for severity in [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]:
        count = severity_counts[severity]
        if count > 0:
            severity_table.add_row(
                f"[{colors[severity]}]{severity.value.upper()}[/{colors[severity]}]",
                str(count),
            )

    console.print(severity_table)

    # GitHub Actions 출력 설정
    set_github_output("findings-count", str(len(all_findings)))
    set_github_output("critical-count", str(severity_counts[Severity.CRITICAL]))
    set_github_output("high-count", str(severity_counts[Severity.HIGH]))


def print_findings_detail(results: list[ScanResult], config: Config) -> None:
    """발견된 취약점 상세 출력"""
    all_findings: list[Finding] = []
    for result in results:
        all_findings.extend(result.findings)

    if not all_findings:
        console.print("\n[green]No security issues found![/green]\n")
        return

    # 심각도 순으로 정렬
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    all_findings.sort(key=lambda f: severity_order[f.severity])

    colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "orange1",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    console.print("\n[bold]📋 Detailed Findings[/bold]\n")

    for i, finding in enumerate(all_findings, 1):
        color = colors[finding.severity]
        severity_badge = f"[{color}][{finding.severity.value.upper()}][/{color}]"

        # 헤더
        header = Text()
        header.append(f"#{i} ", style="bold")
        header.append(f"[{finding.scanner}] ", style="cyan")
        header.append(finding.rule_id, style="bold")

        # 본문 구성
        body_lines = [
            f"{severity_badge} {finding.message}",
            f"[dim]📁 {finding.file_path}:{finding.line_start}[/dim]",
        ]

        if finding.code_snippet:
            snippet = finding.code_snippet[:200]
            if len(finding.code_snippet) > 200:
                snippet += "..."
            body_lines.append(f"[dim]Code: {snippet}[/dim]")

        if finding.suggestion:
            body_lines.append(f"[green]💡 {finding.suggestion}[/green]")

        # CWE/OWASP 정보
        metadata = finding.metadata
        if metadata.get("cwe"):
            cwe_list = metadata["cwe"] if isinstance(metadata["cwe"], list) else [metadata["cwe"]]
            body_lines.append(f"[dim]CWE: {', '.join(str(c) for c in cwe_list[:3])}[/dim]")

        body = "\n".join(body_lines)

        panel = Panel(
            body,
            title=header,
            border_style=color,
            padding=(0, 1),
        )
        console.print(panel)


def run_scanners(config: Config, github_reporter: Any = None) -> list[ScanResult]:
    """모든 스캐너 실행

    Args:
        config: 액션 설정
        github_reporter: GitHubReporter 인스턴스 (Check Run 업데이트용)

    Returns:
        스캔 결과 목록
    """
    results: list[ScanResult] = []
    workspace = os.getenv("GITHUB_WORKSPACE", os.getcwd())

    console.print(f"[dim]Scanning directory: {workspace}[/dim]\n")

    # 개별 스캐너 Check Run 생성 여부
    create_scanner_checks = config.scanner_checks

    # 스캐너 설정 목록: (이름, 모듈명, 클래스명, 아이콘, 추가설정)
    scanners_to_run: list[tuple] = []

    if config.secret_scan:
        scanners_to_run.append(
            (
                "Gitleaks",
                "secret_scanner",
                "SecretScanner",
                "🔐",
                {"scan_history": config.secret_scan_history},
            )
        )
    if config.code_scan:
        scanners_to_run.append(("Semgrep", "code_scanner", "CodeScanner", "🔍", {}))
    if config.dependency_scan:
        scanners_to_run.append(("Trivy", "dependency_scanner", "DependencyScanner", "📦", {}))
    if config.container_scan:
        scanners_to_run.append(
            (
                "Trivy-Container",
                "container_scanner",
                "ContainerScanner",
                "🐳",
                {"image": config.container_image},
            )
        )
    if config.iac_scan:
        scanners_to_run.append(
            ("Checkov", "iac_scanner", "IaCScanner", "🏗️", {"frameworks": config.iac_frameworks})
        )
    if config.native_audit:
        scanners_to_run.append(
            (
                "NativeAudit",
                "native_audit_scanner",
                "NativeAuditScanner",
                "🔧",
                {"tools": config.native_audit_tools},
            )
        )
    if config.sonar_scan:
        scanners_to_run.append(("SonarQube", "sonar_scanner", "SonarScanner", "🔬", {}))

    for scanner_name, module_name, class_name, icon, extra_config in scanners_to_run:
        console.print(f"[bold cyan]{icon} Running {scanner_name}...[/bold cyan]")

        # 개별 스캐너 Check Run 시작 (scanner_checks=true인 경우만)
        if create_scanner_checks and github_reporter and github_reporter.is_available():
            github_reporter.start_scanner_check(scanner_name)

        # 스캐너 동적 로드 및 실행
        try:
            module = __import__(f"scanners.{module_name}", fromlist=[class_name])
            scanner_class = getattr(module, class_name)
            scanner = scanner_class(workspace, **extra_config)
            result = scanner.scan()
            results.append(result)

            # 개별 스캐너 Check Run 완료 (scanner_checks=true인 경우만)
            if create_scanner_checks and github_reporter and github_reporter.is_available():
                findings_dict = [
                    {
                        "scanner": f.scanner,
                        "rule_id": f.rule_id,
                        "severity": f.severity.value,
                        "message": f.message,
                        "file_path": f.file_path,
                        "line_start": f.line_start,
                        "line_end": f.line_end,
                        "suggestion": f.suggestion,
                        "cwe": f.metadata.get("cwe", "") if f.metadata else "",
                        "metadata": f.metadata or {},
                    }
                    for f in result.findings
                ]
                github_reporter.complete_scanner_check(
                    scanner=scanner_name,
                    findings=findings_dict,
                    execution_time=result.execution_time,
                    error=result.error if not result.success else None,
                )
                console.print(f"  [green]✓[/green] {scanner_name} Check Run updated")
            else:
                # 개별 Check Run 없이 결과만 출력
                status = "✓" if result.success else "✗"
                color = "green" if result.success else "red"
                console.print(
                    f"  [{color}]{status}[/{color}] {len(result.findings)} findings "
                    f"({result.execution_time:.2f}s)"
                )

        except Exception as e:
            console.print(f"[red]Error running {scanner_name}: {e}[/red]")
            results.append(
                ScanResult(
                    scanner=scanner_name,
                    success=False,
                    findings=[],
                    error=str(e),
                )
            )
            # 에러 발생 시 Check Run 실패로 완료 (scanner_checks=true인 경우만)
            if create_scanner_checks and github_reporter and github_reporter.is_available():
                github_reporter.complete_scanner_check(
                    scanner=scanner_name,
                    findings=[],
                    error=str(e),
                )

    return results


def run_ai_review(
    results: list[ScanResult],
    config: Config,
    github_reporter: Any = None,
) -> Any:
    """AI 기반 보안 리뷰 실행

    Args:
        results: 스캔 결과 목록
        config: 액션 설정
        github_reporter: GitHubReporter 인스턴스 (Check Run 업데이트용)

    Returns:
        AI 리뷰 결과 상태
    """
    console.print("\n[bold cyan]🤖 Running AI Security Review...[/bold cyan]")

    # API 키 확인
    if not config.openai_api_key and not config.anthropic_api_key:
        console.print("[yellow]⚠️  No API key provided. Skipping AI review.[/yellow]")
        console.print("[dim]Set openai-api-key or anthropic-api-key to enable AI review.[/dim]")
        return None

    # findings 수집
    all_findings = []
    for result in results:
        for finding in result.findings:
            all_findings.append(
                {
                    "scanner": finding.scanner,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "message": finding.message,
                    "file_path": finding.file_path,
                    "line_start": finding.line_start,
                    "line_end": finding.line_end,
                }
            )

    if not all_findings:
        console.print("[green]No findings to review.[/green]")
        return None

    console.print(f"[dim]Reviewing {len(all_findings)} finding(s)...[/dim]")

    # AI Review Check Run 시작 (scanner_checks=true인 경우만)
    create_scanner_checks = config.scanner_checks
    if create_scanner_checks and github_reporter and github_reporter.is_available():
        github_reporter.start_ai_review_check()

    start_time = time.time()

    try:
        from agent import run_security_review

        workspace = os.getenv("GITHUB_WORKSPACE", os.getcwd())
        state = run_security_review(
            findings=all_findings,
            workspace_path=workspace,
        )

        execution_time = time.time() - start_time

        if state.error:
            console.print(f"[red]AI Review error: {state.error}[/red]")
            # Check Run 실패로 완료 (scanner_checks=true인 경우만)
            if create_scanner_checks and github_reporter and github_reporter.is_available():
                github_reporter.complete_ai_review_check(
                    reviews=[],
                    error=state.error,
                    execution_time=execution_time,
                )
            return None

        # 결과 출력
        print_ai_review_results(state)

        # AI Review Check Run 완료 (scanner_checks=true인 경우만)
        if create_scanner_checks and github_reporter and github_reporter.is_available():
            reviews_dict = []
            if hasattr(state, "reviews") and state.reviews:
                for review in state.reviews:
                    reviews_dict.append(
                        {
                            "title": review.analysis.title if hasattr(review, "analysis") else "",
                            "severity": review.analysis.severity.value
                            if hasattr(review, "analysis")
                            else "medium",
                            "is_false_positive": review.analysis.is_false_positive
                            if hasattr(review, "analysis")
                            else False,
                            "false_positive_reason": review.analysis.false_positive_reason
                            if hasattr(review, "analysis")
                            else "",
                            "file_path": review.context.file_path
                            if hasattr(review, "context")
                            else "",
                            "line": review.context.start_line if hasattr(review, "context") else 0,
                            "impact": review.analysis.impact if hasattr(review, "analysis") else "",
                            "fix": review.remediation.summary
                            if hasattr(review, "remediation")
                            else "",
                            "code_fix": review.remediation.code_fix
                            if hasattr(review, "remediation")
                            else "",
                        }
                    )

            github_reporter.complete_ai_review_check(
                reviews=reviews_dict,
                summary=state.summary if hasattr(state, "summary") else None,
                execution_time=execution_time,
            )
            console.print("  [green]✓[/green] AI Review Check Run updated")

        return state

    except ImportError as e:
        execution_time = time.time() - start_time
        console.print(f"[yellow]AI Review dependencies not available: {e}[/yellow]")
        if create_scanner_checks and github_reporter and github_reporter.is_available():
            github_reporter.complete_ai_review_check(
                reviews=[],
                error=f"Dependencies not available: {e}",
                execution_time=execution_time,
            )
        return None
    except Exception as e:
        execution_time = time.time() - start_time
        console.print(f"[red]AI Review failed: {e}[/red]")
        if create_scanner_checks and github_reporter and github_reporter.is_available():
            github_reporter.complete_ai_review_check(
                reviews=[],
                error=str(e),
                execution_time=execution_time,
            )
        return None


def print_ai_review_results(state: Any) -> None:
    """AI 리뷰 결과 출력"""
    from rich.markdown import Markdown

    console.print("\n[bold magenta]🤖 AI Security Review Results[/bold magenta]\n")

    # 요약 출력
    if state.summary:
        console.print(
            Panel(
                Markdown(state.summary),
                title="📝 Executive Summary",
                border_style="magenta",
            )
        )

    # 리뷰 결과 출력
    if state.reviews:
        console.print(f"\n[bold]Analyzed {len(state.reviews)} finding(s):[/bold]\n")

        colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        for i, review in enumerate(state.reviews, 1):
            analysis = review.analysis
            remediation = review.remediation

            # False positive 표시
            if analysis.is_false_positive:
                console.print(
                    Panel(
                        f"[dim]Likely false positive: {analysis.false_positive_reason}[/dim]",
                        title=f"#{i} [dim]{analysis.title}[/dim]",
                        border_style="dim",
                    )
                )
                continue

            color = colors.get(analysis.severity.value, "white")
            severity_badge = f"[{color}][{analysis.severity.value.upper()}][/{color}]"

            body_lines = [
                f"{severity_badge} {analysis.title}",
                "",
                f"[bold]Impact:[/bold] {analysis.impact}",
                "",
                f"[bold]Fix:[/bold] {remediation.summary}",
            ]

            if remediation.code_fix:
                body_lines.append("")
                body_lines.append("[bold]Suggested Code:[/bold]")
                body_lines.append(f"```\n{remediation.code_fix}\n```")

            if remediation.references:
                body_lines.append("")
                body_lines.append("[bold]References:[/bold]")
                for ref in remediation.references[:3]:
                    body_lines.append(f"  • {ref}")

            panel = Panel(
                "\n".join(body_lines),
                title=f"#{i} [{review.context.file_path}:{review.context.start_line}]",
                border_style=color,
            )
            console.print(panel)


def generate_reports(
    results: list[ScanResult],
    all_findings: list[dict],
    config: Config,
    ai_review_result: Any = None,
    github_reporter: Any = None,
) -> bool:
    """리포트 생성 (SARIF, GitHub PR 코멘트, Check Run)"""
    console.print("\n[bold cyan]📊 Generating Reports...[/bold cyan]")

    sarif_generated = False
    sarif_upload_failed = False

    # SARIF 리포트 생성
    try:
        from reporters import SarifReporter

        sarif = SarifReporter()
        for finding in all_findings:
            sarif.add_finding(
                scanner=finding["scanner"],
                rule_id=finding["rule_id"],
                severity=finding["severity"],
                message=finding["message"],
                file_path=finding["file_path"],
                line_start=finding["line_start"],
                line_end=finding.get("line_end"),
                suggestion=finding.get("suggestion"),
            )

        sarif.save(config.sarif_output)
        sarif_generated = True
        console.print(f"  [green]✓[/green] SARIF report saved: {config.sarif_output}")
        set_github_output("sarif-file", config.sarif_output)

    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow] SARIF generation failed: {e}")
        if config.upload_sarif:
            sarif_upload_failed = True

    # GitHub 리포팅
    if config.github_token:
        try:
            from reporters import FindingComment, GitHubReporter

            github = github_reporter or GitHubReporter(
                token=config.github_token,
                severity_threshold=config.severity_threshold.value,
                fail_on_findings=config.fail_on_findings,
                check_name=config.check_name,
            )

            # upload-sarif=true면 GitHub Security(Code Scanning)로 직접 업로드
            if sarif_generated and config.upload_sarif:
                upload_result = github.upload_sarif(
                    sarif_path=config.sarif_output,
                    category=config.sarif_category,
                )
                if upload_result.success:
                    console.print(
                        "  [green]✓[/green] SARIF uploaded to GitHub Security "
                        f"(status={upload_result.processing_status or 'pending'})"
                    )
                    if upload_result.upload_id:
                        set_github_output("sarif-upload-id", upload_result.upload_id)
                else:
                    sarif_upload_failed = True
                    console.print(
                        f"  [yellow]⚠[/yellow] SARIF upload failed: {upload_result.error}"
                    )

            if github.is_available():
                # 스캔 결과 요약
                scan_results = [
                    {
                        "scanner": r.scanner,
                        "success": r.success,
                        "findings_count": len(r.findings),
                        "time": f"{r.execution_time:.2f}s",
                    }
                    for r in results
                ]

                ai_summary = None
                if ai_review_result and hasattr(ai_review_result, "summary"):
                    ai_summary = ai_review_result.summary

                # Job Summary 생성 (post_summary=true인 경우만)
                if config.post_summary:
                    github.post_summary(all_findings, scan_results, ai_summary)
                    console.print("  [green]✓[/green] GitHub Actions summary posted")
                else:
                    console.print("  [dim]Job summary skipped (post-summary=false)[/dim]")

                # PR 컨텍스트에서 코멘트/리뷰 생성
                if github.is_pr_context():
                    # AI 리뷰 결과가 있으면 사용
                    if ai_review_result and hasattr(ai_review_result, "reviews"):
                        finding_comments = []
                        for review in ai_review_result.reviews:
                            if not review.analysis.is_false_positive:
                                finding_comments.append(
                                    FindingComment(
                                        file_path=review.context.file_path,
                                        line=review.context.start_line,
                                        severity=review.analysis.severity.value,
                                        title=review.analysis.title,
                                        message=review.analysis.description,
                                        suggestion=review.remediation.summary,
                                        code_fix=review.remediation.code_fix,
                                    )
                                )

                        if finding_comments:
                            github.create_pr_review(finding_comments, ai_summary)
                            console.print(
                                "  [green]✓[/green] PR review with inline comments created"
                            )
                    else:
                        # 기본 코멘트
                        finding_comments = [
                            FindingComment(
                                file_path=f["file_path"],
                                line=f["line_start"],
                                severity=f["severity"],
                                title=f["rule_id"],
                                message=f["message"],
                                suggestion=f.get("suggestion"),
                            )
                            for f in all_findings[:20]
                        ]
                        if finding_comments:
                            github.create_pr_review(finding_comments)
                            console.print("  [green]✓[/green] PR review created")

                # Note: Summary Check Run 제거됨
                # "Security scan results" Required Check가 이미 동일한 summary를 제공하므로
                # 중복되는 "🛡️ Security Scan Summary" Check Run은 생성하지 않음

            else:
                console.print("  [dim]GitHub API not available (no repo context)[/dim]")

        except Exception as e:
            if config.upload_sarif:
                sarif_upload_failed = True
            console.print(f"  [yellow]⚠[/yellow] GitHub reporting failed: {e}")
    else:
        console.print("  [dim]GitHub token not provided, skipping GitHub reporting[/dim]")
        if config.upload_sarif:
            sarif_upload_failed = True
            console.print("  [yellow]⚠[/yellow] upload-sarif requires github-token")

    return sarif_upload_failed


def print_workflow_annotations(findings: list[dict]) -> None:
    """GitHub Actions 워크플로우 annotation 출력

    ::error file={path},line={line}::{message}
    ::warning file={path},line={line}::{message}
    ::notice file={path},line={line}::{message}

    이 형식으로 출력하면 GitHub Actions UI에서 직접 annotation으로 표시됨
    """
    if not findings:
        return

    # 심각도별 annotation level 매핑
    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "notice",
        "info": "notice",
    }

    console.print(f"\n[bold cyan]📝 Creating {len(findings)} workflow annotations...[/bold cyan]")

    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        level = level_map.get(severity, "warning")

        file_path = _escape_workflow_command_property(str(finding.get("file_path", "")))
        line_start = _safe_positive_int(finding.get("line_start"), default=1)
        line_end = _safe_positive_int(finding.get("line_end"), default=line_start)
        line_end = max(line_start, line_end)

        rule_id = finding.get("rule_id", "unknown")
        scanner = finding.get("scanner", "unknown")
        message = _escape_workflow_command_data(
            str(finding.get("message", "Security issue detected"))
        )

        # GitHub Actions workflow command 출력
        # 형식: ::{level} file={path},line={line},endLine={endLine},title={title}::{message}
        annotation = (
            f"::{level} file={file_path},line={line_start},endLine={line_end},"
            f"title={_escape_workflow_command_property(f'[{scanner}] {rule_id}')}::{message}"
        )
        print(annotation)

    console.print(f"  [green]✓[/green] {len(findings)} annotations created")


def should_fail(findings: list[dict], config: Config) -> bool:
    """필터링된 취약점 기준으로 실패 여부 판단"""
    if not config.fail_on_findings:
        return False

    for finding in findings:
        severity_str = str(finding.get("severity", "info")).lower()
        try:
            severity = Severity.from_string(severity_str)
        except ValueError:
            severity = Severity.INFO

        if severity >= config.severity_threshold:
            return True

    return False


def emit_usage_tracking(
    config: Config,
    results: list[ScanResult],
    findings_count: int,
    suppressed_findings_count: int,
    total_execution_time: float,
    sarif_upload_failed: bool,
    sarif_upload_blocking: bool,
) -> None:
    """로컬 사용량 추적 로그 출력 (외부 전송 없음)."""
    if not config.usage_tracking:
        return

    metrics = {
        "scanners_executed": len(results),
        "scanner_failures": len([r for r in results if not r.success]),
        "findings_count": findings_count,
        "suppressed_findings_count": suppressed_findings_count,
        "execution_time_seconds": round(total_execution_time, 3),
        "upload_sarif": config.upload_sarif,
        "sarif_upload_failed": sarif_upload_failed,
        "sarif_upload_blocking": sarif_upload_blocking,
        "ai_review_enabled": config.ai_review,
        "native_audit_enabled": config.native_audit,
    }
    logger.info("Usage metrics (local-only): %s", json.dumps(metrics, ensure_ascii=False))
    console.print("[dim]Usage tracking: local log only (no external transmission)[/dim]")


def main() -> int:
    """메인 함수"""
    print_banner()

    # 설정 로드
    config = Config.from_env()
    console.print("[dim]Configuration loaded[/dim]")
    console.print(
        f"  Secret Scan: {config.secret_scan}"
        + (" (with history)" if config.secret_scan_history else "")
    )
    console.print(f"  Code Scan: {config.code_scan}")
    console.print(f"  Dependency Scan: {config.dependency_scan}")
    console.print(
        f"  Container Scan: {config.container_scan}"
        + (f" ({config.container_image})" if config.container_image else "")
    )
    console.print(f"  IaC Scan: {config.iac_scan}")
    console.print(
        f"  Native Audit: {config.native_audit}"
        + (f" ({', '.join(config.native_audit_tools or ['auto'])})" if config.native_audit else "")
    )
    console.print(f"  SonarQube Scan: {config.sonar_scan}")
    console.print(f"  SBOM Generate: {config.sbom_generate}")
    console.print(f"  AI Review: {config.ai_review}")
    console.print(f"  Severity Threshold: {config.severity_threshold.value}")
    console.print(f"  SARIF Upload: {config.upload_sarif} (category: {config.sarif_category})")
    console.print(f"  Fail on SARIF upload error: {config.fail_on_sarif_upload_error}")
    console.print(f"  Usage Tracking: {config.usage_tracking} (local-only)")
    console.print(f"  Scanner Checks: {config.scanner_checks}")
    console.print()

    # GitHub Reporter 초기화 (GHAS 스타일 Check Run 관리)
    github_reporter = None
    scan_start_time = time.time()

    if config.github_token:
        try:
            from reporters import GitHubReporter

            github_reporter = GitHubReporter(
                token=config.github_token,
                severity_threshold=config.severity_threshold.value,
                fail_on_findings=config.fail_on_findings,
                check_name=config.check_name,
            )
            if github_reporter.is_available():
                console.print("[green]✓[/green] GitHub Check Run integration enabled")
                if config.skip_check:
                    console.print("  [dim]Required check: skipped[/dim]")
                else:
                    console.print(f"  Required check: {github_reporter.check_name}")
                    # Required Status Check 시작 (GHAS 스타일)
                    github_reporter.start_required_check()
            else:
                console.print("[dim]GitHub API available but no repo context[/dim]")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] GitHub Reporter init failed: {e}")
            logger.exception("GitHub Reporter initialization failed")

    # 스캐너 실행 (각 스캐너별 Check Run 생성)
    results = run_scanners(config, github_reporter)

    # AI 리뷰 실행 (AI Review Check Run 생성)
    ai_review_result = None
    if config.ai_review:
        ai_review_result = run_ai_review(results, config, github_reporter)

    # 결과 요약 출력
    print_scan_summary(results, config)

    # 상세 결과 출력
    print_findings_detail(results, config)

    # 결과 수집
    all_findings = []
    for result in results:
        for finding in result.findings:
            all_findings.append(
                {
                    "scanner": finding.scanner,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "message": finding.message,
                    "file_path": finding.file_path,
                    "line_start": finding.line_start,
                    "line_end": finding.line_end,
                    "suggestion": finding.suggestion,
                }
            )

    # False Positive 필터링
    suppressed_findings = []
    try:
        from config.false_positives import FalsePositiveManager, create_fp_rules_from_config
        from config.loader import load_config as load_yaml_config

        workspace = os.getenv("GITHUB_WORKSPACE", os.getcwd())
        yaml_config = load_yaml_config(config.config_path, workspace)

        if yaml_config.false_positives:
            fp_rules = create_fp_rules_from_config(
                [fp.model_dump() for fp in yaml_config.false_positives]
            )
            fp_manager = FalsePositiveManager(fp_rules)

            # 베이스라인 로드 (있는 경우)
            baseline_path = os.path.join(workspace, ".security-baseline.json")
            fp_manager.load_baseline(baseline_path)

            # 필터링 적용
            all_findings, suppressed_findings = fp_manager.filter_findings(all_findings)

            if suppressed_findings:
                console.print(
                    f"\n[dim]ℹ️  {len(suppressed_findings)} finding(s) suppressed by false positive rules[/dim]"
                )
                for sf in suppressed_findings[:5]:
                    console.print(
                        f"   [dim]- {sf.get('rule_id', 'Unknown')}: {sf.get('suppress_reason', 'No reason')}[/dim]"
                    )
                if len(suppressed_findings) > 5:
                    console.print(f"   [dim]... and {len(suppressed_findings) - 5} more[/dim]")

            logger.info(
                f"False positive filtering: {len(suppressed_findings)} suppressed, "
                f"{len(all_findings)} remaining"
            )
    except ImportError as e:
        logger.warning(f"False positive filtering unavailable: {e}")
    except Exception as e:
        logger.error(f"False positive filtering failed: {e}")

    # GitHub Actions 워크플로우 annotation 출력 (UI에 직접 표시)
    print_workflow_annotations(all_findings)

    # SBOM 생성
    if config.sbom_generate:
        console.print("\n[bold cyan]📦 Generating SBOM...[/bold cyan]")
        try:
            from scanners.sbom_generator import generate_sbom

            workspace = os.getenv("GITHUB_WORKSPACE", os.getcwd())
            sbom_result = generate_sbom(
                workspace=workspace,
                output_format=config.sbom_format,
                output_path=config.sbom_output,
            )

            if sbom_result["success"]:
                console.print(
                    f"  [green]✓[/green] SBOM generated: {sbom_result['output_path']} "
                    f"({sbom_result['components_count']} components)"
                )
                set_github_output("sbom-file", sbom_result["output_path"])
            else:
                console.print(
                    f"  [yellow]⚠[/yellow] SBOM generation failed: {sbom_result.get('error')}"
                )
        except Exception as e:
            console.print(f"  [yellow]⚠[/yellow] SBOM generation error: {e}")
            logger.error(f"SBOM generation error: {e}")

    # 리포팅
    sarif_upload_failed = generate_reports(
        results, all_findings, config, ai_review_result, github_reporter
    )

    sarif_upload_blocking = (
        sarif_upload_failed and config.upload_sarif and config.fail_on_sarif_upload_error
    )

    if sarif_upload_blocking:
        console.print(
            "\n[bold red]❌ SARIF upload failed and "
            "fail-on-sarif-upload-error=true[/bold red]"
        )

    # GitHub Actions 출력
    set_github_output("scan-results", json.dumps(all_findings))

    # 총 실행 시간 계산
    total_execution_time = time.time() - scan_start_time

    required_check_findings = list(all_findings)
    if sarif_upload_blocking:
        required_check_findings.append(
            {
                "scanner": "SARIF Upload",
                "rule_id": "SARIF_UPLOAD_FAILED",
                "severity": "critical",
                "message": "SARIF upload failed while fail-on-sarif-upload-error=true",
                "file_path": config.sarif_output or "security-results.sarif",
                "line_start": 1,
            }
        )

    # Required Status Check 완료 (GHAS 스타일)
    if github_reporter and github_reporter.is_available():
        if not config.skip_check:
            # 스캔 결과를 summary 형태로 변환
            scan_summary = []
            for r in results:
                scan_summary.append(
                    {
                        "scanner": r.scanner,
                        "success": r.success,
                        "findings_count": len(r.findings),
                        "time": f"{r.execution_time:.2f}s",
                    }
                )

            # Required Check 완료
            console.print(f"  Creating Required Check with {len(all_findings)} findings...")
            github_reporter.complete_required_check(
                all_findings=required_check_findings,
                scan_results=scan_summary,
                execution_time=total_execution_time,
            )

            # 전체 Commit Status 생성
            github_reporter.create_overall_status(required_check_findings)

            console.print(
                f"\n[green]✓[/green] GitHub Check completed: {github_reporter.check_name}"
            )

    emit_usage_tracking(
        config=config,
        results=results,
        findings_count=len(all_findings),
        suppressed_findings_count=len(suppressed_findings),
        total_execution_time=total_execution_time,
        sarif_upload_failed=sarif_upload_failed,
        sarif_upload_blocking=sarif_upload_blocking,
    )

    if sarif_upload_blocking:
        return 1

    # 실패 여부 판단
    if should_fail(all_findings, config):
        console.print(
            f"\n[bold red]❌ Security scan failed: "
            f"Found vulnerabilities at or above {config.severity_threshold.value} severity[/bold red]"
        )
        return 1

    console.print("\n[bold green]✅ Security scan completed successfully[/bold green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
