#!/usr/bin/env python3
"""Security Scanner Action - 엔트리포인트"""

import json
import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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

    secret_scan: bool = True
    code_scan: bool = True
    dependency_scan: bool = True
    sonar_scan: bool = False
    ai_review: bool = False
    severity_threshold: Severity = Severity.HIGH
    fail_on_findings: bool = True
    sarif_output: str = "security-results.sarif"
    github_token: str | None = None
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    config_path: str | None = None

    @classmethod
    def from_env(cls) -> "Config":
        """환경 변수에서 설정 로드"""

        def str_to_bool(value: str) -> bool:
            return value.lower() in ("true", "1", "yes")

        return cls(
            secret_scan=str_to_bool(os.getenv("INPUT_SECRET_SCAN", "true")),
            code_scan=str_to_bool(os.getenv("INPUT_CODE_SCAN", "true")),
            dependency_scan=str_to_bool(os.getenv("INPUT_DEPENDENCY_SCAN", "true")),
            sonar_scan=str_to_bool(os.getenv("INPUT_SONAR_SCAN", "false")),
            ai_review=str_to_bool(os.getenv("INPUT_AI_REVIEW", "false")),
            severity_threshold=Severity.from_string(os.getenv("INPUT_SEVERITY_THRESHOLD", "high")),
            fail_on_findings=str_to_bool(os.getenv("INPUT_FAIL_ON_FINDINGS", "true")),
            sarif_output=os.getenv("INPUT_SARIF_OUTPUT", "security-results.sarif"),
            github_token=os.getenv("INPUT_GITHUB_TOKEN"),
            openai_api_key=os.getenv("INPUT_OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("INPUT_ANTHROPIC_API_KEY"),
            config_path=os.getenv("INPUT_CONFIG_PATH"),
        )


def set_github_output(name: str, value: str) -> None:
    """GitHub Actions 출력 설정"""
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"{name}={value}\n")
    else:
        print(f"::set-output name={name}::{value}")


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


def run_scanners(config: Config) -> list[ScanResult]:
    """모든 스캐너 실행"""
    results: list[ScanResult] = []
    workspace = os.getenv("GITHUB_WORKSPACE", os.getcwd())

    console.print(f"[dim]Scanning directory: {workspace}[/dim]\n")

    if config.secret_scan:
        console.print("[bold cyan]🔐 Running Secret Scanner (Gitleaks)...[/bold cyan]")
        from scanners.secret_scanner import SecretScanner

        scanner = SecretScanner(workspace)
        results.append(scanner.scan())

    if config.code_scan:
        console.print("[bold cyan]🔍 Running Code Scanner (Semgrep)...[/bold cyan]")
        from scanners.code_scanner import CodeScanner

        scanner = CodeScanner(workspace)
        results.append(scanner.scan())

    if config.dependency_scan:
        console.print("[bold cyan]📦 Running Dependency Scanner (Trivy)...[/bold cyan]")
        from scanners.dependency_scanner import DependencyScanner

        scanner = DependencyScanner(workspace)
        results.append(scanner.scan())

    if config.sonar_scan:
        console.print("[bold cyan]🔬 Running SonarQube Scanner...[/bold cyan]")
        from scanners.sonar_scanner import SonarScanner

        scanner = SonarScanner(workspace)
        results.append(scanner.scan())

    return results


def run_ai_review(results: list[ScanResult], config: Config) -> Any:
    """AI 기반 보안 리뷰 실행"""
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

    try:
        from agent import run_security_review

        workspace = os.getenv("GITHUB_WORKSPACE", os.getcwd())
        state = run_security_review(
            findings=all_findings,
            workspace_path=workspace,
        )

        if state.error:
            console.print(f"[red]AI Review error: {state.error}[/red]")
            return None

        # 결과 출력
        print_ai_review_results(state)
        return state

    except ImportError as e:
        console.print(f"[yellow]AI Review dependencies not available: {e}[/yellow]")
        return None
    except Exception as e:
        console.print(f"[red]AI Review failed: {e}[/red]")
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
) -> None:
    """리포트 생성 (SARIF, GitHub PR 코멘트, Check Run)"""
    console.print("\n[bold cyan]📊 Generating Reports...[/bold cyan]")

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
        console.print(f"  [green]✓[/green] SARIF report saved: {config.sarif_output}")
        set_github_output("sarif-file", config.sarif_output)

    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow] SARIF generation failed: {e}")

    # GitHub 리포팅
    if config.github_token:
        try:
            from reporters import FindingComment, GitHubReporter

            github = GitHubReporter(config.github_token)

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

                # Job Summary 생성
                github.post_summary(all_findings, scan_results, ai_summary)
                console.print("  [green]✓[/green] GitHub Actions summary posted")

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

                # Check Run 생성
                conclusion = "success" if not all_findings else "neutral"
                critical_high = sum(
                    1 for f in all_findings if f["severity"] in ("critical", "high")
                )
                if critical_high > 0:
                    conclusion = "failure"

                github.create_check_run(
                    name="Security Scan",
                    title=f"Found {len(all_findings)} issue(s)",
                    summary=f"Critical/High: {critical_high}, Total: {len(all_findings)}",
                    findings=all_findings,
                    conclusion=conclusion,
                )
                console.print("  [green]✓[/green] Check Run created")

            else:
                console.print("  [dim]GitHub API not available (no repo context)[/dim]")

        except Exception as e:
            console.print(f"  [yellow]⚠[/yellow] GitHub reporting failed: {e}")
    else:
        console.print("  [dim]GitHub token not provided, skipping GitHub reporting[/dim]")


def should_fail(results: list[ScanResult], config: Config) -> bool:
    """취약점 기준으로 실패 여부 판단"""
    if not config.fail_on_findings:
        return False

    for result in results:
        for finding in result.findings:
            if finding.severity >= config.severity_threshold:
                return True

    return False


def main() -> int:
    """메인 함수"""
    print_banner()

    # 설정 로드
    config = Config.from_env()
    console.print("[dim]Configuration loaded[/dim]")
    console.print(f"  Secret Scan: {config.secret_scan}")
    console.print(f"  Code Scan: {config.code_scan}")
    console.print(f"  Dependency Scan: {config.dependency_scan}")
    console.print(f"  SonarQube Scan: {config.sonar_scan}")
    console.print(f"  AI Review: {config.ai_review}")
    console.print(f"  Severity Threshold: {config.severity_threshold.value}")
    console.print()

    # 스캐너 실행
    results = run_scanners(config)

    # AI 리뷰 실행
    ai_review_result = None
    if config.ai_review:
        ai_review_result = run_ai_review(results, config)

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

    # 리포팅
    generate_reports(results, all_findings, config, ai_review_result)

    # GitHub Actions 출력
    set_github_output("scan-results", json.dumps(all_findings))

    # 실패 여부 판단
    if should_fail(results, config):
        console.print(
            f"\n[bold red]❌ Security scan failed: "
            f"Found vulnerabilities at or above {config.severity_threshold.value} severity[/bold red]"
        )
        return 1

    console.print("\n[bold green]✅ Security scan completed successfully[/bold green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
