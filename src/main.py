#!/usr/bin/env python3
"""Security Scanner Action - 엔트리포인트"""

import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path
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

MAX_WORKFLOW_ANNOTATION_MESSAGE_LENGTH = 2000
MAX_SCANNER_ERROR_MESSAGE_LENGTH = 500


def _env_to_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"true", "1", "yes", "on"}


def _configure_runtime_verbosity() -> tuple[bool, bool]:
    """런타임 verbosity(quiet/verbose) 적용."""
    verbose = _env_to_bool("INPUT_VERBOSE", default=False)
    quiet = _env_to_bool("INPUT_QUIET", default=False)

    # quiet가 verbose보다 우선한다.
    if quiet:
        console.quiet = True
        logging.getLogger().setLevel(logging.WARNING)
        logger.setLevel(logging.WARNING)
    elif verbose:
        console.quiet = False
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    else:
        console.quiet = False
        logging.getLogger().setLevel(logging.INFO)
        logger.setLevel(logging.INFO)

    return verbose, quiet


def _get_workspace(default: str | None = None) -> str:
    """실행 워크스페이스 경로를 안전하게 해석한다.

    - `GITHUB_WORKSPACE`가 비어 있거나 미설정이면 fallback(default 또는 cwd) 사용
    - 항상 절대 경로로 정규화
    """
    raw_workspace = os.getenv("GITHUB_WORKSPACE")
    workspace = str(raw_workspace).strip() if isinstance(raw_workspace, str) else ""
    if not workspace:
        workspace = default or os.getcwd()

    workspace_norm = workspace.replace("\\", "/").strip()
    if _is_windows_absolute_path(workspace_norm):
        return workspace_norm.rstrip("/")

    try:
        return str(Path(workspace).expanduser().resolve(strict=False))
    except Exception:
        return str(Path(default or os.getcwd()).resolve(strict=False))


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
    json_output: str | None = None
    upload_sarif: bool = False
    sarif_category: str = "security-action"
    fail_on_sarif_upload_error: bool = False
    usage_tracking: bool = False
    parallel: bool = False
    github_token: str | None = None
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    config_path: str | None = None

    @classmethod
    def from_env(cls) -> "Config":
        """환경 변수에서 설정 로드"""

        def str_to_bool(value: str | bool | None) -> bool:
            return str(value).strip().lower() in {"true", "1", "yes", "on"}

        iac_frameworks_str = os.getenv("INPUT_IAC_FRAMEWORKS", "")
        iac_frameworks = [f.strip() for f in iac_frameworks_str.split(",") if f.strip()] or None

        native_audit_tools_str = os.getenv("INPUT_NATIVE_AUDIT_TOOLS", "auto")
        native_audit_tools = [
            t.strip() for t in native_audit_tools_str.split(",") if t.strip()
        ] or ["auto"]

        severity_raw = os.getenv("INPUT_SEVERITY_THRESHOLD", "high")
        try:
            severity_threshold = Severity.from_string(severity_raw)
        except ValueError:
            logger.warning(
                "Invalid INPUT_SEVERITY_THRESHOLD=%r, falling back to 'high'",
                severity_raw,
            )
            severity_threshold = Severity.HIGH

        sbom_output = (os.getenv("INPUT_SBOM_OUTPUT") or "").strip() or "sbom.json"
        sarif_output = (os.getenv("INPUT_SARIF_OUTPUT") or "").strip() or "security-results.sarif"

        json_output_raw = os.getenv("INPUT_JSON_OUTPUT")
        json_output = json_output_raw.strip() if isinstance(json_output_raw, str) else None
        if not json_output:
            json_output = None

        sarif_category = (os.getenv("INPUT_SARIF_CATEGORY") or "").strip() or "security-action"

        config_path_raw = os.getenv("INPUT_CONFIG_PATH")
        config_path = config_path_raw.strip() if isinstance(config_path_raw, str) else None
        if not config_path:
            config_path = None

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
            sbom_output=sbom_output,
            # SonarQube
            sonar_scan=str_to_bool(os.getenv("INPUT_SONAR_SCAN", "false")),
            # AI 리뷰
            ai_review=str_to_bool(os.getenv("INPUT_AI_REVIEW", "false")),
            # 공통
            check_name=os.getenv("INPUT_CHECK_NAME", "🛡️ Security Report"),
            skip_check=str_to_bool(os.getenv("INPUT_SKIP_CHECK", "false")),
            scanner_checks=str_to_bool(os.getenv("INPUT_SCANNER_CHECKS", "false")),
            post_summary=str_to_bool(os.getenv("INPUT_POST_SUMMARY", "true")),
            severity_threshold=severity_threshold,
            fail_on_findings=str_to_bool(os.getenv("INPUT_FAIL_ON_FINDINGS", "true")),
            sarif_output=sarif_output,
            json_output=json_output,
            upload_sarif=str_to_bool(os.getenv("INPUT_UPLOAD_SARIF", "false")),
            sarif_category=sarif_category,
            fail_on_sarif_upload_error=str_to_bool(
                os.getenv("INPUT_FAIL_ON_SARIF_UPLOAD_ERROR", "false")
            ),
            usage_tracking=str_to_bool(os.getenv("INPUT_USAGE_TRACKING", "false")),
            parallel=str_to_bool(os.getenv("INPUT_PARALLEL", "false")),
            github_token=os.getenv("INPUT_GITHUB_TOKEN"),
            openai_api_key=os.getenv("INPUT_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("INPUT_ANTHROPIC_API_KEY")
            or os.getenv("ANTHROPIC_API_KEY"),
            config_path=config_path,
        )


def set_github_output(name: str, value: str) -> None:
    """GitHub Actions 출력 설정"""
    value_str = str(value)
    github_output = os.getenv("GITHUB_OUTPUT")
    if not github_output:
        logger.debug("GITHUB_OUTPUT not set; skipping output: %s", name)
        return

    delimiter = "EOF_SECURITY_ACTION"
    while delimiter in value_str:
        delimiter += "_X"

    with open(github_output, "a", encoding="utf-8") as f:
        f.write(f"{name}<<{delimiter}\n{value_str}\n{delimiter}\n")


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


def _resolve_report_output_path(path_value: str, workspace: str) -> Path:
    """리포트 출력 경로를 해석한다.

    - relative 경로는 workspace 기준으로 해석
    - GitHub Actions 환경에서는 workspace 외부 경로 쓰기를 차단
    """
    raw_path = Path(path_value).expanduser()
    workspace_path = Path(workspace).resolve(strict=False)

    if raw_path.is_absolute():
        resolved = raw_path.resolve(strict=False)
    else:
        resolved = (workspace_path / raw_path).resolve(strict=False)

    if os.getenv("GITHUB_ACTIONS", "").lower() == "true":
        if not (resolved == workspace_path or workspace_path in resolved.parents):
            raise ValueError(f"Output path must stay within workspace: {path_value}")

    return resolved


def _format_output_path_for_display(
    original_value: str, resolved_path: Path, workspace: str
) -> str:
    """사용자 표시/액션 output용 경로 문자열 생성."""
    original = str(original_value or "").strip()
    if original and not Path(original).is_absolute():
        return original

    workspace_path = Path(workspace).resolve(strict=False)
    if resolved_path == workspace_path or workspace_path in resolved_path.parents:
        return str(resolved_path.relative_to(workspace_path))

    return str(resolved_path)


def _is_windows_absolute_path(path: str) -> bool:
    """Windows 절대경로 여부 확인 (예: C:/repo/file.py)."""
    return len(path) >= 3 and path[1] == ":" and path[2] == "/"


def _strip_workspace_prefix(path: str, workspace_norm: str) -> str:
    """워크스페이스 prefix를 제거해 상대 경로로 변환."""
    if not workspace_norm:
        return path

    if path == workspace_norm:
        return ""
    if path.startswith(workspace_norm + "/"):
        return path[len(workspace_norm) + 1 :]

    # Windows는 드라이브 문자 대소문자를 무시해 비교한다.
    if _is_windows_absolute_path(path) and _is_windows_absolute_path(workspace_norm):
        path_fold = path.casefold()
        workspace_fold = workspace_norm.casefold()
        if path_fold == workspace_fold:
            return ""
        if path_fold.startswith(workspace_fold + "/"):
            return path[len(workspace_norm) + 1 :]

    return path


def _normalize_workflow_annotation_path(raw_path: str, workspace: str = "") -> str | None:
    """Workflow annotation 파일 경로를 정규화한다."""
    path = str(raw_path or "").strip().replace("\\", "/")
    if not path:
        return None

    if path.startswith("file://"):
        path = path[7:]

    workspace_norm = str(workspace or "").strip().replace("\\", "/").rstrip("/")
    path = _strip_workspace_prefix(path, workspace_norm)

    if path.startswith("/"):
        # workspace 외부 절대경로는 annotation 대상에서 제외
        return None

    while path.startswith("./"):
        path = path[2:]

    # Windows absolute path (e.g. C:/repo/file.py)
    if _is_windows_absolute_path(path):
        return None

    parts = [segment for segment in path.split("/") if segment not in ("", ".")]
    if not parts:
        return None
    if any(segment == ".." for segment in parts):
        return None

    return "/".join(parts)


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
        if result.success:
            status = "✅ Success"
        else:
            status = f"❌ Failed: {_sanitize_runtime_error_message(result.error)}"
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


def print_findings_detail(results: list[ScanResult], config: Config) -> None:
    """발견된 취약점 상세 출력"""
    all_findings: list[Finding] = []
    for result in results:
        all_findings.extend(result.findings)

    if not all_findings:
        failed_scanners = [result.scanner for result in results if not result.success]
        if failed_scanners:
            console.print(
                "\n[yellow]No findings reported, but some scanners failed. "
                "Results may be incomplete.[/yellow]"
            )
            console.print(f"[dim]Failed scanners: {', '.join(failed_scanners)}[/dim]\n")
        else:
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


def set_findings_count_outputs(findings: list[dict[str, Any]]) -> None:
    """필터링 완료된 finding 기준으로 GitHub 출력 카운트를 기록한다."""
    severity_counts = {severity: 0 for severity in Severity}
    for finding in findings:
        severity_str = str(finding.get("severity", "info")).lower()
        try:
            severity = Severity.from_string(severity_str)
        except ValueError:
            severity = Severity.INFO
        severity_counts[severity] += 1

    set_github_output("findings-count", str(len(findings)))
    set_github_output("critical-count", str(severity_counts[Severity.CRITICAL]))
    set_github_output("high-count", str(severity_counts[Severity.HIGH]))


def _serialize_scan_findings(result: ScanResult) -> list[dict[str, Any]]:
    """Check Run 전송용 finding 직렬화."""
    return [
        {
            "scanner": finding.scanner,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "message": finding.message,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "suggestion": finding.suggestion,
            "cwe": finding.metadata.get("cwe", "") if finding.metadata else "",
            "metadata": finding.metadata or {},
        }
        for finding in result.findings
    ]


def _execute_scanner(
    workspace: str,
    scanner_name: str,
    module_name: str,
    class_name: str,
    extra_config: dict[str, Any],
) -> ScanResult:
    """스캐너 모듈 로드 및 실행."""
    try:
        module = __import__(f"scanners.{module_name}", fromlist=[class_name])
        scanner_class = getattr(module, class_name)
        scanner = scanner_class(workspace, **extra_config)
        return scanner.scan()
    except Exception as e:
        logger.exception("Error running scanner %s", scanner_name)
        return ScanResult(
            scanner=scanner_name,
            success=False,
            findings=[],
            error=str(e),
        )


def _sanitize_runtime_error_message(error: str | None) -> str:
    """스캐너 실패 메시지를 UI/리포팅 노출용으로 정규화."""
    return _truncate_text(
        _redact_sensitive_text((error or "Scanner execution failed").strip()),
        MAX_SCANNER_ERROR_MESSAGE_LENGTH,
    )


def run_scanners(config: Config, github_reporter: Any = None) -> list[ScanResult]:
    """모든 스캐너 실행

    Args:
        config: 액션 설정
        github_reporter: GitHubReporter 인스턴스 (Check Run 업데이트용)

    Returns:
        스캔 결과 목록
    """
    results: list[ScanResult] = []
    workspace = _get_workspace()

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

    if not scanners_to_run:
        console.print("[dim]No scanners enabled[/dim]")
        return results

    reporter_available = (
        create_scanner_checks
        and github_reporter is not None
        and hasattr(github_reporter, "is_available")
        and hasattr(github_reporter, "start_scanner_check")
        and hasattr(github_reporter, "complete_scanner_check")
        and github_reporter.is_available()
    )

    # 병렬 실행 경로
    if config.parallel and len(scanners_to_run) > 1:
        console.print("[bold cyan]⚡ Running scanners in parallel...[/bold cyan]")
        if reporter_available:
            for scanner_name, _, _, _, _ in scanners_to_run:
                github_reporter.start_scanner_check(scanner_name)

        max_workers = min(len(scanners_to_run), max(2, os.cpu_count() or 2))
        ordered_results: dict[str, ScanResult] = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_scanner = {
                executor.submit(
                    _execute_scanner,
                    workspace,
                    scanner_name,
                    module_name,
                    class_name,
                    extra_config,
                ): (scanner_name, icon)
                for scanner_name, module_name, class_name, icon, extra_config in scanners_to_run
            }

            for future in as_completed(future_to_scanner):
                scanner_name, icon = future_to_scanner[future]
                result = future.result()
                ordered_results[scanner_name] = result

                if reporter_available:
                    updated = github_reporter.complete_scanner_check(
                        scanner=scanner_name,
                        findings=_serialize_scan_findings(result),
                        execution_time=result.execution_time,
                        error=_sanitize_runtime_error_message(result.error)
                        if not result.success
                        else None,
                    )
                    if updated:
                        console.print(f"  [green]✓[/green] {scanner_name} Check Run updated")
                    else:
                        console.print(
                            f"  [yellow]⚠[/yellow] {scanner_name} Check Run update failed"
                        )
                else:
                    status = "✓" if result.success else "✗"
                    color = "green" if result.success else "red"
                    console.print(
                        f"  [{color}]{status}[/{color}] {icon} {scanner_name}: "
                        f"{len(result.findings)} findings ({result.execution_time:.2f}s)"
                    )

        for scanner_name, _, _, _, _ in scanners_to_run:
            if scanner_name in ordered_results:
                results.append(ordered_results[scanner_name])
            else:
                results.append(
                    ScanResult(
                        scanner=scanner_name,
                        success=False,
                        findings=[],
                        error="Scanner result missing from parallel execution",
                    )
                )

        return results

    # 순차 실행 경로
    for scanner_name, module_name, class_name, icon, extra_config in scanners_to_run:
        console.print(f"[bold cyan]{icon} Running {scanner_name}...[/bold cyan]")

        if reporter_available:
            github_reporter.start_scanner_check(scanner_name)

        result = _execute_scanner(workspace, scanner_name, module_name, class_name, extra_config)
        results.append(result)

        if reporter_available:
            updated = github_reporter.complete_scanner_check(
                scanner=scanner_name,
                findings=_serialize_scan_findings(result),
                execution_time=result.execution_time,
                error=_sanitize_runtime_error_message(result.error) if not result.success else None,
            )
            if updated:
                console.print(f"  [green]✓[/green] {scanner_name} Check Run updated")
            else:
                console.print(f"  [yellow]⚠[/yellow] {scanner_name} Check Run update failed")
        else:
            status = "✓" if result.success else "✗"
            color = "green" if result.success else "red"
            console.print(
                f"  [{color}]{status}[/{color}] {len(result.findings)} findings "
                f"({result.execution_time:.2f}s)"
            )

    return results


def run_ai_review(
    results: list[ScanResult],
    config: Config,
    github_reporter: Any = None,
    prefiltered_findings: list[dict] | None = None,
) -> Any:
    """AI 기반 보안 리뷰 실행

    Args:
        results: 스캔 결과 목록
        config: 액션 설정
        github_reporter: GitHubReporter 인스턴스 (Check Run 업데이트용)
        prefiltered_findings: 필터링된 finding 목록(있으면 우선 사용)

    Returns:
        AI 리뷰 결과 상태
    """
    console.print("\n[bold cyan]🤖 Running AI Security Review...[/bold cyan]")

    # API 키 확인
    if not config.openai_api_key and not config.anthropic_api_key:
        console.print("[yellow]⚠️  No API key provided. Skipping AI review.[/yellow]")
        console.print("[dim]Set openai-api-key or anthropic-api-key to enable AI review.[/dim]")
        return None

    # findings 수집 (필터링 결과가 있으면 우선 사용)
    if prefiltered_findings is not None:
        all_findings = [dict(finding) for finding in prefiltered_findings]
    else:
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
    reporter_available = (
        create_scanner_checks
        and github_reporter is not None
        and hasattr(github_reporter, "is_available")
        and hasattr(github_reporter, "start_ai_review_check")
        and hasattr(github_reporter, "complete_ai_review_check")
        and github_reporter.is_available()
    )
    if reporter_available:
        github_reporter.start_ai_review_check()

    start_time = time.time()

    try:
        from agent import run_security_review

        workspace = _get_workspace()
        state = run_security_review(
            findings=all_findings,
            workspace_path=workspace,
        )

        execution_time = time.time() - start_time

        if state.error:
            sanitized_error = _sanitize_runtime_error_message(state.error)
            console.print(f"[red]AI Review error: {sanitized_error}[/red]")
            # Check Run 실패로 완료 (scanner_checks=true인 경우만)
            if reporter_available:
                github_reporter.complete_ai_review_check(
                    reviews=[],
                    error=sanitized_error,
                    execution_time=execution_time,
                )
            return None

        # 결과 출력
        print_ai_review_results(state)

        # AI Review Check Run 완료 (scanner_checks=true인 경우만)
        if reporter_available:
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
        sanitized_error = _sanitize_runtime_error_message(f"Dependencies not available: {e}")
        console.print(f"[yellow]AI Review dependencies not available: {sanitized_error}[/yellow]")
        if reporter_available:
            github_reporter.complete_ai_review_check(
                reviews=[],
                error=sanitized_error,
                execution_time=execution_time,
            )
        return None
    except Exception as e:
        execution_time = time.time() - start_time
        sanitized_error = _sanitize_runtime_error_message(str(e))
        console.print(f"[red]AI Review failed: {sanitized_error}[/red]")
        if reporter_available:
            github_reporter.complete_ai_review_check(
                reviews=[],
                error=sanitized_error,
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
    scanner_runtime_errors: list[dict] | None = None,
) -> bool:
    """리포트 생성 (SARIF, GitHub PR 코멘트, Check Run)"""
    console.print("\n[bold cyan]📊 Generating Reports...[/bold cyan]")

    sarif_generated = False
    sarif_upload_failed = False
    workspace = _get_workspace()
    resolved_sarif_output: Path | None = None

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

        resolved_sarif_output = _resolve_report_output_path(config.sarif_output, workspace)
        resolved_sarif_output.parent.mkdir(parents=True, exist_ok=True)
        sarif.save(str(resolved_sarif_output))
        sarif_generated = True
        sarif_display_path = _format_output_path_for_display(
            config.sarif_output, resolved_sarif_output, workspace
        )
        console.print(f"  [green]✓[/green] SARIF report saved: {sarif_display_path}")
        set_github_output("sarif-file", sarif_display_path)

    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow] SARIF generation failed: {e}")
        if config.upload_sarif:
            sarif_upload_failed = True

    # 스캔 결과 요약(공통)
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

    # JSON 리포트 생성 (CLI/로컬 UX 보강)
    if config.json_output:
        try:
            output_path = _resolve_report_output_path(config.json_output, workspace)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            severity_counts: dict[str, int] = {}
            for finding in all_findings:
                severity = str(finding.get("severity", "unknown")).lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            json_report = {
                "version": "1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "summary": {
                    "total_findings": len(all_findings),
                    "severity_counts": severity_counts,
                },
                "scan_results": scan_results,
                "findings": all_findings,
            }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(json_report, f, ensure_ascii=False, indent=2)

            json_display_path = _format_output_path_for_display(
                config.json_output, output_path, workspace
            )
            console.print(f"  [green]✓[/green] JSON report saved: {json_display_path}")
            set_github_output("json-file", json_display_path)
        except Exception as e:
            console.print(f"  [yellow]⚠[/yellow] JSON report generation failed: {e}")

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
                sarif_upload_path = (
                    str(resolved_sarif_output) if resolved_sarif_output else config.sarif_output
                )
                upload_result = github.upload_sarif(
                    sarif_path=sarif_upload_path,
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

                    # 스캐너 실행 실패 요약 코멘트 (리포트 전용 모드에서 가시성 강화)
                    if scanner_runtime_errors:
                        comment_body = format_scanner_runtime_error_comment(scanner_runtime_errors)
                        if github.create_pr_comment(comment_body):
                            console.print(
                                "  [yellow]⚠[/yellow] PR comment posted for scanner runtime errors"
                            )

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

    console.print("\n[bold cyan]📝 Creating workflow annotations...[/bold cyan]")

    created = 0
    workspace = _get_workspace()

    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        level = level_map.get(severity, "warning")

        raw_file_path = str(finding.get("file_path", "")).strip()
        if not raw_file_path:
            continue

        normalized_path = _normalize_workflow_annotation_path(raw_file_path, workspace)
        if not normalized_path:
            continue

        file_path = _escape_workflow_command_property(normalized_path)
        line_start = _safe_positive_int(finding.get("line_start"), default=1)
        line_end = _safe_positive_int(finding.get("line_end"), default=line_start)
        line_end = max(line_start, line_end)

        rule_id = finding.get("rule_id", "unknown")
        scanner = finding.get("scanner", "unknown")
        message_text = _truncate_text(
            _redact_sensitive_text(str(finding.get("message", "Security issue detected"))),
            MAX_WORKFLOW_ANNOTATION_MESSAGE_LENGTH,
        )
        message = _escape_workflow_command_data(message_text)

        # GitHub Actions workflow command 출력
        # 형식: ::{level} file={path},line={line},endLine={endLine},title={title}::{message}
        annotation = (
            f"::{level} file={file_path},line={line_start},endLine={line_end},"
            f"title={_escape_workflow_command_property(f'[{scanner}] {rule_id}')}::{message}"
        )
        print(annotation)
        created += 1

    console.print(f"  [green]✓[/green] {created} annotations created")


def collect_scanner_runtime_errors(results: list[ScanResult]) -> list[dict]:
    """스캐너 런타임 실패 목록 추출."""
    errors: list[dict] = []
    for result in results:
        if result.success:
            continue
        sanitized_message = _sanitize_runtime_error_message(result.error)
        errors.append(
            {
                "scanner": result.scanner,
                "message": sanitized_message,
            }
        )
    return errors


def _redact_sensitive_text(value: str) -> str:
    """로그/코멘트 노출 전에 민감정보를 마스킹한다."""
    text = str(value or "")
    if not text:
        return ""

    redacted = text
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        "***REDACTED_PRIVATE_KEY***",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(r"(?i)\b(authorization)\s*:\s*bearer\s+[^\s]+", r"\1: Bearer ***", redacted)
    redacted = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{8,}", "Bearer ***", redacted)
    redacted = re.sub(r"\bgh[pousr]_[A-Za-z0-9_]{10,}\b", "***", redacted)
    redacted = re.sub(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "***", redacted)
    redacted = re.sub(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{12,}\b", "***", redacted)
    redacted = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "***", redacted)
    redacted = re.sub(
        r"(?i)\b(api[_-]?key|token|password|secret)\b\s*[:=]\s*([^\s,;]+)",
        r"\1=***",
        redacted,
    )
    return redacted


def _truncate_text(value: str, limit: int) -> str:
    """텍스트를 지정 길이로 제한한다."""
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def print_scanner_runtime_error_annotations(scanner_errors: list[dict]) -> None:
    """스캐너 런타임 실패를 GitHub Actions annotation으로 출력."""
    if not scanner_errors:
        return

    console.print(
        f"\n[bold yellow]⚠ Creating {len(scanner_errors)} scanner failure annotation(s)...[/bold yellow]"
    )
    for scanner_error in scanner_errors:
        scanner = _escape_workflow_command_property(
            str(scanner_error.get("scanner", "Unknown Scanner"))
        )
        message = _escape_workflow_command_data(
            str(scanner_error.get("message", "Scanner execution failed"))
        )
        print(f"::error title=Scanner Failure ({scanner})::{message}")

    console.print(
        f"  [yellow]⚠[/yellow] {len(scanner_errors)} scanner failure annotation(s) created"
    )


def format_scanner_runtime_error_comment(scanner_errors: list[dict]) -> str:
    """PR/이슈 코멘트용 스캐너 실패 요약 생성."""
    lines = [
        "## ⚠️ Scanner Runtime Errors",
        "",
        "One or more scanners failed to execute. Findings may be incomplete.",
        "",
    ]

    for scanner_error in scanner_errors[:10]:
        scanner = str(scanner_error.get("scanner", "Unknown Scanner"))
        message = str(scanner_error.get("message", "Scanner execution failed")).strip()
        if len(message) > 300:
            message = message[:300] + "..."
        lines.append(f"- **{scanner}**: {message}")

    if len(scanner_errors) > 10:
        lines.append(f"- ... and {len(scanner_errors) - 10} more scanner failure(s)")

    lines.extend(
        [
            "",
            "Please check the workflow logs for full stack traces and environment details.",
        ]
    )

    return "\n".join(lines)


def build_scanner_runtime_error_findings(scanner_errors: list[dict]) -> list[dict]:
    """Required Check 결론 계산에 사용할 스캐너 실패 finding 생성."""
    findings: list[dict] = []
    for scanner_error in scanner_errors:
        scanner = str(scanner_error.get("scanner", "Unknown Scanner")).strip() or "Unknown Scanner"
        message = str(scanner_error.get("message", "Scanner execution failed")).strip()
        if len(message) > 500:
            message = message[:500] + "..."
        findings.append(
            {
                "scanner": scanner,
                "rule_id": "SCANNER_RUNTIME_FAILURE",
                "severity": "critical",
                "message": f"{scanner} failed to execute: {message}",
                "file_path": "",
                "line_start": 1,
            }
        )
    return findings


def load_yaml_runtime_config(config: Config, workspace: str) -> tuple[Any | None, str | None]:
    """실행 시점 YAML 설정 파일 로드."""
    try:
        from config.loader import find_config_file, load_config
    except ImportError:
        return None, None

    config_file: Path | None
    if config.config_path:
        config_file = Path(config.config_path).expanduser()
        if not config_file.is_absolute():
            config_file = Path(workspace) / config_file
        config_file = config_file.resolve(strict=False)
    else:
        config_file = find_config_file(workspace)
        if config_file is not None:
            config_file = config_file.resolve(strict=False)

    if (
        config_file
        and os.getenv("GITHUB_ACTIONS", "").lower() == "true"
        and not _is_within_workspace(config_file, Path(workspace).resolve(strict=False))
    ):
        logger.warning("Ignoring config path outside workspace in GitHub Actions: %s", config_file)
        return None, str(config_file)

    if not config_file or not config_file.exists():
        return None, None

    try:
        yaml_config = load_config(config_path=config_file, workspace=workspace)
        return yaml_config, str(config_file)
    except Exception as e:
        logger.warning("Failed to load YAML config %s: %s", config_file, e)
        return None, str(config_file)


def _is_explicit_field(model: Any, field_name: str) -> bool:
    """설정 모델에서 필드가 명시적으로 지정되었는지 확인."""
    fields_set = getattr(model, "model_fields_set", None)
    if fields_set is None:
        return True
    return field_name in fields_set


def _is_explicit_nested_field(config_model: Any, section_name: str, field_name: str) -> bool:
    """중첩 설정(section.field)이 명시적으로 지정되었는지 확인."""
    section = getattr(config_model, section_name, None)
    if section is None:
        return False

    root_fields_set = getattr(config_model, "model_fields_set", None)
    if root_fields_set is not None and section_name not in root_fields_set:
        return False

    return _is_explicit_field(section, field_name)


def _resolve_path_from_workspace(workspace: str, path_value: str | None) -> str | None:
    if not path_value:
        return None
    workspace_path = Path(workspace).resolve(strict=False)
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        path = workspace_path / path
    resolved = path.resolve(strict=False)

    if os.getenv("GITHUB_ACTIONS", "").lower() == "true" and not _is_within_workspace(
        resolved, workspace_path
    ):
        logger.warning("Ignoring path outside workspace in GitHub Actions: %s", path_value)
        return None

    return str(resolved)


def _is_within_workspace(path: Path, workspace_path: Path) -> bool:
    """경로가 workspace 내부(또는 동일 경로)인지 확인."""
    if path == workspace_path or workspace_path in path.parents:
        return True

    path_norm = str(path).replace("\\", "/").rstrip("/")
    workspace_norm = str(workspace_path).replace("\\", "/").rstrip("/")

    # Windows 드라이브 문자는 대소문자를 무시해 비교한다.
    if _is_windows_absolute_path(path_norm) and _is_windows_absolute_path(workspace_norm):
        path_fold = path_norm.casefold()
        workspace_fold = workspace_norm.casefold()
        return path_fold == workspace_fold or path_fold.startswith(workspace_fold + "/")

    return False


def apply_yaml_runtime_overrides(config: Config, yaml_config: Any, workspace: str) -> None:
    """YAML 설정을 런타임 Config에 반영."""
    if _is_explicit_nested_field(yaml_config, "gitleaks", "enabled"):
        config.secret_scan = bool(yaml_config.gitleaks.enabled)
    if _is_explicit_nested_field(yaml_config, "semgrep", "enabled"):
        config.code_scan = bool(yaml_config.semgrep.enabled)
    if _is_explicit_nested_field(yaml_config, "trivy", "enabled"):
        config.dependency_scan = bool(yaml_config.trivy.enabled)
    if _is_explicit_nested_field(yaml_config, "sonarqube", "enabled"):
        config.sonar_scan = bool(yaml_config.sonarqube.enabled)
    if _is_explicit_nested_field(yaml_config, "ai_review", "enabled"):
        config.ai_review = bool(yaml_config.ai_review.enabled)
    if _is_explicit_nested_field(yaml_config, "reporting", "sarif_output"):
        sarif_output = yaml_config.reporting.sarif_output
        if sarif_output is None or not str(sarif_output).strip():
            logger.warning(
                "Ignoring empty reporting.sarif_output from YAML config; keeping %s",
                config.sarif_output,
            )
        else:
            config.sarif_output = str(sarif_output).strip()
    if _is_explicit_nested_field(yaml_config, "reporting", "json_output"):
        json_output = yaml_config.reporting.json_output
        if json_output is None or not str(json_output).strip():
            config.json_output = None
        else:
            config.json_output = str(json_output).strip()
    if _is_explicit_nested_field(yaml_config, "reporting", "fail_on_findings"):
        config.fail_on_findings = bool(yaml_config.reporting.fail_on_findings)
    if _is_explicit_nested_field(yaml_config, "reporting", "fail_on_severity"):
        fail_on_severity = str(yaml_config.reporting.fail_on_severity or "high")
        try:
            config.severity_threshold = Severity.from_string(fail_on_severity)
        except ValueError:
            logger.warning("Invalid fail_on_severity in YAML config: %s", fail_on_severity)

    # 스캐너가 INPUT_* 값을 직접 참조하므로 필요한 설정은 env에도 반영.
    if _is_explicit_nested_field(yaml_config, "gitleaks", "config_path"):
        gitleaks_config_path = _resolve_path_from_workspace(
            workspace, yaml_config.gitleaks.config_path
        )
        if gitleaks_config_path:
            os.environ["INPUT_GITLEAKS_CONFIG"] = gitleaks_config_path
    if _is_explicit_nested_field(yaml_config, "gitleaks", "baseline_path"):
        gitleaks_baseline_path = _resolve_path_from_workspace(
            workspace, yaml_config.gitleaks.baseline_path
        )
        if gitleaks_baseline_path:
            os.environ["INPUT_GITLEAKS_BASELINE"] = gitleaks_baseline_path

    if _is_explicit_nested_field(yaml_config, "sonarqube", "host_url"):
        host_url = str(yaml_config.sonarqube.host_url or "").strip()
        if host_url:
            os.environ["SONAR_HOST_URL"] = host_url
    if _is_explicit_nested_field(yaml_config, "sonarqube", "project_key"):
        project_key = str(yaml_config.sonarqube.project_key or "").strip()
        if project_key:
            os.environ["SONAR_PROJECT_KEY"] = project_key

    if _is_explicit_nested_field(yaml_config, "ai_review", "enabled"):
        os.environ["INPUT_AI_REVIEW"] = str(config.ai_review).lower()
    if (
        _is_explicit_nested_field(yaml_config, "ai_review", "provider")
        and yaml_config.ai_review.provider
    ):
        os.environ["INPUT_AI_PROVIDER"] = str(yaml_config.ai_review.provider)
    if _is_explicit_nested_field(yaml_config, "ai_review", "model") and yaml_config.ai_review.model:
        os.environ["INPUT_AI_MODEL"] = str(yaml_config.ai_review.model)


def apply_global_excludes(
    findings: list[dict], exclude_patterns: list[str] | None
) -> tuple[list[dict], list[dict]]:
    """global_excludes 패턴으로 결과 필터링."""
    if not exclude_patterns:
        return findings, []

    filtered: list[dict] = []
    suppressed: list[dict] = []

    for finding in findings:
        file_path = str(finding.get("file_path", "")).replace("\\", "/")
        candidates = [file_path, f"/{file_path}"]
        matched_pattern = next(
            (
                pattern
                for pattern in exclude_patterns
                if any(fnmatch(path, pattern) for path in candidates)
            ),
            None,
        )
        if matched_pattern:
            suppressed_finding = dict(finding)
            suppressed_finding["suppress_reason"] = (
                f"Matched global_excludes pattern: {matched_pattern}"
            )
            suppressed.append(suppressed_finding)
        else:
            filtered.append(finding)

    return filtered, suppressed


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
    _configure_runtime_verbosity()
    print_banner()

    # 설정 로드
    config = Config.from_env()
    workspace = _get_workspace()
    # 로컬 실행(`python src/main.py`)에서도 경로 정규화 기준이 일관되도록
    # 런타임 workspace를 환경 변수에 보장한다.
    os.environ["GITHUB_WORKSPACE"] = workspace
    yaml_config, yaml_config_path = load_yaml_runtime_config(config, workspace)
    if yaml_config:
        apply_yaml_runtime_overrides(config, yaml_config, workspace)
        console.print(f"[dim]YAML config loaded: {yaml_config_path}[/dim]")
    elif config.config_path:
        console.print(
            f"[yellow]⚠[/yellow] Config path not found or unreadable: {config.config_path}"
        )

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
    console.print(f"  JSON Output: {config.json_output or '(disabled)'}")
    console.print(f"  Fail on SARIF upload error: {config.fail_on_sarif_upload_error}")
    console.print(f"  Usage Tracking: {config.usage_tracking} (local-only)")
    console.print(f"  Parallel Execution: {config.parallel}")
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
    scanner_runtime_errors = collect_scanner_runtime_errors(results)

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

    # 설정 기반 필터링 (global_excludes + false_positives)
    suppressed_findings = []

    if yaml_config and yaml_config.global_excludes:
        all_findings, global_suppressed = apply_global_excludes(
            all_findings, yaml_config.global_excludes
        )
        suppressed_findings.extend(global_suppressed)

        if global_suppressed:
            console.print(
                f"\n[dim]ℹ️  {len(global_suppressed)} finding(s) suppressed by global_excludes[/dim]"
            )
            for sf in global_suppressed[:5]:
                console.print(
                    f"   [dim]- {sf.get('rule_id', 'Unknown')}: {sf.get('suppress_reason', 'No reason')}[/dim]"
                )
            if len(global_suppressed) > 5:
                console.print(f"   [dim]... and {len(global_suppressed) - 5} more[/dim]")

    try:
        from config.false_positives import FalsePositiveManager, create_fp_rules_from_config

        if yaml_config and yaml_config.false_positives:
            fp_rules = create_fp_rules_from_config(
                [fp.model_dump() for fp in yaml_config.false_positives]
            )
            fp_manager = FalsePositiveManager(fp_rules)

            # 베이스라인 로드 (있는 경우)
            baseline_path = os.path.join(workspace, ".security-baseline.json")
            fp_manager.load_baseline(baseline_path)

            # 필터링 적용
            all_findings, fp_suppressed = fp_manager.filter_findings(all_findings)
            suppressed_findings.extend(fp_suppressed)

            if fp_suppressed:
                console.print(
                    f"\n[dim]ℹ️  {len(fp_suppressed)} finding(s) suppressed by false positive rules[/dim]"
                )
                for sf in fp_suppressed[:5]:
                    console.print(
                        f"   [dim]- {sf.get('rule_id', 'Unknown')}: {sf.get('suppress_reason', 'No reason')}[/dim]"
                    )
                if len(fp_suppressed) > 5:
                    console.print(f"   [dim]... and {len(fp_suppressed) - 5} more[/dim]")

            logger.info(
                f"False positive filtering: {len(suppressed_findings)} suppressed, "
                f"{len(all_findings)} remaining"
            )
    except ImportError as e:
        logger.warning(f"False positive filtering unavailable: {e}")
    except Exception as e:
        logger.error(f"False positive filtering failed: {e}")

    set_findings_count_outputs(all_findings)

    # AI 리뷰 실행 (필터링된 finding 기준)
    ai_review_result = None
    if config.ai_review:
        ai_review_result = run_ai_review(
            results,
            config,
            github_reporter,
            prefiltered_findings=all_findings,
        )

    # GitHub Actions 워크플로우 annotation 출력 (UI에 직접 표시)
    print_workflow_annotations(all_findings)
    print_scanner_runtime_error_annotations(scanner_runtime_errors)

    # SBOM 생성
    if config.sbom_generate:
        console.print("\n[bold cyan]📦 Generating SBOM...[/bold cyan]")
        try:
            from scanners.sbom_generator import generate_sbom

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
        results,
        all_findings,
        config,
        ai_review_result,
        github_reporter,
        scanner_runtime_errors=scanner_runtime_errors,
    )

    sarif_upload_blocking = (
        sarif_upload_failed and config.upload_sarif and config.fail_on_sarif_upload_error
    )

    if sarif_upload_blocking:
        console.print(
            "\n[bold red]❌ SARIF upload failed and fail-on-sarif-upload-error=true[/bold red]"
        )

    # GitHub Actions 출력
    set_github_output("scan-results", json.dumps(all_findings))

    # 총 실행 시간 계산
    total_execution_time = time.time() - scan_start_time

    required_check_findings = list(all_findings)
    required_check_findings.extend(build_scanner_runtime_error_findings(scanner_runtime_errors))
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
            console.print(
                f"  Creating Required Check with {len(required_check_findings)} finding(s)..."
            )
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

    if scanner_runtime_errors:
        if config.fail_on_findings:
            console.print(
                "\n[bold red]❌ Security scan failed due to scanner runtime errors "
                "(fail-on-findings=true)[/bold red]"
            )
            return 1

        console.print(
            "\n[bold yellow]⚠ Security scan completed with scanner runtime errors[/bold yellow]"
        )
        return 0

    console.print("\n[bold green]✅ Security scan completed successfully[/bold green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
