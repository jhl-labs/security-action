"""GitHub 리포터 - PR 코멘트 및 Check Run

GHAS(GitHub Advanced Security) 스타일의 Check Run 및 Status 관리:
- Required Status Check용 통합 체크 ("Security scan results")
- 스캐너별 개별 Check Run
- Commit Status API 지원
- Severity threshold 기반 결론 결정
"""

import logging
import os
from dataclasses import dataclass
from enum import Enum

from github import Github
from github.CheckRun import CheckRun
from github.GithubException import GithubException
from github.PullRequest import PullRequest
from github.Repository import Repository

logger = logging.getLogger(__name__)


class CheckConclusion(Enum):
    """Check Run 결론 상태 (GHAS 호환)"""

    SUCCESS = "success"
    FAILURE = "failure"
    NEUTRAL = "neutral"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    ACTION_REQUIRED = "action_required"  # 수동 검토 필요


class CommitState(Enum):
    """Commit Status 상태"""

    PENDING = "pending"
    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"


@dataclass
class FindingComment:
    """PR 코멘트용 취약점 정보"""

    file_path: str
    line: int
    severity: str
    title: str
    message: str
    suggestion: str | None = None
    code_fix: str | None = None


@dataclass
class CheckRunContext:
    """Check Run 컨텍스트 - 진행 상태 추적용"""

    check_run: CheckRun
    name: str
    scanner: str
    annotations_count: int = 0


class GitHubReporter:
    """GitHub API를 통한 리포팅 (GHAS 스타일)

    GHAS(GitHub Advanced Security)와 유사한 방식으로 Check Run 및 Status 관리:
    - Required Status Check: "Security scan results" (브랜치 보호에 사용 가능)
    - 스캐너별 Check Run: Secret Scan, Code Scan, Dependency Scan 등
    - Commit Status: PR 목록에서 보이는 상태 아이콘
    - Severity Threshold: 설정된 심각도 이상에서 실패 처리
    """

    # GHAS 스타일 통합 체크 이름 (Required Status Check로 사용)
    REQUIRED_CHECK_NAME = "Security scan results"

    SEVERITY_EMOJI = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }

    # 심각도 순서 (비교용)
    SEVERITY_ORDER = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }

    SCANNER_INFO = {
        "Gitleaks": {
            "name": "Secret Scan",
            "icon": "🔐",
            "description": "Scans for hardcoded secrets, API keys, and credentials",
            "context": "security/secret-scan",
        },
        "Semgrep": {
            "name": "Code Scan",
            "icon": "🔍",
            "description": "Static analysis for security vulnerabilities (SAST)",
            "context": "security/code-scan",
        },
        "Trivy": {
            "name": "Dependency Scan",
            "icon": "📦",
            "description": "Scans dependencies for known vulnerabilities (SCA)",
            "context": "security/dependency-scan",
        },
        "Trivy-Container": {
            "name": "Container Scan",
            "icon": "🐳",
            "description": "Scans container images for vulnerabilities",
            "context": "security/container-scan",
        },
        "Checkov": {
            "name": "IaC Scan",
            "icon": "🏗️",
            "description": "Infrastructure as Code security scanning",
            "context": "security/iac-scan",
        },
        "SonarQube": {
            "name": "SonarQube Scan",
            "icon": "🔬",
            "description": "Deep code analysis and security hotspots",
            "context": "security/sonarqube",
        },
        "AI Review": {
            "name": "AI Security Review",
            "icon": "🤖",
            "description": "AI-powered security analysis and remediation suggestions",
            "context": "security/ai-review",
        },
    }

    # GitHub API 제한: 한 번에 최대 50개 어노테이션
    MAX_ANNOTATIONS_PER_REQUEST = 50

    def __init__(
        self,
        token: str | None = None,
        severity_threshold: str = "high",
        fail_on_findings: bool = True,
    ):
        """GitHubReporter 초기화

        Args:
            token: GitHub 토큰
            severity_threshold: 실패 처리할 최소 심각도 (critical, high, medium, low)
            fail_on_findings: 취약점 발견 시 실패 처리 여부
        """
        self.token = token or os.getenv("GITHUB_TOKEN") or os.getenv("INPUT_GITHUB_TOKEN")
        self.severity_threshold = severity_threshold.lower()
        self.fail_on_findings = fail_on_findings
        self.github: Github | None = None
        self.repo: Repository | None = None
        self.pr: PullRequest | None = None
        self._active_check_runs: dict[str, CheckRunContext] = {}
        self._required_check: CheckRun | None = None

        if self.token:
            self.github = Github(self.token)
            self._init_context()

    def _init_context(self) -> None:
        """GitHub Actions 컨텍스트 초기화"""
        repo_name = os.getenv("GITHUB_REPOSITORY")
        if not repo_name or not self.github:
            return

        try:
            self.repo = self.github.get_repo(repo_name)

            # PR 번호 추출
            pr_number = self._get_pr_number()
            if pr_number:
                self.pr = self.repo.get_pull(pr_number)
        except Exception:
            pass

    def _get_pr_number(self) -> int | None:
        """PR 번호 가져오기"""
        # GITHUB_REF에서 추출 (refs/pull/123/merge)
        ref = os.getenv("GITHUB_REF", "")
        if "/pull/" in ref:
            try:
                return int(ref.split("/pull/")[1].split("/")[0])
            except (ValueError, IndexError):
                pass

        # GITHUB_EVENT_PATH에서 추출
        event_path = os.getenv("GITHUB_EVENT_PATH")
        if event_path:
            try:
                import json

                with open(event_path) as f:
                    event = json.load(f)
                    if "pull_request" in event:
                        return event["pull_request"]["number"]
            except Exception:
                pass

        return None

    def is_available(self) -> bool:
        """GitHub API 사용 가능 여부"""
        return self.github is not None and self.repo is not None

    def is_pr_context(self) -> bool:
        """PR 컨텍스트 여부"""
        return self.pr is not None

    # =========================================================================
    # GHAS 스타일: Required Status Check (브랜치 보호용)
    # =========================================================================

    def start_required_check(self) -> bool:
        """Required Status Check 시작 (GHAS의 "Code scanning results" 역할)

        브랜치 보호 규칙에서 이 체크를 필수로 설정하면 PR 머지 전 통과 필요.

        Returns:
            성공 여부
        """
        if not self.repo:
            return False

        sha = self._get_sha()
        if not sha:
            return False

        try:
            self._required_check = self.repo.create_check_run(
                name=self.REQUIRED_CHECK_NAME,
                head_sha=sha,
                status="in_progress",
                output={
                    "title": "Security scan in progress...",
                    "summary": "⏳ Running security scans. Please wait.",
                },
            )
            logger.info(f"Started required check: {self.REQUIRED_CHECK_NAME}")
            return True
        except GithubException as e:
            logger.error(f"Failed to start required check: {e}")
            return False

    def complete_required_check(
        self,
        all_findings: list[dict],
        scan_results: list[dict],
        execution_time: float = 0.0,
    ) -> bool:
        """Required Status Check 완료

        Args:
            all_findings: 전체 취약점 목록
            scan_results: 스캐너별 결과
            execution_time: 총 실행 시간

        Returns:
            성공 여부
        """
        if not self.repo:
            return False

        sha = self._get_sha()
        if not sha:
            return False

        # Severity threshold 기반 결론 결정
        conclusion, title = self._determine_conclusion_with_threshold(all_findings)

        # Summary 생성
        summary = self._generate_required_check_summary(all_findings, scan_results, execution_time)

        try:
            if self._required_check:
                self._required_check.edit(
                    status="completed",
                    conclusion=conclusion.value,
                    output={
                        "title": title,
                        "summary": summary,
                    },
                )
            else:
                self.repo.create_check_run(
                    name=self.REQUIRED_CHECK_NAME,
                    head_sha=sha,
                    status="completed",
                    conclusion=conclusion.value,
                    output={
                        "title": title,
                        "summary": summary,
                    },
                )

            logger.info(f"Completed required check: {conclusion.value} - {title}")
            return True
        except GithubException as e:
            logger.error(f"Failed to complete required check: {e}")
            return False

    def _determine_conclusion_with_threshold(
        self, findings: list[dict]
    ) -> tuple[CheckConclusion, str]:
        """Severity threshold 기반 결론 결정

        Args:
            findings: 취약점 목록

        Returns:
            (CheckConclusion, title) 튜플
        """
        if not findings:
            return CheckConclusion.SUCCESS, "✅ No security issues found"

        if not self.fail_on_findings:
            return (
                CheckConclusion.NEUTRAL,
                f"⚠️ Found {len(findings)} issues (fail-on-findings disabled)",
            )

        # Threshold 이상 심각도 카운트
        threshold_level = self.SEVERITY_ORDER.get(self.severity_threshold, 4)
        critical_findings = []

        for f in findings:
            sev = f.get("severity", "medium").lower()
            sev_level = self.SEVERITY_ORDER.get(sev, 3)
            if sev_level >= threshold_level:
                critical_findings.append(f)

        if critical_findings:
            # 가장 높은 심각도 찾기
            max_severity = max(
                (f.get("severity", "medium").lower() for f in critical_findings),
                key=lambda s: self.SEVERITY_ORDER.get(s, 0),
            )
            emoji = self.SEVERITY_EMOJI.get(max_severity, "🔴")
            return (
                CheckConclusion.FAILURE,
                f"{emoji} Found {len(critical_findings)} {self.severity_threshold}+ severity issues",
            )

        # Threshold 미만 이슈만 있는 경우
        return (
            CheckConclusion.NEUTRAL,
            f"⚠️ Found {len(findings)} issues (below {self.severity_threshold} threshold)",
        )

    def _generate_required_check_summary(
        self,
        all_findings: list[dict],
        scan_results: list[dict],
        execution_time: float,
    ) -> str:
        """Required Check용 summary 생성"""
        lines = [
            "# Security Scan Results",
            "",
            f"⏱️ **Total scan time:** {execution_time:.2f}s",
            "",
        ]

        # 스캐너 결과 테이블
        lines.extend(
            [
                "## Scanners",
                "",
                "| Scanner | Status | Findings |",
                "|---------|--------|----------|",
            ]
        )

        for result in scan_results:
            scanner = result.get("scanner", "Unknown")
            info = self.SCANNER_INFO.get(scanner, {})
            icon = info.get("icon", "🔍")
            status = "✅" if result.get("success") else "❌"
            count = result.get("findings_count", 0)
            lines.append(f"| {icon} {scanner} | {status} | {count} |")

        # 심각도별 요약
        if all_findings:
            severity_counts = {}
            for f in all_findings:
                sev = f.get("severity", "unknown").lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            lines.extend(["", "## Findings by Severity", ""])

            for severity in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    emoji = self.SEVERITY_EMOJI.get(severity, "⚪")
                    marker = (
                        " ⬅️ **BLOCKING**"
                        if (
                            self.fail_on_findings
                            and self.SEVERITY_ORDER.get(severity, 0)
                            >= self.SEVERITY_ORDER.get(self.severity_threshold, 4)
                        )
                        else ""
                    )
                    lines.append(f"- {emoji} **{severity.upper()}**: {count}{marker}")

            lines.append(f"\n**Total: {len(all_findings)} issues**")
            lines.append(f"\n> Threshold: `{self.severity_threshold}` severity and above")
        else:
            lines.extend(
                [
                    "",
                    "## ✅ No Issues Found",
                    "",
                    "All security scans completed successfully.",
                ]
            )

        return "\n".join(lines)

    # =========================================================================
    # Commit Status API (PR 목록에서 보이는 상태)
    # =========================================================================

    def create_commit_status(
        self,
        state: CommitState,
        context: str,
        description: str,
        target_url: str | None = None,
    ) -> bool:
        """Commit Status 생성

        PR 목록에서 보이는 상태 아이콘을 설정합니다.

        Args:
            state: 상태 (pending, success, failure, error)
            context: 컨텍스트 이름 (예: "security/code-scan")
            description: 상태 설명 (140자 제한)
            target_url: 상세 정보 링크

        Returns:
            성공 여부
        """
        if not self.repo:
            return False

        sha = self._get_sha()
        if not sha:
            return False

        try:
            commit = self.repo.get_commit(sha)
            commit.create_status(
                state=state.value,
                context=context,
                description=description[:140],  # GitHub 제한
                target_url=target_url,
            )
            logger.debug(f"Created commit status: {context} = {state.value}")
            return True
        except GithubException as e:
            logger.error(f"Failed to create commit status: {e}")
            return False

    def create_scanner_status(
        self,
        scanner: str,
        state: CommitState,
        findings_count: int = 0,
        target_url: str | None = None,
    ) -> bool:
        """스캐너별 Commit Status 생성

        Args:
            scanner: 스캐너 이름
            state: 상태
            findings_count: 발견된 취약점 수
            target_url: 상세 정보 링크

        Returns:
            성공 여부
        """
        info = self.SCANNER_INFO.get(scanner, {})
        context = info.get("context", f"security/{scanner.lower()}")

        if state == CommitState.PENDING:
            description = f"{scanner} scan in progress..."
        elif state == CommitState.SUCCESS:
            if findings_count == 0:
                description = "No issues found"
            else:
                description = f"Found {findings_count} issues (none blocking)"
        elif state == CommitState.FAILURE:
            description = f"Found {findings_count} blocking issues"
        else:
            description = f"{scanner} scan error"

        return self.create_commit_status(state, context, description, target_url)

    def create_overall_status(
        self,
        findings: list[dict],
        target_url: str | None = None,
    ) -> bool:
        """전체 보안 스캔 상태 생성

        Args:
            findings: 전체 취약점 목록
            target_url: 상세 정보 링크

        Returns:
            성공 여부
        """
        conclusion, _ = self._determine_conclusion_with_threshold(findings)

        if conclusion == CheckConclusion.SUCCESS:
            state = CommitState.SUCCESS
            description = "All security checks passed"
        elif conclusion == CheckConclusion.FAILURE:
            state = CommitState.FAILURE
            blocking_count = sum(
                1
                for f in findings
                if self.SEVERITY_ORDER.get(f.get("severity", "").lower(), 0)
                >= self.SEVERITY_ORDER.get(self.severity_threshold, 4)
            )
            description = f"Found {blocking_count} blocking security issues"
        else:
            state = CommitState.SUCCESS  # neutral은 success로 처리
            description = f"Found {len(findings)} issues (none blocking)"

        return self.create_commit_status(
            state=state,
            context="security/scan",
            description=description,
            target_url=target_url,
        )

    def create_pr_comment(self, body: str) -> bool:
        """PR에 일반 코멘트 생성"""
        if not self.pr:
            return False

        try:
            self.pr.create_issue_comment(body)
            return True
        except Exception:
            return False

    def create_pr_review(
        self,
        findings: list[FindingComment],
        summary: str | None = None,
    ) -> bool:
        """PR 리뷰 생성 (인라인 코멘트 포함)"""
        if not self.pr:
            return False

        try:
            # 변경된 파일 목록 가져오기
            changed_files = {f.filename for f in self.pr.get_files()}

            # 코멘트 생성
            comments = []
            for finding in findings:
                # 변경된 파일만 코멘트 가능
                if finding.file_path not in changed_files:
                    continue

                body = self._format_inline_comment(finding)
                comments.append(
                    {
                        "path": finding.file_path,
                        "line": finding.line,
                        "body": body,
                    }
                )

            # 리뷰 생성
            if comments:
                review_body = summary or self._generate_review_summary(findings)
                self.pr.create_review(
                    body=review_body,
                    event="COMMENT",
                    comments=comments[:50],  # GitHub API 제한
                )
                return True

            # 코멘트가 없으면 일반 코멘트로 대체
            if summary:
                return self.create_pr_comment(summary)

            return False

        except Exception:
            return False

    def _format_inline_comment(self, finding: FindingComment) -> str:
        """인라인 코멘트 포맷"""
        emoji = self.SEVERITY_EMOJI.get(finding.severity.lower(), "⚠️")
        lines = [
            f"## {emoji} {finding.severity.upper()}: {finding.title}",
            "",
            finding.message,
        ]

        if finding.suggestion:
            lines.extend(["", "**Suggestion:**", finding.suggestion])

        if finding.code_fix:
            lines.extend(
                [
                    "",
                    "**Suggested fix:**",
                    "```suggestion",
                    finding.code_fix,
                    "```",
                ]
            )

        return "\n".join(lines)

    def _generate_review_summary(self, findings: list[FindingComment]) -> str:
        """리뷰 요약 생성"""
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        lines = [
            "## 🛡️ Security Scan Results",
            "",
            f"Found **{len(findings)}** security issue(s):",
            "",
        ]

        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = self.SEVERITY_EMOJI[severity]
                lines.append(f"- {emoji} **{severity.upper()}**: {count}")

        lines.extend(
            [
                "",
                "---",
                "_🤖 Generated by Security Scanner Action_",
            ]
        )

        return "\n".join(lines)

    def create_check_run(
        self,
        name: str,
        title: str,
        summary: str,
        findings: list[dict],
        conclusion: str = "neutral",  # success, failure, neutral, cancelled, skipped, timed_out, action_required
    ) -> bool:
        """Check Run 생성"""
        if not self.repo:
            return False

        sha = os.getenv("GITHUB_SHA")
        if not sha:
            return False

        try:
            # GHAS 스타일 어노테이션 생성 (최대 50개)
            annotations = self._create_annotations(findings[:50])

            # Check Run 생성
            check_run = self.repo.create_check_run(
                name=name,
                head_sha=sha,
                status="completed",
                conclusion=conclusion,
                output={
                    "title": title,
                    "summary": summary,
                    "annotations": annotations,
                },
            )
            return check_run is not None

        except Exception:
            return False

    def _severity_to_annotation_level(self, severity: str) -> str:
        """심각도를 어노테이션 레벨로 변환"""
        mapping = {
            "critical": "failure",
            "high": "failure",
            "medium": "warning",
            "low": "notice",
            "info": "notice",
        }
        return mapping.get(severity.lower(), "warning")

    def _get_sha(self) -> str | None:
        """현재 커밋 SHA 가져오기"""
        return os.getenv("GITHUB_SHA")

    # =========================================================================
    # 스캐너별 Check Run 생성/관리
    # =========================================================================

    def start_scanner_check(self, scanner: str) -> CheckRunContext | None:
        """스캐너별 Check Run 시작 (in_progress 상태)

        Args:
            scanner: 스캐너 이름 (Gitleaks, Semgrep, Trivy, SonarQube, AI Review)

        Returns:
            CheckRunContext or None if failed
        """
        if not self.repo:
            return None

        sha = self._get_sha()
        if not sha:
            return None

        scanner_info = self.SCANNER_INFO.get(scanner, {})
        name = scanner_info.get("name", scanner)
        icon = scanner_info.get("icon", "🔍")
        description = scanner_info.get("description", f"Running {scanner}")

        try:
            check_run = self.repo.create_check_run(
                name=f"{icon} {name}",
                head_sha=sha,
                status="in_progress",
                output={
                    "title": f"{scanner} is running...",
                    "summary": f"⏳ {description}\n\nPlease wait while the scan completes.",
                },
            )

            context = CheckRunContext(
                check_run=check_run,
                name=name,
                scanner=scanner,
            )
            self._active_check_runs[scanner] = context
            return context

        except Exception:
            return None

    def update_scanner_check(
        self,
        scanner: str,
        findings_so_far: int = 0,
        message: str | None = None,
    ) -> bool:
        """스캐너 Check Run 진행 상태 업데이트

        Args:
            scanner: 스캐너 이름
            findings_so_far: 현재까지 발견된 취약점 수
            message: 추가 메시지

        Returns:
            성공 여부
        """
        context = self._active_check_runs.get(scanner)
        if not context:
            return False

        scanner_info = self.SCANNER_INFO.get(scanner, {})
        description = scanner_info.get("description", f"Running {scanner}")

        summary_lines = [
            f"⏳ {description}",
            "",
            f"**Findings so far:** {findings_so_far}",
        ]

        if message:
            summary_lines.extend(["", message])

        try:
            context.check_run.edit(
                status="in_progress",
                output={
                    "title": f"Scanning... ({findings_so_far} issues found)",
                    "summary": "\n".join(summary_lines),
                },
            )
            return True
        except Exception:
            return False

    def complete_scanner_check(
        self,
        scanner: str,
        findings: list[dict],
        execution_time: float = 0.0,
        error: str | None = None,
    ) -> bool:
        """스캐너 Check Run 완료

        Args:
            scanner: 스캐너 이름
            findings: 발견된 취약점 목록
            execution_time: 실행 시간 (초)
            error: 에러 메시지 (있는 경우)

        Returns:
            성공 여부
        """
        context = self._active_check_runs.get(scanner)

        # 컨텍스트가 없으면 새로 생성
        if not context:
            return self._create_completed_scanner_check(scanner, findings, execution_time, error)

        # 결론 결정
        conclusion, title = self._determine_conclusion(findings, error)

        # 마크다운 summary 생성
        summary = self._generate_scanner_summary(scanner, findings, execution_time, error)

        # 어노테이션 생성 (50개 이상 처리)
        all_annotations = self._create_annotations(findings)

        try:
            # 첫 번째 50개 어노테이션으로 완료
            first_batch = all_annotations[: self.MAX_ANNOTATIONS_PER_REQUEST]

            context.check_run.edit(
                status="completed",
                conclusion=conclusion,
                output={
                    "title": title,
                    "summary": summary,
                    "text": self._generate_findings_detail_text(findings),
                    "annotations": first_batch,
                },
            )

            # 50개 초과 시 추가 어노테이션 업데이트
            remaining = all_annotations[self.MAX_ANNOTATIONS_PER_REQUEST :]
            self._add_remaining_annotations(context.check_run, remaining, summary)

            # 컨텍스트 정리
            del self._active_check_runs[scanner]
            return True

        except Exception:
            return False

    def _create_completed_scanner_check(
        self,
        scanner: str,
        findings: list[dict],
        execution_time: float = 0.0,
        error: str | None = None,
    ) -> bool:
        """새로운 완료된 스캐너 Check Run 생성"""
        if not self.repo:
            return False

        sha = self._get_sha()
        if not sha:
            return False

        scanner_info = self.SCANNER_INFO.get(scanner, {})
        icon = scanner_info.get("icon", "🔍")
        name = scanner_info.get("name", scanner)

        conclusion, title = self._determine_conclusion(findings, error)
        summary = self._generate_scanner_summary(scanner, findings, execution_time, error)
        all_annotations = self._create_annotations(findings)

        try:
            first_batch = all_annotations[: self.MAX_ANNOTATIONS_PER_REQUEST]

            check_run = self.repo.create_check_run(
                name=f"{icon} {name}",
                head_sha=sha,
                status="completed",
                conclusion=conclusion,
                output={
                    "title": title,
                    "summary": summary,
                    "text": self._generate_findings_detail_text(findings),
                    "annotations": first_batch,
                },
            )

            # 50개 초과 시 추가 어노테이션 업데이트
            remaining = all_annotations[self.MAX_ANNOTATIONS_PER_REQUEST :]
            self._add_remaining_annotations(check_run, remaining, summary)

            return True

        except Exception:
            return False

    def _determine_conclusion(
        self,
        findings: list[dict],
        error: str | None = None,
    ) -> tuple[str, str]:
        """Check Run conclusion 및 title 결정

        Returns:
            (conclusion, title) 튜플
        """
        if error:
            return "failure", f"❌ Scan failed: {error[:50]}"

        if not findings:
            return "success", "✅ No issues found"

        # 심각도별 카운트
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "medium").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        critical_high = severity_counts["critical"] + severity_counts["high"]

        if critical_high > 0:
            return (
                "failure",
                f"🔴 Found {critical_high} critical/high issues ({len(findings)} total)",
            )
        elif severity_counts["medium"] > 0:
            return (
                "neutral",
                f"🟡 Found {severity_counts['medium']} medium issues ({len(findings)} total)",
            )
        else:
            return "success", f"✅ Found {len(findings)} low/info issues"

    def _generate_scanner_summary(
        self,
        scanner: str,
        findings: list[dict],
        execution_time: float = 0.0,
        error: str | None = None,
    ) -> str:
        """스캐너별 마크다운 summary 생성"""
        scanner_info = self.SCANNER_INFO.get(scanner, {})
        icon = scanner_info.get("icon", "🔍")
        description = scanner_info.get("description", scanner)

        lines = [
            f"## {icon} {scanner}",
            "",
            f"> {description}",
            "",
        ]

        if error:
            lines.extend(
                [
                    "### ❌ Scan Failed",
                    "",
                    f"```\n{error}\n```",
                ]
            )
            return "\n".join(lines)

        # 실행 시간
        if execution_time > 0:
            lines.append(f"⏱️ **Execution time:** {execution_time:.2f}s")
            lines.append("")

        if not findings:
            lines.extend(
                [
                    "### ✅ No Issues Found",
                    "",
                    "The scan completed successfully with no security issues detected.",
                ]
            )
            return "\n".join(lines)

        # 심각도별 카운트
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "medium").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        lines.extend(
            [
                "### 📊 Summary",
                "",
                "| Severity | Count |",
                "|----------|-------|",
            ]
        )

        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts[severity]
            if count > 0:
                emoji = self.SEVERITY_EMOJI.get(severity, "⚪")
                lines.append(f"| {emoji} {severity.upper()} | {count} |")

        lines.extend(
            [
                "",
                f"**Total issues:** {len(findings)}",
            ]
        )

        # 상위 5개 취약점 목록
        if findings:
            lines.extend(
                [
                    "",
                    "### 🔍 Top Issues",
                    "",
                ]
            )
            for i, f in enumerate(findings[:5], 1):
                emoji = self.SEVERITY_EMOJI.get(f.get("severity", ""), "⚪")
                rule_id = f.get("rule_id", "Unknown")
                file_path = f.get("file_path", "")
                line = f.get("line_start", 0)
                lines.append(f"{i}. {emoji} **{rule_id}** - `{file_path}:{line}`")

            if len(findings) > 5:
                lines.append(f"\n*...and {len(findings) - 5} more issues*")

        return "\n".join(lines)

    def _generate_findings_detail_text(self, findings: list[dict]) -> str:
        """상세 취약점 목록 텍스트 생성 (Check Run의 text 필드용)"""
        if not findings:
            return ""

        lines = ["## Detailed Findings", ""]

        for i, f in enumerate(findings[:20], 1):
            emoji = self.SEVERITY_EMOJI.get(f.get("severity", ""), "⚪")
            severity = f.get("severity", "unknown").upper()
            rule_id = f.get("rule_id", "Unknown")
            message = f.get("message", "")
            file_path = f.get("file_path", "")
            line_start = f.get("line_start", 0)
            line_end = f.get("line_end") or line_start

            lines.extend(
                [
                    f"### {i}. {emoji} {severity}: {rule_id}",
                    "",
                    f"**Location:** `{file_path}:{line_start}-{line_end}`",
                    "",
                    f"**Message:** {message}",
                    "",
                ]
            )

            if f.get("suggestion"):
                lines.extend([f"**Suggestion:** {f['suggestion']}", ""])

            lines.append("---")
            lines.append("")

        if len(findings) > 20:
            lines.append(f"*Showing 20 of {len(findings)} issues*")

        return "\n".join(lines)

    def _create_annotations(self, findings: list[dict]) -> list[dict]:
        """취약점 목록에서 GHAS 스타일 어노테이션 생성

        포맷 (파싱 용이):
        - title: "RULE_ID"
        - message: "SEVERITY|SCANNER|CWE|MESSAGE"
          예: "high|semgrep|CWE-89|SQL injection vulnerability"

        파싱 예시:
        ```python
        parts = message.split("|", 3)
        severity, scanner, cwe, desc = parts[0], parts[1], parts[2], parts[3]
        ```
        """
        annotations = []
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            scanner = finding.get("scanner", "unknown")
            rule_id = finding.get("rule_id", "UNKNOWN")
            message = finding.get("message", "Security issue detected")
            cwe = finding.get("cwe", finding.get("metadata", {}).get("cwe", ""))

            # GHAS 스타일 간결한 포맷: SEVERITY|SCANNER|CWE|MESSAGE
            structured_message = f"{severity}|{scanner}|{cwe}|{message}"

            annotations.append(
                {
                    "path": finding.get("file_path", ""),
                    "start_line": finding.get("line_start", 1),
                    "end_line": finding.get("line_end") or finding.get("line_start", 1),
                    "annotation_level": self._severity_to_annotation_level(severity),
                    "title": rule_id,
                    "message": structured_message,
                }
            )
        return annotations

    def _add_remaining_annotations(
        self,
        check_run: CheckRun,
        annotations: list[dict],
        summary: str,
    ) -> None:
        """50개 초과 어노테이션을 배치로 추가"""
        if not annotations:
            return

        for i in range(0, len(annotations), self.MAX_ANNOTATIONS_PER_REQUEST):
            batch = annotations[i : i + self.MAX_ANNOTATIONS_PER_REQUEST]
            try:
                check_run.edit(
                    output={
                        "title": check_run.output.title if check_run.output else "",
                        "summary": summary,
                        "annotations": batch,
                    }
                )
            except Exception:
                pass  # 실패해도 계속 진행

    # =========================================================================
    # 통합 Check Run (전체 보안 스캔 요약)
    # =========================================================================

    def create_summary_check_run(
        self,
        scan_results: list[dict],
        all_findings: list[dict],
        ai_summary: str | None = None,
    ) -> bool:
        """통합 보안 스캔 요약 Check Run 생성

        Args:
            scan_results: 스캐너별 결과 목록
            all_findings: 전체 취약점 목록
            ai_summary: AI 분석 요약 (선택)

        Returns:
            성공 여부
        """
        if not self.repo:
            return False

        sha = self._get_sha()
        if not sha:
            return False

        # 결론 결정
        conclusion, title = self._determine_conclusion(all_findings, None)

        # 통합 summary 생성
        summary = self._generate_summary_check_content(scan_results, all_findings, ai_summary)

        try:
            self.repo.create_check_run(
                name="🛡️ Security Scan Summary",
                head_sha=sha,
                status="completed",
                conclusion=conclusion,
                output={
                    "title": title,
                    "summary": summary,
                },
            )
            return True
        except Exception:
            return False

    def _generate_summary_check_content(
        self,
        scan_results: list[dict],
        all_findings: list[dict],
        ai_summary: str | None = None,
    ) -> str:
        """통합 summary 마크다운 생성"""
        lines = [
            "# 🛡️ Security Scan Report",
            "",
        ]

        # 스캐너별 결과 테이블
        lines.extend(
            [
                "## Scanner Results",
                "",
                "| Scanner | Status | Findings | Time |",
                "|---------|--------|----------|------|",
            ]
        )

        for result in scan_results:
            scanner = result.get("scanner", "Unknown")
            scanner_info = self.SCANNER_INFO.get(scanner, {})
            icon = scanner_info.get("icon", "🔍")

            status = "✅" if result.get("success") else "❌"
            findings_count = result.get("findings_count", 0)
            time_str = result.get("time", "N/A")

            lines.append(f"| {icon} {scanner} | {status} | {findings_count} | {time_str} |")

        # 심각도별 요약
        if all_findings:
            severity_counts = {}
            for f in all_findings:
                sev = f.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            lines.extend(
                [
                    "",
                    "## Findings by Severity",
                    "",
                ]
            )

            for severity in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    emoji = self.SEVERITY_EMOJI.get(severity, "⚪")
                    lines.append(f"- {emoji} **{severity.upper()}**: {count}")

            lines.append(f"\n**Total: {len(all_findings)} issues**")
        else:
            lines.extend(
                [
                    "",
                    "## ✅ No Security Issues Found",
                    "",
                    "All scans completed successfully with no vulnerabilities detected.",
                ]
            )

        # AI 분석 요약
        if ai_summary:
            lines.extend(
                [
                    "",
                    "## 🤖 AI Analysis Summary",
                    "",
                    ai_summary,
                ]
            )

        lines.extend(
            [
                "",
                "---",
                "_🤖 Generated by Security Scanner Action_",
            ]
        )

        return "\n".join(lines)

    # =========================================================================
    # AI Review 전용 Check Run
    # =========================================================================

    def start_ai_review_check(self) -> CheckRunContext | None:
        """AI Review Check Run 시작"""
        return self.start_scanner_check("AI Review")

    def complete_ai_review_check(
        self,
        reviews: list[dict],
        summary: str | None = None,
        execution_time: float = 0.0,
        error: str | None = None,
    ) -> bool:
        """AI Review Check Run 완료

        Args:
            reviews: AI 분석 결과 목록
            summary: AI 요약
            execution_time: 실행 시간
            error: 에러 메시지

        Returns:
            성공 여부
        """
        context = self._active_check_runs.get("AI Review")

        if not self.repo:
            return False

        sha = self._get_sha()
        if not sha:
            return False

        scanner_info = self.SCANNER_INFO["AI Review"]
        icon = scanner_info["icon"]
        name = scanner_info["name"]

        # 결론 결정
        if error:
            conclusion = "failure"
            title = f"❌ AI Review failed: {error[:50]}"
        elif not reviews:
            conclusion = "success"
            title = "✅ AI Review: No actionable issues"
        else:
            # 거짓 양성 제외한 실제 이슈 수 계산
            real_issues = sum(1 for r in reviews if not r.get("is_false_positive", False))
            if real_issues == 0:
                conclusion = "success"
                title = f"✅ All {len(reviews)} findings are likely false positives"
            else:
                conclusion = "neutral"
                title = f"🤖 AI reviewed {len(reviews)} findings ({real_issues} actionable)"

        # AI summary 생성
        summary_content = self._generate_ai_review_summary(reviews, summary, execution_time, error)

        try:
            if context:
                context.check_run.edit(
                    status="completed",
                    conclusion=conclusion,
                    output={
                        "title": title,
                        "summary": summary_content,
                        "text": self._generate_ai_review_detail(reviews) if reviews else "",
                    },
                )
                del self._active_check_runs["AI Review"]
            else:
                self.repo.create_check_run(
                    name=f"{icon} {name}",
                    head_sha=sha,
                    status="completed",
                    conclusion=conclusion,
                    output={
                        "title": title,
                        "summary": summary_content,
                        "text": self._generate_ai_review_detail(reviews) if reviews else "",
                    },
                )
            return True
        except Exception:
            return False

    def _generate_ai_review_summary(
        self,
        reviews: list[dict],
        summary: str | None,
        execution_time: float,
        error: str | None,
    ) -> str:
        """AI Review summary 마크다운 생성"""
        lines = [
            "## 🤖 AI Security Review",
            "",
            "> AI-powered analysis of security findings with remediation suggestions",
            "",
        ]

        if error:
            lines.extend([f"### ❌ Error\n\n```\n{error}\n```"])
            return "\n".join(lines)

        if execution_time > 0:
            lines.append(f"⏱️ **Analysis time:** {execution_time:.2f}s")
            lines.append("")

        if summary:
            lines.extend(["### 📝 Executive Summary", "", summary, ""])

        if reviews:
            false_positives = sum(1 for r in reviews if r.get("is_false_positive", False))
            real_issues = len(reviews) - false_positives

            lines.extend(
                [
                    "### 📊 Analysis Results",
                    "",
                    f"- **Total reviewed:** {len(reviews)}",
                    f"- **Actionable issues:** {real_issues}",
                    f"- **False positives:** {false_positives}",
                    "",
                ]
            )

        return "\n".join(lines)

    def _generate_ai_review_detail(self, reviews: list[dict]) -> str:
        """AI Review 상세 결과 텍스트 생성"""
        if not reviews:
            return ""

        lines = ["## Detailed AI Analysis", ""]

        for i, review in enumerate(reviews, 1):
            is_fp = review.get("is_false_positive", False)
            title = review.get("title", "Unknown Issue")
            file_path = review.get("file_path", "")
            line = review.get("line", 0)
            impact = review.get("impact", "")
            fix = review.get("fix", "")

            if is_fp:
                lines.extend(
                    [
                        f"### {i}. ⚪ {title} (False Positive)",
                        "",
                        f"**Location:** `{file_path}:{line}`",
                        "",
                        f"**Reason:** {review.get('false_positive_reason', 'N/A')}",
                        "",
                        "---",
                        "",
                    ]
                )
            else:
                severity = review.get("severity", "medium")
                emoji = self.SEVERITY_EMOJI.get(severity, "⚪")

                lines.extend(
                    [
                        f"### {i}. {emoji} {title}",
                        "",
                        f"**Severity:** {severity.upper()}",
                        f"**Location:** `{file_path}:{line}`",
                        "",
                    ]
                )

                if impact:
                    lines.extend([f"**Impact:** {impact}", ""])

                if fix:
                    lines.extend([f"**Remediation:** {fix}", ""])

                if review.get("code_fix"):
                    lines.extend(
                        [
                            "**Suggested fix:**",
                            "```",
                            review["code_fix"],
                            "```",
                            "",
                        ]
                    )

                lines.extend(["---", ""])

        return "\n".join(lines)

    def post_summary(
        self,
        findings: list[dict],
        scan_results: list[dict],
        ai_summary: str | None = None,
    ) -> str:
        """GitHub Actions Summary 생성 (Job Summary)"""
        lines = [
            "# 🛡️ Security Scan Report",
            "",
        ]

        # 스캐너 결과
        lines.extend(
            [
                "## Scanner Results",
                "",
                "| Scanner | Status | Findings | Time |",
                "|---------|--------|----------|------|",
            ]
        )

        for result in scan_results:
            status = "✅ Success" if result.get("success") else "❌ Failed"
            lines.append(
                f"| {result.get('scanner', 'Unknown')} | {status} | "
                f"{result.get('findings_count', 0)} | {result.get('time', 'N/A')} |"
            )

        # 심각도별 요약
        severity_counts = {}
        for f in findings:
            severity = f.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity_counts:
            lines.extend(
                [
                    "",
                    "## Findings by Severity",
                    "",
                ]
            )
            for severity in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    emoji = self.SEVERITY_EMOJI.get(severity, "⚪")
                    lines.append(f"- {emoji} **{severity.upper()}**: {count}")

        # AI 요약
        if ai_summary:
            lines.extend(
                [
                    "",
                    "## AI Analysis Summary",
                    "",
                    ai_summary,
                ]
            )

        # 상세 findings (상위 10개)
        if findings:
            lines.extend(
                [
                    "",
                    "## Top Findings",
                    "",
                ]
            )
            for i, f in enumerate(findings[:10], 1):
                emoji = self.SEVERITY_EMOJI.get(f.get("severity", ""), "⚪")
                lines.append(
                    f"{i}. {emoji} **{f.get('rule_id', 'Unknown')}** - "
                    f"`{f.get('file_path', '')}:{f.get('line_start', 0)}`"
                )
                lines.append(f"   {f.get('message', '')[:100]}")
                lines.append("")

        lines.extend(
            [
                "",
                "---",
                "_🤖 Generated by Security Scanner Action_",
            ]
        )

        summary = "\n".join(lines)

        # GITHUB_STEP_SUMMARY에 쓰기
        summary_file = os.getenv("GITHUB_STEP_SUMMARY")
        if summary_file:
            try:
                with open(summary_file, "a") as f:
                    f.write(summary)
            except Exception:
                pass

        return summary
