"""GitHub 리포터 - PR 코멘트 및 Check Run"""

import os
from dataclasses import dataclass

from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository


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


class GitHubReporter:
    """GitHub API를 통한 리포팅"""

    SEVERITY_EMOJI = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }

    def __init__(self, token: str | None = None):
        self.token = token or os.getenv("GITHUB_TOKEN") or os.getenv("INPUT_GITHUB_TOKEN")
        self.github: Github | None = None
        self.repo: Repository | None = None
        self.pr: PullRequest | None = None

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
            # 어노테이션 생성
            annotations = []
            for finding in findings[:50]:  # GitHub API 제한
                annotation_level = self._severity_to_annotation_level(
                    finding.get("severity", "medium")
                )
                annotations.append(
                    {
                        "path": finding.get("file_path", ""),
                        "start_line": finding.get("line_start", 1),
                        "end_line": finding.get("line_end") or finding.get("line_start", 1),
                        "annotation_level": annotation_level,
                        "title": finding.get("rule_id", "Security Issue"),
                        "message": finding.get("message", ""),
                    }
                )

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
