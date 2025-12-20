"""Secret Scanner - Gitleaks Wrapper"""

import json
import tempfile
from pathlib import Path

from .base import BaseScanner, Finding, Severity


class SecretScanner(BaseScanner):
    """Gitleaks를 사용한 비밀값 스캐너"""

    @property
    def name(self) -> str:
        return "Gitleaks"

    def _run_scan(self) -> tuple[bool, list[Finding], str | None]:
        """Gitleaks 스캔 실행"""
        findings: list[Finding] = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as report_file:
            report_path = report_file.name

        try:
            # Gitleaks 실행
            cmd = [
                "gitleaks",
                "detect",
                "--source",
                self.workspace,
                "--report-format",
                "json",
                "--report-path",
                report_path,
                "--no-git",  # git history 제외, 현재 파일만 스캔
            ]

            result = self.run_command(cmd)

            # exit code 1은 취약점 발견을 의미
            if result.returncode not in (0, 1):
                return False, [], f"Gitleaks failed: {result.stderr}"

            # 결과 파싱
            report_file_path = Path(report_path)
            if report_file_path.exists() and report_file_path.stat().st_size > 0:
                with open(report_path) as f:
                    raw_findings = json.load(f)

                for item in raw_findings:
                    finding = Finding(
                        scanner=self.name,
                        rule_id=item.get("RuleID", "unknown"),
                        severity=self._map_severity(item.get("RuleID", "")),
                        message=item.get("Description", "Secret detected"),
                        file_path=item.get("File", ""),
                        line_start=item.get("StartLine", 0),
                        line_end=item.get("EndLine"),
                        code_snippet=self._mask_secret(item.get("Secret", "")),
                        metadata={
                            "match": item.get("Match", ""),
                            "entropy": item.get("Entropy", 0),
                            "commit": item.get("Commit", ""),
                        },
                    )
                    findings.append(finding)

            return True, findings, None

        finally:
            # 임시 파일 정리
            Path(report_path).unlink(missing_ok=True)

    def _map_severity(self, rule_id: str) -> Severity:
        """규칙 ID에 따른 심각도 매핑"""
        critical_patterns = [
            "aws",
            "gcp",
            "azure",
            "private-key",
            "github-pat",
            "stripe",
            "twilio",
            "sendgrid",
        ]
        high_patterns = ["api-key", "secret", "token", "password", "credential"]

        rule_lower = rule_id.lower()
        for pattern in critical_patterns:
            if pattern in rule_lower:
                return Severity.CRITICAL

        for pattern in high_patterns:
            if pattern in rule_lower:
                return Severity.HIGH

        return Severity.MEDIUM

    def _mask_secret(self, secret: str) -> str:
        """비밀값 마스킹"""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
