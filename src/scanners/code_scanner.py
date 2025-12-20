"""Code Scanner - Semgrep Wrapper"""

import json
import tempfile
from pathlib import Path

from .base import BaseScanner, Finding, Severity


class CodeScanner(BaseScanner):
    """Semgrep을 사용한 코드 취약점 스캐너"""

    @property
    def name(self) -> str:
        return "Semgrep"

    def _run_scan(self) -> tuple[bool, list[Finding], str | None]:
        """Semgrep 스캔 실행"""
        findings: list[Finding] = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as report_file:
            report_path = report_file.name

        try:
            # Semgrep 실행 - 보안 규칙셋 사용
            cmd = [
                "semgrep",
                "scan",
                "--config",
                "auto",  # 자동 언어 감지 및 기본 보안 규칙
                "--config",
                "p/security-audit",  # 보안 감사 규칙
                "--config",
                "p/owasp-top-ten",  # OWASP Top 10
                "--json",
                "--output",
                report_path,
                "--quiet",
                self.workspace,
            ]

            result = self.run_command(cmd)

            # Semgrep은 발견 시에도 exit 0 반환
            if result.returncode not in (0, 1):
                return False, [], f"Semgrep failed: {result.stderr}"

            # 결과 파싱
            report_file_path = Path(report_path)
            if report_file_path.exists() and report_file_path.stat().st_size > 0:
                with open(report_path) as f:
                    data = json.load(f)

                for item in data.get("results", []):
                    extra = item.get("extra", {})
                    finding = Finding(
                        scanner=self.name,
                        rule_id=item.get("check_id", "unknown"),
                        severity=self._map_severity(extra.get("severity", "INFO")),
                        message=extra.get("message", "Security issue detected"),
                        file_path=item.get("path", ""),
                        line_start=item.get("start", {}).get("line", 0),
                        line_end=item.get("end", {}).get("line"),
                        code_snippet=extra.get("lines", ""),
                        suggestion=self._get_suggestion(extra),
                        metadata={
                            "category": extra.get("metadata", {}).get("category", ""),
                            "cwe": extra.get("metadata", {}).get("cwe", []),
                            "owasp": extra.get("metadata", {}).get("owasp", []),
                            "references": extra.get("metadata", {}).get("references", []),
                        },
                    )
                    findings.append(finding)

            return True, findings, None

        finally:
            Path(report_path).unlink(missing_ok=True)

    def _map_severity(self, semgrep_severity: str) -> Severity:
        """Semgrep 심각도를 표준 심각도로 매핑"""
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        return mapping.get(semgrep_severity.upper(), Severity.INFO)

    def _get_suggestion(self, extra: dict) -> str | None:
        """수정 제안 추출"""
        fix = extra.get("fix")
        if fix:
            return f"Suggested fix:\n{fix}"

        metadata = extra.get("metadata", {})
        if "fix" in metadata:
            return metadata["fix"]

        return None
