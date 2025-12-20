"""Dependency Scanner - Trivy Wrapper"""

import json
import tempfile
from pathlib import Path

from .base import BaseScanner, Finding, Severity


class DependencyScanner(BaseScanner):
    """Trivy를 사용한 의존성 취약점 스캐너"""

    @property
    def name(self) -> str:
        return "Trivy"

    def _run_scan(self) -> tuple[bool, list[Finding], str | None]:
        """Trivy 스캔 실행"""
        findings: list[Finding] = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as report_file:
            report_path = report_file.name

        try:
            # Trivy 실행 - 파일시스템 스캔 (의존성 파일 탐지)
            cmd = [
                "trivy",
                "fs",
                "--format",
                "json",
                "--output",
                report_path,
                "--scanners",
                "vuln",  # 취약점만 스캔
                "--severity",
                "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
                self.workspace,
            ]

            result = self.run_command(cmd)

            if result.returncode != 0:
                # Trivy는 취약점이 있어도 exit 0 반환
                # 실패 시에만 에러 처리
                if "error" in result.stderr.lower():
                    return False, [], f"Trivy failed: {result.stderr}"

            # 결과 파싱
            report_file_path = Path(report_path)
            if report_file_path.exists() and report_file_path.stat().st_size > 0:
                with open(report_path) as f:
                    data = json.load(f)

                for result_item in data.get("Results", []):
                    target = result_item.get("Target", "")
                    vulnerabilities = result_item.get("Vulnerabilities", []) or []

                    for vuln in vulnerabilities:
                        finding = Finding(
                            scanner=self.name,
                            rule_id=vuln.get("VulnerabilityID", "unknown"),
                            severity=self._map_severity(vuln.get("Severity", "UNKNOWN")),
                            message=self._build_message(vuln),
                            file_path=target,
                            line_start=0,  # 의존성 파일은 라인 정보 없음
                            suggestion=self._build_suggestion(vuln),
                            metadata={
                                "package": vuln.get("PkgName", ""),
                                "installed_version": vuln.get("InstalledVersion", ""),
                                "fixed_version": vuln.get("FixedVersion", ""),
                                "cvss": vuln.get("CVSS", {}),
                                "cwe": vuln.get("CweIDs", []),
                                "references": vuln.get("References", []),
                                "primary_url": vuln.get("PrimaryURL", ""),
                            },
                        )
                        findings.append(finding)

            return True, findings, None

        finally:
            Path(report_path).unlink(missing_ok=True)

    def _map_severity(self, trivy_severity: str) -> Severity:
        """Trivy 심각도를 표준 심각도로 매핑"""
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "UNKNOWN": Severity.INFO,
        }
        return mapping.get(trivy_severity.upper(), Severity.INFO)

    def _build_message(self, vuln: dict) -> str:
        """취약점 메시지 생성"""
        pkg_name = vuln.get("PkgName", "Unknown")
        installed = vuln.get("InstalledVersion", "?")
        title = vuln.get("Title", vuln.get("Description", "Vulnerability detected"))

        return f"{pkg_name}@{installed}: {title}"

    def _build_suggestion(self, vuln: dict) -> str | None:
        """수정 제안 생성"""
        fixed_version = vuln.get("FixedVersion")
        if fixed_version:
            pkg_name = vuln.get("PkgName", "package")
            return f"Upgrade {pkg_name} to version {fixed_version} or later"
        return None
