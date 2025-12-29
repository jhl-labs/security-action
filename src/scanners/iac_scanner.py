"""Infrastructure as Code Scanner - Checkov Wrapper

Terraform, Kubernetes, CloudFormation, Dockerfile 등의 IaC 보안 스캔
"""

import json
import logging
import os
import tempfile
from pathlib import Path

from .base import BaseScanner, Finding, Severity

logger = logging.getLogger(__name__)


class IaCScanner(BaseScanner):
    """Checkov을 사용한 IaC 보안 스캐너

    지원 프레임워크:
    - Terraform (HCL, JSON)
    - Kubernetes (YAML, Helm)
    - CloudFormation
    - ARM Templates
    - Dockerfile
    - GitHub Actions
    - Ansible

    Args:
        workspace: 스캔할 워크스페이스 경로
        frameworks: 스캔할 프레임워크 목록 (기본: 자동 감지)
        skip_checks: 건너뛸 체크 ID 목록
        external_checks_dir: 커스텀 체크 디렉토리
    """

    SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }

    # IaC 파일 패턴
    IAC_PATTERNS = {
        "terraform": ["*.tf", "*.tf.json"],
        "kubernetes": ["*.yaml", "*.yml"],
        "cloudformation": ["*.template", "*.json"],
        "dockerfile": ["Dockerfile*", "*.dockerfile"],
        "github_actions": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
        "helm": ["Chart.yaml", "values.yaml"],
    }

    def __init__(
        self,
        workspace: str,
        frameworks: list[str] | None = None,
        skip_checks: list[str] | None = None,
        external_checks_dir: str | None = None,
    ):
        super().__init__(workspace)
        self.frameworks = frameworks or self._detect_frameworks()
        self.skip_checks = skip_checks or os.getenv("INPUT_IAC_SKIP_CHECKS", "").split(",")
        self.skip_checks = [c.strip() for c in self.skip_checks if c.strip()]
        self.external_checks_dir = external_checks_dir or os.getenv("INPUT_IAC_CUSTOM_CHECKS")

    @property
    def name(self) -> str:
        return "Checkov"

    def _detect_frameworks(self) -> list[str]:
        """워크스페이스에서 IaC 프레임워크 자동 감지"""
        detected = []
        workspace_path = Path(self.workspace)

        # Terraform
        if list(workspace_path.rglob("*.tf")):
            detected.append("terraform")

        # Kubernetes / Helm
        if list(workspace_path.rglob("*.yaml")) or list(workspace_path.rglob("*.yml")):
            detected.append("kubernetes")
        if (workspace_path / "Chart.yaml").exists():
            detected.append("helm")

        # Dockerfile
        if list(workspace_path.rglob("Dockerfile*")):
            detected.append("dockerfile")

        # GitHub Actions
        if (workspace_path / ".github" / "workflows").exists():
            detected.append("github_actions")

        # CloudFormation
        for f in workspace_path.rglob("*.template"):
            detected.append("cloudformation")
            break

        logger.info(f"Detected IaC frameworks: {detected if detected else 'none'}")
        return detected

    def _run_scan(self) -> tuple[bool, list[Finding], str | None]:
        """Checkov IaC 스캔 실행"""
        if not self.frameworks:
            logger.info("No IaC frameworks detected, skipping")
            return True, [], None

        findings: list[Finding] = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name

        try:
            cmd = [
                "checkov",
                "--directory",
                self.workspace,
                "--output",
                "json",
                "--output-file-path",
                report_path,
                "--compact",
                "--quiet",
            ]

            # 특정 프레임워크만 스캔
            if self.frameworks:
                cmd.extend(["--framework", ",".join(self.frameworks)])

            # 건너뛸 체크
            if self.skip_checks:
                cmd.extend(["--skip-check", ",".join(self.skip_checks)])

            # 커스텀 체크 디렉토리
            if self.external_checks_dir and Path(self.external_checks_dir).exists():
                cmd.extend(["--external-checks-dir", self.external_checks_dir])

            logger.info(f"Running Checkov for frameworks: {self.frameworks}")
            result = self.run_command(cmd, timeout=300)

            # Checkov은 발견 시 exit code 1 반환
            if result.returncode not in (0, 1):
                return False, [], f"Checkov failed: {result.stderr}"

            # 결과 파싱
            report_file = Path(report_path)
            if report_file.exists() and report_file.stat().st_size > 0:
                with open(report_path) as f:
                    content = f.read()
                    if content.strip():
                        data = json.loads(content)
                        findings = self._parse_results(data)

            logger.info(f"Found {len(findings)} IaC security issues")
            return True, findings, None

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Checkov output: {e}")
            return True, [], None
        except Exception as e:
            logger.error(f"IaC scan error: {e}")
            return False, [], str(e)
        finally:
            Path(report_path).unlink(missing_ok=True)

    def _parse_results(self, data: dict | list) -> list[Finding]:
        """Checkov 결과 파싱"""
        findings = []

        # Checkov 결과는 리스트 또는 딕셔너리일 수 있음
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    findings.extend(self._parse_check_results(item))
        elif isinstance(data, dict):
            findings.extend(self._parse_check_results(data))

        return findings

    def _parse_check_results(self, data: dict) -> list[Finding]:
        """단일 체크 결과 파싱"""
        findings = []

        # failed_checks 처리
        failed_checks = data.get("results", {}).get("failed_checks", [])
        for check in failed_checks:
            finding = self._convert_check(check)
            if finding:
                findings.append(finding)

        return findings

    def _convert_check(self, check: dict) -> Finding | None:
        """Checkov 체크를 Finding으로 변환"""
        severity_str = check.get("severity", "MEDIUM")
        if severity_str is None:
            severity_str = "MEDIUM"

        severity = self.SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)

        # 파일 경로 정규화 (Docker 컨테이너 경로 제거)
        file_path = self.normalize_path(check.get("file_path", ""))

        # 라인 정보
        file_line_range = check.get("file_line_range", [1, 1])
        line_start = file_line_range[0] if isinstance(file_line_range, list) else 1
        line_end = (
            file_line_range[1]
            if isinstance(file_line_range, list) and len(file_line_range) > 1
            else None
        )

        guideline = check.get("guideline", "")
        suggestion = guideline if guideline else check.get("check_name", "")

        return Finding(
            scanner=self.name,
            rule_id=check.get("check_id", "unknown"),
            severity=severity,
            message=check.get("check_name", "IaC security issue detected"),
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            suggestion=suggestion,
            metadata={
                "resource": check.get("resource", ""),
                "check_type": check.get("check_type", ""),
                "bc_check_id": check.get("bc_check_id", ""),
                "guideline": guideline,
                "evaluations": check.get("evaluations"),
            },
        )
