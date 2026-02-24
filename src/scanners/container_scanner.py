"""Container Image Scanner - Trivy Wrapper

컨테이너 이미지의 OS 패키지 및 애플리케이션 의존성 취약점 스캔
"""

import json
import logging
import os
import tempfile
from pathlib import Path

from .base import BaseScanner, Finding, Severity

logger = logging.getLogger(__name__)


class ContainerScanner(BaseScanner):
    """Trivy를 사용한 컨테이너 이미지 스캐너

    Args:
        workspace: 워크스페이스 경로
        image: 스캔할 이미지 이름 (예: nginx:latest)
        dockerfile_path: Dockerfile 경로 (이미지 대신 Dockerfile 스캔 시)
    """

    SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "UNKNOWN": Severity.INFO,
    }

    def __init__(
        self,
        workspace: str,
        image: str | None = None,
        dockerfile_path: str | None = None,
    ):
        super().__init__(workspace)
        self.image = image or os.getenv("INPUT_CONTAINER_IMAGE")
        self.dockerfile_path = dockerfile_path or os.getenv("INPUT_DOCKERFILE_PATH")

    @property
    def name(self) -> str:
        return "Trivy-Container"

    def _run_scan(self) -> tuple[bool, list[Finding], str | None]:
        """컨테이너 이미지 스캔 실행"""
        if not self.image and not self.dockerfile_path:
            # Dockerfile 자동 감지
            dockerfile = Path(self.workspace) / "Dockerfile"
            if dockerfile.exists():
                self.dockerfile_path = str(dockerfile)
            else:
                logger.info("No container image or Dockerfile specified, skipping")
                return True, [], None

        findings: list[Finding] = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            report_path = f.name

        try:
            cmd = [
                "trivy",
                "--format",
                "json",
                "--output",
                report_path,
            ]

            if self.image:
                # 이미지 스캔
                cmd.extend(["image", self.image])
                logger.info(f"Scanning container image: {self.image}")
            elif self.dockerfile_path:
                # Dockerfile 설정 스캔 (misconfig)
                cmd.extend(
                    [
                        "config",
                        "--file-patterns",
                        "Dockerfile",
                        self.dockerfile_path,
                    ]
                )
                logger.info(f"Scanning Dockerfile: {self.dockerfile_path}")

            result = self.run_command(cmd)

            if result.returncode not in (0, 1):
                return False, [], f"Trivy container scan failed: {result.stderr}"

            # 결과 파싱
            report_file = Path(report_path)
            if report_file.exists() and report_file.stat().st_size > 0:
                with open(report_path) as f:
                    data = json.load(f)

                findings = self._parse_results(data)

            logger.info(f"Found {len(findings)} container vulnerabilities")
            return True, findings, None

        except Exception as e:
            logger.error(f"Container scan error: {e}")
            return False, [], str(e)
        finally:
            Path(report_path).unlink(missing_ok=True)

    def _parse_results(self, data: dict) -> list[Finding]:
        """Trivy 결과 파싱"""
        findings = []

        # 이미지 스캔 결과
        results = data.get("Results", [])
        for result in results:
            raw_target = result.get("Target", "")
            target = self._normalize_container_target(raw_target)

            # 취약점
            for vuln in result.get("Vulnerabilities", []):
                findings.append(self._convert_vulnerability(vuln, target))

            # Misconfig (Dockerfile 스캔 시)
            for misconfig in result.get("Misconfigurations", []):
                findings.append(self._convert_misconfig(misconfig, target))

        return [f for f in findings if f is not None]

    def _normalize_container_target(self, target: str) -> str:
        """컨테이너 타겟 경로 정규화

        Trivy가 반환하는 Target은 다음과 같은 형태:
        - 이미지: "nginx:latest (debian 12.8)" 또는 "security-action:scan"
        - 파일시스템: "/path/to/file"

        GitHub SARIF는 유효한 파일 경로 또는 상대 경로를 기대하므로,
        이미지 이름 형식의 경우 Dockerfile로 대체하거나 메타데이터로 저장
        """
        if not target:
            return "Dockerfile"

        # 파일 경로인 경우 (슬래시로 시작하거나 상대 경로)
        if "/" in target and ":" not in target.split("/")[0]:
            return self.normalize_path(target)

        # 이미지 이름인 경우 (예: nginx:latest, security-action:scan)
        # 괄호 안의 OS 정보 제거
        if " (" in target:
            target = target.split(" (")[0]

        # Dockerfile이 있으면 Dockerfile 사용, 없으면 이미지 이름에서 안전한 경로 생성
        dockerfile = Path(self.workspace) / "Dockerfile"
        if dockerfile.exists():
            return "Dockerfile"

        # 이미지 이름을 안전한 파일명으로 변환 (: -> -, / -> -)
        safe_name = target.replace(":", "-").replace("/", "-")
        return f"container-image/{safe_name}"

    def _convert_vulnerability(self, vuln: dict, target: str) -> Finding:
        """취약점을 Finding으로 변환"""
        severity = self.SEVERITY_MAP.get(
            vuln.get("Severity", "UNKNOWN"),
            Severity.MEDIUM,
        )

        pkg_name = vuln.get("PkgName", "")
        installed_version = vuln.get("InstalledVersion", "")
        fixed_version = vuln.get("FixedVersion", "")

        message = vuln.get("Title", vuln.get("Description", "Vulnerability detected"))
        if fixed_version:
            suggestion = f"Upgrade {pkg_name} from {installed_version} to {fixed_version}"
        else:
            suggestion = f"No fix available for {pkg_name} {installed_version}"

        return Finding(
            scanner=self.name,
            rule_id=vuln.get("VulnerabilityID", "unknown"),
            severity=severity,
            message=message,
            file_path=target,
            line_start=1,
            suggestion=suggestion,
            metadata={
                "package": pkg_name,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                "references": vuln.get("References", [])[:3],
                "cwe": vuln.get("CweIDs", []),
            },
        )

    def _convert_misconfig(self, misconfig: dict, target: str) -> Finding:
        """Misconfig를 Finding으로 변환"""
        severity = self.SEVERITY_MAP.get(
            misconfig.get("Severity", "MEDIUM"),
            Severity.MEDIUM,
        )

        return Finding(
            scanner=self.name,
            rule_id=misconfig.get("ID", "unknown"),
            severity=severity,
            message=misconfig.get("Title", misconfig.get("Message", "")),
            file_path=target,
            line_start=misconfig.get("CauseMetadata", {}).get("StartLine", 1),
            line_end=misconfig.get("CauseMetadata", {}).get("EndLine"),
            suggestion=misconfig.get("Resolution", ""),
            metadata={
                "type": misconfig.get("Type", ""),
                "description": misconfig.get("Description", ""),
                "references": misconfig.get("References", [])[:3],
            },
        )
