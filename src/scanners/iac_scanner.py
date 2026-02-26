"""Infrastructure as Code Scanner - Checkov Wrapper

Terraform, Kubernetes, CloudFormation, Dockerfile 등의 IaC 보안 스캔
"""

import json
import logging
import os
import tempfile
from fnmatch import fnmatch
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
    EXCLUDED_SCAN_DIRS = {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "node_modules",
        "vendor",
        "dist",
        "build",
    }
    DEFAULT_SKIP_PATH_REGEX = (
        r"(^|/)(\.git|\.hg|\.svn|\.venv|venv|\.tox|__pycache__|"
        r"node_modules|vendor|dist|build)(/|$)"
    )

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
        self.external_checks_dir = self._resolve_external_checks_dir(
            external_checks_dir or os.getenv("INPUT_IAC_CUSTOM_CHECKS")
        )

    @property
    def name(self) -> str:
        return "Checkov"

    @classmethod
    def _should_skip_scan_dir(cls, directory_name: str) -> bool:
        return directory_name in cls.EXCLUDED_SCAN_DIRS

    def _iter_workspace_files(self):
        """workspace 내부 파일을 순회하되 공통 vendor/cache 디렉토리는 제외한다."""
        workspace_path = Path(self.workspace)

        for root, dirs, files in os.walk(workspace_path, topdown=True):
            dirs[:] = [d for d in dirs if not self._should_skip_scan_dir(d)]
            root_path = Path(root)
            relative_root = root_path.relative_to(workspace_path)

            for file_name in files:
                if relative_root == Path("."):
                    rel_path = file_name
                else:
                    rel_path = f"{relative_root.as_posix()}/{file_name}"
                yield file_name, rel_path, root_path / file_name

    @staticmethod
    def _looks_like_cloudformation_template(file_path: Path) -> bool:
        """CloudFormation 템플릿 시그니처 기반 판별.

        단순 확장자(`*.json`)만으로는 package.json 같은 일반 파일을 오탐지하므로
        내용에 CloudFormation 특징 키워드가 있는 경우에만 감지한다.
        """
        try:
            if not file_path.is_file():
                return False
            if file_path.stat().st_size > 512 * 1024:
                return False
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return False

        if not content.strip():
            return False

        lowered = content.lower()
        name_lower = file_path.name.lower()
        path_lower = file_path.as_posix().lower()

        strong_signals = (
            "awstemplateformatversion",
            "aws::serverless",
            "aws::cloudformation",
        )
        if any(signal in lowered for signal in strong_signals):
            return True

        if "resources" in lowered and "aws::" in lowered:
            return True

        filename_hints = ("cloudformation", "cfn", "template", "sam")
        if any(hint in name_lower or hint in path_lower for hint in filename_hints):
            return "resources" in lowered or "aws::" in lowered

        return False

    def _detect_frameworks(self) -> list[str]:
        """워크스페이스에서 IaC 프레임워크 자동 감지"""
        detected_flags = {
            "terraform": False,
            "kubernetes": False,
            "helm": False,
            "dockerfile": False,
            "github_actions": False,
            "cloudformation": False,
        }

        for file_name, rel_path, file_path in self._iter_workspace_files():
            if not detected_flags["terraform"] and any(
                fnmatch(file_name, pattern) for pattern in self.IAC_PATTERNS["terraform"]
            ):
                detected_flags["terraform"] = True

            if not detected_flags["kubernetes"] and any(
                fnmatch(file_name, pattern) for pattern in self.IAC_PATTERNS["kubernetes"]
            ):
                detected_flags["kubernetes"] = True

            if not detected_flags["helm"] and any(
                fnmatch(file_name, pattern) for pattern in self.IAC_PATTERNS["helm"]
            ):
                detected_flags["helm"] = True

            if not detected_flags["dockerfile"] and any(
                fnmatch(file_name, pattern) for pattern in self.IAC_PATTERNS["dockerfile"]
            ):
                detected_flags["dockerfile"] = True

            if not detected_flags["github_actions"] and any(
                fnmatch(rel_path, pattern) for pattern in self.IAC_PATTERNS["github_actions"]
            ):
                detected_flags["github_actions"] = True

            if not detected_flags["cloudformation"] and any(
                fnmatch(file_name, pattern) for pattern in ["*.template"]
            ):
                detected_flags["cloudformation"] = True
            elif not detected_flags["cloudformation"] and any(
                fnmatch(file_name, pattern) for pattern in ["*.json", "*.yaml", "*.yml"]
            ):
                if self._looks_like_cloudformation_template(file_path):
                    detected_flags["cloudformation"] = True

            if all(detected_flags.values()):
                break

        detected = [name for name, enabled in detected_flags.items() if enabled]

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

            # 공통 대용량/서드파티 디렉토리를 기본 제외해 속도와 노이즈를 줄인다.
            cmd.extend(["--skip-path", self.DEFAULT_SKIP_PATH_REGEX])

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
                with open(report_path, encoding="utf-8") as f:
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
        line_start = 1
        line_end = None
        if isinstance(file_line_range, list) and file_line_range:
            line_start = self._safe_line(file_line_range[0], default=1)
            if len(file_line_range) > 1:
                line_end = self._safe_line(file_line_range[1], default=line_start)
                if line_end < line_start:
                    line_end = line_start

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

    @staticmethod
    def _safe_line(value, default: int = 1) -> int:
        """라인 번호를 양의 정수로 정규화."""
        try:
            return max(1, int(value))
        except (TypeError, ValueError):
            return max(1, default)

    def _resolve_external_checks_dir(self, path_value: str | None) -> str | None:
        """외부 체크 디렉토리를 workspace 기준 절대 경로로 해석."""
        raw = str(path_value or "").strip()
        if not raw:
            return None

        workspace_path = Path(self.workspace).resolve(strict=False)
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = workspace_path / candidate
        resolved = candidate.resolve(strict=False)

        if os.getenv("GITHUB_ACTIONS", "").lower() == "true":
            if not (resolved == workspace_path or workspace_path in resolved.parents):
                logger.warning(
                    "Ignoring IaC custom checks path outside workspace in GitHub Actions: %s",
                    raw,
                )
                return None

        return str(resolved)
