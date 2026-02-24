"""Base Scanner Interface"""

import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
            "warning": cls.MEDIUM,
            "error": cls.HIGH,
        }
        return mapping.get(value.lower(), cls.INFO)

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


class BaseScanner(ABC):
    """스캐너 기본 클래스"""

    # GitHub Actions Docker 컨테이너 내 워크스페이스 경로들
    WORKSPACE_PREFIXES = [
        "/github/workspace/",
        "/github/workspace",
        "/home/runner/work/",
    ]

    def __init__(self, workspace: str):
        self.workspace = workspace

    def normalize_path(self, file_path: str) -> str:
        """파일 경로 정규화 - Docker 컨테이너 경로를 상대 경로로 변환

        GitHub Actions에서 Docker 컨테이너로 실행 시 스캐너가 반환하는 경로가
        /github/workspace/... 형태로 되어 있어 GitHub UI에서 파일을 찾지 못함.
        이 메서드는 해당 prefix를 제거하여 상대 경로로 변환함.

        Args:
            file_path: 원본 파일 경로

        Returns:
            상대 경로로 변환된 파일 경로
        """
        if not file_path:
            return file_path

        # Docker 컨테이너 경로 prefix 제거
        for prefix in self.WORKSPACE_PREFIXES:
            if file_path.startswith(prefix):
                file_path = file_path[len(prefix) :]
                break

        # workspace 경로도 제거 (예: /home/vtopia/git/... 등)
        if self.workspace and file_path.startswith(self.workspace):
            file_path = file_path[len(self.workspace) :]
            if file_path.startswith("/"):
                file_path = file_path[1:]

        # 선행 슬래시 제거
        while file_path.startswith("/"):
            file_path = file_path[1:]

        return file_path

    @property
    @abstractmethod
    def name(self) -> str:
        """스캐너 이름"""
        pass

    @abstractmethod
    def _run_scan(self) -> tuple[bool, list[Finding], str | None]:
        """스캔 실행 (구현 필요)"""
        pass

    def scan(self) -> ScanResult:
        """스캔 실행 및 결과 반환"""
        start_time = time.time()

        try:
            success, findings, error = self._run_scan()
        except Exception as e:
            success = False
            findings = []
            error = str(e)

        execution_time = time.time() - start_time

        return ScanResult(
            scanner=self.name,
            success=success,
            findings=findings,
            error=error,
            execution_time=execution_time,
        )

    def run_command(
        self,
        cmd: list[str],
        capture_output: bool = True,
        timeout: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        """명령어 실행

        Args:
            cmd: 실행할 명령어 리스트
            capture_output: 출력 캡처 여부
            timeout: 타임아웃 (초)
            cwd: 명령어 실행 디렉토리 (기본: workspace)
            env: 추가/대체 환경 변수

        Returns:
            subprocess.CompletedProcess
        """
        return subprocess.run(
            cmd,
            cwd=cwd or self.workspace,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            env=env,
        )
