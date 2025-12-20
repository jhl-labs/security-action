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

    def __init__(self, workspace: str):
        self.workspace = workspace

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
        self, cmd: list[str], capture_output: bool = True
    ) -> subprocess.CompletedProcess:
        """명령어 실행"""
        return subprocess.run(
            cmd,
            cwd=self.workspace,
            capture_output=capture_output,
            text=True,
        )
