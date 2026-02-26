"""Base Scanner Interface"""

import os
import shutil
import subprocess  # nosec B404
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
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
    GH_ACTIONS_SAFE_PATH_PREFIXES = (
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/opt/sonar-scanner/bin",
        "/root/.cargo/bin",
        "/usr/local/go/bin",
        "/root/go/bin",
    )

    def __init__(self, workspace: str):
        self.workspace = workspace

    def _build_safe_env(self, env: dict[str, str] | None = None) -> dict[str, str]:
        """명령 실행용 환경 변수 구성.

        - 기본적으로 현재 프로세스 환경을 상속한다.
        - PATH의 빈 항목/`.`/workspace 하위 경로를 제거해
          저장소 내부 악성 바이너리 하이재킹 가능성을 낮춘다.
        """
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        path_value = merged_env.get("PATH", "")
        if not path_value:
            return merged_env

        workspace_resolved: Path | None
        try:
            workspace_resolved = Path(self.workspace).resolve(strict=False)
        except Exception:
            workspace_resolved = None

        safe_entries: list[str] = []
        seen: set[str] = set()
        for raw_entry in path_value.split(os.pathsep):
            entry = raw_entry.strip()
            if not entry or entry == ".":
                continue

            # 상대 경로 PATH 엔트리는 실행 위치에 따라 해석이 달라져
            # 하이재킹 표면을 키우므로 제외한다.
            if not Path(entry).is_absolute():
                continue

            if workspace_resolved is not None:
                try:
                    entry_path = Path(entry).resolve(strict=False)
                except Exception:
                    entry_path = None

                if entry_path is not None and (
                    entry_path == workspace_resolved or workspace_resolved in entry_path.parents
                ):
                    continue

            if os.getenv("GITHUB_ACTIONS", "").lower() == "true":
                if not any(
                    entry == prefix or entry.startswith(prefix + os.sep)
                    for prefix in self.GH_ACTIONS_SAFE_PATH_PREFIXES
                ):
                    continue

            if entry not in seen:
                safe_entries.append(entry)
                seen.add(entry)

        merged_env["PATH"] = os.pathsep.join(safe_entries)

        return merged_env

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

        normalized_by_workspace = False

        # Docker 컨테이너 경로 prefix 제거
        for prefix in self.WORKSPACE_PREFIXES:
            if file_path.startswith(prefix):
                file_path = file_path[len(prefix) :]
                normalized_by_workspace = True
                break

        # workspace 경로도 제거 (예: /home/vtopia/git/... 등)
        # 경계(`/`)를 확인해 /repo 와 /repo2 같은 유사 prefix 오탐을 방지한다.
        if self.workspace:
            normalized_workspace = self.workspace.replace("\\", "/").rstrip("/")
            normalized_path = file_path.replace("\\", "/")

            if normalized_workspace and (
                normalized_path == normalized_workspace
                or normalized_path.startswith(normalized_workspace + "/")
            ):
                normalized_path = normalized_path[len(normalized_workspace) :]
                file_path = normalized_path
                normalized_by_workspace = True

        # workspace 내부 경로를 상대경로로 만든 경우에만 선행 슬래시를 제거한다.
        # 외부 절대경로까지 상대경로화하면 잘못된 annotation 경로를 만들 수 있다.
        if normalized_by_workspace:
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
        if not cmd:
            raise ValueError("Command must not be empty")

        safe_env = self._build_safe_env(env)
        workspace_path = Path(self.workspace).resolve(strict=False)
        requested_cwd = cwd if cwd else self.workspace
        requested_cwd_path = Path(requested_cwd).expanduser()
        if not requested_cwd_path.is_absolute():
            requested_cwd_path = workspace_path / requested_cwd_path
        resolved_cwd = requested_cwd_path.resolve(strict=False)

        if os.getenv("GITHUB_ACTIONS", "").lower() == "true":
            if not (resolved_cwd == workspace_path or workspace_path in resolved_cwd.parents):
                raise ValueError(
                    f"Command cwd must stay within workspace in GitHub Actions: {requested_cwd}"
                )

        resolved_cmd = list(cmd)
        executable = resolved_cmd[0]

        # PATH 검색형 명령은 절대 경로로 고정해 실행 시점 하이재킹 위험을 줄인다.
        if "/" not in executable and "\\" not in executable:
            resolved_executable = shutil.which(executable, path=safe_env.get("PATH"))
            if resolved_executable:
                resolved_cmd[0] = resolved_executable

        # Bandit B603: command is list-based with shell=False and sanitized PATH/env.
        try:
            return subprocess.run(  # nosec B603
                resolved_cmd,
                cwd=str(resolved_cwd),
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                env=safe_env,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"Required tool not found in PATH: {executable}. "
                "Install the scanner dependency in the runner environment."
            ) from exc
