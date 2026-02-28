"""스캐너 통합 테스트"""

import os
import subprocess
from pathlib import Path

import pytest

from scanners.base import BaseScanner, Finding, ScanResult, Severity
from scanners.code_scanner import CodeScanner
from scanners.dependency_scanner import DependencyScanner
from scanners.parallel import ParallelScanner
from scanners.secret_scanner import SecretScanner

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "vulnerable_samples"


def tool_available(tool_name: str) -> bool:
    """도구 설치 여부 확인"""
    try:
        subprocess.run(
            [tool_name, "--version"],
            capture_output=True,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


class TestSeverity:
    """Severity 열거형 테스트"""

    def test_from_string(self):
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("Medium") == Severity.MEDIUM
        assert Severity.from_string("warning") == Severity.MEDIUM
        assert Severity.from_string("unknown") == Severity.INFO

    def test_comparison(self):
        assert Severity.CRITICAL >= Severity.HIGH
        assert Severity.HIGH >= Severity.MEDIUM
        assert Severity.MEDIUM >= Severity.LOW
        assert Severity.LOW >= Severity.INFO
        assert not Severity.LOW >= Severity.HIGH


class TestFinding:
    """Finding 데이터클래스 테스트"""

    def test_create_finding(self):
        finding = Finding(
            scanner="TestScanner",
            rule_id="test-rule",
            severity=Severity.HIGH,
            message="Test vulnerability",
            file_path="test.py",
            line_start=10,
        )
        assert finding.scanner == "TestScanner"
        assert finding.severity == Severity.HIGH
        assert finding.line_end is None
        assert finding.metadata == {}


class TestSecretScanner:
    """Secret Scanner (Gitleaks) 테스트"""

    @pytest.mark.skipif(
        not tool_available("gitleaks"),
        reason="gitleaks not installed",
    )
    def test_scan_with_secrets(self):
        """비밀값이 있는 디렉토리 스캔"""
        scanner = SecretScanner(str(FIXTURES_DIR))
        result = scanner.scan()

        assert result.scanner == "Gitleaks"
        assert result.success is True
        assert len(result.findings) > 0

        # AWS 키 탐지 확인
        aws_findings = [f for f in result.findings if "aws" in f.rule_id.lower()]
        assert len(aws_findings) > 0

    @pytest.mark.skipif(
        not tool_available("gitleaks"),
        reason="gitleaks not installed",
    )
    def test_scan_clean_directory(self, tmp_path):
        """깨끗한 디렉토리 스캔"""
        # 비밀값 없는 파일 생성
        (tmp_path / "clean.py").write_text("print('hello world')")

        scanner = SecretScanner(str(tmp_path))
        result = scanner.scan()

        assert result.success is True
        assert len(result.findings) == 0

    def test_mask_secret(self):
        """비밀값 마스킹 테스트"""
        scanner = SecretScanner("/tmp")

        # 긴 비밀값
        masked = scanner._mask_secret("1234567890abcdef")
        assert masked == "1234********cdef"

        # 짧은 비밀값
        masked = scanner._mask_secret("short")
        assert masked == "*****"

    def test_resolves_relative_config_and_baseline_paths_to_workspace(self, tmp_path, monkeypatch):
        (tmp_path / "gitleaks.toml").write_text("[rules]\n", encoding="utf-8")
        (tmp_path / "baseline.json").write_text("{}", encoding="utf-8")

        monkeypatch.setenv("INPUT_GITLEAKS_CONFIG", "gitleaks.toml")
        monkeypatch.setenv("INPUT_GITLEAKS_BASELINE", "baseline.json")

        scanner = SecretScanner(str(tmp_path))

        assert scanner.config_path == str((tmp_path / "gitleaks.toml").resolve())
        assert scanner.baseline_path == str((tmp_path / "baseline.json").resolve())

    def test_rejects_workspace_escape_paths_in_github_actions(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("INPUT_GITLEAKS_CONFIG", "../outside.toml")
        monkeypatch.setenv("INPUT_GITLEAKS_BASELINE", "../outside.json")

        scanner = SecretScanner(str(tmp_path))

        assert scanner.config_path is None
        assert scanner.baseline_path is None


class TestCodeScanner:
    """Code Scanner (Semgrep) 테스트"""

    @pytest.mark.skipif(
        not tool_available("semgrep"),
        reason="semgrep not installed",
    )
    def test_scan_vulnerable_code(self):
        """취약한 코드 스캔"""
        scanner = CodeScanner(str(FIXTURES_DIR))
        result = scanner.scan()

        assert result.scanner == "Semgrep"
        assert result.success is True
        # 취약점 발견 기대 (SQL injection, eval 등)
        assert len(result.findings) > 0

    @pytest.mark.skipif(
        not tool_available("semgrep"),
        reason="semgrep not installed",
    )
    def test_scan_clean_code(self, tmp_path):
        """안전한 코드 스캔"""
        safe_code = '''
def add(a: int, b: int) -> int:
    """두 숫자를 더합니다."""
    return a + b
'''
        (tmp_path / "safe.py").write_text(safe_code)

        scanner = CodeScanner(str(tmp_path))
        result = scanner.scan()

        assert result.success is True
        # 안전한 코드는 취약점이 없거나 매우 적어야 함
        high_severity = [f for f in result.findings if f.severity >= Severity.HIGH]
        assert len(high_severity) == 0


class TestDependencyScanner:
    """Dependency Scanner (Trivy) 테스트"""

    @pytest.mark.skipif(
        not tool_available("trivy"),
        reason="trivy not installed",
    )
    def test_scan_vulnerable_dependencies(self):
        """취약한 의존성 스캔"""
        scanner = DependencyScanner(str(FIXTURES_DIR))
        result = scanner.scan()

        assert result.scanner == "Trivy"
        assert result.success is True
        # Trivy DB 갱신에 따라 fixture의 취약점 수는 달라질 수 있으므로
        # 결과 구조와 파싱 안정성만 검증한다.
        assert result.error is None
        assert isinstance(result.findings, list)
        for finding in result.findings:
            assert finding.scanner == "Trivy"
            assert finding.rule_id

    @pytest.mark.skipif(
        not tool_available("trivy"),
        reason="trivy not installed",
    )
    def test_scan_no_dependencies(self, tmp_path):
        """의존성 파일 없는 디렉토리 스캔"""
        (tmp_path / "README.md").write_text("# Test")

        scanner = DependencyScanner(str(tmp_path))
        result = scanner.scan()

        assert result.success is True
        assert len(result.findings) == 0

    def test_build_suggestion(self):
        """수정 제안 생성 테스트"""
        scanner = DependencyScanner("/tmp")

        # 수정 버전이 있는 경우
        vuln = {
            "PkgName": "requests",
            "FixedVersion": "2.28.0",
        }
        suggestion = scanner._build_suggestion(vuln)
        assert "2.28.0" in suggestion
        assert "requests" in suggestion

        # 수정 버전이 없는 경우
        vuln_no_fix = {"PkgName": "oldpkg"}
        assert scanner._build_suggestion(vuln_no_fix) is None


class TestIntegration:
    """통합 테스트"""

    def test_all_scanners_return_scan_result(self, tmp_path):
        """모든 스캐너가 ScanResult를 반환하는지 확인"""
        (tmp_path / "test.py").write_text("x = 1")

        scanners = [
            SecretScanner(str(tmp_path)),
            CodeScanner(str(tmp_path)),
            DependencyScanner(str(tmp_path)),
        ]

        for scanner in scanners:
            result = scanner.scan()
            assert isinstance(result, ScanResult)
            assert isinstance(result.scanner, str)
            assert isinstance(result.success, bool)
            assert isinstance(result.findings, list)
            assert isinstance(result.execution_time, float)


class TestBaseScannerCommandSafety:
    """BaseScanner 명령 실행 안전성 테스트"""

    class _DummyScanner(BaseScanner):
        @property
        def name(self) -> str:
            return "Dummy"

        def _run_scan(self):  # noqa: D401
            return True, [], None

    def test_run_command_filters_workspace_path_and_dot(self, tmp_path, monkeypatch):
        workspace = tmp_path / "repo"
        workspace.mkdir()

        workspace_bin = workspace / "bin"
        workspace_bin.mkdir()
        trusted_bin = tmp_path / "trusted-bin"
        trusted_bin.mkdir()

        malicious_exe = workspace_bin / "demo"
        malicious_exe.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        malicious_exe.chmod(0o755)

        trusted_exe = trusted_bin / "demo"
        trusted_exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        trusted_exe.chmod(0o755)

        scanner = self._DummyScanner(str(workspace))
        captured = {}

        def fake_run(cmd, cwd=None, capture_output=True, text=True, timeout=None, env=None):
            captured["cmd"] = cmd
            captured["cwd"] = cwd
            captured["env"] = env
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        scanner.run_command(
            ["demo", "--version"],
            env={"PATH": f".{os.pathsep}{workspace_bin}{os.pathsep}{trusted_bin}"},
        )

        assert captured["cmd"][0] == str(trusted_exe)
        assert captured["cwd"] == str(workspace)

        effective_path = (captured["env"] or {}).get("PATH", "").split(os.pathsep)
        assert "." not in effective_path
        assert str(workspace_bin) not in effective_path

    def test_run_command_drops_relative_path_entries(self, tmp_path, monkeypatch):
        workspace = tmp_path / "repo"
        workspace.mkdir()
        trusted_bin = tmp_path / "trusted-bin"
        trusted_bin.mkdir()

        trusted_exe = trusted_bin / "demo"
        trusted_exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        trusted_exe.chmod(0o755)

        scanner = self._DummyScanner(str(workspace))
        captured = {}

        def fake_run(cmd, cwd=None, capture_output=True, text=True, timeout=None, env=None):
            captured["cmd"] = cmd
            captured["env"] = env
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        scanner.run_command(
            ["demo"],
            env={"PATH": f"relative-bin{os.pathsep}{trusted_bin}"},
        )

        assert captured["cmd"][0] == str(trusted_exe)
        effective_path = (captured["env"] or {}).get("PATH", "")
        assert "relative-bin" not in effective_path

    def test_run_command_rejects_empty_command(self, tmp_path):
        workspace = tmp_path / "repo"
        workspace.mkdir()
        scanner = self._DummyScanner(str(workspace))

        with pytest.raises(ValueError, match="must not be empty"):
            scanner.run_command([])

    def test_run_command_reports_missing_tool_with_actionable_error(self, tmp_path, monkeypatch):
        workspace = tmp_path / "repo"
        workspace.mkdir()
        scanner = self._DummyScanner(str(workspace))

        def fake_run(cmd, cwd=None, capture_output=True, text=True, timeout=None, env=None):
            raise FileNotFoundError(f"[Errno 2] No such file or directory: '{cmd[0]}'")

        monkeypatch.setattr(subprocess, "run", fake_run)

        with pytest.raises(RuntimeError, match="Required tool not found in PATH: missing-tool"):
            scanner.run_command(["missing-tool"])

    def test_run_command_clears_path_when_only_workspace_entries(self, tmp_path, monkeypatch):
        workspace = tmp_path / "repo"
        workspace.mkdir()
        workspace_bin = workspace / "bin"
        workspace_bin.mkdir()

        scanner = self._DummyScanner(str(workspace))
        captured = {}

        def fake_run(cmd, cwd=None, capture_output=True, text=True, timeout=None, env=None):
            captured["cmd"] = cmd
            captured["env"] = env
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        scanner.run_command(
            ["demo"],
            env={"PATH": f".{os.pathsep}{workspace_bin}"},
        )

        assert (captured["env"] or {}).get("PATH") == ""

    def test_run_command_filters_non_system_path_on_github_actions(self, tmp_path, monkeypatch):
        workspace = tmp_path / "repo"
        workspace.mkdir()

        scanner = self._DummyScanner(str(workspace))
        captured = {}

        def fake_run(cmd, cwd=None, capture_output=True, text=True, timeout=None, env=None):
            captured["cmd"] = cmd
            captured["env"] = env
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        monkeypatch.setenv("GITHUB_ACTIONS", "true")

        scanner.run_command(
            ["sh", "--version"],
            env={"PATH": f"/tmp/malicious{os.pathsep}/usr/bin{os.pathsep}/bin"},
        )

        effective_path = (captured["env"] or {}).get("PATH", "")
        assert "/tmp/malicious" not in effective_path
        assert "/usr/bin" in effective_path

    def test_normalize_path_strips_exact_workspace_prefix_only(self, tmp_path):
        workspace = tmp_path / "repo"
        workspace.mkdir()
        scanner = self._DummyScanner(str(workspace))

        inside = scanner.normalize_path(str(workspace / "src" / "app.py"))
        assert inside == "src/app.py"

        # 유사 prefix(repo2)는 strip되면 안 된다.
        sibling_like = str(workspace) + "2/src/app.py"
        outside = scanner.normalize_path(sibling_like)
        assert outside == sibling_like

    def test_run_command_filters_untrusted_opt_path_on_github_actions(self, tmp_path, monkeypatch):
        workspace = tmp_path / "repo"
        workspace.mkdir()

        scanner = self._DummyScanner(str(workspace))
        captured = {}

        def fake_run(cmd, cwd=None, capture_output=True, text=True, timeout=None, env=None):
            captured["cmd"] = cmd
            captured["env"] = env
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        monkeypatch.setenv("GITHUB_ACTIONS", "true")

        scanner.run_command(
            ["sh", "--version"],
            env={"PATH": (f"/opt/malicious{os.pathsep}/opt/sonar-scanner/bin{os.pathsep}/usr/bin")},
        )

        effective_path = (captured["env"] or {}).get("PATH", "")
        assert "/opt/malicious" not in effective_path
        assert "/opt/sonar-scanner/bin" in effective_path

    def test_run_command_resolves_relative_cwd_against_workspace(self, tmp_path, monkeypatch):
        workspace = tmp_path / "repo"
        workspace.mkdir()
        (workspace / "src").mkdir()

        scanner = self._DummyScanner(str(workspace))
        captured = {}

        def fake_run(cmd, cwd=None, capture_output=True, text=True, timeout=None, env=None):
            captured["cwd"] = cwd
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        scanner.run_command(["echo", "ok"], cwd="src")

        assert captured["cwd"] == str((workspace / "src").resolve())

    def test_run_command_rejects_cwd_outside_workspace_on_github_actions(
        self, tmp_path, monkeypatch
    ):
        workspace = tmp_path / "repo"
        workspace.mkdir()

        scanner = self._DummyScanner(str(workspace))
        monkeypatch.setenv("GITHUB_ACTIONS", "true")

        with pytest.raises(ValueError, match="must stay within workspace"):
            scanner.run_command(["echo", "ok"], cwd="../outside")


class TestParallelScanner:
    """ParallelScanner 동작 테스트"""

    def test_passes_task_config_to_scanner(self, tmp_path):
        class DummyScanner:
            def __init__(self, workspace: str, required_flag: bool = False):
                self.workspace = workspace
                self.required_flag = required_flag

            def scan(self):
                return ScanResult(
                    scanner="Dummy",
                    success=self.required_flag,
                    findings=[],
                    execution_time=0.0,
                )

        runner = ParallelScanner(str(tmp_path), max_workers=1)
        runner.add_scanner(
            name="Dummy",
            scanner_class=DummyScanner,
            config={"required_flag": True},
        )

        results = runner.run_sequential()
        assert len(results) == 1
        assert results[0].success is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
