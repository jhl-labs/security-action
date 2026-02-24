"""스캐너 통합 테스트"""

import subprocess
from pathlib import Path

import pytest

from scanners.base import Finding, ScanResult, Severity
from scanners.code_scanner import CodeScanner
from scanners.dependency_scanner import DependencyScanner
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
        # 알려진 취약점이 있는 패키지 탐지 기대
        assert len(result.findings) > 0

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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
