"""DependencyScanner 단위 테스트"""

from types import SimpleNamespace

from scanners.dependency_scanner import DependencyScanner


def test_dependency_scanner_fails_on_nonzero_exit(monkeypatch, tmp_path):
    scanner = DependencyScanner(str(tmp_path))

    def fake_run_command(*args, **kwargs):
        return SimpleNamespace(returncode=2, stdout="", stderr="network timeout")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is False
    assert findings == []
    assert error is not None
    assert "exit code 2" in error
    assert "network timeout" in error
