"""CodeScanner tests."""

from types import SimpleNamespace

from scanners.code_scanner import CodeScanner


def test_code_scanner_reports_exit_code_and_output_on_failure(monkeypatch, tmp_path):
    scanner = CodeScanner(str(tmp_path))

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        return SimpleNamespace(returncode=2, stdout="rule fetch failed", stderr="")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is False
    assert findings == []
    assert error is not None
    assert "exit code 2" in error
    assert "rule fetch failed" in error
