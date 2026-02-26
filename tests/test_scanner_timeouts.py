"""Scanner command timeout tests."""

from types import SimpleNamespace

from scanners.code_scanner import CodeScanner
from scanners.container_scanner import ContainerScanner
from scanners.dependency_scanner import DependencyScanner
from scanners.secret_scanner import SecretScanner
from scanners.sonar_scanner import SonarScanner


def test_secret_scanner_sets_timeout(monkeypatch, tmp_path):
    scanner = SecretScanner(str(tmp_path), scan_history=False)
    captured = {}

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        captured["timeout"] = timeout
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is True
    assert findings == []
    assert error is None
    assert captured["timeout"] == 600


def test_code_scanner_sets_timeout(monkeypatch, tmp_path):
    scanner = CodeScanner(str(tmp_path))
    captured = {}

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        captured["timeout"] = timeout
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is True
    assert findings == []
    assert error is None
    assert captured["timeout"] == 900


def test_dependency_scanner_sets_timeout(monkeypatch, tmp_path):
    scanner = DependencyScanner(str(tmp_path))
    captured = {}

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        captured["timeout"] = timeout
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is True
    assert findings == []
    assert error is None
    assert captured["timeout"] == 900


def test_container_scanner_sets_timeout(monkeypatch, tmp_path):
    scanner = ContainerScanner(str(tmp_path), image="nginx:latest")
    captured = {}

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        captured["timeout"] = timeout
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is True
    assert findings == []
    assert error is None
    assert captured["timeout"] == 900


def test_sonar_scanner_sets_timeout(monkeypatch, tmp_path):
    scanner = SonarScanner(
        workspace=str(tmp_path),
        server_url="https://sonar.example.com",
        token="dummy-token",
        project_key="demo",
    )

    props_file = tmp_path / "sonar-project.properties"
    props_file.write_text("sonar.projectKey=demo\n", encoding="utf-8")
    captured = {}

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        captured["timeout"] = timeout
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    ok, error = scanner._execute_scanner()

    assert ok is True
    assert error is None
    assert captured["timeout"] == 1800
