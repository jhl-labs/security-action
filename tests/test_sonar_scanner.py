"""Sonar scanner tests."""

from types import SimpleNamespace

from scanners.sonar_scanner import SonarScanner


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code
        self.text = ""

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def _new_scanner() -> SonarScanner:
    return SonarScanner(
        workspace="/tmp/repo",
        server_url="https://sonar.example.com",
        token="dummy-token",
        project_key="acme_project",
    )


def test_fetch_issues_supports_paging_total(monkeypatch):
    scanner = _new_scanner()
    calls = []

    page_payloads = {
        1: {
            "issues": [{"key": "ISSUE-1"}] * 100,
            "paging": {"pageIndex": 1, "pageSize": 100, "total": 150},
        },
        2: {
            "issues": [{"key": "ISSUE-2"}] * 50,
            "paging": {"pageIndex": 2, "pageSize": 100, "total": 150},
        },
    }

    def fake_get(url, params=None, headers=None, timeout=30):  # noqa: ARG001
        calls.append(params["p"])
        return _FakeResponse(page_payloads[params["p"]])

    monkeypatch.setattr("scanners.sonar_scanner.httpx.get", fake_get)
    issues = scanner._fetch_issues()

    assert len(issues) == 150
    assert calls == [1, 2]


def test_fetch_hotspots_supports_paging_total(monkeypatch):
    scanner = _new_scanner()
    calls = []

    page_payloads = {
        1: {
            "hotspots": [{"key": "HSP-1"}] * 100,
            "paging": {"pageIndex": 1, "pageSize": 100, "total": 120},
        },
        2: {
            "hotspots": [{"key": "HSP-2"}] * 20,
            "paging": {"pageIndex": 2, "pageSize": 100, "total": 120},
        },
    }

    def fake_get(url, params=None, headers=None, timeout=30):  # noqa: ARG001
        calls.append(params["p"])
        return _FakeResponse(page_payloads[params["p"]])

    monkeypatch.setattr("scanners.sonar_scanner.httpx.get", fake_get)
    hotspots = scanner._fetch_hotspots()

    assert len(hotspots) == 120
    assert calls == [1, 2]


def test_fetch_hotspots_falls_back_to_page_length_when_total_missing(monkeypatch):
    scanner = _new_scanner()
    calls = []

    page_payloads = {
        1: {"hotspots": [{"key": "HSP-1"}] * 100},
        2: {"hotspots": [{"key": "HSP-2"}] * 3},
    }

    def fake_get(url, params=None, headers=None, timeout=30):  # noqa: ARG001
        calls.append(params["p"])
        return _FakeResponse(page_payloads[params["p"]])

    monkeypatch.setattr("scanners.sonar_scanner.httpx.get", fake_get)
    hotspots = scanner._fetch_hotspots()

    assert len(hotspots) == 103
    assert calls == [1, 2]


def test_execute_scanner_passes_token_via_env_not_cli(monkeypatch, tmp_path):
    scanner = SonarScanner(
        workspace=str(tmp_path),
        server_url="https://sonar.example.com",
        token="secret-token",
        project_key="acme_project",
    )

    captured: dict = {}

    def fake_run_command(cmd, timeout=None, env=None, **kwargs):  # noqa: ANN001, ANN202, ARG001
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        captured["env"] = env
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, error = scanner._execute_scanner()

    assert success is True
    assert error is None
    assert captured["cmd"][0] == "sonar-scanner"
    assert any(arg == "-Dsonar.host.url=https://sonar.example.com" for arg in captured["cmd"])
    assert any(arg == "-Dsonar.projectKey=acme_project" for arg in captured["cmd"])
    assert not any("secret-token" in arg for arg in captured["cmd"])
    assert captured["timeout"] == 1800
    assert captured["env"] == {"SONAR_TOKEN": "secret-token"}


def test_execute_scanner_overrides_repo_properties_with_secure_cli_values(monkeypatch, tmp_path):
    (tmp_path / "sonar-project.properties").write_text(
        "sonar.host.url=https://attacker.example.com\nsonar.projectKey=attacker_project\n",
        encoding="utf-8",
    )

    scanner = SonarScanner(
        workspace=str(tmp_path),
        server_url="https://sonar.example.com",
        token="secret-token",
        project_key="acme_project",
    )

    captured: dict = {}

    def fake_run_command(cmd, timeout=None, env=None, **kwargs):  # noqa: ANN001, ANN202, ARG001
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        captured["env"] = env
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, error = scanner._execute_scanner()

    assert success is True
    assert error is None
    assert f"-Dproject.settings={tmp_path / 'sonar-project.properties'}" in captured["cmd"]
    assert any(arg == "-Dsonar.host.url=https://sonar.example.com" for arg in captured["cmd"])
    assert any(arg == "-Dsonar.projectKey=acme_project" for arg in captured["cmd"])
    assert not any("secret-token" in arg for arg in captured["cmd"])


def test_run_scan_rejects_remote_http_with_token(monkeypatch, tmp_path):
    scanner = SonarScanner(
        workspace=str(tmp_path),
        server_url="http://sonar.internal:9000",
        token="secret-token",
        project_key="acme_project",
    )

    monkeypatch.setattr(scanner, "_execute_scanner", lambda: (True, None))
    monkeypatch.setattr(scanner, "_fetch_issues", lambda: [])
    monkeypatch.setattr(scanner, "_fetch_hotspots", lambda: [])

    errors: list[str] = []

    def fake_error(message, *args, **kwargs):  # noqa: ANN001, ANN202, ARG001
        if args:
            errors.append(message % args)
        else:
            errors.append(message)

    monkeypatch.setattr("scanners.sonar_scanner.logger.error", fake_error)

    success, findings, error = scanner._run_scan()
    assert success is False
    assert findings == []
    assert error is not None
    assert "insecure http" in error.lower()
    assert any("insecure http" in message.lower() for message in errors)


def test_run_scan_rejects_url_with_embedded_credentials(tmp_path):
    scanner = SonarScanner(
        workspace=str(tmp_path),
        server_url="https://user:pass@sonar.example.com",
        token="secret-token",
        project_key="acme_project",
    )

    success, findings, error = scanner._run_scan()

    assert success is False
    assert findings == []
    assert error is not None
    assert "embedded credentials" in error.lower()


def test_run_scan_rejects_unsupported_url_scheme(tmp_path):
    scanner = SonarScanner(
        workspace=str(tmp_path),
        server_url="ftp://sonar.example.com",
        token="secret-token",
        project_key="acme_project",
    )

    success, findings, error = scanner._run_scan()

    assert success is False
    assert findings == []
    assert error is not None
    assert "unsupported sonar_host_url scheme" in error.lower()


def test_run_scan_allows_localhost_http_with_token(monkeypatch, tmp_path):
    scanner = SonarScanner(
        workspace=str(tmp_path),
        server_url="http://localhost:9000",
        token="secret-token",
        project_key="acme_project",
    )

    monkeypatch.setattr(scanner, "_execute_scanner", lambda: (True, None))
    monkeypatch.setattr(scanner, "_fetch_issues", lambda: [])
    monkeypatch.setattr(scanner, "_fetch_hotspots", lambda: [])

    success, findings, error = scanner._run_scan()
    assert success is True
    assert findings == []
    assert error is None


def test_init_sanitizes_multiline_property_values(monkeypatch, tmp_path):
    warnings: list[str] = []

    def fake_warning(message, *args, **kwargs):  # noqa: ANN001, ANN202, ARG001
        warnings.append(message % args if args else message)

    monkeypatch.setattr("scanners.sonar_scanner.logger.warning", fake_warning)

    scanner = SonarScanner(
        workspace=str(tmp_path),
        server_url="https://sonar.example.com\nsonar.login=attacker",
        token="secret-token",
        project_key="demo_project\nsonar.sources=/tmp/evil",
    )

    assert scanner.server_url == "https://sonar.example.com"
    assert scanner.project_key == "demo_project"

    props = scanner._generate_properties()
    assert "sonar.host.url=https://sonar.example.com" in props
    assert "sonar.projectKey=demo_project" in props
    assert "sonar.login=attacker" not in props
    assert "sonar.sources=/tmp/evil" not in props
    assert len(warnings) >= 2
