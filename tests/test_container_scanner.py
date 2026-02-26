"""Container scanner tests."""

from types import SimpleNamespace

from scanners.container_scanner import ContainerScanner


def test_container_scan_retries_without_file_patterns_on_compat_error(tmp_path, monkeypatch):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n")

    scanner = ContainerScanner(str(tmp_path), dockerfile_path=str(dockerfile))
    calls = []

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        calls.append(list(cmd))
        if len(calls) == 1:
            return SimpleNamespace(
                returncode=2,
                stdout="",
                stderr="unknown flag: --file-patterns",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is True
    assert findings == []
    assert error is None
    assert len(calls) == 2
    assert "--file-patterns" in calls[0]
    assert "--file-patterns" not in calls[1]


def test_container_scan_does_not_retry_on_non_compat_error(tmp_path, monkeypatch):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n")

    scanner = ContainerScanner(str(tmp_path), dockerfile_path=str(dockerfile))
    calls = []

    def fake_run_command(cmd, capture_output=True, timeout=None, cwd=None, env=None):  # noqa: ARG001
        calls.append(list(cmd))
        return SimpleNamespace(returncode=2, stdout="", stderr="network timeout")

    monkeypatch.setattr(scanner, "run_command", fake_run_command)

    success, findings, error = scanner._run_scan()

    assert success is False
    assert findings == []
    assert error is not None
    assert len(calls) == 1


def test_normalize_container_target_treats_registry_image_as_image_name(tmp_path):
    scanner = ContainerScanner(str(tmp_path))

    target = scanner._normalize_container_target("ghcr.io/acme/security-action:1.2.3 (alpine 3.20)")

    assert target == "container-image/ghcr.io-acme-security-action-1.2.3"


def test_normalize_container_target_keeps_existing_workspace_file_path(tmp_path):
    target_file = tmp_path / "reports" / "scan.json"
    target_file.parent.mkdir(parents=True)
    target_file.write_text("{}")

    scanner = ContainerScanner(str(tmp_path))

    target = scanner._normalize_container_target("reports/scan.json")

    assert target == "reports/scan.json"


def test_container_scanner_resolves_relative_dockerfile_path(tmp_path):
    dockerfile = tmp_path / "infra" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text("FROM scratch\n")

    scanner = ContainerScanner(str(tmp_path), dockerfile_path="infra/Dockerfile")

    assert scanner.dockerfile_path == str(dockerfile.resolve(strict=False))


def test_container_scanner_rejects_workspace_escape_dockerfile_path_in_actions(
    tmp_path, monkeypatch
):
    outside = tmp_path.parent / "outside.Dockerfile"
    outside.write_text("FROM scratch\n")

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    scanner = ContainerScanner(str(tmp_path), dockerfile_path=str(outside))

    assert scanner.dockerfile_path is None
