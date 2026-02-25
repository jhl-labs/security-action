"""SBOM generator 테스트"""

import json
import subprocess

from scanners.sbom_generator import SBOMGenerator


def test_generate_resolves_relative_output_to_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "repo"
    workspace.mkdir()

    output_rel = "reports/sbom.json"
    output_file = workspace / output_rel

    def fake_run(cmd, capture_output=True, text=True, timeout=None, cwd=None):
        assert cwd == str(workspace)
        assert cmd[0] == "syft"
        assert f"cyclonedx-json={output_file}" in cmd

        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps({"components": [{"name": "pkg"}]}), encoding="utf-8")

        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    generator = SBOMGenerator(
        workspace=str(workspace),
        output_format="cyclonedx-json",
        output_path=output_rel,
    )
    result = generator.generate()

    assert result["success"] is True
    assert result["components_count"] == 1
    assert result["output_path"] == output_rel


def test_get_components_uses_workspace_relative_output_path(tmp_path):
    workspace = tmp_path / "repo"
    workspace.mkdir()

    output_rel = "sbom.json"
    output_file = workspace / output_rel
    output_file.write_text(
        json.dumps(
            {
                "components": [
                    {
                        "name": "demo",
                        "version": "1.0.0",
                        "type": "library",
                        "purl": "pkg:pypi/demo@1.0.0",
                        "licenses": [{"license": {"id": "MIT"}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    generator = SBOMGenerator(
        workspace=str(workspace),
        output_format="cyclonedx-json",
        output_path=output_rel,
    )
    components = generator.get_components()

    assert len(components) == 1
    assert components[0]["name"] == "demo"
    assert components[0]["version"] == "1.0.0"
    assert components[0]["licenses"] == ["MIT"]
