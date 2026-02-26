"""Tests for security-action rollout workflow renderer skill script."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path

import pytest


def _load_render_module():
    root = Path(__file__).resolve().parents[1]
    script_path = root / "skills" / "security-action-rollout" / "scripts" / "render_workflow.py"
    spec = importlib.util.spec_from_file_location("render_workflow_skill", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _args(**overrides) -> argparse.Namespace:
    values = {
        "workflow_name": "Security Scan",
        "job_name": "security",
        "action_ref": "jhl-labs/security-action@main",
        "runs_on": "ubuntu-latest",
        "events": "pull_request,push",
        "target_branch": "main",
        "pr_types": "opened,synchronize,reopened",
        "schedule_cron": None,
        "mode": "report",
        "severity_threshold": "high",
        "upload_sarif": False,
        "sarif_category": "security-action",
        "parallel": False,
        "scanner_checks": False,
        "post_summary": True,
        "native_audit": False,
        "config_path": None,
        "github_token_expr": "${{ secrets.GITHUB_TOKEN }}",
        "enable_ai_review": False,
        "ai_provider": "openai",
        "ai_model_expr": "${{ secrets.AI_MODEL }}",
        "openai_api_key_expr": "${{ secrets.OPENAI_API_KEY }}",
        "openai_base_url_expr": "${{ secrets.OPENAI_BASE_URL }}",
        "anthropic_api_key_expr": "${{ secrets.ANTHROPIC_API_KEY }}",
        "enable_sonar": False,
        "sonar_host_url_expr": "${{ secrets.SONAR_HOST_URL }}",
        "sonar_token_expr": "${{ secrets.SONAR_TOKEN }}",
        "sonar_project_key": "security-action",
        "output": ".github/workflows/security-check.yaml",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_build_workflow_rejects_empty_runs_on():
    module = _load_render_module()
    with pytest.raises(ValueError, match="runs-on"):
        module.build_workflow(_args(runs_on=""))


def test_build_workflow_rejects_schedule_without_cron():
    module = _load_render_module()
    with pytest.raises(ValueError, match="schedule-cron"):
        module.build_workflow(_args(events="push,schedule", schedule_cron=""))


def test_build_workflow_rejects_unsupported_events():
    module = _load_render_module()
    with pytest.raises(ValueError, match="Unsupported event"):
        module.build_workflow(_args(events="pushh,pull_request"))


def test_build_workflow_rejects_invalid_severity_threshold():
    module = _load_render_module()
    with pytest.raises(ValueError, match="severity-threshold"):
        module.build_workflow(_args(severity_threshold="urgent"))


def test_build_workflow_omits_pull_request_permission_for_push_only_event():
    module = _load_render_module()
    workflow = module.build_workflow(_args(events="push"))

    assert "pull-requests: write" not in workflow
    assert "contents: read" in workflow
    assert "checks: write" in workflow


def test_build_workflow_includes_pull_request_permission_for_pr_event():
    module = _load_render_module()
    workflow = module.build_workflow(_args(events="pull_request"))

    assert "pull-requests: write" in workflow
