"""CLI 테스트"""

import argparse
import builtins
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import cli


def test_parse_args_upload_sarif(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "security-scan",
            ".",
            "--sarif",
            "security-results.sarif",
            "--upload-sarif",
            "--sarif-category",
            "security-selfhosted",
        ],
    )
    args = cli.parse_args()
    assert args.sarif_output == "security-results.sarif"
    assert args.upload_sarif is True
    assert args.sarif_category == "security-selfhosted"


def test_parse_args_no_scan_flags(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "security-scan",
            ".",
            "--no-secret-scan",
            "--no-code-scan",
            "--no-dependency-scan",
        ],
    )
    args = cli.parse_args()
    assert args.secret_scan is False
    assert args.code_scan is False
    assert args.dependency_scan is False


def test_parse_args_ai_options(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "security-scan",
            ".",
            "--ai-review",
            "--ai-provider",
            "openai",
            "--ai-model",
            "gpt-4o-mini",
            "--openai-base-url",
            "https://llm.example/v1",
            "--usage-tracking",
        ],
    )
    args = cli.parse_args()
    assert args.ai_review is True
    assert args.ai_provider == "openai"
    assert args.ai_model == "gpt-4o-mini"
    assert args.openai_base_url == "https://llm.example/v1"
    assert args.usage_tracking is True


def test_main_sets_upload_sarif_env(monkeypatch):
    args = argparse.Namespace(
        path=".",
        secret_scan=True,
        code_scan=True,
        dependency_scan=True,
        ai_review=False,
        ai_provider="auto",
        ai_model=None,
        openai_api_key=None,
        openai_base_url=None,
        anthropic_api_key=None,
        usage_tracking=False,
        severity_threshold="high",
        sarif_output="security-results.sarif",
        upload_sarif=True,
        sarif_category="security-action",
        fail_on_sarif_upload_error=True,
        json_output=None,
        no_fail=False,
        config=None,
        parallel=False,
        verbose=False,
        quiet=False,
    )

    monkeypatch.setattr(cli, "parse_args", lambda: args)
    monkeypatch.setitem(sys.modules, "main", SimpleNamespace(main=lambda: 0))

    exit_code = cli.main()
    assert exit_code == 0
    assert os.environ["INPUT_UPLOAD_SARIF"] == "true"
    assert os.environ["INPUT_SARIF_CATEGORY"] == "security-action"
    assert os.environ["INPUT_FAIL_ON_SARIF_UPLOAD_ERROR"] == "true"
    assert os.environ["INPUT_PARALLEL"] == "false"
    assert os.environ["INPUT_VERBOSE"] == "false"
    assert os.environ["INPUT_QUIET"] == "false"


def test_main_resets_sarif_flags_when_not_enabled(monkeypatch):
    args = argparse.Namespace(
        path=".",
        secret_scan=True,
        code_scan=True,
        dependency_scan=True,
        ai_review=False,
        ai_provider="auto",
        ai_model=None,
        openai_api_key=None,
        openai_base_url=None,
        anthropic_api_key=None,
        usage_tracking=False,
        severity_threshold="high",
        sarif_output=None,
        upload_sarif=False,
        sarif_category="security-action",
        fail_on_sarif_upload_error=False,
        json_output=None,
        no_fail=False,
        config=None,
        parallel=False,
        verbose=False,
        quiet=False,
    )

    monkeypatch.setattr(cli, "parse_args", lambda: args)
    monkeypatch.setitem(sys.modules, "main", SimpleNamespace(main=lambda: 0))
    monkeypatch.setenv("INPUT_UPLOAD_SARIF", "true")
    monkeypatch.setenv("INPUT_FAIL_ON_SARIF_UPLOAD_ERROR", "true")
    monkeypatch.setenv("INPUT_SARIF_CATEGORY", "stale-category")

    exit_code = cli.main()

    assert exit_code == 0
    assert os.environ["INPUT_UPLOAD_SARIF"] == "false"
    assert os.environ["INPUT_FAIL_ON_SARIF_UPLOAD_ERROR"] == "false"
    assert os.environ["INPUT_SARIF_CATEGORY"] == "security-action"


def test_main_sets_ai_env(monkeypatch):
    args = argparse.Namespace(
        path=".",
        secret_scan=True,
        code_scan=True,
        dependency_scan=True,
        ai_review=True,
        ai_provider="openai",
        ai_model="gpt-4.1-mini",
        openai_api_key="dummy-key",
        openai_base_url="https://llm.example.local/v1",
        anthropic_api_key=None,
        usage_tracking=True,
        severity_threshold="high",
        sarif_output=None,
        upload_sarif=False,
        sarif_category="security-action",
        fail_on_sarif_upload_error=False,
        json_output=None,
        no_fail=False,
        config=None,
        parallel=False,
        verbose=False,
        quiet=False,
    )

    monkeypatch.setattr(cli, "parse_args", lambda: args)
    monkeypatch.setitem(sys.modules, "main", SimpleNamespace(main=lambda: 0))

    exit_code = cli.main()
    assert exit_code == 0
    assert os.environ["INPUT_AI_REVIEW"] == "true"
    assert os.environ["INPUT_AI_PROVIDER"] == "openai"
    assert os.environ["INPUT_AI_MODEL"] == "gpt-4.1-mini"
    assert os.environ["INPUT_OPENAI_BASE_URL"] == "https://llm.example.local/v1"
    assert os.environ["OPENAI_BASE_URL"] == "https://llm.example.local/v1"
    assert os.environ["INPUT_USAGE_TRACKING"] == "true"
    assert os.environ["INPUT_PARALLEL"] == "false"
    assert os.environ["INPUT_VERBOSE"] == "false"
    assert os.environ["INPUT_QUIET"] == "false"


def test_main_sets_quiet_verbose_env(monkeypatch):
    args = argparse.Namespace(
        path=".",
        secret_scan=True,
        code_scan=True,
        dependency_scan=True,
        ai_review=False,
        ai_provider="auto",
        ai_model=None,
        openai_api_key=None,
        openai_base_url=None,
        anthropic_api_key=None,
        usage_tracking=False,
        severity_threshold="high",
        sarif_output=None,
        upload_sarif=False,
        sarif_category="security-action",
        fail_on_sarif_upload_error=False,
        json_output=None,
        no_fail=False,
        config=None,
        parallel=False,
        verbose=True,
        quiet=True,
    )

    monkeypatch.setattr(cli, "parse_args", lambda: args)
    monkeypatch.setitem(sys.modules, "main", SimpleNamespace(main=lambda: 0))

    exit_code = cli.main()
    assert exit_code == 0
    assert os.environ["INPUT_VERBOSE"] == "true"
    assert os.environ["INPUT_QUIET"] == "true"


def test_main_sets_json_output_env(monkeypatch):
    args = argparse.Namespace(
        path=".",
        secret_scan=True,
        code_scan=True,
        dependency_scan=True,
        ai_review=False,
        ai_provider="auto",
        ai_model=None,
        openai_api_key=None,
        openai_base_url=None,
        anthropic_api_key=None,
        usage_tracking=False,
        severity_threshold="high",
        sarif_output=None,
        upload_sarif=False,
        sarif_category="security-action",
        fail_on_sarif_upload_error=False,
        json_output="reports/security.json",
        no_fail=False,
        config=None,
        parallel=False,
        verbose=False,
        quiet=False,
    )

    monkeypatch.setattr(cli, "parse_args", lambda: args)
    monkeypatch.setitem(sys.modules, "main", SimpleNamespace(main=lambda: 0))

    exit_code = cli.main()
    assert exit_code == 0
    assert os.environ["INPUT_JSON_OUTPUT"] == "reports/security.json"


def test_main_falls_back_to_src_main_import(monkeypatch):
    args = argparse.Namespace(
        path=".",
        secret_scan=True,
        code_scan=True,
        dependency_scan=True,
        ai_review=False,
        ai_provider="auto",
        ai_model=None,
        openai_api_key=None,
        openai_base_url=None,
        anthropic_api_key=None,
        usage_tracking=False,
        severity_threshold="high",
        sarif_output=None,
        upload_sarif=False,
        sarif_category="security-action",
        fail_on_sarif_upload_error=False,
        json_output=None,
        no_fail=False,
        config=None,
        parallel=False,
        verbose=False,
        quiet=False,
    )

    monkeypatch.setattr(cli, "parse_args", lambda: args)

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "main":
            raise ImportError("main module blocked")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setitem(sys.modules, "src.main", SimpleNamespace(main=lambda: 0))

    exit_code = cli.main()
    assert exit_code == 0


def test_main_returns_2_when_scan_path_not_directory(monkeypatch):
    args = argparse.Namespace(
        path="/tmp/definitely-not-an-existing-directory-xyz",
        secret_scan=True,
        code_scan=True,
        dependency_scan=True,
        ai_review=False,
        ai_provider="auto",
        ai_model=None,
        openai_api_key=None,
        openai_base_url=None,
        anthropic_api_key=None,
        usage_tracking=False,
        severity_threshold="high",
        sarif_output=None,
        upload_sarif=False,
        sarif_category="security-action",
        fail_on_sarif_upload_error=False,
        json_output=None,
        no_fail=False,
        config=None,
        parallel=False,
        verbose=False,
        quiet=False,
    )

    monkeypatch.setattr(cli, "parse_args", lambda: args)
    exit_code = cli.main()
    assert exit_code == 2


def test_main_inserts_src_dir_before_importing_main(monkeypatch):
    args = argparse.Namespace(
        path=".",
        secret_scan=True,
        code_scan=True,
        dependency_scan=True,
        ai_review=False,
        ai_provider="auto",
        ai_model=None,
        openai_api_key=None,
        openai_base_url=None,
        anthropic_api_key=None,
        usage_tracking=False,
        severity_threshold="high",
        sarif_output=None,
        upload_sarif=False,
        sarif_category="security-action",
        fail_on_sarif_upload_error=False,
        json_output=None,
        no_fail=False,
        config=None,
        parallel=False,
        verbose=False,
        quiet=False,
    )

    monkeypatch.setattr(cli, "parse_args", lambda: args)
    expected_src_dir = str(Path(cli.__file__).resolve().parent)

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "main":
            assert expected_src_dir in sys.path
            return SimpleNamespace(main=lambda: 0)
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    exit_code = cli.main()
    assert exit_code == 0
