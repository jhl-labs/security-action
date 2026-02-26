"""AI Agent 테스트"""

from types import SimpleNamespace

import pytest

import agent.nodes as agent_nodes
from agent.nodes import (
    SENSITIVE_CONTEXT_PLACEHOLDER,
    _redact_sensitive_text,
    analyze_findings_node,
    detect_language,
    extract_code_context,
    parse_json_response,
)
from agent.state import (
    AgentConfig,
    AgentState,
    CodeContext,
    FindingAnalysis,
    RemediationSuggestion,
    ReviewCategory,
    ReviewSeverity,
    SecurityReview,
)


class TestAgentState:
    """Agent 상태 테스트"""

    def test_create_agent_state(self):
        state = AgentState(
            findings=[{"rule_id": "test"}],
            workspace_path="/tmp/test",
        )
        assert len(state.findings) == 1
        assert state.workspace_path == "/tmp/test"
        assert state.completed is False

    def test_agent_config_defaults(self):
        config = AgentConfig()
        assert config.model_provider == "openai"
        assert config.model_name == "gpt-4o"
        assert config.openai_api_key is None
        assert config.anthropic_api_key is None
        assert config.temperature == 0.1


class TestCodeContext:
    """코드 컨텍스트 테스트"""

    def test_create_code_context(self):
        context = CodeContext(
            file_path="test.py",
            start_line=10,
            end_line=20,
            code_snippet="print('hello')",
            language="python",
        )
        assert context.file_path == "test.py"
        assert context.language == "python"


class TestFindingAnalysis:
    """취약점 분석 테스트"""

    def test_create_finding_analysis(self):
        analysis = FindingAnalysis(
            finding_id="test-1",
            category=ReviewCategory.SQL_INJECTION,
            severity=ReviewSeverity.HIGH,
            title="SQL Injection",
            description="User input in query",
            impact="Data breach",
        )
        assert analysis.category == ReviewCategory.SQL_INJECTION
        assert analysis.is_false_positive is False


class TestNodeFunctions:
    """노드 함수 테스트"""

    def test_detect_language(self):
        assert detect_language("test.py") == "python"
        assert detect_language("app.js") == "javascript"
        assert detect_language("main.go") == "go"
        assert detect_language("unknown.xyz") == "text"

    def test_extract_code_context_file_not_found(self):
        context = extract_code_context(
            workspace="/nonexistent",
            file_path="missing.py",
            line_start=1,
        )
        assert "[File not found]" in context.code_snippet

    def test_extract_code_context_real_file(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text("line1\nline2\nline3\nline4\nline5\n")

        context = extract_code_context(
            workspace=str(tmp_path),
            file_path="test.py",
            line_start=2,
            line_end=3,
            context_lines=1,
        )

        assert "line2" in context.code_snippet
        assert context.language == "python"

    def test_extract_code_context_normalizes_invalid_line_numbers(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text("line1\nline2\n")

        context = extract_code_context(
            workspace=str(tmp_path),
            file_path="test.py",
            line_start=0,
            line_end=-5,
        )

        assert context.start_line == 1
        assert context.end_line == 1
        assert "line1" in context.code_snippet

    def test_extract_code_context_blocks_outside_workspace_path(self, tmp_path):
        outside = tmp_path.parent / "outside.py"
        outside.write_text("print('outside')\n")

        context = extract_code_context(
            workspace=str(tmp_path),
            file_path=str(outside),
            line_start=1,
        )

        assert "[File outside workspace]" in context.code_snippet

    def test_extract_code_context_windows_case_insensitive_workspace_path(self):
        context = extract_code_context(
            workspace="C:/Repo/Project",
            file_path="c:/repo/project/src/app.py",
            line_start=1,
        )

        # Windows 드라이브 경로는 대소문자 차이만으로 workspace 외부로 오판하지 않는다.
        assert context.code_snippet == "[File not found]"

    def test_extract_code_context_windows_path_traversal_is_blocked(self):
        context = extract_code_context(
            workspace="C:/Repo/Project",
            file_path="c:/repo/project/../outside.txt",
            line_start=1,
        )

        assert context.code_snippet == "[File outside workspace]"

    def test_parse_json_response_clean(self):
        response = '{"key": "value"}'
        result = parse_json_response(response)
        assert result["key"] == "value"

    def test_generate_summary_node_handles_info_severity(self, monkeypatch):
        class FakeLLM:
            def invoke(self, messages):  # noqa: ARG002
                return SimpleNamespace(content="summary ok")

        monkeypatch.setattr(agent_nodes, "get_llm", lambda config: FakeLLM())

        state = AgentState(
            findings=[],
            analyses=[
                FindingAnalysis(
                    finding_id="finding-1",
                    category=ReviewCategory.OTHER,
                    severity=ReviewSeverity.INFO,
                    title="Informational finding",
                    description="details",
                    impact="low",
                )
            ],
        )
        config = AgentConfig()

        updated = agent_nodes.generate_summary_node(state, config)
        assert updated.completed is True
        assert updated.summary == "summary ok"

    def test_parse_json_response_with_markdown(self):
        response = '```json\n{"key": "value"}\n```'
        result = parse_json_response(response)
        assert result["key"] == "value"

    def test_parse_json_response_invalid(self):
        response = "not json at all"
        result = parse_json_response(response)
        assert result == {}

    def test_redact_sensitive_text_masks_common_token_formats(self):
        text = (
            "Authorization: Bearer abcdefghijklmnop\n"
            "token=ghp_1234567890ABCDEFtoken\n"
            "openai=sk-test_secret_value_12345\n"
            "aws=AKIAABCDEFGHIJKLMNOP\n"
        )

        redacted = _redact_sensitive_text(text)

        assert "ghp_1234567890ABCDEFtoken" not in redacted
        assert "sk-test_secret_value_12345" not in redacted
        assert "AKIAABCDEFGHIJKLMNOP" not in redacted
        assert "***REDACTED***" in redacted

    def test_analyze_findings_node_redacts_secret_context_for_llm(self, monkeypatch):
        captured = {}

        class FakeLLM:
            def invoke(self, messages):
                captured["prompt"] = messages[1].content
                return SimpleNamespace(
                    content=(
                        '{"category":"other","severity":"medium","title":"ok",'
                        '"description":"d","impact":"i","is_false_positive":false,"confidence":0.8}'
                    )
                )

        monkeypatch.setattr(agent_nodes, "get_llm", lambda config: FakeLLM())

        state = AgentState(
            findings=[
                {
                    "scanner": "Gitleaks",
                    "rule_id": "generic-secret",
                    "severity": "high",
                    "message": "Hardcoded secret detected",
                    "file_path": "app.py",
                    "line_start": 1,
                }
            ],
            code_contexts=[
                CodeContext(
                    file_path="app.py",
                    start_line=1,
                    end_line=1,
                    code_snippet='API_KEY = "super-secret-value"',
                    surrounding_code='API_KEY = "super-secret-value"\nprint("x")',
                    language="python",
                )
            ],
        )

        updated = analyze_findings_node(state, AgentConfig())

        assert len(updated.analyses) == 1
        prompt = captured["prompt"]
        assert SENSITIVE_CONTEXT_PLACEHOLDER in prompt
        assert "super-secret-value" not in prompt


class TestSecurityReview:
    """보안 리뷰 테스트"""

    def test_create_security_review(self):
        analysis = FindingAnalysis(
            finding_id="test-1",
            category=ReviewCategory.XSS,
            severity=ReviewSeverity.MEDIUM,
            title="XSS Vulnerability",
            description="innerHTML usage",
            impact="Script injection",
        )
        context = CodeContext(
            file_path="app.js",
            start_line=10,
            end_line=10,
            code_snippet="element.innerHTML = userInput",
        )
        remediation = RemediationSuggestion(
            finding_id="test-1",
            summary="Use textContent instead",
            detailed_explanation="innerHTML can execute scripts",
        )
        review = SecurityReview(
            finding_id="test-1",
            analysis=analysis,
            context=context,
            remediation=remediation,
            pr_comment="Fix XSS vulnerability",
        )

        assert review.finding_id == "test-1"
        assert review.analysis.category == ReviewCategory.XSS


class TestGraphCreation:
    """그래프 생성 테스트"""

    def test_create_graph(self):
        from agent.graph import create_security_review_graph

        config = AgentConfig()
        graph = create_security_review_graph(config)

        assert graph is not None
        # 노드 확인
        assert "extract_contexts" in graph.nodes
        assert "analyze_findings" in graph.nodes
        assert "generate_remediations" in graph.nodes

    def test_create_config_from_env_provider_model_override(self, monkeypatch):
        from agent.graph import create_config_from_env

        monkeypatch.setenv("INPUT_AI_PROVIDER", "openai")
        monkeypatch.setenv("INPUT_AI_MODEL", "gpt-4.1-mini")
        monkeypatch.setenv("INPUT_OPENAI_BASE_URL", "https://llm.example.local/v1")
        monkeypatch.setenv("INPUT_OPENAI_API_KEY", "dummy")

        config = create_config_from_env()
        assert config.model_provider == "openai"
        assert config.model_name == "gpt-4.1-mini"
        assert config.openai_api_key == "dummy"
        assert config.openai_base_url == "https://llm.example.local/v1"

    def test_create_config_from_env_auto_selects_anthropic_when_only_anthropic_key(
        self, monkeypatch
    ):
        from agent.graph import create_config_from_env

        monkeypatch.delenv("INPUT_AI_PROVIDER", raising=False)
        monkeypatch.delenv("INPUT_AI_MODEL", raising=False)
        monkeypatch.delenv("INPUT_OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("INPUT_ANTHROPIC_API_KEY", "dummy")

        config = create_config_from_env()
        assert config.model_provider == "anthropic"
        assert config.model_name == "claude-3-5-sonnet-20241022"
        assert config.anthropic_api_key == "dummy"

    def test_create_config_from_env_rejects_remote_http_openai_base_url_with_key(self, monkeypatch):
        from agent.graph import create_config_from_env

        monkeypatch.setenv("INPUT_AI_PROVIDER", "openai")
        monkeypatch.setenv("INPUT_OPENAI_API_KEY", "dummy")
        monkeypatch.setenv("INPUT_OPENAI_BASE_URL", "http://llm.example.com/v1")

        with pytest.raises(ValueError, match="insecure HTTP"):
            create_config_from_env()

    def test_create_config_from_env_auto_falls_back_to_anthropic_on_insecure_openai_http(
        self, monkeypatch
    ):
        from agent.graph import create_config_from_env

        monkeypatch.delenv("INPUT_AI_PROVIDER", raising=False)
        monkeypatch.setenv("INPUT_OPENAI_API_KEY", "openai-dummy")
        monkeypatch.setenv("INPUT_OPENAI_BASE_URL", "http://llm.example.com/v1")
        monkeypatch.setenv("INPUT_ANTHROPIC_API_KEY", "anthropic-dummy")

        config = create_config_from_env()
        assert config.model_provider == "anthropic"
        assert config.anthropic_api_key == "anthropic-dummy"
        assert config.openai_api_key is None
        assert config.openai_base_url is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
