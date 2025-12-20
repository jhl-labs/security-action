"""AI Agent 테스트"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

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
from agent.nodes import detect_language, extract_code_context, parse_json_response


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

    def test_parse_json_response_clean(self):
        response = '{"key": "value"}'
        result = parse_json_response(response)
        assert result["key"] == "value"

    def test_parse_json_response_with_markdown(self):
        response = '```json\n{"key": "value"}\n```'
        result = parse_json_response(response)
        assert result["key"] == "value"

    def test_parse_json_response_invalid(self):
        response = "not json at all"
        result = parse_json_response(response)
        assert result == {}


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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
