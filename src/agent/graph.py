"""LangGraph 기반 Security Review Agent"""

import os
from collections.abc import Callable

from langgraph.graph import END, StateGraph

from .nodes import (
    analyze_findings_node,
    extract_contexts_node,
    generate_remediations_node,
    generate_reviews_node,
    generate_summary_node,
)
from .state import AgentConfig, AgentState


def _bind_config(
    node_fn: Callable[[AgentState, AgentConfig], AgentState],
    config: AgentConfig,
) -> Callable[[AgentState], AgentState]:
    """AgentConfig를 노드 함수에 바인딩한 단일 인자 callable 생성."""

    def _wrapped(state: AgentState) -> AgentState:
        return node_fn(state, config)

    return _wrapped


def create_security_review_graph(config: AgentConfig | None = None) -> StateGraph:
    """Security Review Agent 그래프 생성"""
    if config is None:
        config = AgentConfig()

    # StateGraph 생성
    workflow = StateGraph(AgentState)

    # 노드 추가 (config를 바인딩)
    workflow.add_node(
        "extract_contexts",
        _bind_config(extract_contexts_node, config),
    )
    workflow.add_node(
        "analyze_findings",
        _bind_config(analyze_findings_node, config),
    )
    workflow.add_node(
        "generate_remediations",
        _bind_config(generate_remediations_node, config),
    )
    workflow.add_node(
        "generate_reviews",
        _bind_config(generate_reviews_node, config),
    )
    workflow.add_node(
        "generate_summary",
        _bind_config(generate_summary_node, config),
    )

    # 엣지 정의 (순차 실행)
    workflow.set_entry_point("extract_contexts")
    workflow.add_edge("extract_contexts", "analyze_findings")
    workflow.add_edge("analyze_findings", "generate_remediations")
    workflow.add_edge("generate_remediations", "generate_reviews")
    workflow.add_edge("generate_reviews", "generate_summary")
    workflow.add_edge("generate_summary", END)

    return workflow


def run_security_review(
    findings: list[dict],
    workspace_path: str,
    config: AgentConfig | None = None,
) -> AgentState:
    """Security Review 실행

    Args:
        findings: 스캐너에서 발견된 취약점 목록
        workspace_path: 소스 코드 경로
        config: Agent 설정

    Returns:
        AgentState: 리뷰 결과가 담긴 상태
    """
    if config is None:
        config = create_config_from_env()

    # 그래프 생성 및 컴파일
    workflow = create_security_review_graph(config)
    app = workflow.compile()

    # 초기 상태
    initial_state = AgentState(
        findings=findings,
        workspace_path=workspace_path,
    )

    # 실행
    try:
        final_state = app.invoke(initial_state)
        return final_state
    except Exception as e:
        initial_state.error = str(e)
        return initial_state


def create_config_from_env() -> AgentConfig:
    """환경 변수에서 Agent 설정 생성"""
    openai_key = os.getenv("INPUT_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
    anthropic_key = os.getenv("INPUT_ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    provider_input = (os.getenv("INPUT_AI_PROVIDER") or "auto").strip().lower()
    model_input = (os.getenv("INPUT_AI_MODEL") or "").strip()
    openai_base_url = (os.getenv("INPUT_OPENAI_BASE_URL") or os.getenv("OPENAI_BASE_URL") or "").strip()

    # API 키에 따라 provider 결정
    if provider_input in {"openai", "anthropic"}:
        provider = provider_input
    elif anthropic_key and not openai_key:
        provider = "anthropic"
    else:
        provider = "openai"

    default_model = "claude-3-5-sonnet-20241022" if provider == "anthropic" else "gpt-4o"
    model = model_input or default_model

    return AgentConfig(
        model_provider=provider,
        model_name=model,
        openai_base_url=openai_base_url or None,
        temperature=0.1,
        max_tokens=4096,
        max_findings_to_review=20,
        include_code_context=True,
        context_lines=10,
    )
