"""LangGraph 기반 Security Review Agent"""

import os
from functools import partial

from langgraph.graph import END, StateGraph

from .nodes import (
    analyze_findings_node,
    extract_contexts_node,
    generate_remediations_node,
    generate_reviews_node,
    generate_summary_node,
)
from .state import AgentConfig, AgentState


def create_security_review_graph(config: AgentConfig | None = None) -> StateGraph:
    """Security Review Agent 그래프 생성"""
    if config is None:
        config = AgentConfig()

    # StateGraph 생성
    workflow = StateGraph(AgentState)

    # 노드 추가 (config를 바인딩)
    workflow.add_node(
        "extract_contexts",
        partial(extract_contexts_node, config=config),
    )
    workflow.add_node(
        "analyze_findings",
        partial(analyze_findings_node, config=config),
    )
    workflow.add_node(
        "generate_remediations",
        partial(generate_remediations_node, config=config),
    )
    workflow.add_node(
        "generate_reviews",
        partial(generate_reviews_node, config=config),
    )
    workflow.add_node(
        "generate_summary",
        partial(generate_summary_node, config=config),
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

    # API 키에 따라 provider 결정
    if anthropic_key and not openai_key:
        provider = "anthropic"
        model = "claude-3-5-sonnet-20241022"
    else:
        provider = "openai"
        model = "gpt-4o"

    return AgentConfig(
        model_provider=provider,
        model_name=model,
        temperature=0.1,
        max_tokens=4096,
        max_findings_to_review=20,
        include_code_context=True,
        context_lines=10,
    )
