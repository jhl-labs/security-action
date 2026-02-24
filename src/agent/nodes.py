"""Agent 노드 구현"""

import json
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage

from .prompts import (
    ANALYZE_FINDING_PROMPT,
    GENERATE_PR_COMMENT_PROMPT,
    GENERATE_REMEDIATION_PROMPT,
    GENERATE_SUMMARY_PROMPT,
    SYSTEM_PROMPT,
)
from .state import (
    AgentConfig,
    AgentState,
    CodeContext,
    FindingAnalysis,
    RemediationSuggestion,
    ReviewCategory,
    ReviewSeverity,
    SecurityReview,
)


def get_llm(config: AgentConfig):
    """LLM 인스턴스 생성"""
    if config.model_provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=config.model_name,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )
    else:  # openai
        from langchain_openai import ChatOpenAI

        kwargs = {
            "model": config.model_name,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
        }
        if config.openai_base_url:
            kwargs["base_url"] = config.openai_base_url

        return ChatOpenAI(**kwargs)


def detect_language(file_path: str) -> str:
    """파일 확장자로 언어 감지"""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".cpp": "cpp",
        ".c": "c",
        ".rs": "rust",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".sql": "sql",
        ".sh": "bash",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".html": "html",
        ".css": "css",
    }
    ext = Path(file_path).suffix.lower()
    return ext_map.get(ext, "text")


def extract_code_context(
    workspace: str,
    file_path: str,
    line_start: int,
    line_end: int | None = None,
    context_lines: int = 10,
) -> CodeContext:
    """파일에서 코드 컨텍스트 추출"""
    full_path = Path(workspace) / file_path
    language = detect_language(file_path)

    if not full_path.exists():
        return CodeContext(
            file_path=file_path,
            start_line=line_start,
            end_line=line_end or line_start,
            code_snippet="[File not found]",
            language=language,
        )

    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        total_lines = len(lines)
        line_end = line_end or line_start

        # 메인 코드 스니펫 (1-indexed to 0-indexed)
        snippet_start = max(0, line_start - 1)
        snippet_end = min(total_lines, line_end)
        code_snippet = "".join(lines[snippet_start:snippet_end])

        # 주변 코드 (context)
        context_start = max(0, line_start - 1 - context_lines)
        context_end = min(total_lines, line_end + context_lines)
        surrounding_code = "".join(lines[context_start:context_end])

        return CodeContext(
            file_path=file_path,
            start_line=line_start,
            end_line=line_end,
            code_snippet=code_snippet.strip(),
            surrounding_code=surrounding_code.strip(),
            language=language,
        )
    except Exception as e:
        return CodeContext(
            file_path=file_path,
            start_line=line_start,
            end_line=line_end or line_start,
            code_snippet=f"[Error reading file: {e}]",
            language=language,
        )


def parse_json_response(response: str) -> dict:
    """LLM 응답에서 JSON 추출"""
    # JSON 블록 찾기
    if "```json" in response:
        start = response.find("```json") + 7
        end = response.find("```", start)
        response = response[start:end]
    elif "```" in response:
        start = response.find("```") + 3
        end = response.find("```", start)
        response = response[start:end]

    # 정리
    response = response.strip()

    try:
        return json.loads(response)
    except json.JSONDecodeError:
        # 기본값 반환
        return {}


# ============ Node Functions ============


def extract_contexts_node(state: AgentState, config: AgentConfig) -> AgentState:
    """코드 컨텍스트 추출 노드"""
    contexts = []

    for finding in state.findings[: config.max_findings_to_review]:
        context = extract_code_context(
            workspace=state.workspace_path,
            file_path=finding.get("file_path", ""),
            line_start=finding.get("line_start", 1),
            line_end=finding.get("line_end"),
            context_lines=config.context_lines,
        )
        contexts.append(context)

    state.code_contexts = contexts
    return state


def analyze_findings_node(state: AgentState, config: AgentConfig) -> AgentState:
    """취약점 분석 노드"""
    llm = get_llm(config)
    analyses = []

    for i, finding in enumerate(state.findings[: config.max_findings_to_review]):
        context = state.code_contexts[i] if i < len(state.code_contexts) else None

        prompt = ANALYZE_FINDING_PROMPT.format(
            scanner=finding.get("scanner", "Unknown"),
            rule_id=finding.get("rule_id", "unknown"),
            severity=finding.get("severity", "medium"),
            message=finding.get("message", ""),
            file_path=finding.get("file_path", ""),
            line_start=finding.get("line_start", 0),
            language=context.language if context else "text",
            code_snippet=context.code_snippet if context else "[No code available]",
            surrounding_code=context.surrounding_code if context else "",
        )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]

        try:
            response = llm.invoke(messages)
            data = parse_json_response(response.content)

            analysis = FindingAnalysis(
                finding_id=f"finding-{i}",
                category=ReviewCategory(data.get("category", "other")),
                severity=ReviewSeverity(data.get("severity", finding.get("severity", "medium"))),
                title=data.get("title", finding.get("message", "Security Issue")),
                description=data.get("description", ""),
                impact=data.get("impact", ""),
                is_false_positive=data.get("is_false_positive", False),
                false_positive_reason=data.get("false_positive_reason"),
                confidence=data.get("confidence", 0.8),
            )
        except Exception as e:
            # 실패 시 기본 분석 생성
            analysis = FindingAnalysis(
                finding_id=f"finding-{i}",
                category=ReviewCategory.OTHER,
                severity=ReviewSeverity(finding.get("severity", "medium")),
                title=finding.get("message", "Security Issue"),
                description=f"Analysis failed: {e}",
                impact="Unable to determine",
            )

        analyses.append(analysis)

    state.analyses = analyses
    return state


def generate_remediations_node(state: AgentState, config: AgentConfig) -> AgentState:
    """수정 제안 생성 노드"""
    llm = get_llm(config)
    remediations = []

    for i, analysis in enumerate(state.analyses):
        # False positive는 건너뛰기
        if analysis.is_false_positive:
            remediations.append(
                RemediationSuggestion(
                    finding_id=analysis.finding_id,
                    summary="No action required - false positive",
                    detailed_explanation=analysis.false_positive_reason
                    or "This appears to be a false positive.",
                    effort_estimate="low",
                )
            )
            continue

        context = state.code_contexts[i] if i < len(state.code_contexts) else None

        prompt = GENERATE_REMEDIATION_PROMPT.format(
            category=analysis.category.value,
            severity=analysis.severity.value,
            title=analysis.title,
            description=analysis.description,
            impact=analysis.impact,
            language=context.language if context else "text",
            code_snippet=context.code_snippet if context else "[No code available]",
        )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]

        try:
            response = llm.invoke(messages)
            data = parse_json_response(response.content)

            remediation = RemediationSuggestion(
                finding_id=analysis.finding_id,
                summary=data.get("summary", "Fix the security issue"),
                detailed_explanation=data.get("detailed_explanation", ""),
                code_fix=data.get("code_fix"),
                references=data.get("references", []),
                effort_estimate=data.get("effort_estimate", "medium"),
            )
        except Exception as e:
            remediation = RemediationSuggestion(
                finding_id=analysis.finding_id,
                summary="Review and fix the security issue",
                detailed_explanation=f"Remediation generation failed: {e}",
            )

        remediations.append(remediation)

    state.remediations = remediations
    return state


def generate_reviews_node(state: AgentState, config: AgentConfig) -> AgentState:
    """최종 리뷰 생성 노드"""
    llm = get_llm(config)
    reviews = []

    for i, (analysis, remediation) in enumerate(zip(state.analyses, state.remediations)):
        context = state.code_contexts[i] if i < len(state.code_contexts) else None

        # PR 코멘트 생성
        prompt = GENERATE_PR_COMMENT_PROMPT.format(
            title=analysis.title,
            severity=analysis.severity.value,
            category=analysis.category.value,
            description=analysis.description,
            impact=analysis.impact,
            file_path=context.file_path if context else "unknown",
            line_start=context.start_line if context else 0,
            remediation_summary=remediation.summary,
            code_fix=remediation.code_fix or "See detailed explanation",
        )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]

        try:
            response = llm.invoke(messages)
            pr_comment = response.content.strip()
        except Exception:
            pr_comment = (
                f"**{analysis.severity.value.upper()}**: {analysis.title}\n\n{remediation.summary}"
            )

        review = SecurityReview(
            finding_id=analysis.finding_id,
            analysis=analysis,
            context=context
            or CodeContext(
                file_path="unknown",
                start_line=0,
                end_line=0,
                code_snippet="",
            ),
            remediation=remediation,
            pr_comment=pr_comment,
        )
        reviews.append(review)

    state.reviews = reviews
    return state


def generate_summary_node(state: AgentState, config: AgentConfig) -> AgentState:
    """요약 생성 노드"""
    llm = get_llm(config)

    # 심각도별 카운트
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    categories = set()
    key_findings = []

    for analysis in state.analyses:
        if not analysis.is_false_positive:
            severity_counts[analysis.severity.value] += 1
            categories.add(analysis.category.value)
            if analysis.severity in [ReviewSeverity.CRITICAL, ReviewSeverity.HIGH]:
                key_findings.append(f"- {analysis.title}")

    prompt = GENERATE_SUMMARY_PROMPT.format(
        total_findings=len(state.analyses),
        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
        medium_count=severity_counts["medium"],
        low_count=severity_counts["low"],
        categories=", ".join(categories) if categories else "None",
        key_findings="\n".join(key_findings[:5]) if key_findings else "No critical/high findings",
    )

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    try:
        response = llm.invoke(messages)
        state.summary = response.content.strip()
    except Exception as e:
        state.summary = f"Summary generation failed: {e}"

    state.completed = True
    return state
