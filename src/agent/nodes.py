"""Agent 노드 구현"""

import json
import posixpath
import re
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

SENSITIVE_CONTEXT_PLACEHOLDER = "[REDACTED: sensitive code omitted for AI safety]"
_SECRET_FINDER_KEYWORDS = (
    "secret",
    "token",
    "password",
    "credential",
    "private key",
    "apikey",
    "api key",
    "auth",
)


def _redact_sensitive_text(text: str) -> str:
    """LLM 전송 전 민감정보를 마스킹한다."""
    value = str(text or "")
    if not value:
        return value

    redacted = value
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        "***REDACTED_PRIVATE_KEY***",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(?i)\b(authorization)\s*:\s*bearer\s+[^\s]+",
        r"\1: Bearer ***REDACTED***",
        redacted,
    )
    redacted = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{8,}", "Bearer ***REDACTED***", redacted)
    redacted = re.sub(r"\bgh[pousr]_[A-Za-z0-9_]{10,}\b", "***REDACTED***", redacted)
    redacted = re.sub(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "***REDACTED***", redacted)
    redacted = re.sub(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{12,}\b", "***REDACTED***", redacted)
    redacted = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "***REDACTED***", redacted)
    redacted = re.sub(
        r"(?i)\b(api[_-]?key|token|password|secret)\b\s*[:=]\s*([^\s,;]+)",
        r"\1=***REDACTED***",
        redacted,
    )
    return redacted


def _is_secret_related_finding(finding: dict | None) -> bool:
    """finding이 secret/credential 유출 성격인지 판단."""
    if not finding:
        return False

    scanner = str(finding.get("scanner", "")).lower()
    if "gitleaks" in scanner or "secret" in scanner:
        return True

    combined = " ".join(
        [
            str(finding.get("rule_id", "")),
            str(finding.get("message", "")),
        ]
    ).lower()
    return any(keyword in combined for keyword in _SECRET_FINDER_KEYWORDS)


def _sanitize_context_for_prompt(
    finding: dict | None, context: CodeContext | None
) -> tuple[str, str]:
    """프롬프트 전송용 코드 컨텍스트를 안전하게 변환."""
    if context is None:
        return "[No code available]", ""

    if _is_secret_related_finding(finding):
        return SENSITIVE_CONTEXT_PLACEHOLDER, ""

    snippet = _redact_sensitive_text(context.code_snippet)
    surrounding = _redact_sensitive_text(context.surrounding_code)
    if not snippet.strip():
        snippet = "[No code available]"

    return snippet, surrounding


def get_llm(config: AgentConfig):
    """LLM 인스턴스 생성"""
    if config.model_provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        kwargs = {
            "model": config.model_name,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
        }
        if config.anthropic_api_key:
            kwargs["api_key"] = config.anthropic_api_key

        return ChatAnthropic(
            **kwargs,
        )
    else:  # openai
        from langchain_openai import ChatOpenAI

        kwargs = {
            "model": config.model_name,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
        }
        if config.openai_api_key:
            kwargs["api_key"] = config.openai_api_key
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
    try:
        safe_line_start = max(1, int(line_start))
    except (TypeError, ValueError):
        safe_line_start = 1

    if line_end is None:
        safe_line_end = safe_line_start
    else:
        try:
            safe_line_end = max(safe_line_start, int(line_end))
        except (TypeError, ValueError):
            safe_line_end = safe_line_start

    if not str(file_path).strip():
        return CodeContext(
            file_path=file_path,
            start_line=safe_line_start,
            end_line=safe_line_end,
            code_snippet="[File path not provided]",
            language="text",
        )

    workspace_root = Path(workspace).resolve()
    full_path = _resolve_context_path(workspace_root, file_path, workspace)
    language = detect_language(file_path)

    if full_path is None:
        return CodeContext(
            file_path=file_path,
            start_line=safe_line_start,
            end_line=safe_line_end,
            code_snippet="[File outside workspace]",
            language=language,
        )

    if not full_path.exists():
        return CodeContext(
            file_path=file_path,
            start_line=safe_line_start,
            end_line=safe_line_end,
            code_snippet="[File not found]",
            language=language,
        )

    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        total_lines = len(lines)

        # 메인 코드 스니펫 (1-indexed to 0-indexed)
        snippet_start = max(0, safe_line_start - 1)
        snippet_end = min(total_lines, safe_line_end)
        code_snippet = "".join(lines[snippet_start:snippet_end])

        # 주변 코드 (context)
        context_start = max(0, safe_line_start - 1 - context_lines)
        context_end = min(total_lines, safe_line_end + context_lines)
        surrounding_code = "".join(lines[context_start:context_end])

        return CodeContext(
            file_path=file_path,
            start_line=safe_line_start,
            end_line=safe_line_end,
            code_snippet=code_snippet.strip(),
            surrounding_code=surrounding_code.strip(),
            language=language,
        )
    except Exception as e:
        return CodeContext(
            file_path=file_path,
            start_line=safe_line_start,
            end_line=safe_line_end,
            code_snippet=f"[Error reading file: {e}]",
            language=language,
        )


def _is_windows_absolute_path(path: str) -> bool:
    """Windows 절대경로 여부 확인 (예: C:/repo/file.py)."""
    normalized = str(path or "").replace("\\", "/")
    return len(normalized) >= 3 and normalized[1] == ":" and normalized[2] == "/"


def _normalize_windows_absolute_path(path: str) -> str | None:
    """Windows 절대경로를 비교용으로 정규화한다.

    - 구분자 통일 (`\\` -> `/`)
    - 드라이브 문자를 대문자로 정규화
    - `.` / `..` 세그먼트 제거
    """
    raw = str(path or "").replace("\\", "/").strip()
    if not _is_windows_absolute_path(raw):
        return None

    drive = raw[0].upper()
    tail = "/" + raw[2:].lstrip("/")
    normalized_tail = posixpath.normpath(tail)
    return f"{drive}:{normalized_tail}"


def _is_within_workspace(resolved: Path, workspace_root: Path) -> bool:
    """경로가 workspace 내부인지 확인 (Windows 대소문자 차이 허용)."""
    if resolved == workspace_root or workspace_root in resolved.parents:
        return True

    resolved_norm = str(resolved).replace("\\", "/").rstrip("/")
    workspace_norm = str(workspace_root).replace("\\", "/").rstrip("/")

    if _is_windows_absolute_path(resolved_norm) and _is_windows_absolute_path(workspace_norm):
        resolved_fold = resolved_norm.casefold()
        workspace_fold = workspace_norm.casefold()
        return resolved_fold == workspace_fold or resolved_fold.startswith(workspace_fold + "/")

    return False


def _resolve_context_path(
    workspace_root: Path,
    file_path: str,
    workspace_raw: str | None = None,
) -> Path | None:
    """컨텍스트 파일 경로를 workspace 내부로 제한해 해석."""
    raw_workspace = str(workspace_raw or "").replace("\\", "/").strip()
    raw_file_path = str(file_path or "").replace("\\", "/").strip()

    # Cross-platform(예: Linux CI에서 Windows 경로 테스트)에서도
    # Windows 절대경로를 workspace 기준으로 정확히 판정한다.
    windows_workspace = _normalize_windows_absolute_path(raw_workspace)
    windows_file = _normalize_windows_absolute_path(raw_file_path)
    if windows_file:
        if not windows_workspace:
            return None
        workspace_fold = windows_workspace.casefold().rstrip("/")
        file_fold = windows_file.casefold().rstrip("/")
        if file_fold == workspace_fold:
            return workspace_root
        if file_fold.startswith(workspace_fold + "/"):
            relative_path = windows_file[len(windows_workspace) :].lstrip("/")
            if not relative_path:
                return workspace_root
            return workspace_root / Path(relative_path)
        return None

    candidate = Path(file_path)
    if not candidate.is_absolute():
        candidate = workspace_root / candidate

    try:
        resolved = candidate.resolve(strict=False)
    except Exception:
        return None

    if _is_within_workspace(resolved, workspace_root):
        return resolved

    return None


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
        safe_code_snippet, safe_surrounding_code = _sanitize_context_for_prompt(finding, context)
        safe_message = _redact_sensitive_text(str(finding.get("message", "")))

        prompt = ANALYZE_FINDING_PROMPT.format(
            scanner=finding.get("scanner", "Unknown"),
            rule_id=finding.get("rule_id", "unknown"),
            severity=finding.get("severity", "medium"),
            message=safe_message,
            file_path=finding.get("file_path", ""),
            line_start=finding.get("line_start", 0),
            language=context.language if context else "text",
            code_snippet=safe_code_snippet,
            surrounding_code=safe_surrounding_code,
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
        original_finding = state.findings[i] if i < len(state.findings) else None
        safe_code_snippet, _ = _sanitize_context_for_prompt(original_finding, context)

        prompt = GENERATE_REMEDIATION_PROMPT.format(
            category=analysis.category.value,
            severity=analysis.severity.value,
            title=analysis.title,
            description=analysis.description,
            impact=analysis.impact,
            language=context.language if context else "text",
            code_snippet=safe_code_snippet,
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
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    categories = set()
    key_findings = []

    for analysis in state.analyses:
        if not analysis.is_false_positive:
            severity_key = analysis.severity.value
            severity_counts[severity_key] = severity_counts.get(severity_key, 0) + 1
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
