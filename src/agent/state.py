"""Agent 상태 및 타입 정의"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Annotated

from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field


class ReviewSeverity(str, Enum):
    """리뷰 심각도"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ReviewCategory(str, Enum):
    """리뷰 카테고리"""

    SECRET_EXPOSURE = "secret_exposure"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    INSECURE_CRYPTO = "insecure_crypto"
    OTHER = "other"


class CodeContext(BaseModel):
    """코드 컨텍스트"""

    file_path: str
    start_line: int
    end_line: int
    code_snippet: str
    surrounding_code: str = ""
    language: str = "unknown"


class FindingAnalysis(BaseModel):
    """취약점 분석 결과"""

    finding_id: str
    category: ReviewCategory
    severity: ReviewSeverity
    title: str
    description: str
    impact: str
    is_false_positive: bool = False
    false_positive_reason: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)


class RemediationSuggestion(BaseModel):
    """수정 제안"""

    finding_id: str
    summary: str
    detailed_explanation: str
    code_fix: str | None = None
    references: list[str] = Field(default_factory=list)
    effort_estimate: str = "medium"  # low, medium, high


class SecurityReview(BaseModel):
    """보안 리뷰 결과"""

    finding_id: str
    analysis: FindingAnalysis
    context: CodeContext
    remediation: RemediationSuggestion
    pr_comment: str


@dataclass
class AgentState:
    """LangGraph Agent 상태"""

    # 입력
    findings: list[dict] = field(default_factory=list)
    workspace_path: str = ""

    # 처리 중
    current_finding_index: int = 0
    code_contexts: list[CodeContext] = field(default_factory=list)
    analyses: list[FindingAnalysis] = field(default_factory=list)
    remediations: list[RemediationSuggestion] = field(default_factory=list)

    # 출력
    reviews: list[SecurityReview] = field(default_factory=list)
    summary: str = ""

    # 메시지 (LangGraph)
    messages: Annotated[list, add_messages] = field(default_factory=list)

    # 메타데이터
    error: str | None = None
    completed: bool = False


class AgentConfig(BaseModel):
    """Agent 설정"""

    model_provider: str = "openai"  # openai, anthropic
    model_name: str = "gpt-4o"
    openai_base_url: str | None = None
    temperature: float = 0.1
    max_tokens: int = 4096
    max_findings_to_review: int = 20
    include_code_context: bool = True
    context_lines: int = 10
