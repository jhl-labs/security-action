"""Reporters package exports.

`SarifReporter`는 항상 제공하고,
GitHub API 연동 클래스들은 선택 의존성(PyGithub/httpx) 로딩이 실패할 수 있어
필요할 때만 명시적으로 ImportError를 내도록 처리한다.
"""

from .sarif_reporter import SarifReporter

_GITHUB_EXPORTS = {
    "CheckConclusion",
    "CheckRunContext",
    "CommitState",
    "FindingComment",
    "GitHubReporter",
    "SarifUploadResult",
}

_GITHUB_IMPORT_ERROR: Exception | None = None

__all__ = [
    "SarifReporter",
    "CheckConclusion",
    "CheckRunContext",
    "CommitState",
    "FindingComment",
    "GitHubReporter",
    "SarifUploadResult",
]

try:
    from .github_reporter import (
        CheckConclusion,
        CheckRunContext,
        CommitState,
        FindingComment,
        GitHubReporter,
        SarifUploadResult,
    )
except Exception as exc:  # pragma: no cover - 환경별 선택 의존성 경로
    _GITHUB_IMPORT_ERROR = exc


def __getattr__(name: str):
    if name in _GITHUB_EXPORTS and _GITHUB_IMPORT_ERROR is not None:
        raise ImportError(
            "GitHub reporter dependencies are not available. "
            "Install optional GitHub reporting requirements."
        ) from _GITHUB_IMPORT_ERROR
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
