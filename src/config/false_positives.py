"""오탐(False Positive) 관리"""

import fnmatch
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class FPRule:
    """오탐 규칙"""

    id: str
    pattern: str | None = None  # 파일 경로 패턴 (glob)
    rule_id: str | None = None  # 스캐너 규칙 ID (정규식)
    scanner: str | None = None  # 특정 스캐너만
    message_pattern: str | None = None  # 메시지 패턴 (정규식)
    reason: str = ""
    expires: str | None = None  # YYYY-MM-DD

    def is_expired(self) -> bool:
        """만료 여부 확인"""
        if not self.expires:
            return False
        try:
            exp_date = datetime.strptime(self.expires, "%Y-%m-%d")
            return datetime.now() > exp_date
        except ValueError:
            return False


class FalsePositiveManager:
    """오탐 관리자"""

    def __init__(self, rules: list[FPRule] | None = None):
        self.rules = rules or []
        self._baseline: dict[str, dict] = {}
        self._suppressed: list[dict] = []

    def add_rule(self, rule: FPRule) -> None:
        """규칙 추가"""
        self.rules.append(rule)

    def load_baseline(self, baseline_path: str | Path) -> None:
        """베이스라인 파일 로드 (이전 스캔 결과)"""
        path = Path(baseline_path)
        if not path.exists():
            return

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("findings", []):
                    fp = self._fingerprint(item)
                    self._baseline[fp] = item
        except Exception as e:
            logger.warning("Failed to load false-positive baseline from %s: %s", path, e)

    def save_baseline(self, baseline_path: str | Path, findings: list[dict]) -> None:
        """베이스라인 파일 저장"""
        baseline_findings: list[dict] = []
        for finding in findings:
            baseline_item = dict(finding)
            baseline_item["suppressed"] = bool(baseline_item.get("suppressed", True))
            baseline_item.setdefault("suppress_reason", "Baseline match")
            baseline_findings.append(baseline_item)

        data = {
            "version": "1.0",
            "generated_at": datetime.now().isoformat(),
            "findings": baseline_findings,
        }
        with open(baseline_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _fingerprint(self, finding: dict) -> str:
        """취약점 고유 지문 생성"""
        key = (
            f"{finding.get('scanner', '')}"
            f":{finding.get('rule_id', '')}"
            f":{finding.get('file_path', '')}"
            f":{finding.get('line_start', '')}"
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def is_false_positive(self, finding: dict) -> tuple[bool, str | None]:
        """오탐 여부 확인

        Returns:
            (is_fp, reason) - 오탐이면 (True, 이유), 아니면 (False, None)
        """
        # 규칙 기반 체크
        for rule in self.rules:
            if rule.is_expired():
                continue

            if self._matches_rule(finding, rule):
                self._suppressed.append(
                    {
                        "finding": finding,
                        "rule_id": rule.id,
                        "reason": rule.reason,
                    }
                )
                return True, rule.reason

        # 베이스라인 체크 (이전에 억제된 것)
        fp = self._fingerprint(finding)
        if fp in self._baseline:
            baseline_item = self._baseline[fp]
            # 하위 호환: 과거 baseline 포맷( suppressed 필드 없음 )도 억제로 간주.
            if baseline_item.get("suppressed", True):
                return True, baseline_item.get("suppress_reason", "Baseline match")

        return False, None

    def _matches_rule(self, finding: dict, rule: FPRule) -> bool:
        """규칙 매칭 확인"""
        # 스캐너 체크
        if rule.scanner and finding.get("scanner", "").lower() != rule.scanner.lower():
            return False

        # 파일 패턴 체크
        if rule.pattern:
            file_path = finding.get("file_path", "")
            normalized_path = str(file_path).replace("\\", "/")
            pattern = rule.pattern.replace("\\", "/")
            # '**/test/**' 같은 패턴이 루트 디렉토리부터 시작하는 경로도 매칭되도록
            # 상대/절대 후보를 모두 검사한다.
            candidates = [normalized_path, f"/{normalized_path}"]
            if not any(fnmatch.fnmatch(candidate, pattern) for candidate in candidates):
                return False

        # 규칙 ID 체크 (정규식)
        if rule.rule_id:
            rule_id = finding.get("rule_id", "")
            if not re.search(rule.rule_id, rule_id, re.IGNORECASE):
                return False

        # 메시지 패턴 체크
        if rule.message_pattern:
            message = finding.get("message", "")
            if not re.search(rule.message_pattern, message, re.IGNORECASE):
                return False

        return True

    def filter_findings(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        """취약점 필터링

        Returns:
            (valid_findings, suppressed_findings)
        """
        valid = []
        suppressed = []

        for finding in findings:
            finding_copy = dict(finding)
            is_fp, reason = self.is_false_positive(finding_copy)
            if is_fp:
                finding_copy["suppressed"] = True
                finding_copy["suppress_reason"] = reason
                suppressed.append(finding_copy)
            else:
                valid.append(finding_copy)

        return valid, suppressed

    def get_suppressed(self) -> list[dict]:
        """억제된 취약점 목록"""
        return self._suppressed

    def generate_report(self) -> dict:
        """억제 리포트 생성"""
        return {
            "total_suppressed": len(self._suppressed),
            "by_rule": self._group_by_rule(),
            "details": self._suppressed,
        }

    def _group_by_rule(self) -> dict[str, int]:
        """규칙별 그룹화"""
        counts: dict[str, int] = {}
        for item in self._suppressed:
            rule_id = item.get("rule_id", "unknown")
            counts[rule_id] = counts.get(rule_id, 0) + 1
        return counts


def create_fp_rules_from_config(config_rules: list[dict]) -> list[FPRule]:
    """설정에서 FP 규칙 생성"""
    rules = []
    for rule_data in config_rules:
        rules.append(
            FPRule(
                id=rule_data.get("id", ""),
                pattern=rule_data.get("pattern"),
                rule_id=rule_data.get("rule_id"),
                scanner=rule_data.get("scanner"),
                message_pattern=rule_data.get("message_pattern"),
                reason=rule_data.get("reason", ""),
                expires=rule_data.get("expires"),
            )
        )
    return rules
