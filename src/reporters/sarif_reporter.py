"""SARIF (Static Analysis Results Interchange Format) 리포터

GitHub Code Scanning과 호환되는 SARIF 2.1.0 포맷 출력
https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class SarifMessage:
    """SARIF 메시지"""

    text: str


@dataclass
class SarifArtifactLocation:
    """SARIF 아티팩트 위치"""

    uri: str
    uriBaseId: str = "%SRCROOT%"


@dataclass
class SarifRegion:
    """SARIF 코드 영역"""

    startLine: int
    startColumn: int = 1
    endLine: int | None = None
    endColumn: int | None = None


@dataclass
class SarifPhysicalLocation:
    """SARIF 물리적 위치"""

    artifactLocation: SarifArtifactLocation
    region: SarifRegion


@dataclass
class SarifLocation:
    """SARIF 위치"""

    physicalLocation: SarifPhysicalLocation


@dataclass
class SarifFix:
    """SARIF 수정 제안"""

    description: SarifMessage
    artifactChanges: list[dict] = field(default_factory=list)


@dataclass
class SarifResult:
    """SARIF 결과"""

    ruleId: str
    level: str  # error, warning, note, none
    message: SarifMessage
    locations: list[SarifLocation]
    fingerprints: dict[str, str] = field(default_factory=dict)
    fixes: list[SarifFix] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class SarifReportingDescriptor:
    """SARIF 규칙 정의"""

    id: str
    name: str
    shortDescription: SarifMessage
    fullDescription: SarifMessage | None = None
    helpUri: str | None = None
    help: SarifMessage | None = None
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class SarifDriver:
    """SARIF 도구 드라이버"""

    name: str
    version: str
    informationUri: str
    rules: list[SarifReportingDescriptor] = field(default_factory=list)


@dataclass
class SarifTool:
    """SARIF 도구"""

    driver: SarifDriver


@dataclass
class SarifRun:
    """SARIF 실행"""

    tool: SarifTool
    results: list[SarifResult] = field(default_factory=list)
    invocations: list[dict] = field(default_factory=list)


@dataclass
class SarifReport:
    """SARIF 리포트"""

    version: str = "2.1.0"
    schema: str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    runs: list[SarifRun] = field(default_factory=list)

    def to_dict(self) -> dict:
        """딕셔너리로 변환"""

        def convert(obj):
            if hasattr(obj, "__dataclass_fields__"):
                result = {}
                for k, v in asdict(obj).items():
                    # $schema 필드 처리
                    if k == "schema":
                        result["$schema"] = v
                    else:
                        result[k] = v
                return result
            return obj

        return {
            "$schema": self.schema,
            "version": self.version,
            "runs": [self._run_to_dict(run) for run in self.runs],
        }

    def _run_to_dict(self, run: SarifRun) -> dict:
        """Run을 딕셔너리로 변환"""
        return {
            "tool": {
                "driver": {
                    "name": run.tool.driver.name,
                    "version": run.tool.driver.version,
                    "informationUri": run.tool.driver.informationUri,
                    "rules": [self._rule_to_dict(r) for r in run.tool.driver.rules],
                }
            },
            "results": [self._result_to_dict(r) for r in run.results],
            "invocations": run.invocations,
        }

    def _rule_to_dict(self, rule: SarifReportingDescriptor) -> dict:
        """규칙을 딕셔너리로 변환"""
        result = {
            "id": rule.id,
            "name": rule.name,
            "shortDescription": {"text": rule.shortDescription.text},
        }
        if rule.fullDescription:
            result["fullDescription"] = {"text": rule.fullDescription.text}
        if rule.helpUri:
            result["helpUri"] = rule.helpUri
        if rule.help:
            result["help"] = {"text": rule.help.text}
        if rule.properties:
            result["properties"] = rule.properties
        return result

    def _result_to_dict(self, result: SarifResult) -> dict:
        """결과를 딕셔너리로 변환"""
        output = {
            "ruleId": result.ruleId,
            "level": result.level,
            "message": {"text": result.message.text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": loc.physicalLocation.artifactLocation.uri,
                            "uriBaseId": loc.physicalLocation.artifactLocation.uriBaseId,
                        },
                        "region": {
                            "startLine": loc.physicalLocation.region.startLine,
                            "startColumn": loc.physicalLocation.region.startColumn,
                            **(
                                {"endLine": loc.physicalLocation.region.endLine}
                                if loc.physicalLocation.region.endLine
                                else {}
                            ),
                            **(
                                {"endColumn": loc.physicalLocation.region.endColumn}
                                if loc.physicalLocation.region.endColumn
                                else {}
                            ),
                        },
                    }
                }
                for loc in result.locations
            ],
        }
        if result.fingerprints:
            output["fingerprints"] = result.fingerprints
        if result.properties:
            output["properties"] = result.properties
        return output


class SarifReporter:
    """SARIF 리포터"""

    UNKNOWN_LOCATION_URI = "unknown-location"
    SEVERITY_TO_LEVEL = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    def __init__(self):
        self.rules: dict[str, SarifReportingDescriptor] = {}
        self.results: list[SarifResult] = []

    @staticmethod
    def _is_windows_absolute_path(path: str) -> bool:
        """Windows 절대경로 여부 확인 (예: C:/repo/file.py)."""
        normalized = path.replace("\\", "/")
        return len(normalized) >= 3 and normalized[1] == ":" and normalized[2] == "/"

    @classmethod
    def _strip_workspace_prefix(cls, path: str, workspace: str) -> str:
        """워크스페이스 prefix를 제거해 상대 경로로 변환."""
        if not workspace:
            return path

        if path == workspace:
            return ""
        if path.startswith(workspace + "/"):
            return path[len(workspace) + 1 :]

        # Windows 드라이브 문자는 대소문자를 무시해 비교한다.
        if cls._is_windows_absolute_path(path) and cls._is_windows_absolute_path(workspace):
            path_fold = path.casefold()
            workspace_fold = workspace.casefold()
            if path_fold == workspace_fold:
                return ""
            if path_fold.startswith(workspace_fold + "/"):
                return path[len(workspace) + 1 :]

        return path

    @classmethod
    def _normalize_artifact_uri(cls, raw_path: str | None) -> str:
        """SARIF artifactLocation.uri 정규화."""
        path = str(raw_path or "").strip().replace("\\", "/")
        if not path:
            return cls.UNKNOWN_LOCATION_URI

        if path.startswith("file://"):
            path = path[7:]

        workspace = os.getenv("GITHUB_WORKSPACE", "").strip().replace("\\", "/").rstrip("/")
        path = cls._strip_workspace_prefix(path, workspace)

        while path.startswith("./"):
            path = path[2:]
        path = path.lstrip("/")

        if path.startswith("/") or cls._is_windows_absolute_path(path):
            return cls.UNKNOWN_LOCATION_URI

        parts = [segment for segment in path.split("/") if segment not in ("", ".")]
        if not parts or any(segment == ".." for segment in parts):
            return cls.UNKNOWN_LOCATION_URI

        return "/".join(parts)

    @staticmethod
    def _normalize_region(
        line_start: int | str | None,
        line_end: int | str | None = None,
    ) -> tuple[int, int | None]:
        """SARIF region 라인 범위를 양의 정수로 정규화."""
        try:
            start = max(1, int(line_start))
        except (TypeError, ValueError):
            start = 1

        if line_end is None:
            return start, None

        try:
            end_candidate = int(line_end)
        except (TypeError, ValueError):
            return start, None

        if end_candidate < start:
            return start, start

        return start, end_candidate

    def add_finding(
        self,
        scanner: str,
        rule_id: str,
        severity: str,
        message: str,
        file_path: str,
        line_start: int,
        line_end: int | None = None,
        suggestion: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        """취약점 결과 추가"""
        normalized_path = self._normalize_artifact_uri(file_path)
        normalized_start_line, normalized_end_line = self._normalize_region(line_start, line_end)

        # 규칙 등록
        full_rule_id = f"{scanner}/{rule_id}"
        if full_rule_id not in self.rules:
            self.rules[full_rule_id] = SarifReportingDescriptor(
                id=full_rule_id,
                name=rule_id,
                shortDescription=SarifMessage(text=message[:200]),
                properties={
                    "security-severity": self._get_security_severity(severity),
                    "tags": ["security"],
                },
            )

        # 위치 생성
        location = SarifLocation(
            physicalLocation=SarifPhysicalLocation(
                artifactLocation=SarifArtifactLocation(uri=normalized_path),
                region=SarifRegion(
                    startLine=normalized_start_line,
                    endLine=normalized_end_line,
                ),
            )
        )

        properties = {
            "scanner": scanner,
            "severity": severity,
            **(metadata or {}),
        }
        if suggestion:
            properties["recommendation"] = suggestion

        # 결과 생성
        result = SarifResult(
            ruleId=full_rule_id,
            level=self.SEVERITY_TO_LEVEL.get(severity.lower(), "warning"),
            message=SarifMessage(text=message),
            locations=[location],
            fingerprints={
                "primaryLocationLineHash": f"{normalized_path}:{normalized_start_line}:{rule_id}",
            },
            properties=properties,
        )

        self.results.append(result)

    def _get_security_severity(self, severity: str) -> str:
        """GitHub 보안 심각도 점수 반환 (0.0 - 10.0)"""
        scores = {
            "critical": "9.0",
            "high": "7.0",
            "medium": "5.0",
            "low": "3.0",
            "info": "1.0",
        }
        return scores.get(severity.lower(), "5.0")

    def generate_report(self) -> SarifReport:
        """SARIF 리포트 생성"""
        driver = SarifDriver(
            name="Security Scanner Action",
            version="0.1.0",
            informationUri=self._build_information_uri(),
            rules=list(self.rules.values()),
        )

        run = SarifRun(
            tool=SarifTool(driver=driver),
            results=self.results,
            invocations=[
                {
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                }
            ],
        )

        return SarifReport(runs=[run])

    def _build_information_uri(self) -> str:
        """SARIF tool 정보 URI 생성"""
        server_url = os.getenv("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
        repo = os.getenv("GITHUB_ACTION_REPOSITORY") or os.getenv("GITHUB_REPOSITORY")
        if repo:
            return f"{server_url}/{repo}"
        return "https://github.com/jhl-labs/security-action"

    def save(self, output_path: str) -> None:
        """SARIF 파일 저장"""
        report = self.generate_report()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)

    def to_json(self) -> str:
        """JSON 문자열로 변환"""
        report = self.generate_report()
        return json.dumps(report.to_dict(), indent=2)
