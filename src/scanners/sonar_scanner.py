"""SonarQube Scanner Wrapper

SonarQube Community Edition을 사용한 코드 품질 및 보안 분석
- 데이터플로우 기반 SAST
- 코드 스멜 탐지
- 중복 코드 분석
- 복잡도 분석
"""

import os
from pathlib import Path

import httpx

from .base import BaseScanner, Finding, Severity


class SonarScanner(BaseScanner):
    """SonarQube 스캐너"""

    # SonarQube 심각도 매핑
    SEVERITY_MAP = {
        "BLOCKER": Severity.CRITICAL,
        "CRITICAL": Severity.CRITICAL,
        "MAJOR": Severity.HIGH,
        "MINOR": Severity.MEDIUM,
        "INFO": Severity.LOW,
    }

    # 보안 관련 룰 타입
    SECURITY_TYPES = {"VULNERABILITY", "SECURITY_HOTSPOT"}

    def __init__(
        self,
        workspace: str,
        server_url: str | None = None,
        token: str | None = None,
        project_key: str | None = None,
    ):
        super().__init__(workspace)
        self.server_url = server_url or os.getenv("SONAR_HOST_URL", "http://localhost:9000")
        self.token = token or os.getenv("SONAR_TOKEN")
        self.project_key = project_key or os.getenv(
            "SONAR_PROJECT_KEY", self._generate_project_key()
        )

    @property
    def name(self) -> str:
        return "SonarQube"

    def _generate_project_key(self) -> str:
        """프로젝트 키 생성"""
        # GitHub Actions 환경에서 repo 이름 사용
        repo = os.getenv("GITHUB_REPOSITORY", "")
        if repo:
            return repo.replace("/", "_")
        return Path(self.workspace).name

    def _run_scan(self) -> tuple[bool, list[Finding], str | None]:
        """SonarQube 스캔 실행"""
        findings: list[Finding] = []

        # sonar-scanner 실행
        success, error = self._execute_scanner()
        if not success:
            return False, [], error

        # 결과 가져오기 (API 호출)
        try:
            issues = self._fetch_issues()
            for issue in issues:
                finding = self._convert_issue(issue)
                if finding:
                    findings.append(finding)

            # Security Hotspots 가져오기
            hotspots = self._fetch_hotspots()
            for hotspot in hotspots:
                finding = self._convert_hotspot(hotspot)
                if finding:
                    findings.append(finding)

            return True, findings, None

        except Exception as e:
            return False, [], f"Failed to fetch results: {e}"

    def _execute_scanner(self) -> tuple[bool, str | None]:
        """sonar-scanner CLI 실행"""
        # 프로퍼티 파일 생성
        props = self._generate_properties()
        props_file = Path(self.workspace) / "sonar-project.properties"

        # 기존 파일이 없으면 생성
        if not props_file.exists():
            with open(props_file, "w") as f:
                f.write(props)
            created_props = True
        else:
            created_props = False

        try:
            cmd = ["sonar-scanner"]
            if self.token:
                cmd.extend([f"-Dsonar.token={self.token}"])

            result = self.run_command(cmd)

            if result.returncode != 0:
                return False, f"sonar-scanner failed: {result.stderr}"

            return True, None

        finally:
            # 생성한 프로퍼티 파일 정리
            if created_props and props_file.exists():
                props_file.unlink()

    def _generate_properties(self) -> str:
        """sonar-project.properties 생성"""
        props = [
            f"sonar.projectKey={self.project_key}",
            "sonar.sources=.",
            f"sonar.host.url={self.server_url}",
            "sonar.sourceEncoding=UTF-8",
        ]

        # 언어별 설정
        props.extend(
            [
                "sonar.python.version=3.11",
                "sonar.javascript.node.maxspace=4096",
            ]
        )

        # 제외 패턴
        props.extend(
            [
                "sonar.exclusions=**/node_modules/**,**/vendor/**,**/.git/**,**/dist/**,**/build/**",
                "sonar.test.exclusions=**/test/**,**/tests/**,**/*_test.py,**/*_test.go",
            ]
        )

        return "\n".join(props)

    def _fetch_issues(self) -> list[dict]:
        """SonarQube API에서 이슈 가져오기"""
        if not self.token:
            return []

        issues = []
        page = 1
        page_size = 100

        while True:
            url = f"{self.server_url}/api/issues/search"
            params = {
                "componentKeys": self.project_key,
                "types": "VULNERABILITY,BUG,CODE_SMELL",
                "statuses": "OPEN,CONFIRMED,REOPENED",
                "ps": page_size,
                "p": page,
            }

            try:
                response = httpx.get(
                    url,
                    params=params,
                    headers={"Authorization": f"Bearer {self.token}"},
                    timeout=30,
                )
                response.raise_for_status()
                data = response.json()

                issues.extend(data.get("issues", []))

                # 페이징
                total = data.get("total", 0)
                if page * page_size >= total:
                    break
                page += 1

            except Exception:
                break

        return issues

    def _fetch_hotspots(self) -> list[dict]:
        """Security Hotspots 가져오기"""
        if not self.token:
            return []

        url = f"{self.server_url}/api/hotspots/search"
        params = {
            "projectKey": self.project_key,
            "status": "TO_REVIEW",
        }

        try:
            response = httpx.get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=30,
            )
            response.raise_for_status()
            return response.json().get("hotspots", [])
        except Exception:
            return []

    def _convert_issue(self, issue: dict) -> Finding | None:
        """SonarQube 이슈를 Finding으로 변환"""
        # 보안 관련 이슈만 필터링 (옵션)
        issue_type = issue.get("type", "")

        severity = self.SEVERITY_MAP.get(
            issue.get("severity", "MINOR"),
            Severity.MEDIUM,
        )

        # 컴포넌트에서 파일 경로 추출
        component = issue.get("component", "")
        file_path = component.split(":")[-1] if ":" in component else component

        # 텍스트 범위
        text_range = issue.get("textRange", {})
        line_start = text_range.get("startLine", 1)
        line_end = text_range.get("endLine")

        return Finding(
            scanner=self.name,
            rule_id=issue.get("rule", "unknown"),
            severity=severity,
            message=issue.get("message", ""),
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            metadata={
                "type": issue_type,
                "effort": issue.get("effort", ""),
                "debt": issue.get("debt", ""),
                "tags": issue.get("tags", []),
                "sonar_key": issue.get("key", ""),
            },
        )

    def _convert_hotspot(self, hotspot: dict) -> Finding | None:
        """Security Hotspot을 Finding으로 변환"""
        # 취약점 확률에 따른 심각도
        vulnerability_probability = hotspot.get("vulnerabilityProbability", "MEDIUM")
        severity_map = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        severity = severity_map.get(vulnerability_probability, Severity.MEDIUM)

        component = hotspot.get("component", "")
        file_path = component.split(":")[-1] if ":" in component else component

        return Finding(
            scanner=self.name,
            rule_id=hotspot.get("securityCategory", "security-hotspot"),
            severity=severity,
            message=hotspot.get("message", "Security Hotspot detected"),
            file_path=file_path,
            line_start=hotspot.get("line", 1),
            metadata={
                "type": "SECURITY_HOTSPOT",
                "status": hotspot.get("status", ""),
                "category": hotspot.get("securityCategory", ""),
                "sonar_key": hotspot.get("key", ""),
            },
        )


class SonarCloudScanner(SonarScanner):
    """SonarCloud 스캐너 (클라우드 버전)"""

    def __init__(
        self,
        workspace: str,
        token: str | None = None,
        organization: str | None = None,
        project_key: str | None = None,
    ):
        super().__init__(
            workspace=workspace,
            server_url="https://sonarcloud.io",
            token=token or os.getenv("SONAR_TOKEN"),
            project_key=project_key,
        )
        self.organization = organization or os.getenv("SONAR_ORGANIZATION")

    @property
    def name(self) -> str:
        return "SonarCloud"

    def _generate_properties(self) -> str:
        """SonarCloud용 프로퍼티"""
        props = super()._generate_properties()
        if self.organization:
            props += f"\nsonar.organization={self.organization}"
        return props
