"""SonarQube Scanner Wrapper

SonarQube Community Edition을 사용한 코드 품질 및 보안 분석
- 데이터플로우 기반 SAST
- 코드 스멜 탐지
- 중복 코드 분석
- 복잡도 분석
"""

import logging
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .base import BaseScanner, Finding, Severity

logger = logging.getLogger(__name__)


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
    LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

    def __init__(
        self,
        workspace: str,
        server_url: str | None = None,
        token: str | None = None,
        project_key: str | None = None,
    ):
        super().__init__(workspace)
        self.server_url = (
            self._sanitize_single_line(
                server_url or os.getenv("SONAR_HOST_URL", "http://localhost:9000"),
                field_name="SONAR_HOST_URL",
            )
            or "http://localhost:9000"
        )
        self.token = token or os.getenv("SONAR_TOKEN")
        self.project_key = self._sanitize_single_line(
            project_key or os.getenv("SONAR_PROJECT_KEY", self._generate_project_key()),
            field_name="SONAR_PROJECT_KEY",
        )
        if not self.project_key:
            self.project_key = self._generate_project_key()
        self._unsupported_server_url_scheme = not self._is_supported_server_scheme(self.server_url)
        self._server_url_has_credentials = self._has_url_credentials(self.server_url)

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

    @staticmethod
    def _sanitize_single_line(value: str | None, field_name: str) -> str:
        """설정값을 단일 라인으로 정규화해 프로퍼티 주입을 방지."""
        text = str(value or "").strip()
        if not text:
            return ""

        first_line = text.splitlines()[0].strip()
        sanitized = "".join(ch for ch in first_line if ch >= " " and ch != "\x7f").strip()

        if text != sanitized:
            logger.warning(
                "%s contains multi-line/control characters; using sanitized single-line value",
                field_name,
            )

        return sanitized

    def _run_scan(self) -> tuple[bool, list[Finding], str | None]:
        """SonarQube 스캔 실행"""
        findings: list[Finding] = []

        if self._unsupported_server_url_scheme:
            message = "Unsupported SONAR_HOST_URL scheme. Use http:// or https://."
            logger.error("%s server_url=%s", message, self._sanitize_url_for_log(self.server_url))
            return False, findings, message

        if self._server_url_has_credentials:
            message = (
                "Refusing SONAR_HOST_URL with embedded credentials. "
                "Provide credentials only via SONAR_TOKEN."
            )
            logger.error("%s server_url=%s", message, self._sanitize_url_for_log(self.server_url))
            return False, findings, message

        if self._is_remote_insecure_http():
            message = (
                "Refusing SonarQube token transmission over insecure HTTP SONAR_HOST_URL. "
                "Use HTTPS (or localhost only)."
            )
            logger.error(
                "%s server_url=%s",
                message,
                self._sanitize_url_for_log(self.server_url),
            )
            return False, findings, message

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
        # repository의 sonar-project.properties를 로드하더라도,
        # 민감한 핵심 값(host/project/sources)은 command-line -D로 강제 오버라이드해
        # 토큰 전송 대상/프로젝트 식별자 하이재킹을 방지한다.
        cmd = self._build_scanner_command()
        scanner_env = {"SONAR_TOKEN": self.token} if self.token else None
        result = self.run_command(cmd, timeout=1800, env=scanner_env)

        if result.returncode != 0:
            return False, f"sonar-scanner failed: {result.stderr}"

        return True, None

    def _build_scanner_command(self) -> list[str]:
        """sonar-scanner 실행 명령 구성.

        보안상 중요한 프로퍼티는 command-line 인자로 전달해
        저장소 내 sonar-project.properties 값을 덮어쓴다.
        """
        cmd = ["sonar-scanner"]

        props_file = Path(self.workspace) / "sonar-project.properties"
        if props_file.exists():
            cmd.append(f"-Dproject.settings={props_file}")

        for prop_line in self._generate_properties().splitlines():
            normalized = prop_line.strip()
            if not normalized:
                continue
            cmd.append(f"-D{normalized}")

        return cmd

    def _is_remote_insecure_http(self) -> bool:
        """토큰이 설정된 상태에서 원격 HTTP URL을 사용하는지 확인."""
        if not self.token:
            return False

        parsed = urlparse(self.server_url)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()
        if scheme != "http":
            return False

        return host not in self.LOCAL_HOSTS

    @staticmethod
    def _is_supported_server_scheme(url: str) -> bool:
        """지원하는 Sonar 서버 URL scheme 여부 확인."""
        scheme = (urlparse(url).scheme or "").lower()
        return scheme in {"http", "https"}

    @staticmethod
    def _has_url_credentials(url: str) -> bool:
        """URL에 userinfo(username/password)가 포함됐는지 확인."""
        parsed = urlparse(url)
        return bool(parsed.username or parsed.password)

    @staticmethod
    def _sanitize_url_for_log(url: str) -> str:
        """로그 출력용 URL(credential/query/fragment 제거)."""
        try:
            parsed = urlparse(url)
            netloc = parsed.hostname or ""
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            return parsed._replace(netloc=netloc, query="", fragment="").geturl()
        except Exception:
            return url

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
            logger.warning("SonarQube token not provided, skipping issue fetch")
            return []

        issues = []
        page = 1
        page_size = 100

        logger.info(
            "Fetching issues from SonarQube: %s", self._sanitize_url_for_log(self.server_url)
        )

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

                page_issues = data.get("issues", [])
                if not isinstance(page_issues, list):
                    logger.error("Unexpected SonarQube issues payload: issues is not a list")
                    break

                issues.extend(page_issues)

                # 페이징 (SonarQube 버전별로 total 또는 paging.total 사용)
                total = self._extract_total(data)
                if total is not None:
                    if page * page_size >= total:
                        break
                elif len(page_issues) < page_size:
                    break

                page += 1

            except httpx.HTTPStatusError as e:
                logger.error(
                    f"SonarQube API error (page {page}): "
                    f"HTTP {e.response.status_code} - {e.response.text[:200]}"
                )
                break
            except httpx.TimeoutException:
                logger.error(f"SonarQube API timeout (page {page})")
                break
            except Exception as e:
                logger.error(f"SonarQube API error (page {page}): {type(e).__name__}: {e}")
                break

        logger.info(f"Fetched {len(issues)} issues from SonarQube")
        return issues

    @staticmethod
    def _extract_total(data: dict) -> int | None:
        """SonarQube 검색 API 응답에서 total 추출"""
        total = data.get("total")
        if isinstance(total, int):
            return total

        paging = data.get("paging")
        if isinstance(paging, dict):
            paging_total = paging.get("total")
            if isinstance(paging_total, int):
                return paging_total

        return None

    def _fetch_hotspots(self) -> list[dict]:
        """Security Hotspots 가져오기"""
        if not self.token:
            logger.warning("SonarQube token not provided, skipping hotspot fetch")
            return []

        logger.info("Fetching security hotspots from SonarQube")

        hotspots: list[dict] = []
        page = 1
        page_size = 100

        while True:
            url = f"{self.server_url}/api/hotspots/search"
            params = {
                "projectKey": self.project_key,
                "status": "TO_REVIEW",
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

                page_hotspots = data.get("hotspots", [])
                if not isinstance(page_hotspots, list):
                    logger.error("Unexpected SonarQube hotspot payload: hotspots is not a list")
                    break

                hotspots.extend(page_hotspots)

                total = self._extract_total(data)
                if total is not None:
                    if page * page_size >= total:
                        break
                elif len(page_hotspots) < page_size:
                    break

                page += 1

            except httpx.HTTPStatusError as e:
                logger.error(
                    f"SonarQube hotspots API error (page {page}): "
                    f"HTTP {e.response.status_code} - {e.response.text[:200]}"
                )
                break
            except httpx.TimeoutException:
                logger.error(f"SonarQube hotspots API timeout (page {page})")
                break
            except Exception as e:
                logger.error(f"SonarQube hotspots API error (page {page}): {type(e).__name__}: {e}")
                break

        logger.info(f"Fetched {len(hotspots)} security hotspots")
        return hotspots

    def _convert_issue(self, issue: dict) -> Finding | None:
        """SonarQube 이슈를 Finding으로 변환"""
        # 보안 관련 이슈만 필터링 (옵션)
        issue_type = issue.get("type", "")

        severity = self.SEVERITY_MAP.get(
            issue.get("severity", "MINOR"),
            Severity.MEDIUM,
        )

        # 컴포넌트에서 파일 경로 추출 및 정규화
        component = issue.get("component", "")
        file_path = component.split(":")[-1] if ":" in component else component
        file_path = self.normalize_path(file_path)

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

        # 컴포넌트에서 파일 경로 추출 및 정규화
        component = hotspot.get("component", "")
        file_path = component.split(":")[-1] if ":" in component else component
        file_path = self.normalize_path(file_path)

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
