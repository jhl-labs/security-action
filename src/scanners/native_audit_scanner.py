"""Native Dependency Audit Scanner

언어별 네이티브 의존성 스캐너 통합 모듈:
- npm audit (Node.js)
- pip-audit (Python)
- govulncheck (Go)
- cargo-audit (Rust)
- bundler-audit (Ruby)
- composer audit (PHP)
"""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

from .base import BaseScanner, Finding, Severity

logger = logging.getLogger(__name__)


class NativeAuditScanner(BaseScanner):
    """통합 네이티브 의존성 스캐너"""

    # 지원하는 패키지 관리자와 관련 파일
    PACKAGE_MANAGERS = {
        "npm": {
            "files": ["package-lock.json", "package.json", "yarn.lock", "pnpm-lock.yaml"],
            "command": "npm",
            "display_name": "npm audit",
        },
        "pip": {
            "files": ["requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml"],
            "command": "pip-audit",
            "display_name": "pip-audit",
        },
        "go": {
            "files": ["go.mod", "go.sum"],
            "command": "govulncheck",
            "display_name": "govulncheck",
        },
        "cargo": {
            "files": ["Cargo.lock", "Cargo.toml"],
            "command": "cargo-audit",
            "display_name": "cargo-audit",
        },
        "bundler": {
            "files": ["Gemfile.lock", "Gemfile"],
            "command": "bundler-audit",
            "display_name": "bundler-audit",
        },
        "composer": {
            "files": ["composer.lock", "composer.json"],
            "command": "composer",
            "display_name": "composer audit",
        },
    }

    # 심각도 매핑 (각 도구별)
    SEVERITY_MAP = {
        # npm audit
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        # pip-audit / govulncheck
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        # CVSS 기반 변환
    }

    def __init__(self, workspace: str, tools: list[str] | None = None):
        """
        Args:
            workspace: 스캔 대상 디렉토리
            tools: 사용할 도구 목록 (None 또는 ['auto']면 자동 감지)
        """
        super().__init__(workspace)
        self.tools = tools or ["auto"]
        self._detected_managers: list[str] = []

    @property
    def name(self) -> str:
        return "NativeAudit"

    def _detect_package_managers(self) -> list[str]:
        """프로젝트에서 사용하는 패키지 관리자 자동 감지"""
        detected = []
        workspace_path = Path(self.workspace)

        for manager, config in self.PACKAGE_MANAGERS.items():
            for file_pattern in config["files"]:
                # 루트 디렉토리와 하위 디렉토리 모두 검색
                matches = list(workspace_path.glob(file_pattern)) + list(
                    workspace_path.glob(f"**/{file_pattern}")
                )
                if matches:
                    detected.append(manager)
                    logger.info(f"Detected {manager} package manager: {matches[0]}")
                    break

        return detected

    def _is_tool_available(self, tool: str) -> bool:
        """도구가 시스템에 설치되어 있는지 확인"""
        config = self.PACKAGE_MANAGERS.get(tool)
        if not config:
            return False

        command = config["command"]

        # 특수 케이스 처리
        if tool == "composer":
            return shutil.which("composer") is not None
        if tool == "npm":
            return shutil.which("npm") is not None

        return shutil.which(command) is not None

    def _run_scan(self) -> tuple[bool, list[Finding], str | None]:
        """네이티브 의존성 스캔 실행"""
        all_findings: list[Finding] = []
        errors: list[str] = []

        # 도구 목록 결정
        if "auto" in self.tools:
            self._detected_managers = self._detect_package_managers()
            logger.info(f"Auto-detected package managers: {self._detected_managers}")
        else:
            self._detected_managers = [t for t in self.tools if t in self.PACKAGE_MANAGERS]

        if not self._detected_managers:
            logger.info("No package managers detected or specified")
            return True, [], None

        # 각 패키지 관리자별 스캔 실행
        for manager in self._detected_managers:
            if not self._is_tool_available(manager):
                logger.warning(f"{manager} tool not available, skipping")
                continue

            try:
                display_name = self.PACKAGE_MANAGERS[manager]["display_name"]
                logger.info(f"Running {display_name}...")

                findings = self._run_audit(manager)
                all_findings.extend(findings)

                logger.info(f"{display_name}: found {len(findings)} vulnerabilities")

            except Exception as e:
                error_msg = f"{manager} audit failed: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        error = "; ".join(errors) if errors else None
        return len(errors) == 0, all_findings, error

    def _run_audit(self, manager: str) -> list[Finding]:
        """특정 패키지 관리자의 audit 실행"""
        if manager == "npm":
            return self._run_npm_audit()
        elif manager == "pip":
            return self._run_pip_audit()
        elif manager == "go":
            return self._run_govulncheck()
        elif manager == "cargo":
            return self._run_cargo_audit()
        elif manager == "bundler":
            return self._run_bundler_audit()
        elif manager == "composer":
            return self._run_composer_audit()
        else:
            logger.warning(f"Unknown package manager: {manager}")
            return []

    def _run_npm_audit(self) -> list[Finding]:
        """npm audit 실행"""
        findings: list[Finding] = []

        # package-lock.json이 있는 디렉토리 찾기
        workspace_path = Path(self.workspace)
        lock_files = list(workspace_path.glob("**/package-lock.json"))

        if not lock_files:
            # package.json만 있는 경우 npm install 먼저 실행
            package_jsons = list(workspace_path.glob("**/package.json"))
            if package_jsons:
                logger.info("No package-lock.json found, running npm install first")
                for pj in package_jsons[:5]:  # 최대 5개 디렉토리만
                    subprocess.run(
                        ["npm", "install", "--package-lock-only"],
                        cwd=str(pj.parent),
                        capture_output=True,
                        timeout=120,
                    )
                lock_files = list(workspace_path.glob("**/package-lock.json"))

        for lock_file in lock_files[:10]:  # 최대 10개 디렉토리
            scan_dir = lock_file.parent
            rel_dir = (
                scan_dir.relative_to(workspace_path) if scan_dir != workspace_path else Path(".")
            )

            try:
                # npm audit --json 실행
                result = self.run_command(
                    ["npm", "audit", "--json", "--audit-level=info"],
                    timeout=300,
                    cwd=str(scan_dir),
                )

                # npm audit는 취약점이 있으면 exit code 1을 반환하므로 returncode 무시
                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                        findings.extend(self._parse_npm_audit(audit_data, str(rel_dir)))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse npm audit output: {e}")

            except Exception as e:
                logger.error(f"npm audit failed in {scan_dir}: {e}")

        return findings

    def _parse_npm_audit(self, data: dict, base_dir: str) -> list[Finding]:
        """npm audit JSON 결과 파싱"""
        findings: list[Finding] = []

        # npm v7+ format (advisories in vulnerabilities)
        vulnerabilities = data.get("vulnerabilities", {})
        for pkg_name, vuln_info in vulnerabilities.items():
            severity_str = vuln_info.get("severity", "low")
            severity = self.SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            # via 필드에서 상세 정보 추출
            via = vuln_info.get("via", [])
            if isinstance(via, list) and via:
                for v in via:
                    if isinstance(v, dict):
                        finding = Finding(
                            scanner="npm-audit",
                            rule_id=v.get("name", pkg_name),
                            severity=severity,
                            message=v.get("title", f"Vulnerability in {pkg_name}"),
                            file_path=self.normalize_path(
                                os.path.join(base_dir, "package-lock.json")
                            ),
                            line_start=1,
                            metadata={
                                "package": pkg_name,
                                "vulnerable_versions": v.get("range", ""),
                                "url": v.get("url", ""),
                                "cwe": v.get("cwe", []),
                                "cvss": v.get("cvss", {}),
                                "source": v.get("source"),
                            },
                        )
                        findings.append(finding)
            else:
                # via가 문자열인 경우 (상위 의존성 참조)
                finding = Finding(
                    scanner="npm-audit",
                    rule_id=pkg_name,
                    severity=severity,
                    message=f"Vulnerability in {pkg_name} (via dependency chain)",
                    file_path=self.normalize_path(os.path.join(base_dir, "package-lock.json")),
                    line_start=1,
                    metadata={
                        "package": pkg_name,
                        "via": via,
                        "effects": vuln_info.get("effects", []),
                        "fix_available": vuln_info.get("fixAvailable", False),
                    },
                )
                findings.append(finding)

        return findings

    def _run_pip_audit(self) -> list[Finding]:
        """pip-audit 실행"""
        findings: list[Finding] = []
        workspace_path = Path(self.workspace)

        req_files = sorted(workspace_path.glob("**/requirements*.txt"))
        lock_files = sorted(
            list(workspace_path.glob("**/Pipfile.lock"))
            + list(workspace_path.glob("**/poetry.lock"))
        )

        if not req_files and not lock_files:
            logger.info("No Python dependency files found")
            return []

        # requirements*.txt가 있으면 파일 기반(-r)으로 감사한다.
        # 그렇지 않으면 lock file 디렉토리에서 환경 기반 감사로 fallback.
        if req_files:
            for req_file in req_files[:10]:
                rel_req = req_file.relative_to(workspace_path)
                try:
                    result = self.run_command(
                        [
                            "pip-audit",
                            "--format",
                            "json",
                            "--progress-spinner",
                            "off",
                            "-r",
                            str(rel_req),
                        ],
                        timeout=300,
                        cwd=self.workspace,
                    )

                    if result.stdout:
                        try:
                            audit_data = json.loads(result.stdout)
                            findings.extend(self._parse_pip_audit(audit_data, str(rel_req)))
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse pip-audit output for {rel_req}: {e}")

                except Exception as e:
                    logger.error(f"pip-audit failed for {rel_req}: {e}")
        else:
            logger.info(
                "requirements*.txt not found. Falling back to environment-based pip-audit "
                "for Pipfile.lock/poetry.lock directories."
            )
            for lock_file in lock_files[:5]:
                scan_dir = lock_file.parent
                rel_lock = lock_file.relative_to(workspace_path)
                try:
                    result = self.run_command(
                        ["pip-audit", "--format", "json", "--progress-spinner", "off"],
                        timeout=300,
                        cwd=str(scan_dir),
                    )

                    if result.stdout:
                        try:
                            audit_data = json.loads(result.stdout)
                            findings.extend(self._parse_pip_audit(audit_data, str(rel_lock)))
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse pip-audit output for {rel_lock}: {e}")

                except Exception as e:
                    logger.error(f"pip-audit failed in {scan_dir}: {e}")

        return findings

    def _parse_pip_audit(
        self, data: dict | list, source_file: str = "requirements.txt"
    ) -> list[Finding]:
        """pip-audit JSON 결과 파싱

        pip-audit 버전에 따라 출력 포맷이 다르다.
        - 구버전: list[{"name": ..., "version": ..., "vulns": [...]}]
        - 신버전: {"dependencies": [...], "fixes": [...]}
        """
        findings: list[Finding] = []

        dependencies: list[dict]
        if isinstance(data, dict):
            raw_dependencies = data.get("dependencies", [])
            if not isinstance(raw_dependencies, list):
                logger.warning("Unexpected pip-audit JSON format: dependencies is not a list")
                return findings
            dependencies = [d for d in raw_dependencies if isinstance(d, dict)]
        elif isinstance(data, list):
            dependencies = [d for d in data if isinstance(d, dict)]
        else:
            logger.warning("Unexpected pip-audit JSON type: %s", type(data).__name__)
            return findings

        for dep in dependencies:
            pkg_name = dep.get("name", "unknown")
            version = dep.get("version", "")
            vulns = dep.get("vulns", [])
            if not isinstance(vulns, list):
                continue

            for v in vulns:
                if not isinstance(v, dict):
                    continue

                # CVSS 점수로 심각도 결정
                severity = Severity.MEDIUM
                aliases = v.get("aliases", [])

                # fix_versions가 있으면 수정 버전 정보 추가
                fix_versions = v.get("fix_versions", [])
                fix_msg = f" (fix: {', '.join(fix_versions)})" if fix_versions else ""

                finding = Finding(
                    scanner="pip-audit",
                    rule_id=v.get("id", "UNKNOWN"),
                    severity=severity,
                    message=f"{v.get('description', 'Vulnerability')} in {pkg_name}=={version}{fix_msg}",
                    file_path=self.normalize_path(source_file),
                    line_start=1,
                    metadata={
                        "package": pkg_name,
                        "version": version,
                        "vuln_id": v.get("id"),
                        "aliases": aliases,
                        "fix_versions": fix_versions,
                    },
                )
                findings.append(finding)

        return findings

    def _run_govulncheck(self) -> list[Finding]:
        """govulncheck 실행"""
        findings: list[Finding] = []
        workspace_path = Path(self.workspace)

        # go.mod 파일 찾기
        go_mods = list(workspace_path.glob("**/go.mod"))

        if not go_mods:
            logger.info("No go.mod files found")
            return []

        for go_mod in go_mods[:5]:  # 최대 5개 모듈
            mod_dir = go_mod.parent

            try:
                # govulncheck -json 실행
                result = self.run_command(
                    ["govulncheck", "-json", "./..."],
                    timeout=300,
                    cwd=str(mod_dir),
                )

                if result.stdout:
                    findings.extend(self._parse_govulncheck(result.stdout, mod_dir))

            except Exception as e:
                logger.error(f"govulncheck failed in {mod_dir}: {e}")

        return findings

    def _parse_govulncheck(self, output: str, mod_dir: Path) -> list[Finding]:
        """govulncheck JSON 결과 파싱 (NDJSON 형식)"""
        findings: list[Finding] = []
        rel_dir = (
            mod_dir.relative_to(Path(self.workspace))
            if mod_dir != Path(self.workspace)
            else Path(".")
        )

        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)

                # finding 타입만 처리
                if "finding" not in entry:
                    continue

                finding_data = entry["finding"]
                osv = finding_data.get("osv", "")

                # 트레이스에서 파일 정보 추출
                trace = finding_data.get("trace", [])
                file_path = os.path.join(str(rel_dir), "go.mod")
                line_num = 1

                if trace:
                    for t in trace:
                        if t.get("position", {}).get("filename"):
                            file_path = t["position"]["filename"]
                            line_num = t["position"].get("line", 1)
                            break

                finding = Finding(
                    scanner="govulncheck",
                    rule_id=osv,
                    severity=Severity.HIGH,  # govulncheck는 기본적으로 높은 심각도
                    message=f"Go vulnerability {osv}",
                    file_path=self.normalize_path(file_path),
                    line_start=line_num,
                    metadata={
                        "osv": osv,
                        "trace": trace,
                    },
                )
                findings.append(finding)

            except json.JSONDecodeError:
                continue

        return findings

    def _run_cargo_audit(self) -> list[Finding]:
        """cargo-audit 실행"""
        findings: list[Finding] = []
        workspace_path = Path(self.workspace)

        # Cargo.lock 파일 찾기
        cargo_locks = list(workspace_path.glob("**/Cargo.lock"))

        if not cargo_locks:
            logger.info("No Cargo.lock files found")
            return []

        for cargo_lock in cargo_locks[:5]:
            lock_dir = cargo_lock.parent
            rel_dir = (
                lock_dir.relative_to(workspace_path) if lock_dir != workspace_path else Path(".")
            )

            try:
                # cargo-audit --json 실행
                result = self.run_command(
                    ["cargo-audit", "audit", "--json"],
                    timeout=300,
                    cwd=str(lock_dir),
                )

                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                        findings.extend(self._parse_cargo_audit(audit_data, str(rel_dir)))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse cargo-audit output: {e}")

            except Exception as e:
                logger.error(f"cargo-audit failed in {lock_dir}: {e}")

        return findings

    def _parse_cargo_audit(self, data: dict, base_dir: str) -> list[Finding]:
        """cargo-audit JSON 결과 파싱"""
        findings: list[Finding] = []

        vulnerabilities = data.get("vulnerabilities", {}).get("list", [])
        for vuln in vulnerabilities:
            advisory = vuln.get("advisory", {})
            package = vuln.get("package", {})

            # CVSS로 심각도 결정
            cvss = advisory.get("cvss")
            if cvss:
                score = (
                    float(cvss.split("/")[0].replace("CVSS:", ""))
                    if isinstance(cvss, str)
                    else cvss
                )
                if score >= 9.0:
                    severity = Severity.CRITICAL
                elif score >= 7.0:
                    severity = Severity.HIGH
                elif score >= 4.0:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
            else:
                severity = Severity.MEDIUM

            finding = Finding(
                scanner="cargo-audit",
                rule_id=advisory.get("id", "UNKNOWN"),
                severity=severity,
                message=f"{advisory.get('title', 'Vulnerability')} in {package.get('name', 'unknown')}",
                file_path=self.normalize_path(os.path.join(base_dir, "Cargo.lock")),
                line_start=1,
                metadata={
                    "package": package.get("name"),
                    "version": package.get("version"),
                    "advisory_id": advisory.get("id"),
                    "url": advisory.get("url"),
                    "categories": advisory.get("categories", []),
                    "cvss": cvss,
                },
            )
            findings.append(finding)

        return findings

    def _run_bundler_audit(self) -> list[Finding]:
        """bundler-audit 실행"""
        findings: list[Finding] = []
        workspace_path = Path(self.workspace)

        # Gemfile.lock 찾기
        gemfiles = list(workspace_path.glob("**/Gemfile.lock"))

        if not gemfiles:
            logger.info("No Gemfile.lock files found")
            return []

        for gemfile in gemfiles[:5]:
            gem_dir = gemfile.parent
            rel_dir = (
                gem_dir.relative_to(workspace_path) if gem_dir != workspace_path else Path(".")
            )

            try:
                # bundler-audit 실행 (JSON 출력 없음, 텍스트 파싱)
                result = self.run_command(
                    ["bundler-audit", "check", "--format", "json"],
                    timeout=300,
                    cwd=str(gem_dir),
                )

                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                        findings.extend(self._parse_bundler_audit(audit_data, str(rel_dir)))
                    except json.JSONDecodeError:
                        # 텍스트 형식으로 파싱 시도
                        findings.extend(self._parse_bundler_audit_text(result.stdout, str(rel_dir)))

            except Exception as e:
                logger.error(f"bundler-audit failed in {gem_dir}: {e}")

        return findings

    def _parse_bundler_audit(self, data: dict, base_dir: str) -> list[Finding]:
        """bundler-audit JSON 결과 파싱"""
        findings: list[Finding] = []

        for result in data.get("results", []):
            advisory = result.get("advisory", {})
            gem = result.get("gem", {})

            severity = self._cvss_to_severity(advisory.get("cvss_v3", 5.0))

            finding = Finding(
                scanner="bundler-audit",
                rule_id=advisory.get("id", "UNKNOWN"),
                severity=severity,
                message=f"{advisory.get('title', 'Vulnerability')} in {gem.get('name', 'unknown')}",
                file_path=self.normalize_path(os.path.join(base_dir, "Gemfile.lock")),
                line_start=1,
                metadata={
                    "package": gem.get("name"),
                    "version": gem.get("version"),
                    "advisory_id": advisory.get("id"),
                    "url": advisory.get("url"),
                    "patched_versions": advisory.get("patched_versions", []),
                },
            )
            findings.append(finding)

        return findings

    def _parse_bundler_audit_text(self, output: str, base_dir: str) -> list[Finding]:
        """bundler-audit 텍스트 출력 파싱 (fallback)"""
        findings: list[Finding] = []

        # 간단한 텍스트 파싱 (상세 구현 필요)
        lines = output.strip().split("\n")
        current_vuln = {}

        for line in lines:
            if line.startswith("Name:"):
                current_vuln["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("CVE:") or line.startswith("GHSA:"):
                current_vuln["id"] = line.split(":", 1)[1].strip()
            elif line.startswith("Criticality:"):
                crit = line.split(":", 1)[1].strip().lower()
                current_vuln["severity"] = self.SEVERITY_MAP.get(crit, Severity.MEDIUM)
            elif line.startswith("Title:"):
                current_vuln["title"] = line.split(":", 1)[1].strip()

                # 취약점 정보가 완성되면 Finding 생성
                if current_vuln.get("name"):
                    finding = Finding(
                        scanner="bundler-audit",
                        rule_id=current_vuln.get("id", "UNKNOWN"),
                        severity=current_vuln.get("severity", Severity.MEDIUM),
                        message=f"{current_vuln.get('title', 'Vulnerability')} in {current_vuln['name']}",
                        file_path=self.normalize_path(os.path.join(base_dir, "Gemfile.lock")),
                        line_start=1,
                        metadata=current_vuln.copy(),
                    )
                    findings.append(finding)
                    current_vuln = {}

        return findings

    def _run_composer_audit(self) -> list[Finding]:
        """composer audit 실행"""
        findings: list[Finding] = []
        workspace_path = Path(self.workspace)

        # composer.lock 찾기
        composer_locks = list(workspace_path.glob("**/composer.lock"))

        if not composer_locks:
            logger.info("No composer.lock files found")
            return []

        for composer_lock in composer_locks[:5]:
            lock_dir = composer_lock.parent
            rel_dir = (
                lock_dir.relative_to(workspace_path) if lock_dir != workspace_path else Path(".")
            )

            try:
                # composer audit --format json 실행
                result = self.run_command(
                    ["composer", "audit", "--format", "json", "--no-interaction"],
                    timeout=300,
                    cwd=str(lock_dir),
                )

                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                        findings.extend(self._parse_composer_audit(audit_data, str(rel_dir)))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse composer audit output: {e}")

            except Exception as e:
                logger.error(f"composer audit failed in {lock_dir}: {e}")

        return findings

    def _parse_composer_audit(self, data: dict, base_dir: str) -> list[Finding]:
        """composer audit JSON 결과 파싱"""
        findings: list[Finding] = []

        advisories = data.get("advisories", {})
        for pkg_name, pkg_advisories in advisories.items():
            for advisory in pkg_advisories:
                # CVSS로 심각도 결정
                cvss = advisory.get("cvss", {})
                score = cvss.get("score", 5.0) if isinstance(cvss, dict) else 5.0
                severity = self._cvss_to_severity(score)

                finding = Finding(
                    scanner="composer-audit",
                    rule_id=advisory.get("advisoryId", "UNKNOWN"),
                    severity=severity,
                    message=f"{advisory.get('title', 'Vulnerability')} in {pkg_name}",
                    file_path=self.normalize_path(os.path.join(base_dir, "composer.lock")),
                    line_start=1,
                    metadata={
                        "package": pkg_name,
                        "affected_versions": advisory.get("affectedVersions"),
                        "advisory_id": advisory.get("advisoryId"),
                        "cve": advisory.get("cve"),
                        "link": advisory.get("link"),
                        "sources": advisory.get("sources", []),
                    },
                )
                findings.append(finding)

        return findings

    def _cvss_to_severity(self, score: float) -> Severity:
        """CVSS 점수를 심각도로 변환"""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0:
            return Severity.LOW
        else:
            return Severity.INFO
