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
from fnmatch import fnmatch
from pathlib import Path

from .base import BaseScanner, Finding, Severity

logger = logging.getLogger(__name__)


class NativeAuditScanner(BaseScanner):
    """통합 네이티브 의존성 스캐너"""

    EXCLUDED_SCAN_DIRS = {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "node_modules",
        "vendor",
        "dist",
        "build",
        # 테스트 fixture/testdata는 실제 배포 의존성이 아닌 샘플 데이터인 경우가 많아
        # 네이티브 감사 시 과도한 설치/리소스 사용을 유발할 수 있으므로 기본 제외한다.
        "fixtures",
        "__fixtures__",
        "testdata",
    }

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
    EXPECTED_EXIT_CODES = {
        "npm": {0, 1},
        "pip-audit": {0, 1},
        "govulncheck": {0, 3},
        "cargo-audit": {0, 1},
        "bundler-audit": {0, 1},
        "composer-audit": {0, 1},
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

        for manager, config in self.PACKAGE_MANAGERS.items():
            for file_pattern in config["files"]:
                matches = self._find_files([file_pattern], max_results=1)
                if matches:
                    detected.append(manager)
                    logger.info(f"Detected {manager} package manager: {matches[0]}")
                    break

        return detected

    @classmethod
    def _should_skip_scan_dir(cls, directory_name: str) -> bool:
        return directory_name in cls.EXCLUDED_SCAN_DIRS

    def _find_files(self, patterns: list[str], max_results: int | None = None) -> list[Path]:
        """워크스페이스 내부에서 파일 패턴 매칭 결과를 반환한다.

        공통 vendor/cache 디렉토리는 탐색에서 제외해 불필요한 스캔과
        과도한 실행 시간을 줄인다.
        """
        workspace_path = Path(self.workspace)
        matched: list[Path] = []
        normalized_patterns = [p.strip() for p in patterns if p and p.strip()]
        if not normalized_patterns:
            return matched

        for root, dirs, files in os.walk(workspace_path, topdown=True):
            dirs[:] = [d for d in dirs if not self._should_skip_scan_dir(d)]
            root_path = Path(root)

            for file_name in files:
                if not any(fnmatch(file_name, pattern) for pattern in normalized_patterns):
                    continue
                matched.append(root_path / file_name)
                if max_results is not None and len(matched) >= max_results:
                    return sorted(matched)

        return sorted(matched)

    def _is_tool_available(self, tool: str) -> bool:
        """도구가 시스템에 설치되어 있는지 확인"""
        config = self.PACKAGE_MANAGERS.get(tool)
        if not config:
            return False

        command = config["command"]
        safe_path = self._build_safe_env().get("PATH", "")

        # 특수 케이스 처리
        if tool == "composer":
            return shutil.which("composer", path=safe_path) is not None
        if tool == "npm":
            return shutil.which("npm", path=safe_path) is not None

        return shutil.which(command, path=safe_path) is not None

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
                missing_msg = f"{manager} tool not available"
                logger.error("%s, marking scanner result as failed", missing_msg)
                errors.append(missing_msg)
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

    def _assert_audit_command_output(
        self,
        tool_name: str,
        result,
        cwd: Path | str,
    ) -> None:
        """audit 명령 종료 코드/출력을 검증한다.

        - 취약점 발견 시 non-zero를 반환하는 도구를 고려해 허용 종료 코드를 적용한다.
        - non-zero인데 stdout이 비어 있으면 런타임 실패로 간주한다.
        - 허용되지 않은 종료 코드여도 stdout이 있으면 파싱 시도 후 최종 판정한다.
        """
        expected_codes = self.EXPECTED_EXIT_CODES.get(tool_name, {0})
        stdout = (result.stdout or "").strip()

        if result.returncode in expected_codes:
            if result.returncode != 0 and not stdout:
                raise RuntimeError(self._format_command_error(tool_name, result, cwd))
            return

        if not stdout:
            raise RuntimeError(self._format_command_error(tool_name, result, cwd))

        logger.warning(
            "%s returned unexpected exit code %s in %s; attempting to parse output",
            tool_name,
            result.returncode,
            cwd,
        )

    @staticmethod
    def _format_command_error(tool_name: str, result, cwd: Path | str) -> str:
        """감사 도구 실패 메시지 생성."""
        output = (result.stderr or result.stdout or "").strip()
        if not output:
            output = "no output"
        if len(output) > 500:
            output = output[:500] + "..."
        return f"{tool_name} command failed in {cwd} (exit code {result.returncode}): {output}"

    def _run_npm_audit(self) -> list[Finding]:
        """npm audit 실행"""
        findings: list[Finding] = []

        # package-lock.json이 있는 디렉토리 찾기
        workspace_path = Path(self.workspace)
        lock_files = self._find_files(["package-lock.json"])

        if not lock_files:
            # package.json만 있는 경우 npm install 먼저 실행
            package_jsons = self._find_files(["package.json"])
            if package_jsons:
                logger.info("No package-lock.json found, running npm install first")
                install_failures: list[str] = []
                for pj in package_jsons[:5]:  # 최대 5개 디렉토리만
                    result = self.run_command(
                        [
                            "npm",
                            "install",
                            "--package-lock-only",
                            "--ignore-scripts",
                            "--no-audit",
                            "--no-fund",
                        ],
                        cwd=str(pj.parent),
                        timeout=120,
                    )
                    if result.returncode != 0:
                        stderr = (result.stderr or "").strip()
                        failure_msg = (
                            f"{pj.parent}: {stderr[:300]}"
                            if stderr
                            else f"{pj.parent}: exit code {result.returncode}"
                        )
                        install_failures.append(failure_msg)
                        logger.warning(
                            "npm install --package-lock-only failed in %s: %s",
                            pj.parent,
                            stderr[:300] if stderr else f"exit code {result.returncode}",
                        )
                lock_files = self._find_files(["package-lock.json"])
                if not lock_files:
                    remaining = max(0, len(package_jsons) - 5)
                    remaining_msg = (
                        f" (skipped {remaining} additional package.json directories due to limit)"
                        if remaining
                        else ""
                    )
                    if install_failures:
                        preview = "; ".join(install_failures[:3])
                        raise RuntimeError(
                            "package-lock.json generation failed before npm audit: "
                            f"{preview}{remaining_msg}"
                        )
                    raise RuntimeError(
                        "package.json detected but package-lock.json was not generated "
                        f"before npm audit{remaining_msg}"
                    )

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
                self._assert_audit_command_output("npm", result, scan_dir)
                findings_before = len(findings)
                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                        findings.extend(self._parse_npm_audit(audit_data, str(rel_dir)))
                    except json.JSONDecodeError as e:
                        if result.returncode != 0:
                            raise RuntimeError(
                                f"Failed to parse npm audit JSON in {scan_dir}: {e}"
                            ) from e
                        logger.warning(f"Failed to parse npm audit output: {e}")

                if (
                    result.returncode not in self.EXPECTED_EXIT_CODES["npm"]
                    and len(findings) == findings_before
                ):
                    raise RuntimeError(self._format_command_error("npm", result, scan_dir))

            except Exception as e:
                raise RuntimeError(f"npm audit failed in {scan_dir}: {e}") from e

        return findings

    def _parse_npm_audit(self, data: dict, base_dir: str) -> list[Finding]:
        """npm audit JSON 결과 파싱"""
        findings: list[Finding] = []

        # npm v7+ format (advisories in vulnerabilities)
        vulnerabilities = data.get("vulnerabilities", {})
        if not isinstance(vulnerabilities, dict):
            return findings

        for pkg_name, vuln_info in vulnerabilities.items():
            if not isinstance(vuln_info, dict):
                continue

            severity_str = vuln_info.get("severity", "low")
            severity_key = str(severity_str)
            severity = self.SEVERITY_MAP.get(
                severity_key.lower(),
                self.SEVERITY_MAP.get(severity_key.upper(), Severity.MEDIUM),
            )

            # via 필드에서 상세 정보 추출
            via = vuln_info.get("via", [])
            if isinstance(via, list) and via:
                added = False
                for v in via:
                    if isinstance(v, dict):
                        added = True
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
                # via가 문자열만 있는 경우도 취약점 체인으로 기록
                if not added:
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

        req_files = self._find_files(["requirements*.txt"])
        lock_files = self._find_files(["Pipfile.lock", "poetry.lock"])

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
                    self._assert_audit_command_output("pip-audit", result, self.workspace)
                    findings_before = len(findings)
                    if result.stdout:
                        try:
                            audit_data = json.loads(result.stdout)
                            findings.extend(self._parse_pip_audit(audit_data, str(rel_req)))
                        except json.JSONDecodeError as e:
                            if result.returncode != 0:
                                raise RuntimeError(
                                    f"Failed to parse pip-audit JSON for {rel_req}: {e}"
                                ) from e
                            logger.warning(f"Failed to parse pip-audit output for {rel_req}: {e}")

                    if (
                        result.returncode not in self.EXPECTED_EXIT_CODES["pip-audit"]
                        and len(findings) == findings_before
                    ):
                        raise RuntimeError(
                            self._format_command_error("pip-audit", result, self.workspace)
                        )

                except Exception as e:
                    raise RuntimeError(f"pip-audit failed for {rel_req}: {e}") from e
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
                    self._assert_audit_command_output("pip-audit", result, scan_dir)
                    findings_before = len(findings)
                    if result.stdout:
                        try:
                            audit_data = json.loads(result.stdout)
                            findings.extend(self._parse_pip_audit(audit_data, str(rel_lock)))
                        except json.JSONDecodeError as e:
                            if result.returncode != 0:
                                raise RuntimeError(
                                    f"Failed to parse pip-audit JSON for {rel_lock}: {e}"
                                ) from e
                            logger.warning(f"Failed to parse pip-audit output for {rel_lock}: {e}")

                    if (
                        result.returncode not in self.EXPECTED_EXIT_CODES["pip-audit"]
                        and len(findings) == findings_before
                    ):
                        raise RuntimeError(
                            self._format_command_error("pip-audit", result, scan_dir)
                        )

                except Exception as e:
                    raise RuntimeError(f"pip-audit failed in {scan_dir}: {e}") from e

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

        # go.mod 파일 찾기
        go_mods = self._find_files(["go.mod"])

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
                self._assert_audit_command_output("govulncheck", result, mod_dir)
                findings_before = len(findings)
                if result.stdout:
                    findings.extend(self._parse_govulncheck(result.stdout, mod_dir))

                if (
                    result.returncode not in self.EXPECTED_EXIT_CODES["govulncheck"]
                    and len(findings) == findings_before
                ):
                    raise RuntimeError(self._format_command_error("govulncheck", result, mod_dir))

            except Exception as e:
                raise RuntimeError(f"govulncheck failed in {mod_dir}: {e}") from e

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
        cargo_locks = self._find_files(["Cargo.lock"])

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
                self._assert_audit_command_output("cargo-audit", result, lock_dir)
                findings_before = len(findings)
                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                        findings.extend(self._parse_cargo_audit(audit_data, str(rel_dir)))
                    except json.JSONDecodeError as e:
                        if result.returncode != 0:
                            raise RuntimeError(
                                f"Failed to parse cargo-audit JSON in {lock_dir}: {e}"
                            ) from e
                        logger.warning(f"Failed to parse cargo-audit output: {e}")

                if (
                    result.returncode not in self.EXPECTED_EXIT_CODES["cargo-audit"]
                    and len(findings) == findings_before
                ):
                    raise RuntimeError(self._format_command_error("cargo-audit", result, lock_dir))

            except Exception as e:
                raise RuntimeError(f"cargo-audit failed in {lock_dir}: {e}") from e

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
            score = self._extract_cvss_score(cvss)
            if score is not None:
                severity = self._cvss_to_severity(score)
            elif isinstance(cvss, str) and cvss.upper().startswith("CVSS:"):
                # CVSS 벡터 문자열(CVSS:3.1/...)은 base score가 직접 포함되지 않으므로
                # 과소평가를 피하기 위해 보수적으로 HIGH로 처리한다.
                severity = Severity.HIGH
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

    @staticmethod
    def _extract_cvss_score(cvss: str | float | int | None) -> float | None:
        """CVSS 입력에서 base score 추출.

        지원 형식:
        - 숫자(7.5)
        - 문자열 숫자("7.5")
        - 선두 점수 문자열("7.5/AV:N/...")
        """
        if isinstance(cvss, (int, float)):
            return float(cvss)
        if not isinstance(cvss, str):
            return None

        value = cvss.strip()
        if not value:
            return None

        # 벡터 문자열은 별도 처리(예: CVSS:3.1/AV:N/...)
        if value.upper().startswith("CVSS:"):
            return None

        token = value.split("/", 1)[0]
        try:
            return float(token)
        except ValueError:
            return None

    def _run_bundler_audit(self) -> list[Finding]:
        """bundler-audit 실행"""
        findings: list[Finding] = []
        workspace_path = Path(self.workspace)

        # Gemfile.lock 찾기
        gemfiles = self._find_files(["Gemfile.lock"])

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
                self._assert_audit_command_output("bundler-audit", result, gem_dir)
                findings_before = len(findings)
                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                        findings.extend(self._parse_bundler_audit(audit_data, str(rel_dir)))
                    except json.JSONDecodeError:
                        if result.returncode == 0:
                            raise RuntimeError(f"Failed to parse bundler-audit output in {gem_dir}")
                        # 텍스트 형식으로 파싱 시도 (취약점 발견 시 non-zero 대응)
                        findings.extend(self._parse_bundler_audit_text(result.stdout, str(rel_dir)))

                if (
                    result.returncode not in self.EXPECTED_EXIT_CODES["bundler-audit"]
                    and len(findings) == findings_before
                ):
                    raise RuntimeError(self._format_command_error("bundler-audit", result, gem_dir))

            except Exception as e:
                raise RuntimeError(f"bundler-audit failed in {gem_dir}: {e}") from e

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
        composer_locks = self._find_files(["composer.lock"])

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
                self._assert_audit_command_output("composer-audit", result, lock_dir)
                findings_before = len(findings)
                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                        findings.extend(self._parse_composer_audit(audit_data, str(rel_dir)))
                    except json.JSONDecodeError as e:
                        if result.returncode != 0:
                            raise RuntimeError(
                                f"Failed to parse composer audit JSON in {lock_dir}: {e}"
                            ) from e
                        logger.warning(f"Failed to parse composer audit output: {e}")

                if (
                    result.returncode not in self.EXPECTED_EXIT_CODES["composer-audit"]
                    and len(findings) == findings_before
                ):
                    raise RuntimeError(
                        self._format_command_error("composer-audit", result, lock_dir)
                    )

            except Exception as e:
                raise RuntimeError(f"composer audit failed in {lock_dir}: {e}") from e

        return findings

    def _parse_composer_audit(self, data: dict, base_dir: str) -> list[Finding]:
        """composer audit JSON 결과 파싱"""
        findings: list[Finding] = []

        advisories = data.get("advisories", {})
        if not isinstance(advisories, dict):
            logger.warning("Unexpected composer audit JSON format: advisories is not a dict")
            return findings

        for pkg_name, pkg_advisories in advisories.items():
            if not isinstance(pkg_advisories, list):
                continue
            for advisory in pkg_advisories:
                if not isinstance(advisory, dict):
                    continue
                # CVSS로 심각도 결정
                cvss = advisory.get("cvss", {})
                raw_score = cvss.get("score", 5.0) if isinstance(cvss, dict) else cvss
                score = self._extract_cvss_score(raw_score)
                if score is None:
                    score = 5.0
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
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 5.0

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
