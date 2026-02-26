"""SBOM Generator - Syft Wrapper

Software Bill of Materials (SBOM) 생성
CycloneDX 및 SPDX 포맷 지원
"""

import json
import logging
import os
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SBOMGenerator:
    """Syft를 사용한 SBOM 생성기

    SBOM (Software Bill of Materials)은 소프트웨어의 모든 구성 요소와
    의존성을 나열한 목록입니다.

    지원 포맷:
    - CycloneDX (JSON/XML)
    - SPDX (JSON/TagValue)
    - Syft JSON (기본)

    Args:
        workspace: 스캔할 워크스페이스 경로
        output_format: 출력 포맷 (cyclonedx-json, spdx-json, syft-json)
        output_path: SBOM 출력 파일 경로
        image: 컨테이너 이미지 스캔 시 이미지 이름
    """

    SUPPORTED_FORMATS = {
        "cyclonedx-json": "application/vnd.cyclonedx+json",
        "cyclonedx-xml": "application/vnd.cyclonedx+xml",
        "spdx-json": "application/spdx+json",
        "spdx-tag-value": "text/spdx",
        "syft-json": "application/json",
    }
    GH_ACTIONS_SAFE_PATH_PREFIXES = (
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/opt/sonar-scanner/bin",
        "/root/.cargo/bin",
        "/usr/local/go/bin",
        "/root/go/bin",
    )

    def __init__(
        self,
        workspace: str,
        output_format: str = "cyclonedx-json",
        output_path: str | None = None,
        image: str | None = None,
    ):
        self.workspace = workspace
        self.output_format = output_format
        self.output_path = output_path or os.getenv("INPUT_SBOM_OUTPUT", "sbom.json")
        self.image = image or os.getenv("INPUT_SBOM_IMAGE")

    def _resolve_output_file(self) -> Path:
        """출력 파일 경로를 절대 경로로 해석한다.

        relative 경로는 workspace 기준으로 처리해 GitHub Actions 컨테이너에서도
        실제 생성 위치와 존재성 검증 위치가 일치하도록 보장한다.
        """
        output_file = Path(self.output_path).expanduser()
        workspace_path = Path(self.workspace).resolve(strict=False)

        if output_file.is_absolute():
            resolved = output_file.resolve(strict=False)
        else:
            resolved = (workspace_path / output_file).resolve(strict=False)

        if os.getenv("GITHUB_ACTIONS", "").lower() == "true":
            if not (resolved == workspace_path or workspace_path in resolved.parents):
                raise ValueError(f"SBOM output path must stay within workspace: {self.output_path}")

        return resolved

    def _format_output_path_for_display(self, resolved_path: Path) -> str:
        """로그/결과 표시용 출력 경로 문자열."""
        original = str(self.output_path or "").strip()
        if original and not Path(original).is_absolute():
            return original

        workspace_path = Path(self.workspace).resolve(strict=False)
        if resolved_path == workspace_path or workspace_path in resolved_path.parents:
            return str(resolved_path.relative_to(workspace_path))

        return str(resolved_path)

    def _build_safe_env(self) -> dict[str, str]:
        """Syft 실행용 환경 변수 구성.

        PATH에서 빈 항목/`.`/workspace 하위 경로를 제거해
        저장소 내부 바이너리 하이재킹을 방지한다.
        """
        env = os.environ.copy()
        path_value = env.get("PATH", "")
        if not path_value:
            return env

        try:
            workspace_resolved = Path(self.workspace).resolve(strict=False)
        except Exception:
            workspace_resolved = None

        safe_entries: list[str] = []
        seen: set[str] = set()
        for raw_entry in path_value.split(os.pathsep):
            entry = raw_entry.strip()
            if not entry or entry == ".":
                continue

            # 상대 경로 PATH 엔트리는 실행 위치 의존적이라 제외한다.
            if not Path(entry).is_absolute():
                continue

            if workspace_resolved is not None:
                try:
                    entry_path = Path(entry).resolve(strict=False)
                except Exception:
                    entry_path = None

                if entry_path is not None and (
                    entry_path == workspace_resolved or workspace_resolved in entry_path.parents
                ):
                    continue

            if os.getenv("GITHUB_ACTIONS", "").lower() == "true":
                if not any(
                    entry == prefix or entry.startswith(prefix + os.sep)
                    for prefix in self.GH_ACTIONS_SAFE_PATH_PREFIXES
                ):
                    continue

            if entry not in seen:
                safe_entries.append(entry)
                seen.add(entry)

        env["PATH"] = os.pathsep.join(safe_entries)

        return env

    def generate(self) -> dict[str, Any]:
        """SBOM 생성

        Returns:
            생성 결과 딕셔너리:
            - success: 성공 여부
            - output_path: 생성된 SBOM 파일 경로
            - components_count: 발견된 구성 요소 수
            - format: 출력 포맷
            - error: 에러 메시지 (실패 시)
        """
        logger.info(f"Generating SBOM in {self.output_format} format")

        try:
            # 출력 경로 준비
            output_file = self._resolve_output_file()
            output_file.parent.mkdir(parents=True, exist_ok=True)

            # Syft 명령 구성
            cmd = ["syft"]

            if self.image:
                cmd.append(self.image)
                logger.info(f"Scanning container image: {self.image}")
            else:
                cmd.extend(["dir:" + self.workspace])
                logger.info(f"Scanning directory: {self.workspace}")

            cmd.extend(
                [
                    "--output",
                    f"{self.output_format}={str(output_file)}",
                ]
            )

            safe_env = self._build_safe_env()

            # 실행
            # Bandit B603: command is list-based with shell=False and sanitized PATH/env.
            result = subprocess.run(  # nosec B603
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=self.workspace,
                env=safe_env,
            )

            if result.returncode != 0:
                logger.error(f"Syft failed: {result.stderr}")
                return {
                    "success": False,
                    "error": result.stderr,
                }

            # 결과 확인
            if not output_file.exists():
                return {
                    "success": False,
                    "error": "SBOM file was not created",
                }

            # 구성 요소 수 카운트
            components_count = self._count_components(output_file)
            display_output_path = self._format_output_path_for_display(output_file)

            logger.info(f"SBOM generated: {display_output_path} ({components_count} components)")

            return {
                "success": True,
                "output_path": display_output_path,
                "components_count": components_count,
                "format": self.output_format,
                "mime_type": self.SUPPORTED_FORMATS.get(self.output_format, "application/json"),
            }

        except subprocess.TimeoutExpired:
            logger.error("SBOM generation timed out")
            return {
                "success": False,
                "error": "SBOM generation timed out (5 minutes)",
            }
        except FileNotFoundError:
            logger.error(
                "Syft not found. Install with: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh"
            )
            return {
                "success": False,
                "error": "Syft not installed",
            }
        except Exception as e:
            logger.error(f"SBOM generation error: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    def _count_components(self, sbom_file: Path) -> int:
        """SBOM에서 구성 요소 수 카운트"""
        try:
            with open(sbom_file, encoding="utf-8") as f:
                data = json.load(f)

            # CycloneDX 포맷
            if "components" in data:
                return len(data["components"])

            # SPDX 포맷
            if "packages" in data:
                return len(data["packages"])

            # Syft JSON 포맷
            if "artifacts" in data:
                return len(data["artifacts"])

            return 0
        except (json.JSONDecodeError, KeyError):
            return 0

    def get_components(self) -> list[dict]:
        """SBOM에서 구성 요소 목록 추출"""
        try:
            sbom_file = self._resolve_output_file()
        except ValueError:
            return []

        if not sbom_file.exists():
            return []

        try:
            with open(sbom_file, encoding="utf-8") as f:
                data = json.load(f)

            components = []

            # CycloneDX 포맷
            if "components" in data:
                for comp in data["components"]:
                    components.append(
                        {
                            "name": comp.get("name", ""),
                            "version": comp.get("version", ""),
                            "type": comp.get("type", ""),
                            "purl": comp.get("purl", ""),
                            "licenses": [
                                lic.get("license", {}).get("id", "")
                                for lic in comp.get("licenses", [])
                            ],
                        }
                    )

            # SPDX 포맷
            elif "packages" in data:
                for pkg in data["packages"]:
                    components.append(
                        {
                            "name": pkg.get("name", ""),
                            "version": pkg.get("versionInfo", ""),
                            "type": pkg.get("primaryPackagePurpose", ""),
                            "purl": pkg.get("externalRefs", [{}])[0].get("referenceLocator", "")
                            if pkg.get("externalRefs")
                            else "",
                            "licenses": [pkg.get("licenseConcluded", "")],
                        }
                    )

            # Syft JSON 포맷
            elif "artifacts" in data:
                for artifact in data["artifacts"]:
                    components.append(
                        {
                            "name": artifact.get("name", ""),
                            "version": artifact.get("version", ""),
                            "type": artifact.get("type", ""),
                            "purl": artifact.get("purl", ""),
                            "licenses": artifact.get("licenses", []),
                        }
                    )

            return components

        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse SBOM: {e}")
            return []


def generate_sbom(
    workspace: str,
    output_format: str = "cyclonedx-json",
    output_path: str = "sbom.json",
    image: str | None = None,
) -> dict[str, Any]:
    """SBOM 생성 헬퍼 함수"""
    generator = SBOMGenerator(
        workspace=workspace,
        output_format=output_format,
        output_path=output_path,
        image=image,
    )
    return generator.generate()
