"""SBOM Generator - Syft Wrapper

Software Bill of Materials (SBOM) 생성
CycloneDX 및 SPDX 포맷 지원
"""

import json
import logging
import os
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
        output_file = Path(self.output_path)
        if output_file.is_absolute():
            return output_file
        return Path(self.workspace) / output_file

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
        import subprocess

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

            # 실행
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=self.workspace,
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

            logger.info(f"SBOM generated: {self.output_path} ({components_count} components)")

            return {
                "success": True,
                "output_path": str(self.output_path),
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
            with open(sbom_file) as f:
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
        sbom_file = self._resolve_output_file()
        if not sbom_file.exists():
            return []

        try:
            with open(sbom_file) as f:
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
