#!/usr/bin/env python3
"""Security Action CLI

로컬에서 보안 스캔을 실행할 수 있는 CLI 도구
"""

import argparse
import os
import sys

from rich.console import Console

console = Console()


def parse_args() -> argparse.Namespace:
    """명령행 인자 파싱"""
    parser = argparse.ArgumentParser(
        prog="security-scan",
        description="Security Scanner Action - GitHub Advanced Security Alternative",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 현재 디렉토리 스캔
  python -m cli

  # 특정 디렉토리 스캔
  python -m cli /path/to/project

  # 특정 스캐너만 실행
  python -m cli --secret-scan --no-code-scan --no-dependency-scan

  # AI 리뷰 활성화
  python -m cli --ai-review --openai-api-key $OPENAI_API_KEY

  # 설정 파일 사용
  python -m cli --config .security-action.yml
        """,
    )

    # 위치 인자
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="스캔할 디렉토리 경로 (기본: 현재 디렉토리)",
    )

    # 스캐너 옵션
    scanner_group = parser.add_argument_group("Scanner Options")
    scanner_group.add_argument(
        "--secret-scan/--no-secret-scan",
        dest="secret_scan",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="비밀값 스캔 (Gitleaks)",
    )
    scanner_group.add_argument(
        "--code-scan/--no-code-scan",
        dest="code_scan",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="코드 취약점 스캔 (Semgrep)",
    )
    scanner_group.add_argument(
        "--dependency-scan/--no-dependency-scan",
        dest="dependency_scan",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="의존성 취약점 스캔 (Trivy)",
    )

    # AI 옵션
    ai_group = parser.add_argument_group("AI Review Options")
    ai_group.add_argument(
        "--ai-review",
        action="store_true",
        help="AI 기반 코드 리뷰 활성화",
    )
    ai_group.add_argument(
        "--openai-api-key",
        help="OpenAI API 키",
    )
    ai_group.add_argument(
        "--anthropic-api-key",
        help="Anthropic API 키",
    )

    # 출력 옵션
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--severity-threshold",
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
        help="실패 기준 심각도 (기본: high)",
    )
    output_group.add_argument(
        "--sarif",
        dest="sarif_output",
        metavar="FILE",
        help="SARIF 출력 파일",
    )
    output_group.add_argument(
        "--json",
        dest="json_output",
        metavar="FILE",
        help="JSON 출력 파일",
    )
    output_group.add_argument(
        "--no-fail",
        action="store_true",
        help="취약점 발견 시에도 실패하지 않음",
    )

    # 기타 옵션
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="설정 파일 경로",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="스캐너 병렬 실행",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="상세 출력",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="최소 출력",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    return parser.parse_args()


def main() -> int:
    """CLI 메인 함수"""
    args = parse_args()

    # 환경 변수 설정
    workspace = os.path.abspath(args.path)
    os.environ["GITHUB_WORKSPACE"] = workspace
    os.environ["INPUT_SECRET_SCAN"] = str(args.secret_scan).lower()
    os.environ["INPUT_CODE_SCAN"] = str(args.code_scan).lower()
    os.environ["INPUT_DEPENDENCY_SCAN"] = str(args.dependency_scan).lower()
    os.environ["INPUT_AI_REVIEW"] = str(args.ai_review).lower()
    os.environ["INPUT_SEVERITY_THRESHOLD"] = args.severity_threshold
    os.environ["INPUT_FAIL_ON_FINDINGS"] = str(not args.no_fail).lower()

    if args.openai_api_key:
        os.environ["INPUT_OPENAI_API_KEY"] = args.openai_api_key
        os.environ["OPENAI_API_KEY"] = args.openai_api_key
    if args.anthropic_api_key:
        os.environ["INPUT_ANTHROPIC_API_KEY"] = args.anthropic_api_key
        os.environ["ANTHROPIC_API_KEY"] = args.anthropic_api_key
    if args.sarif_output:
        os.environ["INPUT_SARIF_OUTPUT"] = args.sarif_output
    if args.config:
        os.environ["INPUT_CONFIG_PATH"] = args.config

    # 메인 모듈 임포트 및 실행
    try:
        from main import main as run_main

        return run_main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        return 130
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
