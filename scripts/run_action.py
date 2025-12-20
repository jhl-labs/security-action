#!/usr/bin/env python3
"""
로컬 환경에서 Security Action 실행
Docker 없이 직접 스캐너를 실행하여 테스트
"""

import os
import sys

# 프로젝트 루트를 Python 경로에 추가
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(project_root, "src"))

# 환경 변수 설정 (기본값)
os.environ.setdefault("INPUT_SECRET_SCAN", "true")
os.environ.setdefault("INPUT_CODE_SCAN", "true")
os.environ.setdefault("INPUT_DEPENDENCY_SCAN", "true")
os.environ.setdefault("INPUT_AI_REVIEW", "false")
os.environ.setdefault("INPUT_SEVERITY_THRESHOLD", "high")
os.environ.setdefault("INPUT_FAIL_ON_FINDINGS", "false")  # 테스트 시 실패 방지

if __name__ == "__main__":
    # 대상 디렉토리 설정
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]
    else:
        target_dir = os.path.join(project_root, "tests", "fixtures", "vulnerable_samples")

    os.environ["GITHUB_WORKSPACE"] = target_dir
    print(f"Scanning: {target_dir}\n")

    # main 모듈 실행
    from main import main
    exit_code = main()
    sys.exit(exit_code)
