#!/bin/bash
#
# Security Action - Entrypoint Wrapper
#

set -uo pipefail

# 시작 시간 기록
START_TIME=$(date +%s)
STATUS="success"
EXIT_CODE=0

# Python 메인 스크립트 실행
echo "🔍 Starting Security Scanner..."
python /action/src/main.py
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    STATUS="failure"
fi

# 실행 결과에 따라 status 설정
if [ $EXIT_CODE -eq 0 ]; then
    STATUS="success"
fi

# 실행 시간 계산 (초 단위)
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# 기업/폐쇄망 self-hosted runner 호환:
# 외부 스크립트 다운로드/실행을 하지 않고 로컬 로그만 남김
if [ "${INPUT_USAGE_TRACKING:-false}" = "true" ]; then
    echo "📊 Usage tracking summary: status=$STATUS duration=${DURATION}s"
    echo "ℹ️ External telemetry is disabled in this build."
fi

# 원래 exit code 반환
exit $EXIT_CODE
