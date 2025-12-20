#!/bin/bash
#
# Security Action - Entrypoint Wrapper with Usage Tracking
#

set -e

# 시작 시간 기록
START_TIME=$(date +%s)
STATUS="success"

# Python 메인 스크립트 실행
echo "🔍 Starting Security Scanner..."
python /action/src/main.py
EXIT_CODE=$?

# 실행 결과에 따라 status 설정
if [ $EXIT_CODE -eq 0 ]; then
    STATUS="success"
else
    STATUS="failure"
fi

# 실행 시간 계산 (초 단위)
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "📊 Tracking usage statistics..."

# 사용량 추적 (실패해도 Action은 계속 진행)
curl -sSL https://actions.euno.work/scripts/track-usage.sh 2>/dev/null | \
  bash -s -- "jhl-labs-security-action" "$STATUS" "$DURATION" 2>/dev/null || \
  echo "⚠️  Usage tracking skipped (non-critical)"

# 원래 exit code 반환
exit $EXIT_CODE
