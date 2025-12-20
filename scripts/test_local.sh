#!/bin/bash
# 로컬 테스트 스크립트
# 사용법: ./scripts/test_local.sh [target_dir]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TARGET_DIR="${1:-$PROJECT_ROOT/tests/fixtures/vulnerable_samples}"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║             🛡️  Security Scanner Local Test               ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Target directory: $TARGET_DIR"
echo ""

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 도구 설치 확인
check_tool() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1 found: $(command -v "$1")"
        return 0
    else
        echo -e "${RED}✗${NC} $1 not found"
        return 1
    fi
}

echo "=== Checking required tools ==="
MISSING_TOOLS=0
check_tool "gitleaks" || MISSING_TOOLS=$((MISSING_TOOLS + 1))
check_tool "semgrep" || MISSING_TOOLS=$((MISSING_TOOLS + 1))
check_tool "trivy" || MISSING_TOOLS=$((MISSING_TOOLS + 1))
echo ""

if [ $MISSING_TOOLS -gt 0 ]; then
    echo -e "${YELLOW}Warning: $MISSING_TOOLS tool(s) missing. Install with:${NC}"
    echo "  - gitleaks: https://github.com/gitleaks/gitleaks#installing"
    echo "  - semgrep: pip install semgrep"
    echo "  - trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    echo ""
fi

# Gitleaks 테스트
echo "=== Running Gitleaks (Secret Scanner) ==="
if command -v gitleaks &> /dev/null; then
    gitleaks detect --source "$TARGET_DIR" --no-git -v || true
else
    echo -e "${YELLOW}Skipped: gitleaks not installed${NC}"
fi
echo ""

# Semgrep 테스트
echo "=== Running Semgrep (Code Scanner) ==="
if command -v semgrep &> /dev/null; then
    semgrep scan --config auto --config p/security-audit "$TARGET_DIR" || true
else
    echo -e "${YELLOW}Skipped: semgrep not installed${NC}"
fi
echo ""

# Trivy 테스트
echo "=== Running Trivy (Dependency Scanner) ==="
if command -v trivy &> /dev/null; then
    trivy fs --scanners vuln "$TARGET_DIR" || true
else
    echo -e "${YELLOW}Skipped: trivy not installed${NC}"
fi
echo ""

echo "=== Test Complete ==="
