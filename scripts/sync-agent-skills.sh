#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_SKILL_DIR="$ROOT_DIR/skills/security-action-rollout"

copy_skill() {
  local target_dir="$1"
  mkdir -p "$target_dir"
  rsync -a --delete --exclude 'agents' "$BASE_SKILL_DIR/" "$target_dir/"
  if [ -f "$target_dir/agents/openai.yaml" ]; then
    rm "$target_dir/agents/openai.yaml"
  fi
  if [ -d "$target_dir/agents" ]; then
    rmdir "$target_dir/agents" 2>/dev/null || true
  fi
}

copy_skill "$ROOT_DIR/.agents/skills/security-action-rollout"
copy_skill "$ROOT_DIR/.claude/skills/security-action-rollout"
copy_skill "$ROOT_DIR/.roo/skills/security-action-rollout"
copy_skill "$ROOT_DIR/.gemini/skills/security-action-rollout"

echo "Synced security-action-rollout skill to .agents/.claude/.roo/.gemini skill directories"
