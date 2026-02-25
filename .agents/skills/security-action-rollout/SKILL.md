---
name: security-action-rollout
description: Configure and roll out jhl-labs/security-action GitHub Actions workflows across one or many repositories. Use when asked to add or tune security scan workflows, select report-only vs blocking mode, configure self-hosted runners, decide SARIF upload policy, wire optional AI review or SonarQube secrets, and prepare repeatable rollout plans.
---

# Security Action Rollout

Execute rollout in a deterministic order and keep defaults safe for private repositories.

## Workflow

1. Run intake first.
2. Confirm a deployment profile.
3. Generate workflow and optional config artifacts.
4. Validate permissions and expected behavior.
5. Produce rollout checklist for multiple repositories.

Load [references/intake.md](references/intake.md) before asking questions.

## Intake Rules

- Ask only missing required items.
- Ask in the user's language.
- If user says "decide for me", apply defaults from `references/intake.md`.
- Echo final assumptions before writing files.

## Output Contract

Always deliver these outputs when implementing:

1. `.github/workflows/security-check.yaml` (or user-specified path).
2. Optional `.security-action.yml` when user requests false-positive/global exclude management.
3. A short "required secrets" checklist.
4. A short "permissions rationale" list.

For multi-repo rollout, additionally deliver a repo-by-repo plan table (repo, runner, mode, sarif, status).

## Profiles

Use [references/workflow-recipes.md](references/workflow-recipes.md) to choose one profile:

- `private-report`: report-only, `upload-sarif: 'false'`.
- `pr-gate`: PR blocking mode (`fail-on-findings: 'true'`).
- `self-hosted-report`: report-only on custom runner labels.

Use [references/secrets-and-permissions.md](references/secrets-and-permissions.md) for secret and permission requirements.

## Script Usage

Use `scripts/render_workflow.py` when the user wants repeatable generation for many repositories.

Example:

```bash
python skills/security-action-rollout/scripts/render_workflow.py \
  --workflow-name "Security Scan" \
  --job-name security \
  --runs-on "self-hosted,linux,jhl-space" \
  --mode report \
  --upload-sarif false \
  --events "pull_request,push" \
  --target-branch main \
  --output .github/workflows/security-check.yaml
```

If manual editing is requested, use the recipes directly instead of the script.

## Guardrails

- Keep `upload-sarif` default `false` unless user explicitly opts in.
- If `upload-sarif: 'true'`, include `security-events: write` permission.
- Keep report-only mode non-blocking by default (`fail-on-findings: 'false'`).
- Add optional AI/Sonar inputs only when user provides secret names and enables those features.
