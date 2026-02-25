# Security Action Rollout Context

Use the `security-action-rollout` skill for configuring `jhl-labs/security-action` workflows.

Default policy for private repositories:
- `upload-sarif: 'false'`
- report-only mode (`fail-on-findings: 'false'`)

Before generating files, ask for:
1. runner labels
2. blocking vs report mode
3. SARIF upload policy
4. trigger events/branches
5. optional AI/Sonar secret names

Then create/update:
- `.github/workflows/security-check.yaml`
- optional `.security-action.yml`
