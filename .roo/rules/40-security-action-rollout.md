Use the `security-action-rollout` skill when users ask to add or tune `jhl-labs/security-action` workflows.

Default for private repos:
- report-only mode (`fail-on-findings: 'false'`)
- `upload-sarif: 'false'`

Always collect missing inputs interactively:
- runner labels
- gate vs report mode
- triggers/branches
- optional AI/Sonar settings and secret names
