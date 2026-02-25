# Intake

Collect required values in this order.

## Required Questions

1. Target scope
- Single repo or multiple repos?
- If multiple, ask for repo list.

2. Runner
- `ubuntu-latest` or self-hosted labels?
- If self-hosted, ask labels exactly (example: `self-hosted,linux,jhl-space`).

3. Policy mode
- `report` (non-blocking) or `gate` (blocking)?

4. SARIF upload
- Enable GitHub Security upload?
- Default `false` for private/GHES unless user explicitly opts in.

5. Triggers
- `pull_request`, `push`, `schedule`, `workflow_dispatch` 중 무엇을 사용할지.
- If `push` or `pull_request`, ask target branch (default `main`).

6. Optional integrations
- AI review 사용 여부와 secret names
- SonarQube 사용 여부와 secret names
- Native audit / container / IaC / SBOM 사용 여부

## Default Profile (when user says "알아서")

- Profile: `private-report`
- `runs-on`: `ubuntu-latest`
- Events: `pull_request` + `push` on `main`
- `severity-threshold`: `high`
- `fail-on-findings`: `false`
- `upload-sarif`: `false`
- `fail-on-sarif-upload-error`: `false`
- `parallel`: `false`
- `scanner-checks`: `false`
- `post-summary`: `true`
- Enabled scanners: secret/code/dependency only
- AI review: disabled
- SonarQube: disabled

## Fast Confirmation Template

Use this after intake before editing files:

```text
확인할 설정입니다.
- Runner: <runs-on>
- Mode: <report|gate>
- upload-sarif: <true|false>
- Triggers: <...>
- Optional: <ai/sonar/native/container/iac/sbom>
이대로 적용할까요?
```
