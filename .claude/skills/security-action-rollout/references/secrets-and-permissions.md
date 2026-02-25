# Secrets and Permissions

## Required Secret

- `GITHUB_TOKEN`

## Optional Secrets

### AI review (OpenAI-compatible)

- `AI_MODEL`
- `OPENAI_API_KEY`
- `OPENAI_BASE_URL`

### SonarQube

- `SONAR_HOST_URL`
- `SONAR_TOKEN`
- (optional) `SONAR_PROJECT_KEY` if not hardcoded in workflow

## Minimum Permissions Baseline

Use this baseline when check runs / PR review comment outputs are needed:

```yaml
permissions:
  contents: read
  checks: write
  statuses: write
  pull-requests: write
```

## Additional Permission for SARIF Upload

If `upload-sarif: 'true'` is enabled:

```yaml
permissions:
  security-events: write
```

## Practical Policy

- Private/GHES default: `upload-sarif: 'false'`
- Public or licensed environment: enable SARIF upload only when requested
- If SARIF upload is optional, keep `fail-on-sarif-upload-error: 'false'`
