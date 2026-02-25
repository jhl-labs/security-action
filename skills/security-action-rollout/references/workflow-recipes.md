# Workflow Recipes

## 1) private-report (default)

```yaml
name: Security Scan

on:
  pull_request:
    branches: [main]
    types: [opened, synchronize, reopened]
  push:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: write
      statuses: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        uses: jhl-labs/security-action@main
        with:
          secret-scan: 'true'
          code-scan: 'true'
          dependency-scan: 'true'
          severity-threshold: 'high'
          fail-on-findings: 'false'
          upload-sarif: 'false'
          fail-on-sarif-upload-error: 'false'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## 2) pr-gate (blocking)

```yaml
name: PR Security Gate

on:
  pull_request:
    branches: [main]
    types: [opened, synchronize, reopened]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: write
      statuses: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        uses: jhl-labs/security-action@main
        with:
          secret-scan: 'true'
          code-scan: 'true'
          dependency-scan: 'true'
          severity-threshold: 'high'
          fail-on-findings: 'true'
          upload-sarif: 'false'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## 3) self-hosted-report

```yaml
name: Security Scan (Self-hosted)

on:
  pull_request:
    branches: [main]
    types: [opened, synchronize, reopened]
  push:
    branches: [main]

jobs:
  security:
    runs-on: [self-hosted, linux, jhl-space]
    permissions:
      contents: read
      checks: write
      statuses: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        uses: jhl-labs/security-action@main
        with:
          secret-scan: 'true'
          code-scan: 'true'
          dependency-scan: 'true'
          severity-threshold: 'high'
          fail-on-findings: 'false'
          upload-sarif: 'false'
          parallel: 'false'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Optional blocks

### Enable AI review

```yaml
          ai-review: 'true'
          ai-provider: 'openai'
          ai-model: ${{ secrets.AI_MODEL }}
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          openai-base-url: ${{ secrets.OPENAI_BASE_URL }}
```

### Enable SonarQube

```yaml
          sonar-scan: 'true'
          sonar-host-url: ${{ secrets.SONAR_HOST_URL }}
          sonar-token: ${{ secrets.SONAR_TOKEN }}
          sonar-project-key: 'my-project'
```

### Enable SARIF upload

When enabling this, add `security-events: write` permission.

```yaml
    permissions:
      contents: read
      checks: write
      statuses: write
      pull-requests: write
      security-events: write
```

```yaml
          upload-sarif: 'true'
          sarif-category: 'security-action'
          fail-on-sarif-upload-error: 'false'
```
