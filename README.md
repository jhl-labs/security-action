# Security Scanner Action

GitHub Advanced Security 기능을 오픈소스 도구들로 구현한 통합 보안 스캐너 GitHub Action입니다.

## 주요 기능

| 기능 | 도구 | 설명 |
|------|------|------|
| **Secret Scanning** | [Gitleaks](https://github.com/gitleaks/gitleaks) | API 키, 비밀번호, 토큰 등 민감 정보 탐지 |
| **Code Scanning (SAST)** | [Semgrep](https://github.com/semgrep/semgrep) | 정적 코드 분석, OWASP Top 10 취약점 탐지 |
| **Dependency Scanning (SCA)** | [Trivy](https://github.com/aquasecurity/trivy) | 의존성 취약점 (CVE) 탐지 |
| **Code Quality** | [SonarQube](https://www.sonarsource.com/products/sonarqube/) | 심층 SAST, 코드 품질, Security Hotspot |
| **AI Code Review** | [LangGraph](https://github.com/langchain-ai/langgraph) | AI 기반 보안 코드 리뷰 및 수정 제안 |

## 빠른 시작

### 기본 사용법

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        uses: jhl-labs/security-action@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

이 설정만으로 **Secret Scanning**, **Code Scanning**, **Dependency Scanning**이 모두 활성화됩니다.

## 상세 설정

### 모든 옵션 사용 예시

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 9 * * 1'  # 매주 월요일 오전 9시

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # SARIF 업로드용
      pull-requests: write    # PR 코멘트용

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # 전체 히스토리 (secret scanning에 권장)

      - name: Run Security Scan
        id: security
        uses: jhl-labs/security-action@main
        with:
          # 스캐너 활성화/비활성화
          secret-scan: 'true'
          code-scan: 'true'
          dependency-scan: 'true'
          sonar-scan: 'false'
          ai-review: 'false'

          # 심각도 설정
          severity-threshold: 'high'  # critical, high, medium, low
          fail-on-findings: 'true'

          # 출력 설정
          sarif-output: 'security-results.sarif'

          # GitHub 연동
          github-token: ${{ secrets.GITHUB_TOKEN }}

      # SARIF 결과를 GitHub Security 탭에 업로드
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-results.sarif

      # 결과 요약 출력
      - name: Security Summary
        if: always()
        run: |
          echo "총 발견: ${{ steps.security.outputs.findings-count }}"
          echo "Critical: ${{ steps.security.outputs.critical-count }}"
          echo "High: ${{ steps.security.outputs.high-count }}"
```

## 입력 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `secret-scan` | `true` | Gitleaks를 사용한 비밀값 스캔 활성화 |
| `code-scan` | `true` | Semgrep을 사용한 코드 취약점 스캔 활성화 |
| `dependency-scan` | `true` | Trivy를 사용한 의존성 취약점 스캔 활성화 |
| `sonar-scan` | `false` | SonarQube 코드 품질 스캔 활성화 |
| `ai-review` | `false` | AI 기반 코드 리뷰 활성화 |
| `severity-threshold` | `high` | 워크플로우 실패 기준 심각도 |
| `fail-on-findings` | `true` | 취약점 발견 시 워크플로우 실패 처리 |
| `sarif-output` | `security-results.sarif` | SARIF 결과 파일 경로 |
| `github-token` | `${{ github.token }}` | GitHub API 토큰 |
| `config-path` | - | 커스텀 설정 파일 경로 |

### SonarQube 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `sonar-host-url` | `http://localhost:9000` | SonarQube 서버 URL |
| `sonar-token` | - | SonarQube 인증 토큰 |
| `sonar-project-key` | - | SonarQube 프로젝트 키 |

### AI Review 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `openai-api-key` | - | OpenAI API 키 |
| `anthropic-api-key` | - | Anthropic API 키 (대안) |

## 출력 값

| 출력 | 설명 |
|------|------|
| `scan-results` | 전체 스캔 결과 JSON |
| `findings-count` | 발견된 총 취약점 수 |
| `critical-count` | Critical 심각도 취약점 수 |
| `high-count` | High 심각도 취약점 수 |
| `sarif-file` | SARIF 결과 파일 경로 |

## 사용 시나리오

### 1. PR에서만 스캔 (빠른 피드백)

```yaml
name: PR Security Check

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jhl-labs/security-action@main
        with:
          secret-scan: 'true'
          code-scan: 'true'
          dependency-scan: 'false'  # 속도를 위해 비활성화
          severity-threshold: 'critical'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### 2. 전체 스캔 (정기 실행)

```yaml
name: Full Security Audit

on:
  schedule:
    - cron: '0 2 * * *'  # 매일 새벽 2시
  workflow_dispatch:  # 수동 실행 허용

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: jhl-labs/security-action@main
        with:
          secret-scan: 'true'
          code-scan: 'true'
          dependency-scan: 'true'
          severity-threshold: 'low'  # 모든 이슈 보고
          fail-on-findings: 'false'  # 실패하지 않음
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### 3. SonarQube 통합

```yaml
name: Security + Quality Scan

on: [push]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: jhl-labs/security-action@main
        with:
          secret-scan: 'true'
          code-scan: 'true'
          dependency-scan: 'true'
          sonar-scan: 'true'
          sonar-host-url: ${{ secrets.SONAR_HOST_URL }}
          sonar-token: ${{ secrets.SONAR_TOKEN }}
          sonar-project-key: 'my-project'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### 4. AI 코드 리뷰 활성화

```yaml
name: AI Security Review

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: jhl-labs/security-action@main
        with:
          secret-scan: 'true'
          code-scan: 'true'
          dependency-scan: 'true'
          ai-review: 'true'
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          # 또는 anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## 커스텀 설정 파일

프로젝트 루트에 `.security-action.yml` 파일을 생성하여 상세 설정을 할 수 있습니다.

```yaml
# .security-action.yml
version: "1.0"

# Gitleaks 설정
gitleaks:
  enabled: true
  severity_threshold: low
  exclude_patterns:
    - "**/test*/**"
    - "**/testdata/**"

# Semgrep 설정
semgrep:
  enabled: true
  severity_threshold: medium
  rulesets:
    - auto
    - p/security-audit
    - p/owasp-top-ten
  exclude_rules:
    - "generic.secrets.security.detected-generic-secret"

# Trivy 설정
trivy:
  enabled: true
  severity_threshold: medium
  ignore_unfixed: false

# SonarQube 설정
sonarqube:
  enabled: false
  host_url: http://localhost:9000
  quality_gate_wait: false

# AI 리뷰 설정
ai_review:
  enabled: false
  provider: openai
  model: gpt-4o
  max_findings: 20

# 오탐(False Positive) 관리
false_positives:
  - id: ignore-test-secrets
    pattern: "**/test*/**"
    rule_id: ".*secret.*"
    reason: "Test files contain fake secrets"

  - id: ignore-example-config
    pattern: "**/example-*"
    reason: "Example configuration files"

# 전역 제외 패턴
global_excludes:
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/.git/**"
  - "**/dist/**"
  - "**/build/**"
```

설정 파일 사용:

```yaml
- uses: jhl-labs/security-action@main
  with:
    config-path: '.security-action.yml'
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

## GitHub Security 탭 연동

SARIF 결과를 GitHub Security 탭에 표시하려면:

```yaml
- name: Run Security Scan
  uses: jhl-labs/security-action@main
  with:
    sarif-output: 'results.sarif'
    github-token: ${{ secrets.GITHUB_TOKEN }}

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

## 지원 언어

| 스캐너 | 지원 언어 |
|--------|-----------|
| **Gitleaks** | 모든 텍스트 파일 (언어 무관) |
| **Semgrep** | Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, C, C++, Kotlin, Swift, Rust 등 |
| **Trivy** | Python (pip), Node.js (npm/yarn), Go, Java (Maven/Gradle), Ruby (Bundler), PHP (Composer), .NET (NuGet) 등 |
| **SonarQube** | Python, JavaScript, TypeScript, Java, C#, Go, PHP, Ruby, Kotlin, Scala 등 |

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

### 사용 도구 라이선스

| 도구 | 라이선스 | 상업적 사용 |
|------|----------|-------------|
| Gitleaks | MIT | ✅ |
| Semgrep OSS | LGPL-2.1 | ✅ |
| Trivy | Apache-2.0 | ✅ |
| SonarQube CE | LGPL-3.0 | ✅ |
| LangGraph | MIT | ✅ |

모든 도구는 **기업 환경에서 무료로 사용 가능**합니다.

## 문제 해결

### 스캔이 너무 오래 걸림

```yaml
# 특정 스캐너만 활성화
secret-scan: 'true'
code-scan: 'true'
dependency-scan: 'false'  # 비활성화
```

### 너무 많은 오탐(False Positive)

`.security-action.yml`에 `false_positives` 규칙을 추가하세요.

### SonarQube 연결 실패

1. `sonar-host-url`이 접근 가능한지 확인
2. `sonar-token`이 올바른지 확인
3. 방화벽/네트워크 설정 확인

## 기여

버그 리포트, 기능 요청, PR을 환영합니다.

## 관련 링크

- [Gitleaks 문서](https://github.com/gitleaks/gitleaks)
- [Semgrep 문서](https://semgrep.dev/docs/)
- [Trivy 문서](https://aquasecurity.github.io/trivy/)
- [SonarQube 문서](https://docs.sonarsource.com/sonarqube/)
- [LangGraph 문서](https://langchain-ai.github.io/langgraph/)
