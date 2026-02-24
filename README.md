# Security Scanner Action

GitHub Advanced Security 기능을 오픈소스 도구들로 구현한 통합 보안 스캐너 GitHub Action입니다.

## 주요 기능

| 기능 | 도구 | 설명 |
|------|------|------|
| **Secret Scanning** | [Gitleaks](https://github.com/gitleaks/gitleaks) | API 키, 비밀번호, 토큰 등 민감 정보 탐지 (Git history 포함) |
| **Code Scanning (SAST)** | [Semgrep](https://github.com/semgrep/semgrep) | 정적 코드 분석, OWASP Top 10 취약점 탐지 |
| **Dependency Scanning (SCA)** | [Trivy](https://github.com/aquasecurity/trivy) | 의존성 취약점 (CVE) 탐지 |
| **Container Scanning** | [Trivy](https://github.com/aquasecurity/trivy) | 컨테이너 이미지 취약점 및 Dockerfile 스캔 |
| **IaC Scanning** | [Checkov](https://github.com/bridgecrewio/checkov) | Terraform, K8s, CloudFormation, Dockerfile 보안 스캔 |
| **SBOM Generation** | [Syft](https://github.com/anchore/syft) | Software Bill of Materials 생성 (CycloneDX/SPDX) |
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
          upload-sarif: 'false'  # Private repo 기본 권장
          sarif-category: 'security-action'

          # GitHub 연동
          github-token: ${{ secrets.GITHUB_TOKEN }}

      # 결과 요약 출력
      - name: Security Summary
        if: always()
        run: |
          echo "총 발견: ${{ steps.security.outputs.findings-count }}"
          echo "Critical: ${{ steps.security.outputs.critical-count }}"
          echo "High: ${{ steps.security.outputs.high-count }}"
```

## 입력 옵션

### 기본 스캐너

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `secret-scan` | `true` | Gitleaks를 사용한 비밀값 스캔 활성화 |
| `secret-scan-history` | `false` | Git commit history 전체 스캔 (과거 유출 탐지) |
| `code-scan` | `true` | Semgrep을 사용한 코드 취약점 스캔 활성화 |
| `dependency-scan` | `true` | Trivy를 사용한 의존성 취약점 스캔 활성화 |

### 추가 스캐너

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `container-scan` | `false` | 컨테이너 이미지 취약점 스캔 (Trivy) |
| `container-image` | - | 스캔할 컨테이너 이미지 (예: `nginx:latest`) |
| `iac-scan` | `false` | IaC 보안 스캔 (Checkov) |
| `iac-frameworks` | - | IaC 프레임워크 (예: `terraform,kubernetes`) |

### SBOM 생성

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `sbom-generate` | `false` | SBOM 생성 활성화 (Syft) |
| `sbom-format` | `cyclonedx-json` | 출력 포맷 (`cyclonedx-json`, `spdx-json`, `syft-json`) |
| `sbom-output` | `sbom.json` | SBOM 출력 파일 경로 |

### SonarQube 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `sonar-scan` | `false` | SonarQube 코드 품질 스캔 활성화 |
| `sonar-host-url` | `http://localhost:9000` | SonarQube 서버 URL |
| `sonar-token` | - | SonarQube 인증 토큰 |
| `sonar-project-key` | - | SonarQube 프로젝트 키 |

### AI Review 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `ai-review` | `false` | AI 기반 코드 리뷰 활성화 |
| `ai-provider` | `auto` | AI 제공자 (`auto`, `openai`, `anthropic`) |
| `ai-model` | - | AI 모델명 (예: `gpt-4o`) |
| `openai-api-key` | - | OpenAI API 키 |
| `openai-base-url` | - | OpenAI 호환 API Base URL |
| `anthropic-api-key` | - | Anthropic API 키 (대안) |

### 공통 설정

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `severity-threshold` | `high` | 워크플로우 실패 기준 심각도 |
| `fail-on-findings` | `true` | 취약점 발견 시 워크플로우 실패 처리 |
| `sarif-output` | `security-results.sarif` | SARIF 결과 파일 경로 |
| `upload-sarif` | `false` | 생성한 SARIF를 GitHub Security(Code Scanning)에 직접 업로드 |
| `sarif-category` | `security-action` | SARIF 카테고리(runAutomationDetails.id) |
| `fail-on-sarif-upload-error` | `false` | SARIF 업로드 실패 시 워크플로우 실패 처리 |
| `usage-tracking` | `false` | 사용량 로그 출력(외부 전송 없음) |
| `github-token` | `${{ github.token }}` | GitHub API 토큰 |
| `config-path` | - | 커스텀 설정 파일 경로 |

## 출력 값

| 출력 | 설명 |
|------|------|
| `scan-results` | 전체 스캔 결과 JSON |
| `findings-count` | 발견된 총 취약점 수 |
| `critical-count` | Critical 심각도 취약점 수 |
| `high-count` | High 심각도 취약점 수 |
| `sarif-file` | SARIF 결과 파일 경로 |
| `sarif-upload-id` | GitHub Code Scanning SARIF 업로드 ID |
| `sbom-file` | SBOM 결과 파일 경로 |

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
          ai-provider: 'openai'
          ai-model: ${{ secrets.AI_MODEL }}
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          openai-base-url: ${{ secrets.OPENAI_BASE_URL }}
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

SARIF 결과를 GitHub Security 탭에 표시하면 다음과 같은 이점이 있습니다:
- **Code Scanning Alerts**: Security 탭에서 취약점 관리
- **PR 차단**: Branch protection rules와 연동
- **이력 추적**: 시간에 따른 취약점 변화 확인

### 설정 방법

```yaml
name: Security Scan with GitHub Security Integration

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # 필수: SARIF 업로드 권한

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Security Scan
        uses: jhl-labs/security-action@main
        with:
          sarif-output: 'security-results.sarif'
          upload-sarif: 'true'  # Public 또는 Private+GHAS에서 사용
          sarif-category: 'security-scanner'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### 주의사항

- **Public 리포지토리**: Code Scanning은 무료
- **Private 리포지토리**: GitHub Advanced Security 라이선스 필요
- `security-events: write` 권한 필수
- 별도 `github/codeql-action/upload-sarif` step 없이 `upload-sarif: 'true'`로 업로드 가능

## Self-hosted Runner 가이드

Self-hosted/GHES 환경에서 GHAS 수준의 워크플로우를 맞추려면 아래 설정을 권장합니다.

```yaml
jobs:
  security:
    runs-on: [self-hosted, linux]
    permissions:
      contents: read
      security-events: write
      checks: write
      statuses: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: jhl-labs/security-action@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          upload-sarif: 'false' # Private/GHES 기본. 라이선스/정책 준비 시 true 권장
          sarif-category: 'security-action-selfhosted'
          fail-on-sarif-upload-error: 'false'
```

- `GITHUB_API_URL` 환경이 자동 감지되어 GHES API로 연동됩니다.
- 외부 텔레메트리 스크립트 실행 없이 동작합니다.

## 추가 시나리오

### 5. 컨테이너 이미지 스캔

```yaml
name: Container Security Scan

on:
  push:
    paths:
      - 'Dockerfile'
      - 'docker-compose.yml'

jobs:
  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker Image
        run: docker build -t my-app:${{ github.sha }} .

      - name: Scan Container Image
        uses: jhl-labs/security-action@main
        with:
          container-scan: 'true'
          container-image: 'my-app:${{ github.sha }}'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### 6. IaC (Terraform/Kubernetes) 스캔

```yaml
name: IaC Security Scan

on:
  push:
    paths:
      - '**/*.tf'
      - '**/*.yaml'
      - '**/*.yml'

jobs:
  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan IaC Files
        uses: jhl-labs/security-action@main
        with:
          secret-scan: 'false'
          code-scan: 'false'
          dependency-scan: 'false'
          iac-scan: 'true'
          iac-frameworks: 'terraform,kubernetes,dockerfile'
          severity-threshold: 'high'
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### 7. SBOM 생성 및 저장

```yaml
name: Generate SBOM

on:
  release:
    types: [published]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        uses: jhl-labs/security-action@main
        with:
          secret-scan: 'false'
          code-scan: 'false'
          dependency-scan: 'true'
          sbom-generate: 'true'
          sbom-format: 'cyclonedx-json'
          sbom-output: 'sbom-${{ github.ref_name }}.json'
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload SBOM as Release Asset
        uses: softprops/action-gh-release@v1
        with:
          files: sbom-${{ github.ref_name }}.json
```

### 8. 전체 기능 활성화 (종합 보안 스캔)

```yaml
name: Comprehensive Security Scan

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # 매주 월요일 새벽 2시

jobs:
  full-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # 전체 히스토리

      - name: Full Security Scan
        uses: jhl-labs/security-action@main
        with:
          # 기본 스캐너
          secret-scan: 'true'
          secret-scan-history: 'true'  # Git 히스토리 포함
          code-scan: 'true'
          dependency-scan: 'true'
          # 추가 스캐너
          container-scan: 'true'
          iac-scan: 'true'
          # SBOM 생성
          sbom-generate: 'true'
          sbom-format: 'cyclonedx-json'
          # 공통 설정
          severity-threshold: 'medium'
          fail-on-findings: 'false'  # 리포팅만
          sarif-output: 'security-results.sarif'
          upload-sarif: 'false'  # Private 기본값. Security 탭 업로드가 필요하면 true
          github-token: ${{ secrets.GITHUB_TOKEN }}
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

---

## 부록 (Appendix)

### 부록 A: 보안 스캔 도구 상세

보안을 처음 접하는 개발자를 위해 각 도구의 역할과 작동 방식을 상세히 설명합니다.

#### 1. Gitleaks (Secret Scanner)

**목적**: Git 저장소에서 API 키, 비밀번호, 토큰 등 민감 정보를 탐지합니다.

**작동 방식**:
- 정규표현식 기반 패턴 매칭
- 엔트로피 분석 (무작위 문자열 탐지)
- Git 히스토리 전체 검사 가능 (과거 커밋에서 삭제된 시크릿도 탐지)

**탐지 대상 예시**:
- AWS Access Key / Secret Key
- GitHub Personal Access Token
- Slack Webhook URL
- RSA/SSH 개인키
- 데이터베이스 비밀번호 패턴

**왜 중요한가?**
- 실수로 커밋된 비밀키가 GitHub에 공개되면 수 분 내에 해커에게 발견됩니다
- 삭제해도 Git 히스토리에 남아있어 여전히 노출됩니다
- AWS 키 유출 시 수백만원의 요금 폭탄 사례가 실제로 발생합니다

#### 2. Semgrep (Code Scanner / SAST)

**목적**: 소스코드의 보안 취약점 및 버그를 실행 없이 탐지합니다.

**작동 방식**:
- AST(추상 구문 트리) 기반 의미론적 패턴 매칭
- 단순 텍스트 검색이 아닌 코드 구조를 이해
- 2,000개 이상의 사전 정의된 규칙 제공

**탐지 대상 예시**:
- SQL Injection (`"SELECT * FROM users WHERE id = " + user_input`)
- XSS (Cross-Site Scripting)
- 하드코딩된 자격증명
- 안전하지 않은 역직렬화
- 경로 탐색(Path Traversal) 취약점

**왜 중요한가?**
- OWASP Top 10 취약점의 대부분을 개발 단계에서 발견 가능
- 코드 리뷰에서 놓칠 수 있는 보안 이슈를 자동으로 탐지
- 배포 전에 취약점을 수정하면 비용이 100배 이상 절감됩니다

#### 3. Trivy (Dependency & Container Scanner / SCA)

**목적**: 의존성 패키지 및 컨테이너 이미지의 알려진 취약점(CVE)을 탐지합니다.

**작동 방식**:
- 취약점 데이터베이스(NVD, GitHub Advisory 등)와 비교
- 패키지 버전별 알려진 취약점 매칭
- 취약점에 대한 수정 버전 정보 제공

**지원 대상**:
| 유형 | 지원 항목 |
|------|----------|
| 패키지 매니저 | npm, pip, Maven, Go modules, Cargo, Bundler 등 |
| 컨테이너 | Docker 이미지, OS 패키지 (Alpine, Debian, Ubuntu 등) |
| IaC | Terraform, Kubernetes YAML, Dockerfile |

**왜 중요한가?**
- 현대 애플리케이션의 80% 이상이 오픈소스 라이브러리로 구성됩니다
- Log4Shell(CVE-2021-44228)처럼 하나의 라이브러리 취약점이 전 세계를 마비시킬 수 있습니다
- 의존성 취약점은 공급망 공격(Supply Chain Attack)의 주요 경로입니다

#### 4. Checkov (IaC Scanner)

**목적**: Infrastructure as Code 파일의 보안 설정 오류를 탐지합니다.

**작동 방식**:
- 사전 정의된 정책(Policy as Code)으로 검사
- 클라우드 보안 모범 사례와 비교
- CIS 벤치마크, SOC2 등 컴플라이언스 체크

**지원 프레임워크**:
- Terraform (AWS, GCP, Azure)
- CloudFormation
- Kubernetes YAML
- Dockerfile
- GitHub Actions

**탐지 예시**:
- S3 버킷 공개 접근 설정
- 암호화 미설정 (RDS, EBS, S3 등)
- 과도한 IAM 권한 (`*:*`)
- 보안 그룹에서 0.0.0.0/0 허용

**왜 중요한가?**
- 클라우드 보안 사고의 90%가 설정 오류에서 발생합니다
- 코드로 인프라를 관리하면 설정 오류도 코드 리뷰로 방지할 수 있습니다
- 배포 전에 발견하면 실제 인프라 노출 위험을 제거합니다

#### 5. Syft (SBOM Generator)

**목적**: 프로젝트에 포함된 모든 소프트웨어 구성요소 목록(SBOM)을 생성합니다.

**출력 포맷**:
- CycloneDX (OWASP 표준)
- SPDX (Linux Foundation 표준)

**생성되는 정보**:
- 패키지 이름 및 버전
- 라이선스 정보
- 의존성 관계
- 파일 해시

**왜 중요한가?**
- 미국 정부 납품 소프트웨어는 SBOM 제출이 의무입니다 (행정명령 14028)
- 취약점 발생 시 영향받는 시스템을 빠르게 파악할 수 있습니다
- 라이선스 컴플라이언스 확인에 필수입니다

#### 6. SonarQube (Deep SAST + Code Quality)

**목적**: 심층 정적 분석과 코드 품질 측정을 동시에 수행합니다.

**특징**:
- 데이터 흐름 분석 (변수가 어디서 어디로 흐르는지 추적)
- 오염 분석(Taint Analysis): 사용자 입력이 위험한 함수에 도달하는지 추적
- Security Hotspot: 자동 판단 불가, 개발자 검토 필요한 코드 표시

**추가 기능**:
- 코드 스멜 (유지보수 어려운 코드)
- 중복 코드 탐지
- 기술 부채 측정
- 테스트 커버리지

**왜 중요한가?**
- Semgrep보다 더 깊은 분석이 필요할 때 사용합니다
- 보안과 코드 품질을 한 번에 관리할 수 있습니다
- 기업 환경에서 품질 게이트로 활용 가능합니다

---

### 부록 B: 보안 용어 사전

#### 스캔 방식

| 용어 | 전체 명칭 | 설명 |
|------|----------|------|
| **SAST** | Static Application Security Testing | 소스코드를 실행하지 않고 분석하는 정적 보안 테스트. 개발 초기에 취약점 발견 가능. Semgrep, SonarQube가 해당 |
| **DAST** | Dynamic Application Security Testing | 실행 중인 애플리케이션을 외부에서 테스트하는 동적 보안 테스트. OWASP ZAP이 대표적 |
| **SCA** | Software Composition Analysis | 오픈소스/서드파티 라이브러리의 취약점과 라이선스 분석. Trivy가 해당 |
| **IAST** | Interactive Application Security Testing | SAST + DAST 결합, 런타임에서 코드 내부 분석. 에이전트 설치 필요 |

#### 취약점 식별 체계

| 용어 | 전체 명칭 | 설명 |
|------|----------|------|
| **CVE** | Common Vulnerabilities and Exposures | 공개된 보안 취약점의 고유 식별자. 예: CVE-2021-44228 (Log4Shell) |
| **CWE** | Common Weakness Enumeration | 취약점 유형 분류 체계. 예: CWE-89 (SQL Injection), CWE-79 (XSS) |
| **CVSS** | Common Vulnerability Scoring System | 취약점 심각도 점수 (0.0~10.0). 7.0 이상이면 High/Critical |
| **NVD** | National Vulnerability Database | 미국 NIST가 운영하는 취약점 데이터베이스 |

#### 보안 표준 및 프레임워크

| 용어 | 설명 |
|------|------|
| **OWASP** | Open Web Application Security Project. 웹 보안 비영리 재단 |
| **OWASP Top 10** | 가장 위험한 웹 취약점 10가지 목록. 3~4년마다 갱신. Injection, Broken Auth, XSS 등 포함 |
| **SARIF** | Static Analysis Results Interchange Format. 정적 분석 결과를 표현하는 표준 JSON 포맷. GitHub Security 탭과 호환 |
| **SBOM** | Software Bill of Materials. 소프트웨어에 포함된 모든 구성요소 목록. 식품의 성분표와 유사한 개념 |
| **CIS Benchmark** | Center for Internet Security에서 제공하는 보안 구성 가이드라인 |

#### 기타 주요 용어

| 용어 | 설명 |
|------|------|
| **IaC** | Infrastructure as Code. 인프라를 코드로 관리 (Terraform, K8s YAML 등) |
| **Security Hotspot** | 자동으로 취약점 여부 판단 불가, 개발자가 수동 검토해야 하는 코드 영역 |
| **False Positive** | 오탐. 취약점이 아닌데 취약점으로 잘못 탐지된 경우 |
| **True Positive** | 정탐. 실제 취약점이 정확히 탐지된 경우 |
| **Zero-Day** | 패치가 아직 없는 신규 취약점. 공개되면 즉시 공격에 악용될 위험 |
| **Supply Chain Attack** | 공급망 공격. 의존성 패키지를 통한 공격. event-stream, ua-parser-js 사건이 대표적 |
| **Exploit** | 취약점을 실제로 악용하는 공격 코드 또는 기법 |
| **CVE PoC** | 취약점 개념 증명 코드. 공개되면 공격 위험이 급격히 증가 |

---

### 부록 C: 심각도 수준 가이드

#### 심각도 분류표

| 수준 | CVSS 점수 | 설명 | 권장 대응 시간 |
|------|----------|------|---------------|
| 🔴 **Critical** | 9.0~10.0 | 즉시 악용 가능, 시스템 전체 장악 또는 대규모 데이터 유출 위험 | 즉시 (24시간 내) |
| 🟠 **High** | 7.0~8.9 | 심각한 데이터 유출 또는 서비스 중단 가능 | 1주일 내 |
| 🟡 **Medium** | 4.0~6.9 | 제한된 조건에서 악용 가능, 부분적 영향 | 1개월 내 |
| 🔵 **Low** | 0.1~3.9 | 악용 어려움, 영향 범위 제한적 | 다음 릴리스 |
| ⚪ **Info** | 0.0 | 정보성 알림, 직접적 보안 영향 없음 | 선택적 |

#### 심각도 결정 요소 (CVSS 기준)

| 요소 | 설명 | 점수 영향 |
|------|------|----------|
| **공격 벡터** | 네트워크/인접/로컬/물리적 접근 필요 여부 | 네트워크 > 로컬 |
| **공격 복잡도** | 얼마나 쉽게 악용할 수 있는가 | 낮음 > 높음 |
| **권한 요구** | 공격에 인증/권한이 필요한가 | 불필요 > 높은 권한 |
| **사용자 상호작용** | 피해자의 동작이 필요한가 | 불필요 > 필요 |
| **영향 범위** | 기밀성/무결성/가용성 중 어떤 것이 영향받는가 | 3가지 모두 > 일부 |

#### 실제 대응 예시

| 상황 | 권장 조치 |
|------|----------|
| Critical CVE + Exploit 공개 | 즉시 패치 또는 서비스 일시 중단 검토 |
| High 취약점 + 인터넷 노출 서비스 | 1주일 내 패치, 임시 WAF 규칙 적용 |
| Medium 취약점 + 내부 시스템 | 정기 패치 주기에 포함 |
| Low 취약점 | 다음 릴리스에 포함, 모니터링 |

#### 이 Action에서의 활용

```yaml
# Critical/High만 차단 (권장)
severity-threshold: 'high'
fail-on-findings: 'true'

# 모든 이슈 리포팅 (감사용)
severity-threshold: 'low'
fail-on-findings: 'false'
```
