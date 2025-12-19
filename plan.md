# Security Action 구현 계획

## 개요
GitHub Advanced Security 기능을 오픈소스 도구들로 구현하는 GitHub Action

## 핵심 기능

### 1. Secret Scanning (비밀값 노출 탐지)
- **도구**: [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT License)
- **기능**: API 키, 비밀번호, 토큰 등 민감 정보 탐지
- **대안**: TruffleHog (AGPL-3.0, 기업용 주의)

### 2. Code Scanning (보안 취약점 코드 분석)
- **도구**: [Semgrep](https://github.com/semgrep/semgrep) (LGPL-2.1)
- **기능**: SAST(정적 분석), OWASP Top 10 취약점 탐지
- **지원 언어**: Python, JavaScript, TypeScript, Go, Java, Ruby 등

### 3. Dependency Scanning (의존성 취약점 진단)
- **도구**: [Trivy](https://github.com/aquasecurity/trivy) (Apache-2.0)
- **기능**: SCA(Software Composition Analysis), CVE 탐지
- **대안**: OWASP Dependency-Check (Apache-2.0)

### 4. AI 기반 코드 리뷰 (LangGraph Agent)
- **프레임워크**: LangGraph
- **기능**:
  - 보안 관점 코드 리뷰
  - 취약점 설명 및 수정 제안
  - PR 코멘트 자동 생성

## 프로젝트 구조

```
security-action/
├── action.yml                 # GitHub Action 정의
├── Dockerfile                 # 컨테이너 기반 실행
├── src/
│   ├── main.py               # 엔트리포인트
│   ├── scanners/
│   │   ├── secret_scanner.py    # Gitleaks 래퍼
│   │   ├── code_scanner.py      # Semgrep 래퍼
│   │   └── dependency_scanner.py # Trivy 래퍼
│   ├── agent/
│   │   ├── graph.py          # LangGraph 워크플로우
│   │   ├── nodes.py          # Agent 노드들
│   │   └── prompts.py        # 프롬프트 템플릿
│   └── reporters/
│       ├── github_reporter.py # PR 코멘트, Check Run
│       └── sarif_reporter.py  # SARIF 포맷 출력
├── config/
│   ├── semgrep-rules/        # 커스텀 Semgrep 룰
│   └── gitleaks.toml         # Gitleaks 설정
├── tests/
├── requirements.txt
└── README.md
```

## 구현 단계

### Phase 1: 기본 인프라
- [ ] GitHub Action 기본 구조 (action.yml, Dockerfile)
- [ ] 스캐너 도구 설치 및 실행 환경
- [ ] 기본 입출력 처리

### Phase 2: 스캐너 통합
- [ ] Gitleaks 통합 (Secret Scanning)
- [ ] Semgrep 통합 (Code Scanning)
- [ ] Trivy 통합 (Dependency Scanning)
- [ ] 결과 파싱 및 통합

### Phase 3: AI Agent 구현
- [ ] LangGraph 기반 Agent 설계
- [ ] 스캐너 결과 분석 노드
- [ ] 코드 컨텍스트 이해 노드
- [ ] 수정 제안 생성 노드

### Phase 4: 리포팅
- [ ] GitHub PR 코멘트 생성
- [ ] GitHub Check Run 연동
- [ ] SARIF 포맷 출력 (Code Scanning 연동)

### Phase 5: 고도화
- [ ] 커스텀 룰 지원
- [ ] 오탐(False Positive) 관리
- [ ] 성능 최적화

## 사용 도구 라이선스 정리

| 도구 | 라이선스 | 기업 사용 |
|------|----------|-----------|
| Gitleaks | MIT | O |
| Semgrep OSS | LGPL-2.1 | O |
| Trivy | Apache-2.0 | O |
| LangGraph | MIT | O |

## Action 사용 예시

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/security-action@v1
        with:
          secret-scan: true
          code-scan: true
          dependency-scan: true
          ai-review: true
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

## 기술 스택
- **언어**: Python 3.11+
- **AI Framework**: LangGraph, LangChain
- **LLM**: OpenAI GPT-4 / Claude (선택 가능)
- **Container**: Docker

## 참고 자료
- [GitHub Advanced Security 문서](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security)
- [Gitleaks 문서](https://github.com/gitleaks/gitleaks)
- [Semgrep 문서](https://semgrep.dev/docs/)
- [Trivy 문서](https://aquasecurity.github.io/trivy/)
- [LangGraph 문서](https://langchain-ai.github.io/langgraph/)
