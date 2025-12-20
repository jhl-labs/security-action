FROM python:3.11-slim

LABEL maintainer="Security Action Team"
LABEL description="Security Scanner Action - GitHub Advanced Security Alternative"

# 환경 변수 설정
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# 시스템 의존성 설치 (Java for SonarQube Scanner)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    wget \
    ca-certificates \
    unzip \
    openjdk-21-jre-headless \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# Gitleaks 설치 (v8.x)
ARG GITLEAKS_VERSION=8.21.2
RUN wget -q https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    && tar -xzf gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    && mv gitleaks /usr/local/bin/ \
    && rm -f gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    && gitleaks version

# Trivy 설치
ARG TRIVY_VERSION=0.58.0
RUN wget -q https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    && tar -xzf trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    && mv trivy /usr/local/bin/ \
    && rm -f trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    && trivy --version

# SonarQube Scanner 설치
ARG SONAR_SCANNER_VERSION=6.2.1.4610
RUN wget -q https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip \
    && unzip -q sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip \
    && mv sonar-scanner-${SONAR_SCANNER_VERSION}-linux-x64 /opt/sonar-scanner \
    && ln -s /opt/sonar-scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner \
    && rm -f sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip \
    && sonar-scanner --version

ENV SONAR_SCANNER_HOME=/opt/sonar-scanner
ENV PATH="${SONAR_SCANNER_HOME}/bin:${PATH}"

# 작업 디렉토리 설정
WORKDIR /action

# Python 의존성 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Semgrep은 pip으로 설치됨 (requirements.txt에 포함)

# 소스 코드 복사
COPY src/ ./src/
COPY config/ ./config/

# 엔트리포인트 설정
ENTRYPOINT ["python", "/action/src/main.py"]
