FROM python:3.11-slim

LABEL maintainer="Security Action Team"
LABEL description="Security Scanner Action - GitHub Advanced Security Alternative"

# 환경 변수 설정
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# 시스템 의존성 설치 (Java for SonarQube Scanner, Ruby for bundler-audit)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    wget \
    ca-certificates \
    unzip \
    openjdk-21-jre-headless \
    ruby \
    ruby-dev \
    cargo \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# Node.js 설치 (npm audit용)
ARG NODE_VERSION=20.20.0
ARG NODE_SHA256=4f48b52acf42130844a3a75e94da0e9629009d09e4101b2304895c24f3fbe609
RUN wget -q https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz \
    && echo "${NODE_SHA256}  node-v${NODE_VERSION}-linux-x64.tar.xz" | sha256sum -c - \
    && tar -xJf node-v${NODE_VERSION}-linux-x64.tar.xz -C /usr/local --strip-components=1 \
    && rm -f node-v${NODE_VERSION}-linux-x64.tar.xz \
    && node --version && npm --version

# Go 설치 (govulncheck용)
ARG GO_VERSION=1.22.5
ARG GO_SHA256=904b924d435eaea086515bc63235b192ea441bd8c9b198c507e85009e6e4c7f0
ARG GOVULNCHECK_VERSION=v1.1.4
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && echo "${GO_SHA256}  go${GO_VERSION}.linux-amd64.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm -f go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# govulncheck 설치
RUN go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION} \
    && govulncheck --version || true

# cargo-audit 설치 (Rust)
ARG CARGO_AUDIT_VERSION=0.22.1
RUN cargo install cargo-audit --locked --version ${CARGO_AUDIT_VERSION} \
    && /root/.cargo/bin/cargo-audit --version

ENV PATH="/root/.cargo/bin:${PATH}"

# bundler-audit 설치 (Ruby)
ARG BUNDLER_AUDIT_VERSION=0.9.3
RUN gem install bundler-audit -v "${BUNDLER_AUDIT_VERSION}" --no-document \
    && bundler-audit version

# Composer 설치 (PHP)
RUN apt-get update && apt-get install -y --no-install-recommends php-cli \
    && rm -rf /var/lib/apt/lists/* \
    && EXPECTED_CHECKSUM="$(wget -q -O - https://composer.github.io/installer.sig)" \
    && php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
    && ACTUAL_CHECKSUM="$(php -r 'echo hash_file("sha384", "composer-setup.php");')" \
    && test "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" \
    && php composer-setup.php --install-dir=/usr/local/bin --filename=composer \
    && rm -f composer-setup.php \
    && composer --version

# Gitleaks 설치 (v8.x)
ARG GITLEAKS_VERSION=8.21.2
ARG GITLEAKS_SHA256=5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba
RUN wget -q https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    && echo "${GITLEAKS_SHA256}  gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | sha256sum -c - \
    && tar -xzf gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    && mv gitleaks /usr/local/bin/ \
    && rm -f gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    && gitleaks version

# Trivy 설치
ARG TRIVY_VERSION=0.58.0
ARG TRIVY_SHA256=eb79a4da633be9c22ce8e9c73a78c0f57ffb077fb92cb1968aaf9c686a20c549
RUN wget -q https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    && echo "${TRIVY_SHA256}  trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | sha256sum -c - \
    && tar -xzf trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    && mv trivy /usr/local/bin/ \
    && rm -f trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    && trivy --version

# SonarQube Scanner 설치
ARG SONAR_SCANNER_VERSION=6.2.1.4610
ARG SONAR_SCANNER_SHA256=0b8a3049f0bd5de7abc1582c78c233960d3d4ed7cc983a1d1635e8552f8bb439
RUN wget -q https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip \
    && echo "${SONAR_SCANNER_SHA256}  sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip" | sha256sum -c - \
    && unzip -q sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip \
    && mv sonar-scanner-${SONAR_SCANNER_VERSION}-linux-x64 /opt/sonar-scanner \
    && ln -s /opt/sonar-scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner \
    && rm -f sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip \
    && sonar-scanner --version

ENV SONAR_SCANNER_HOME=/opt/sonar-scanner
ENV PATH="${SONAR_SCANNER_HOME}/bin:${PATH}"

# Syft 설치 (SBOM 생성)
ARG SYFT_VERSION=1.17.0
ARG SYFT_SHA256=3485e831c21fd80b41fa3fc1f72e10367989b2d1aee082d642b5b0e658a02b44
RUN wget -q https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz \
    && echo "${SYFT_SHA256}  syft_${SYFT_VERSION}_linux_amd64.tar.gz" | sha256sum -c - \
    && tar -xzf syft_${SYFT_VERSION}_linux_amd64.tar.gz syft \
    && mv syft /usr/local/bin/syft \
    && rm -f syft_${SYFT_VERSION}_linux_amd64.tar.gz \
    && syft version

# 작업 디렉토리 설정
WORKDIR /action

# Python 의존성 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Semgrep은 pip으로 설치됨 (requirements.txt에 포함)

# 소스 코드 복사
COPY src/ ./src/
COPY config/ ./config/

# Wrapper 스크립트 복사
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 엔트리포인트 설정
ENTRYPOINT ["/entrypoint.sh"]
