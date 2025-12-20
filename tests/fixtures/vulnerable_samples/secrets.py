"""
테스트용 비밀값 샘플 - Gitleaks 탐지 테스트
주의: 이 파일은 테스트 목적으로만 사용됩니다.
모든 값은 가짜이며 실제로 동작하지 않습니다.
"""

# AWS 키 (가짜)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GitHub 토큰 (가짜 - 형식만 맞춤)
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Slack 웹훅 (가짜)
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# 개인키 형식 (가짜)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
FAKE_KEY_FOR_TESTING_PURPOSES_ONLY_NOT_REAL
-----END RSA PRIVATE KEY-----"""

# API 키 패턴 (가짜)
API_KEY = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


def get_database_connection():
    # 하드코딩된 비밀번호 (테스트용)
    password = "super_secret_password_123"
    return f"postgresql://admin:{password}@localhost/db"
