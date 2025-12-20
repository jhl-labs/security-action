"""
테스트용 취약한 코드 샘플 - Semgrep 탐지 테스트
주의: 이 코드는 보안 취약점을 포함하고 있으며,
테스트 목적으로만 사용됩니다. 실제 프로젝트에서 사용하지 마세요.
"""

import os
import pickle
import subprocess
import sqlite3


# SQL Injection 취약점
def get_user_unsafe(user_id: str) -> dict:
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 위험: 사용자 입력을 직접 쿼리에 삽입
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()


# Command Injection 취약점
def run_command_unsafe(user_input: str) -> str:
    # 위험: 사용자 입력을 직접 쉘 명령어에 사용
    result = os.system(f"echo {user_input}")
    return str(result)


# Subprocess Shell Injection
def execute_unsafe(cmd: str) -> bytes:
    # 위험: shell=True와 사용자 입력 조합
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout


# Pickle 역직렬화 취약점
def load_data_unsafe(data: bytes) -> object:
    # 위험: 신뢰할 수 없는 데이터 역직렬화
    return pickle.loads(data)


# Eval 사용
def calculate_unsafe(expression: str) -> float:
    # 위험: 사용자 입력을 eval로 실행
    return eval(expression)


# 하드코딩된 비밀번호
def authenticate(username: str, password: str) -> bool:
    # 위험: 하드코딩된 자격 증명
    if username == "admin" and password == "admin123":
        return True
    return False


# Path Traversal
def read_file_unsafe(filename: str) -> str:
    # 위험: 경로 검증 없이 파일 읽기
    with open(f"/var/data/{filename}") as f:
        return f.read()


# SSRF 취약점
def fetch_url_unsafe(url: str) -> str:
    import urllib.request
    # 위험: URL 검증 없이 외부 요청
    return urllib.request.urlopen(url).read().decode()
