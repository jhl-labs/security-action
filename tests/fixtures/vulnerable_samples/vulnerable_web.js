/**
 * 테스트용 취약한 웹 코드 샘플 - Semgrep 탐지 테스트
 * 주의: 이 코드는 보안 취약점을 포함하고 있습니다.
 */

// XSS 취약점 - innerHTML 사용
function displayUserInput(userInput) {
    // 위험: 사용자 입력을 직접 innerHTML에 삽입
    document.getElementById('output').innerHTML = userInput;
}

// XSS 취약점 - document.write 사용
function writeContent(content) {
    // 위험: document.write 사용
    document.write(content);
}

// DOM-based XSS
function processHash() {
    // 위험: location.hash를 검증 없이 사용
    const hash = window.location.hash.substring(1);
    document.getElementById('content').innerHTML = hash;
}

// eval 사용
function executeCode(code) {
    // 위험: 동적 코드 실행
    return eval(code);
}

// 안전하지 않은 정규식 (ReDoS)
function validateEmail(email) {
    // 위험: 재귀적 정규식 패턴
    const regex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    return regex.test(email);
}

// Prototype Pollution 가능성
function merge(target, source) {
    // 위험: 객체 병합 시 __proto__ 검사 없음
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}

// 하드코딩된 자격 증명
const config = {
    apiKey: "sk-1234567890abcdef",
    dbPassword: "password123",
    secretToken: "secret_token_value"
};

// 안전하지 않은 랜덤
function generateToken() {
    // 위험: Math.random()은 암호학적으로 안전하지 않음
    return Math.random().toString(36).substring(2);
}
