from app.detector import detect_sensitive_data
from app.risk_engine import calculate_risk
from app.policy import apply_policy
from app.redactor import redact_data


def test_normal_text():

    text = "Hello, how are you?"

    findings = detect_sensitive_data(text)

    assert len(findings) == 0


def test_email():

    text = "Contact me at anu@gmail.com"

    findings = detect_sensitive_data(text)

    assert any(
        item["category"] == "email"
        for item in findings
    )


def test_phone():

    text = "My phone number is 9876543210"

    findings = detect_sensitive_data(text)

    assert any(
        item["category"] == "phone"
        for item in findings
    )


def test_password():

    text = "password=MySecret123"

    findings = detect_sensitive_data(text)

    assert any(
        item["category"] == "password"
        for item in findings
    )


def test_risk_score():

    findings = [
        {
            "category": "email",
            "confidence": 0.85
        },
        {
            "category": "phone",
            "confidence": 1.0
        }
    ]

    score = calculate_risk(findings)

    assert score == 50


def test_block_policy():

    findings = [
        {
            "category": "password",
            "confidence": 0.95
        }
    ]

    score = calculate_risk(findings)

    action = apply_policy(
        score,
        findings
    )

    assert action == "BLOCK"


def test_redact_policy():

    findings = [
        {
            "category": "email",
            "confidence": 0.85
        }
    ]

    score = calculate_risk(findings)

    action = apply_policy(
        score,
        findings
    )

    assert action == "REDACT"


def test_allow_policy():

    findings = []

    score = calculate_risk(findings)

    action = apply_policy(
        score,
        findings
    )

    assert action == "ALLOW"


def test_api_key():

    text = "api_key=abcdefghijklmnop123456"

    findings = detect_sensitive_data(text)

    assert any(
        item["category"] == "api_key"
        for item in findings
    )


def test_jwt():

    text = (
        "eyJaaaaaaaaaaa."
        "bbbbbbbbbbb."
        "ccccccccccc"
    )

    findings = detect_sensitive_data(text)

    assert any(
        item["category"] == "jwt_token"
        for item in findings
    )


def test_bearer_token():

    text = (
        "Authorization: Bearer "
        "abcdefghijklmnopqrstuvwxyz123456"
    )

    findings = detect_sensitive_data(text)

    assert any(
        item["category"] == "bearer_token"
        for item in findings
    )


def test_ip_address():

    text = "Server IP is 192.168.1.10"

    findings = detect_sensitive_data(text)

    assert any(
        item["category"] == "ip_address"
        for item in findings
    )


def test_redaction():

    text = "My email is student@example.com"

    findings = detect_sensitive_data(text)

    safe_text = redact_data(
        text,
        findings
    )

    assert "student@example.com" not in safe_text
    assert "[REDACTED_EMAIL]" in safe_text