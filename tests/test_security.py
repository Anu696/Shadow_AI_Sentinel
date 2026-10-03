from detect import detect_sensitive_data
from risk_engine import calculate_risk
from policy import apply_policy


def test_normal_text():

    text = "Hello, how are you?"

    findings = detect_sensitive_data(text)

    assert len(findings) == 0

    print("PASS: Normal text")


def test_email():

    text = "Contact me at anu@gmail.com"

    findings = detect_sensitive_data(text)

    assert any(
        item["category"] == "email"
        for item in findings
    )

    print("PASS: Email detection")


def test_phone():

    text = "My phone number is 9876543210"

    findings = detect_sensitive_data(text)

    assert any(
        item["category"] == "phone"
        for item in findings
    )

    print("PASS: Phone detection")


def test_password():

    text = "password=MySecret123"

    findings = detect_sensitive_data(text)

    assert any(
        item["category"] == "password"
        for item in findings
    )

    print("PASS: Password detection")


def test_risk_score():

    findings = [
        {"category": "email"},
        {"category": "phone"}
    ]

    score = calculate_risk(findings)

    assert score == 70

    print("PASS: Risk calculation")


def test_block_policy():

    action = apply_policy(85)

    assert action == "BLOCK"

    print("PASS: BLOCK policy")


def test_redact_policy():

    action = apply_policy(50)

    assert action == "REDACT"

    print("PASS: REDACT policy")


def test_allow_policy():

    action = apply_policy(10)

    assert action == "ALLOW"

    print("PASS: ALLOW policy")
    
def test_api_key():

    text ="api_key=abcdefghijklmnop123456"

    findings = detect_sensitive_data(text)

    assert any(
        item["category"] == "api_key"
        for item in findings
    )

    print("PASS: API key detection")


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

    print("PASS: JWT detection")


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

    print("PASS: Bearer token detection")


# Run all tests

test_normal_text()
test_email()
test_phone()
test_password()
test_risk_score()
test_block_policy()
test_redact_policy()
test_allow_policy()
test_api_key()
test_jwt()
test_bearer_token()

print("\nAll tests completed!")