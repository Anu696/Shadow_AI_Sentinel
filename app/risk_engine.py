
RISK_WEIGHTS = {
    "api_key": 90,
    "password": 85,
    "secret_token": 85,
    "jwt_token": 90,
    "bearer_token": 90,
    "credit_card": 90,
    "phone": 40,
    "email": 30,
    "ip_address": 20,
}

VIOLATION_WEIGHTS = {
    "prompt_injection": 80,
    "data_exfiltration": 95,
    "security_bypass": 90,
}


def calculate_risk(findings, violation_result=None):
    """Calculate a combined risk score from 0 to 100."""

    risk_values = []

    # 1. Calculate risk from sensitive-data findings
    for item in findings or []:
        category = item["category"]
        base_risk = RISK_WEIGHTS.get(category, 0)
        confidence = item.get("confidence", 1.0)

        adjusted_risk = base_risk * confidence
        risk_values.append(adjusted_risk)

    if findings:
        sensitive_score = max(risk_values, default=0)
        sensitive_score += (len(findings) - 1) * 10
    else:
        sensitive_score = 0

    # 2. Calculate risk from detected violations
    violation_score = 0

    if violation_result and violation_result.get("is_violation"):
        violations = violation_result.get("violations", [])

        violation_risks = [
            VIOLATION_WEIGHTS.get(item.get("category"), 80)
            for item in violations
        ]

        if violation_risks:
            violation_score = max(violation_risks)
            violation_score += (len(violation_risks) - 1) * 5
        else:
            violation_score = 80

    # 3. Combine both scores and cap at 100
    combined_score = max(sensitive_score, violation_score)

    return min(round(combined_score), 100)
