RISK_WEIGHTS = {
    "api_key": 90,
    "password": 85,
    "secret_token": 85,
    "jwt_token": 90,
    "bearer_token": 90,
    "credit_card": 90,
    "phone": 40,
    "email": 30,
    "ip_address": 20
}


def calculate_risk(findings):

    if not findings:
        return 0

    risk_values = []

    for item in findings:

        category = item["category"]

        base_risk = RISK_WEIGHTS.get(
            category,
            0
        )

        confidence = item.get(
            "confidence",
            1.0
        )

        adjusted_risk = base_risk * confidence

        risk_values.append(adjusted_risk)

    base_score = max(risk_values)

    extra_score = (len(findings) - 1) * 10

    return min(
        round(base_score + extra_score),
        100
    )