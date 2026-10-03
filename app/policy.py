HIGH_RISK_CATEGORIES = {
    "api_key",
    "password",
    "secret_token",
    "jwt_token",
    "bearer_token",
    "credit_card"
}


def apply_policy(risk_score, findings):

    categories = {
        item["category"]
        for item in findings
    }

    if categories.intersection(
        HIGH_RISK_CATEGORIES
    ):
        return "BLOCK"

    if risk_score >= 30:
        return "REDACT"

    return "ALLOW"