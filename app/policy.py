HIGH_RISK_CATEGORIES = {
    "api_key",
    "password",
    "secret_token",
    "jwt_token",
    "bearer_token",
    "credit_card"
}

MEDIUM_RISK_CATEGORIES = {
    "email",
    "phone",
    "ip_address"
}


def apply_policy(risk_score, findings):

    categories = {
        item["category"]
        for item in findings
    }

    # High-risk secrets
    if categories.intersection(HIGH_RISK_CATEGORIES):
        return "BLOCK"

    # Medium-risk sensitive information
    if categories.intersection(MEDIUM_RISK_CATEGORIES):
        return "REDACT"

    # Low-risk or no sensitive information
    return "ALLOW"