import os


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


# Read configuration from environment
REDACT_THRESHOLD = int(
    os.getenv("REDACT_THRESHOLD", "25")
)

BLOCK_HIGH_RISK = os.getenv(
    "BLOCK_HIGH_RISK",
    "true"
).lower() == "true"


def apply_policy(risk_score, findings):

    categories = {
        item["category"]
        for item in findings
    }

    # Block high-risk secrets when enabled
    if (
        BLOCK_HIGH_RISK
        and categories.intersection(
            HIGH_RISK_CATEGORIES
        )
    ):
        return "BLOCK"

    # Redact medium-risk sensitive information
    if categories.intersection(
        MEDIUM_RISK_CATEGORIES
    ):
        return "REDACT"

    # Use configured threshold
    if risk_score >= REDACT_THRESHOLD:
        return "REDACT"

    return "ALLOW"