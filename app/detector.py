import re

from app.patterns import PATTERNS


def has_secret_context(text, match):
    """
    Check whether secret-related keywords
    are present near the detected value.
    """

    start = max(0, match.start() - 40)
    end = min(len(text), match.end() + 40)

    context = text[start:end].lower()

    keywords = [
        "password",
        "secret",
        "api key",
        "token",
        "credential",
        "authorization"
    ]

    return any(
        keyword in context
        for keyword in keywords
    )


def get_confidence(category, text, match):

    # High-confidence secrets
    if category in [
        "api_key",
        "password",
        "secret_token",
        "jwt_token",
        "bearer_token"
    ]:
        return 0.95

    # Credit card
    if category == "credit_card":
        return 0.90

    # Personal information
    if category in [
        "email",
        "phone"
    ]:
        # Increase confidence when
        # secret-related context is present
        if has_secret_context(text, match):
            return 0.95

        return 0.85

    # IP addresses can be normal technical information
    if category == "ip_address":
        return 0.70

    # Default confidence
    return 0.50


def detect_sensitive_data(text):

    findings = []

    # Check every security pattern
    for category, pattern in PATTERNS.items():

        for match in re.finditer(pattern, text):

            confidence = get_confidence(
                category,
                text,
                match
            )

            findings.append({
                "category": category,

                # Internal use only
                # Required for redaction
                "value": match.group(),

                "confidence": confidence,

                # Match position
                # Required by redactor.py
                "start": match.start(),
                "end": match.end()
            })

    return findings