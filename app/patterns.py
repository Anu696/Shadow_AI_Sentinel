PATTERNS = {

    # -------------------------
    # Personal Information
    # -------------------------

    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",

    "phone": r"\b(?:\+91[- ]?)?[6-9]\d{9}\b",

    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",


    # -------------------------
    # Password / Secrets
    # -------------------------

    "password": (
        r"(?i)\b(?:password|passwd|pwd)"
        r"\s*[:=]\s*[^\s,;]+"
    ),

    "secret_token": (
    r"(?i)\b(?:secret_token|secret-token|secret|token|access_token)"
    r"\s*[:=]\s*[A-Za-z0-9_-]{16,}\b"
    ),


    "api_key": (
        r"(?i)\b(?:api[_-]?key|apikey)"
        r"\s*[:=]\s*[A-Za-z0-9_\-]{16,}"
    ),


    # -------------------------
    # JWT
    # -------------------------

    "jwt_token": (
        r"\beyJ[A-Za-z0-9_-]{10,}"
        r"\.[A-Za-z0-9_-]{10,}"
        r"\.[A-Za-z0-9_-]{10,}\b"
    ),


    # -------------------------
    # Bearer Token
    # -------------------------

    "bearer_token": (
        r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*"
    ),


    # -------------------------
    # Credit Card
    # -------------------------

    "credit_card": (
        r"\b(?:\d{4}[- ]?){3}\d{4}\b"
    )
}