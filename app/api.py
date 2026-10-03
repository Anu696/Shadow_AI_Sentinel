from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.detector import detect_sensitive_data
from app.risk_engine import calculate_risk
from app.policy import apply_policy
from app.redactor import redact_data


app = FastAPI(
    title="Shadow AI Security Engine",
    description="Sensitive data detection and risk analysis API",
    version="1.0"
)


# -----------------------------
# Request Model
# -----------------------------

class ScanRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        description="Text to scan for sensitive information"
    )


# -----------------------------
# Finding Response Model
# -----------------------------

class Finding(BaseModel):
    category: str
    confidence: float = Field(
        ge=0.0,
        le=1.0
    )


# -----------------------------
# Scan Response Model
# -----------------------------

class ScanResponse(BaseModel):
    risk_score: int = Field(
        ge=0,
        le=100
    )

    action: str

    findings: list[Finding]

    safe_text: Optional[str]


# -----------------------------
# Home Endpoint
# -----------------------------

@app.get("/")
def home():

    return {
        "message": "Shadow AI Security Engine is running"
    }


# -----------------------------
# Health Check
# -----------------------------

@app.get("/health")
def health_check():

    return {
        "status": "healthy",
        "service": "security-engine"
    }


# -----------------------------
# Scan Endpoint
# -----------------------------

@app.post(
    "/scan",
    response_model=ScanResponse
)
def scan_prompt(request: ScanRequest):

    prompt = request.prompt.strip()

    if not prompt:
        raise HTTPException(
            status_code=400,
            detail="Prompt cannot be empty"
        )

    try:

        # 1. Detect sensitive information
        findings = detect_sensitive_data(prompt)

        # 2. Calculate risk
        risk_score = calculate_risk(findings)

        # 3. Apply security policy
        action = apply_policy(
            risk_score,
            findings
        )

        # 4. Generate safe output
        if action == "ALLOW":

            safe_text = prompt

        elif action == "REDACT":

            safe_text = redact_data(
                prompt,
                findings
            )

        else:

            # BLOCK means the prompt must not continue
            safe_text = None

        # Never return actual sensitive values
        safe_findings = [
            {
                "category": item["category"],
                "confidence": item["confidence"]
            }
            for item in findings
        ]

        return {
            "risk_score": risk_score,
            "action": action,
            "findings": safe_findings,
            "safe_text": safe_text
        }

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Security scan failed"
        )