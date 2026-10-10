
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.detector import detect_sensitive_data
from app.risk_engine import calculate_risk
from app.policy import apply_policy
from app.redactor import redact_data
from app.sentiment import analyze_sentiment
from app.violation_detector import detect_violations


app = FastAPI(
    title="Shadow AI Security Engine",
    description=(
        "Sensitive data detection, risk analysis, "
        "sentiment analysis and violation detection API"
    ),
    version="1.1"
)


# -----------------------------
# Request Model
# -----------------------------

class ScanRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        description="Text to scan"
    )


# -----------------------------
# Finding Response Model
# -----------------------------

class Finding(BaseModel):
    category: str
    confidence: float = Field(ge=0.0, le=1.0)


# -----------------------------
# Scan Response Model
# -----------------------------

class ScanResponse(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    action: str
    findings: list[Finding]
    safe_text: Optional[str]
    sentiment: dict
    violation_detection: dict


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

@app.post("/scan", response_model=ScanResponse)
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

        # 2. Calculate existing risk score
        risk_score = calculate_risk(findings)

        # 3. Apply existing security policy
        action = apply_policy(risk_score, findings)

        # 4. Detect sentiment
        sentiment_result = analyze_sentiment(prompt)

        # 5. Detect policy violations
        violation_result = detect_violations(prompt)

        # 6. Prevent known violations from continuing
        # This is an additional block, without changing
        # the existing policy implementation.
        if violation_result["is_violation"]:
            action = "BLOCK"

        # 7. Generate safe output
        if action == "ALLOW":
            safe_text = prompt

        elif action == "REDACT":
            safe_text = redact_data(prompt, findings)

        else:
            safe_text = None

        # 8. Never expose actual sensitive values
        safe_findings = [
            {
                "category": item["category"],
                "confidence": item["confidence"]
            }
            for item in findings
        ]

        # 9. Return combined results
        return {
            "risk_score": risk_score,
            "action": action,
            "findings": safe_findings,
            "safe_text": safe_text,
            "sentiment": sentiment_result,
            "violation_detection": violation_result
        }

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Security scan failed"
        )
