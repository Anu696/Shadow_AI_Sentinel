
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
    description="API for detecting sensitive data and security violations.",
    version="1.2"
)


# Request Model
class ScanRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        description="Text to scan"
    )


# Finding Model
class Finding(BaseModel):
    category: str
    confidence: float = Field(ge=0.0, le=1.0)


# Response Model
class ScanResponse(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    action: str
    findings: list[Finding]
    safe_text: Optional[str]
    sentiment: dict
    violation_detection: dict


# Home Route
@app.get("/")
def home():
    return {
        "message": "Shadow AI Security Engine is running"
    }


# Health Check Route
@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


# Main Security Scan Route
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

        # 2. Analyze sentiment
        sentiment_result = analyze_sentiment(prompt)

        # 3. Detect security violations
        violation_result = detect_violations(prompt)

        # 4. Calculate combined risk score
        # Requires the updated risk_engine.py
        risk_score = calculate_risk(
            findings,
            violation_result
        )

        # 5. Apply existing security policy
        action = apply_policy(
            risk_score,
            findings
        )

        # 6. Block prompts containing detected violations
        if violation_result["is_violation"]:
            action = "BLOCK"

        # 7. Generate safe output
        if action == "ALLOW":
            safe_text = prompt

        elif action == "REDACT":
            safe_text = redact_data(
                prompt,
                findings
            )

        else:
            safe_text = None

        # 8. Remove sensitive values from findings
        safe_findings = [
            {
                "category": item["category"],
                "confidence": item["confidence"]
            }
            for item in findings
        ]

        # 9. Return complete scan results
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

