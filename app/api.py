from fastapi import FastAPI
from pydantic import BaseModel

from app.detector import detect_sensitive_data
from app.risk_engine import calculate_risk
from app.policy import apply_policy
from app.redactor import redact_data


app = FastAPI(
    title="Shadow AI Security Engine",
    description="Sensitive data detection and risk analysis API",
    version="1.0"
)


class ScanRequest(BaseModel):
    prompt: str


@app.get("/")
def home():
    return {
        "message": "Shadow AI Security Engine is running"
    }


@app.post("/scan")
def scan_prompt(request: ScanRequest):

    prompt = request.prompt

    findings = detect_sensitive_data(prompt)

    risk_score = calculate_risk(findings)

    action = apply_policy(
        risk_score,
        findings
    )

    if action == "ALLOW":
        safe_text = prompt

    elif action == "REDACT":
        safe_text = redact_data(
            prompt,
            findings
        )

    else:
        safe_text = None

    return {
        "risk_score": risk_score,
        "action": action,
        "findings": [
            {
                "category": item["category"],
                "confidence": item["confidence"]
            }
            for item in findings
        ],
        "safe_text": safe_text
    }