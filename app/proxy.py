from fastapi import FastAPI
from pydantic import BaseModel

from app.detector import detect_sensitive_data
from app.risk_engine import calculate_risk
from app.policy import apply_policy
from app.redactor import redact_data


proxy_app = FastAPI(
    title="Shadow AI Proxy",
    description="Security proxy for LLM requests",
    version="1.0"
)


class ProxyRequest(BaseModel):
    prompt: str


@proxy_app.get("/")
def proxy_home():
    return {
        "message": "Shadow AI Proxy is running"
    }


@proxy_app.post("/proxy")
def proxy_request(request: ProxyRequest):

    prompt = request.prompt.strip()

    # 1. Detect sensitive data
    findings = detect_sensitive_data(prompt)

    # 2. Calculate risk
    risk_score = calculate_risk(findings)

    # 3. Apply security policy
    action = apply_policy(
        risk_score,
        findings
    )

    # 4. Handle security decision
    if action == "BLOCK":

        return {
            "action": "BLOCK",
            "risk_score": risk_score,
            "message": "Request blocked because sensitive information was detected."
        }

    if action == "REDACT":

        safe_prompt = redact_data(
            prompt,
            findings
        )

        return {
            "action": "REDACT",
            "risk_score": risk_score,
            "original_prompt_forwarded": False,
            "safe_prompt": safe_prompt
        }

    return {
        "action": "ALLOW",
        "risk_score": risk_score,
        "safe_prompt": prompt
    }