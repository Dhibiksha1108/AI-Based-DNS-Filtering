"""
DNS Threat Intelligence & Machine Learning
Module: FastAPI Backend API & Web Dashboard

Exposes the Security Decision Engine via HTTP endpoints and serves the Web Dashboard.
"""

import os
import sys
from fastapi import FastAPI, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.security_engine import analyze_domain

app = FastAPI(
    title="AI-Based DNS Filtering API & Web Dashboard",
    description="API and Web Dashboard for AI-based DNS threat detection combining Threat Intelligence (URLhaus) and ML (Random Forest).",
    version="1.0.0"
)

# Frontend Directory & Static Files Setup
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


class DomainAnalysisRequest(BaseModel):
    domain: str = Field(
        ...,
        description="The domain name query string to analyze.",
        example="google.com"
    )


@app.get("/", tags=["Dashboard"])
def get_dashboard():
    """
    Serve the Web Dashboard UI.
    """
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "status": "running",
        "service": "AI-Based DNS Filtering API"
    }


@app.get("/health", tags=["General"])
def health_check():
    """
    Health check endpoint for service monitoring.
    """
    return {
        "status": "healthy"
    }


@app.post("/analyze", tags=["Security Engine"])
def analyze_domain_endpoint(request: DomainAnalysisRequest):
    """
    Analyze a domain query using Threat Intelligence lookups and ML classification.
    Returns deterministic ALLOW / BLOCK security decisions and decision rationale.
    """
    domain = request.domain.strip() if request.domain else ""

    if not domain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid domain input: 'domain' field cannot be empty."
        )

    try:
        result = analyze_domain(domain)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred during domain analysis."
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.api:app", host="127.0.0.1", port=8000, reload=True)
