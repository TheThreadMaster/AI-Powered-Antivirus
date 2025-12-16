"""Anomaly Detection Module - ML-based threat scoring endpoints."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from pathlib import Path
from typing import Optional

from ..services import anomaly

router = APIRouter(prefix="/api/anomaly", tags=["Anomaly Detection"])


class ScoreRequest(BaseModel):
    path: str


class ScoreResponse(BaseModel):
    path: str
    risk: float
    verdict: str
    mime: Optional[str] = None
    size: Optional[int] = None
    hash: Optional[str] = None
    filetype: Optional[str] = None
    entropy: Optional[float] = None
    yara: Optional[list[str]] = None


@router.post("/score", response_model=ScoreResponse)
def score_file(request: ScoreRequest):
    """
    Score a file using ML anomaly detection.
    
    Returns risk score (0-1), verdict (benign/suspicious/malicious), and file metadata.
    """
    try:
        p = Path(request.path)
        if not p.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        result = anomaly.score_path(request.path)
        return ScoreResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scoring file: {str(e)}")


@router.get("/health")
def health_check():
    """Check if anomaly detection module is operational."""
    return {
        "status": "operational",
        "module": "anomaly_detection",
        "model_loaded": anomaly._MODEL is not None,
        "scaler_loaded": anomaly._SCALER is not None
    }

