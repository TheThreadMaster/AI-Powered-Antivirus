"""Sandbox Analysis Module - File behavior simulation endpoints."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from pathlib import Path
from typing import Optional, List

from ..services import sandbox

router = APIRouter(prefix="/api/sandbox", tags=["Sandbox"])


class AnalyzeRequest(BaseModel):
    path: str


class AnalyzeResponse(BaseModel):
    path: str
    verdict: str
    syscalls: List[str]
    registry: List[str]
    network: List[str]
    score: Optional[float] = None


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_file(request: AnalyzeRequest):
    """
    Analyze a file in sandbox environment.
    
    Returns behavior analysis including system calls, registry access, and network activity.
    """
    try:
        p = Path(request.path)
        if not p.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        result = sandbox.analyze_path(request.path)
        return AnalyzeResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing file: {str(e)}")


@router.get("/health")
def health_check():
    """Check if Sandbox module is operational."""
    return {
        "status": "operational",
        "module": "sandbox"
    }

