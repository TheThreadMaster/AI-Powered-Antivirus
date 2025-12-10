"""Snort IDS Module - Intrusion detection system endpoints."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List

from ..services import snort

router = APIRouter(prefix="/api/snort", tags=["Snort IDS"])


class AlertResponse(BaseModel):
    raw: str
    sid: Optional[str] = None
    msg: Optional[str] = None
    src: Optional[str] = None
    dst: Optional[str] = None
    time: Optional[str] = None


@router.get("/alerts")
def get_alerts(path: Optional[str] = None, limit: int = 200):
    """
    Read Snort IDS alerts from log file.
    
    Returns list of alerts with optional parsing.
    """
    try:
        alerts = snort.read_alerts(path)
        return {
            "count": len(alerts),
            "alerts": alerts[:limit]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading Snort alerts: {str(e)}")


@router.get("/health")
def health_check():
    """Check if Snort IDS module is operational."""
    # Try to read alerts to verify module works
    try:
        alerts = snort.read_alerts()
        return {
            "status": "operational",
            "module": "snort_ids",
            "alerts_available": len(alerts) > 0,
            "sample_count": len(alerts)
        }
    except Exception as e:
        return {
            "status": "error",
            "module": "snort_ids",
            "error": str(e)
        }

