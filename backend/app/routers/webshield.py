"""WebShield Module - URL filtering and blocking endpoints."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from ..services import webshield
from ..store import DB

router = APIRouter(prefix="/api/webshield", tags=["WebShield"])


class ScoreRequest(BaseModel):
    url: str


class BlockRequest(BaseModel):
    url: str
    force: bool = True


class CheckAndBlockRequest(BaseModel):
    url: str
    auto_block_threshold: float = 0.6


@router.post("/score")
def score_url(request: ScoreRequest):
    """
    Score a URL for risk assessment.
    
    Returns risk score, category, and detailed analysis.
    """
    try:
        result = webshield.score_url(request.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scoring URL: {str(e)}")


@router.post("/block")
def block_url_endpoint(request: BlockRequest):
    """
    Block a URL at OS level (modifies hosts file).
    
    Returns blocking status and host information.
    """
    try:
        result = webshield.block_url(request.url, force=request.force)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error blocking URL: {str(e)}")


@router.post("/check-and-block")
def check_and_block_url(request: CheckAndBlockRequest):
    """
    Check URL risk and automatically block if above threshold.
    
    Returns scoring result and blocking status.
    """
    try:
        result = webshield.check_and_block_url(
            request.url, 
            auto_block_threshold=request.auto_block_threshold,
            db=DB
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking/blocking URL: {str(e)}")


@router.get("/blocked")
def list_blocked_urls(limit: int = 500):
    """List all blocked URLs."""
    try:
        urls = DB.list_blocked_urls(limit=limit)
        return {
            "count": len(urls),
            "urls": [
                {
                    "id": u.id,
                    "url": u.url,
                    "host": u.host,
                    "score": u.score,
                    "category": u.category,
                    "os_blocked": u.os_blocked,
                    "created": u.created.isoformat() if u.created else None,
                    "last_accessed": u.last_accessed.isoformat() if u.last_accessed else None,
                }
                for u in urls
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing blocked URLs: {str(e)}")


@router.get("/health")
def health_check():
    """Check if WebShield module is operational."""
    return {
        "status": "operational",
        "module": "webshield",
        "blocked_count": len(DB.list_blocked_urls(limit=1000))
    }

