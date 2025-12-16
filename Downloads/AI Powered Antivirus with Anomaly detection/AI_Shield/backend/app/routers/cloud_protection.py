"""Cloud Protection Module - Cloud-delivered threat intelligence endpoints."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from ..services.cloud_protection import get_cloud_service

router = APIRouter(prefix="/api/cloud-protection", tags=["Cloud Protection"])


class CheckFileRequest(BaseModel):
    file_path: str


class CheckUrlRequest(BaseModel):
    url: str


class CheckIpRequest(BaseModel):
    ip: str


class SubmitSampleRequest(BaseModel):
    file_path: str
    verdict: Optional[str] = "suspicious"
    severity: Optional[str] = "medium"


@router.get("/status")
def get_status():
    """Get cloud protection status and statistics."""
    service = get_cloud_service()
    stats = service.get_stats()
    return {
        "enabled": service.enabled,
        "auto_submit_enabled": service.auto_submit_enabled,
        "stats": stats.get("stats", {}),
        "cache_size": stats.get("cache_size", 0),
        "submissions_tracked": stats.get("submissions_tracked", 0),
    }


@router.post("/check-file")
def check_file(request: CheckFileRequest):
    """
    Check a file against cloud threat intelligence.
    
    Returns cloud-based threat detection results including:
    - Cloud verdict (clean, suspicious, malicious)
    - Cloud score (0.0 to 1.0)
    - Threat intelligence sources
    - Detection details
    """
    try:
        service = get_cloud_service()
        result = service.check_file(request.file_path)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking file: {str(e)}")


@router.post("/check-url")
def check_url(request: CheckUrlRequest):
    """
    Check a URL against cloud reputation services.
    
    Returns cloud-based reputation assessment including:
    - Reputation status (clean, suspicious, malicious)
    - Confidence score
    - Threat intelligence sources
    """
    try:
        service = get_cloud_service()
        result = service.check_url(request.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking URL: {str(e)}")


@router.post("/check-ip")
def check_ip(request: CheckIpRequest):
    """
    Check an IP address against cloud reputation services.
    
    Returns cloud-based reputation assessment including:
    - Reputation status (clean, suspicious, malicious)
    - Confidence score
    - Threat intelligence sources
    """
    try:
        service = get_cloud_service()
        result = service.check_ip(request.ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking IP: {str(e)}")


@router.post("/enable")
def enable_cloud_protection():
    """Enable cloud-delivered protection."""
    try:
        service = get_cloud_service()
        service.enable()
        return {
            "success": True,
            "message": "Cloud protection enabled",
            "enabled": service.enabled,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error enabling cloud protection: {str(e)}")


@router.post("/disable")
def disable_cloud_protection():
    """Disable cloud-delivered protection."""
    try:
        service = get_cloud_service()
        service.disable()
        return {
            "success": True,
            "message": "Cloud protection disabled",
            "enabled": service.enabled,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error disabling cloud protection: {str(e)}")


@router.post("/clear-cache")
def clear_cache():
    """Clear the cloud protection cache."""
    try:
        service = get_cloud_service()
        service.clear_cache()
        return {
            "success": True,
            "message": "Cache cleared",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error clearing cache: {str(e)}")


@router.post("/submit-sample")
def submit_sample(request: SubmitSampleRequest):
    """
    Manually submit a threat sample to cloud platforms for analysis.
    
    Supports:
    - VirusTotal (requires VIRUSTOTAL_API_KEY)
    - Hybrid Analysis (requires HYBRID_ANALYSIS_API_KEY and HYBRID_ANALYSIS_API_SECRET)
    """
    try:
        service = get_cloud_service()
        result = service.submit_threat_sample(
            request.file_path,
            request.verdict,
            request.severity
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error submitting sample: {str(e)}")


@router.get("/submission-status")
def get_submission_status(file_path: str):
    """Get submission status for a specific file."""
    try:
        service = get_cloud_service()
        status = service.get_submission_status(file_path)
        if status:
            return status
        else:
            return {
                "submitted": False,
                "message": "No submission found for this file"
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting submission status: {str(e)}")


@router.get("/submissions")
def list_submissions(limit: int = 50):
    """List recent file submissions to cloud platforms."""
    try:
        service = get_cloud_service()
        submissions = service.list_submissions(limit)
        return {
            "count": len(submissions),
            "submissions": submissions
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing submissions: {str(e)}")


@router.post("/auto-submit/enable")
def enable_auto_submit():
    """Enable automatic sample submission for detected threats."""
    try:
        service = get_cloud_service()
        service.enable_auto_submit()
        return {
            "success": True,
            "message": "Automatic sample submission enabled",
            "auto_submit_enabled": service.auto_submit_enabled,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error enabling auto-submit: {str(e)}")


@router.post("/auto-submit/disable")
def disable_auto_submit():
    """Disable automatic sample submission."""
    try:
        service = get_cloud_service()
        service.disable_auto_submit()
        return {
            "success": True,
            "message": "Automatic sample submission disabled",
            "auto_submit_enabled": service.auto_submit_enabled,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error disabling auto-submit: {str(e)}")


@router.get("/health")
def health_check():
    """Check if Cloud Protection module is operational."""
    try:
        service = get_cloud_service()
        stats = service.get_stats()
        return {
            "status": "operational",
            "module": "cloud_protection",
            "enabled": service.enabled,
            "auto_submit_enabled": service.auto_submit_enabled,
            "cache_size": stats.get("cache_size", 0),
            "submissions_tracked": stats.get("submissions_tracked", 0),
        }
    except Exception as e:
        return {
            "status": "error",
            "module": "cloud_protection",
            "error": str(e),
        }

