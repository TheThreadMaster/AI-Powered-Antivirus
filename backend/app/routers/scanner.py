"""Background Scanner Module - File system monitoring endpoints."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from pathlib import Path

from ..services import background

# Import state from main - will be set up after main initializes
LIVE_SCAN_STATE = None
_threat_callback = None
ws_manager = None

def init_scanner_router(scan_state, callback, ws_mgr):
    """Initialize router with dependencies from main."""
    global LIVE_SCAN_STATE, _threat_callback, ws_manager
    LIVE_SCAN_STATE = scan_state
    _threat_callback = callback
    ws_manager = ws_mgr

router = APIRouter(prefix="/api/scanner/background", tags=["Background Scanner"])


class AddPathRequest(BaseModel):
    path: str


class RemovePathRequest(BaseModel):
    path: str


class UpdateConfigRequest(BaseModel):
    enabled: Optional[bool] = None
    scan_delay: Optional[float] = None
    auto_quarantine: Optional[bool] = None
    exclude_patterns: Optional[List[str]] = None


@router.get("/status")
def get_status():
    """Get background scanner status and configuration."""
    if LIVE_SCAN_STATE is None:
        raise HTTPException(status_code=503, detail="Scanner not initialized")
    return {
        "enabled": LIVE_SCAN_STATE.enabled,
        "paths": LIVE_SCAN_STATE.paths,
        "recent_quarantine": LIVE_SCAN_STATE.recent_quarantine,
        "exclude_patterns": LIVE_SCAN_STATE.exclude_patterns,
        "scan_delay": LIVE_SCAN_STATE.scan_delay,
        "auto_quarantine": LIVE_SCAN_STATE.auto_quarantine,
        "threat_report_interval": LIVE_SCAN_STATE.threat_report_interval,
        "stats": LIVE_SCAN_STATE.stats,
        "recent_threats": LIVE_SCAN_STATE.recent_threats,
    }


@router.post("/toggle")
def toggle_scanner(enabled: bool):
    """Enable or disable background scanner."""
    if LIVE_SCAN_STATE is None:
        raise HTTPException(status_code=503, detail="Scanner not initialized")
    
    LIVE_SCAN_STATE.enabled = enabled
    scanner = background.get_scanner()
    
    if enabled:
        scanner.start_monitoring(
            paths=LIVE_SCAN_STATE.paths,
            scan_callback=_threat_callback if _threat_callback else (lambda fp, res: None),
            exclude_patterns=LIVE_SCAN_STATE.exclude_patterns,
            scan_delay=LIVE_SCAN_STATE.scan_delay,
            threat_report_interval=LIVE_SCAN_STATE.threat_report_interval * 60,  # Convert minutes to seconds
        )
    else:
        scanner.stop_monitoring()
    
    return get_status()


@router.post("/add-path")
def add_scan_path(request: AddPathRequest):
    """Add a directory path to monitor."""
    if LIVE_SCAN_STATE is None:
        raise HTTPException(status_code=503, detail="Scanner not initialized")
    
    try:
        p = Path(request.path)
        if not p.exists() or not p.is_dir():
            raise HTTPException(status_code=400, detail="Path does not exist or is not a directory")
        
        if request.path not in LIVE_SCAN_STATE.paths:
            LIVE_SCAN_STATE.paths.append(request.path)
        
        # Restart monitoring
        scanner = background.get_scanner()
        if LIVE_SCAN_STATE.enabled:
            scanner.start_monitoring(
                paths=LIVE_SCAN_STATE.paths,
                scan_callback=_threat_callback if _threat_callback else (lambda fp, res: None),
                exclude_patterns=LIVE_SCAN_STATE.exclude_patterns,
                scan_delay=LIVE_SCAN_STATE.scan_delay,
                threat_report_interval=LIVE_SCAN_STATE.threat_report_interval * 60,  # Convert minutes to seconds
            )
        
        return {
            "success": True,
            "message": "Path added successfully",
            "path": request.path,
            "paths": LIVE_SCAN_STATE.paths
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error adding path: {str(e)}")


@router.delete("/remove-path")
def remove_scan_path(request: RemovePathRequest):
    """Remove a directory path from monitoring."""
    if LIVE_SCAN_STATE is None:
        raise HTTPException(status_code=503, detail="Scanner not initialized")
    
    try:
        if request.path in LIVE_SCAN_STATE.paths:
            LIVE_SCAN_STATE.paths.remove(request.path)
        
        # Restart monitoring
        scanner = background.get_scanner()
        if LIVE_SCAN_STATE.enabled:
            scanner.start_monitoring(
                paths=LIVE_SCAN_STATE.paths,
                scan_callback=_threat_callback if _threat_callback else (lambda fp, res: None),
                exclude_patterns=LIVE_SCAN_STATE.exclude_patterns,
                scan_delay=LIVE_SCAN_STATE.scan_delay,
                threat_report_interval=LIVE_SCAN_STATE.threat_report_interval * 60,  # Convert minutes to seconds
            )
        
        return {
            "success": True,
            "message": "Path removed successfully",
            "path": request.path,
            "paths": LIVE_SCAN_STATE.paths
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error removing path: {str(e)}")


@router.post("/config")
def update_config(request: UpdateConfigRequest):
    """Update background scanner configuration."""
    if LIVE_SCAN_STATE is None:
        raise HTTPException(status_code=503, detail="Scanner not initialized")
    
    if request.scan_delay is not None:
        LIVE_SCAN_STATE.scan_delay = max(0.1, min(10.0, request.scan_delay))
    
    if request.auto_quarantine is not None:
        LIVE_SCAN_STATE.auto_quarantine = request.auto_quarantine
    
    if request.exclude_patterns is not None:
        LIVE_SCAN_STATE.exclude_patterns = request.exclude_patterns
    
    if request.enabled is not None:
        LIVE_SCAN_STATE.enabled = request.enabled
    
    # Restart monitoring with new config
    scanner = background.get_scanner()
    if LIVE_SCAN_STATE.enabled:
        scanner.start_monitoring(
            paths=LIVE_SCAN_STATE.paths,
            scan_callback=_threat_callback if _threat_callback else (lambda fp, res: None),
            exclude_patterns=LIVE_SCAN_STATE.exclude_patterns,
            scan_delay=LIVE_SCAN_STATE.scan_delay,
            threat_report_interval=LIVE_SCAN_STATE.threat_report_interval * 60,  # Convert minutes to seconds
        )
    else:
        scanner.stop_monitoring()
    
    return get_status()


@router.get("/health")
def health_check():
    """Check if Background Scanner module is operational."""
    if LIVE_SCAN_STATE is None:
        return {
            "status": "error",
            "module": "background_scanner",
            "error": "Scanner not initialized"
        }
    return {
        "status": "operational",
        "module": "background_scanner",
        "enabled": LIVE_SCAN_STATE.enabled,
        "paths_count": len(LIVE_SCAN_STATE.paths),
        "auto_quarantine": LIVE_SCAN_STATE.auto_quarantine
    }

