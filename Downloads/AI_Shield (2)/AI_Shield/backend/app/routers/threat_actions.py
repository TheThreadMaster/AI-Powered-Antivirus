"""Threat Actions Module - File quarantine and deletion endpoints."""
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from sqlmodel import Session

from ..services import threat_actions
from ..store import DB, Threat

router = APIRouter(prefix="/api/threats/actions", tags=["Threat Actions"])


class QuarantineRequest(BaseModel):
    threat_id: int


class RestoreRequest(BaseModel):
    quarantined_filename: str
    restore_path: Optional[str] = None


class DeleteRequest(BaseModel):
    threat_id: int
    use_recycle_bin: Optional[bool] = True  # Send to Recycle Bin on Windows (default: True)


class RestrictPermissionsRequest(BaseModel):
    file_path: str
    level: Optional[str] = "standard"  # standard, strict, moderate


@router.post("/quarantine")
def quarantine_file_endpoint(request: QuarantineRequest):
    """
    Quarantine a file associated with a threat.
    
    Moves file to quarantine directory with obfuscated name and restrictive permissions.
    """
    try:
        with Session(DB.engine) as s:
            threat = s.get(Threat, request.threat_id)
            if not threat:
                raise HTTPException(status_code=404, detail="Threat not found")
            
            success = threat_actions.quarantine_file(threat)
            if success:
                return {
                    "success": True,
                    "message": "File quarantined successfully",
                    "threat_id": request.threat_id
                }
            else:
                raise HTTPException(status_code=500, detail="Failed to quarantine file")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error quarantining file: {str(e)}")


@router.post("/delete")
def delete_file_endpoint(request: DeleteRequest):
    """
    Delete a file associated with a threat using delete_anomalies.py script.
    
    On Windows: Sends file to Recycle Bin by default (can be permanently deleted).
    On Linux/macOS: Permanently deletes the file.
    
    This endpoint uses the enhanced delete_anomalies.py script which:
    - Handles admin authorization automatically
    - Creates a separate deletion script for execution
    - Provides better error handling and logging
    
    Args:
        threat_id: ID of the threat to delete
        use_recycle_bin: If True (default), send to Recycle Bin on Windows.
                        On Linux/macOS, this parameter is ignored (always permanent).
    """
    try:
        with Session(DB.engine) as s:
            threat = s.get(Threat, request.threat_id)
            if not threat:
                raise HTTPException(status_code=404, detail="Threat not found")
            
            # Try using delete_anomalies.py script first
            try:
                from ..services import delete_anomalies_service
                delete_result = delete_anomalies_service.delete_anomaly_file_simple(
                    threat_id=request.threat_id,
                    use_recycle_bin=request.use_recycle_bin
                )
                
                if delete_result.get("success"):
                    deletion_method = "Recycle Bin" if (os.name == 'nt' and request.use_recycle_bin) else "permanently deleted"
                    return {
                        "success": True,
                        "message": f"File {deletion_method} successfully using delete_anomalies.py",
                        "threat_id": request.threat_id,
                        "permanently_deleted": not (os.name == 'nt' and request.use_recycle_bin),
                        "deletion_method": deletion_method,
                        "deleted_files": delete_result.get("deleted_files", []),
                        "script_used": True
                    }
                else:
                    # Fall through to standard deletion if delete_anomalies.py fails
                    error_msg = delete_result.get("error", "Unknown error")
                    print(f"[Delete Endpoint] delete_anomalies.py failed: {error_msg}, using fallback")
            except ImportError:
                # delete_anomalies_service not available, use fallback
                pass
            except Exception as e:
                print(f"[Delete Endpoint] Error using delete_anomalies.py: {e}, using fallback")
            
            # Fallback to standard deletion method
            result = threat_actions.delete_file(threat, use_recycle_bin=request.use_recycle_bin)
            
            if result is None:
                deletion_method = "Recycle Bin" if (os.name == 'nt' and request.use_recycle_bin) else "permanently deleted"
                return {
                    "success": True,
                    "message": f"File {deletion_method} successfully",
                    "threat_id": request.threat_id,
                    "permanently_deleted": not (os.name == 'nt' and request.use_recycle_bin),
                    "deletion_method": deletion_method,
                    "script_used": False
                }
            else:
                return {
                    "success": False,
                    "message": "File deletion failed",
                    "threat_id": request.threat_id,
                    "permanently_deleted": False,
                    "script_used": False
                }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting file: {str(e)}")


@router.get("/quarantined")
def list_quarantined_files():
    """
    List all quarantined files with metadata.
    
    Returns list of quarantined files with original and obfuscated names.
    """
    try:
        files = threat_actions.list_quarantined_files()
        return {
            "count": len(files),
            "files": files
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing quarantined files: {str(e)}")


@router.post("/restore")
def restore_file_endpoint(request: RestoreRequest):
    """
    Restore a quarantined file to its original location or specified path.
    """
    try:
        success = threat_actions.restore_quarantined_file(
            request.quarantined_filename,
            request.restore_path
        )
        if success:
            return {
                "success": True,
                "message": "File restored successfully",
                "quarantined_filename": request.quarantined_filename,
                "restore_path": request.restore_path
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to restore file")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error restoring file: {str(e)}")


@router.post("/restrict-permissions")
def restrict_permissions_endpoint(request: RestrictPermissionsRequest):
    """
    Manually restrict permissions on an anomaly file without quarantining it.
    
    This endpoint allows you to restrict permissions on files detected as anomalies
    (high risk, suspicious, or malicious files) without moving them to quarantine.
    Useful for in-place protection of suspicious files.
    
    Permission levels:
    - "standard": Read-only, no execute (default)
    - "strict": Maximum restrictions (no permissions on Unix, all denies on Windows)
    - "moderate": Read-only with minimal restrictions
    """
    try:
        # Validate level
        valid_levels = ["standard", "strict", "moderate"]
        level = request.level.lower() if request.level else "standard"
        if level not in valid_levels:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid permission level. Must be one of: {', '.join(valid_levels)}"
            )
        
        result = threat_actions.restrict_anomaly_file_permissions(request.file_path, level)
        
        if result["success"]:
            return result
        else:
            raise HTTPException(
                status_code=500, 
                detail=result.get("message", "Failed to restrict permissions")
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error restricting permissions: {str(e)}")


@router.get("/health")
def health_check():
    """Check if Threat Actions module is operational."""
    try:
        quarantined = threat_actions.list_quarantined_files()
        return {
            "status": "operational",
            "module": "threat_actions",
            "quarantined_count": len(quarantined)
        }
    except Exception as e:
        return {
            "status": "error",
            "module": "threat_actions",
            "error": str(e)
        }

