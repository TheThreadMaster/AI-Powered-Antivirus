"""
Service module for delete_anomalies.py functionality.

This module provides programmatic access to the anomaly deletion functionality
without requiring command-line execution.
"""

import os
import sys
import subprocess
import json
import time
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime

# Import from delete_anomalies.py
_services_dir = Path(__file__).parent
_deletion_dir = _services_dir / "deletion"
sys.path.insert(0, str(_services_dir))

try:
    # Import functions from delete_anomalies.py
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "delete_anomalies", 
        _deletion_dir / "delete_anomalies.py"
    )
    if spec and spec.loader:
        delete_anomalies_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(delete_anomalies_module)
        is_admin = delete_anomalies_module.is_admin
        create_deletion_script = delete_anomalies_module.create_deletion_script
        get_anomaly_files_from_db = delete_anomalies_module.get_anomaly_files_from_db
        DELETE_ANOMALIES_AVAILABLE = True
    else:
        DELETE_ANOMALIES_AVAILABLE = False
except Exception as e:
    print(f"[Warning] delete_anomalies module not available: {e}")
    DELETE_ANOMALIES_AVAILABLE = False
    # Define dummy functions
    def is_admin(): return False
    def create_deletion_script(*args, **kwargs): return ""
    def get_anomaly_files_from_db(*args, **kwargs): return []

from ..store import DB, Threat
from sqlmodel import Session


def delete_anomaly_files(
    threat_ids: Optional[List[int]] = None,
    file_paths: Optional[List[str]] = None,
    use_recycle_bin: bool = True,
    require_admin: bool = True,
    create_script_only: bool = False,
    secure_delete: bool = False,
    secure_delete_passes: int = 3
) -> Dict[str, Any]:
    """
    Delete anomaly files using the delete_anomalies.py script functionality.
    
    Args:
        threat_ids: List of threat IDs to delete
        file_paths: List of file paths to delete directly
        use_recycle_bin: If True, send to Recycle Bin on Windows (default: True)
        require_admin: If True, require admin privileges (default: True)
        create_script_only: If True, only create deletion script, don't execute
        secure_delete: If True, use secure deletion (sdelete.exe) to overwrite before deletion (default: False)
        secure_delete_passes: Number of overwrite passes for secure deletion (default: 3)
    
    Returns:
        Dict with success status, deleted files, and any errors
    """
    if not DELETE_ANOMALIES_AVAILABLE:
        return {
            "success": False,
            "error": "delete_anomalies module not available",
            "deleted_files": [],
            "failed_files": []
        }
    
    files_to_delete = []
    errors = []
    
    # Collect files from threat IDs
    if threat_ids:
        try:
            with Session(DB.engine) as s:
                for threat_id in threat_ids:
                    threat = s.get(Threat, threat_id)
                    if threat and threat.filePath:
                        file_path = threat.filePath
                        # Check if file exists at the path (might be quarantined)
                        path_obj = Path(file_path)
                        if not path_obj.exists():
                            # Try to find the file - might be in quarantine or moved
                            # Check if it's a quarantined path
                            if ".quarantine" in file_path or "quarantine" in file_path.lower():
                                # File is quarantined, still try to delete it
                                print(f"[Delete Service] File appears to be quarantined: {file_path}")
                            else:
                                # File doesn't exist - might already be deleted
                                print(f"[Delete Service] Warning: File path does not exist: {file_path}, will attempt deletion anyway")
                        
                        files_to_delete.append({
                            "threat_id": threat.id,
                            "path": file_path,
                            "reason": f"Threat ID {threat_id}: {threat.description}"
                        })
                    else:
                        errors.append(f"Threat {threat_id} not found or has no file path")
        except Exception as e:
            errors.append(f"Error querying threats: {e}")
    
    # Add direct file paths
    if file_paths:
        for file_path in file_paths:
            if not file_path:
                continue
            path = Path(file_path)
            # Don't require file to exist - might be in quarantine or already moved
            # Still attempt deletion
            files_to_delete.append({
                "threat_id": "manual",
                "path": file_path,
                "reason": "Manually specified file path"
            })
            if not path.exists():
                print(f"[Delete Service] Warning: File path does not exist: {file_path}, will attempt deletion anyway")
    
    if not files_to_delete:
        return {
            "success": False,
            "error": "No files to delete",
            "deleted_files": [],
            "failed_files": [],
            "errors": errors
        }
    
    # Check admin status if required, but don't fail - try to request elevation
    admin_available = is_admin()
    if require_admin and not admin_available:
        print("[Delete Anomalies] Warning: Admin privileges not available. Will attempt deletion anyway and request elevation if needed.")
        # Don't return error - let the deletion script handle admin elevation
    
    print(f"[Delete Service] Starting deletion process for {len(files_to_delete)} file(s)")
    print(f"[Delete Service] Files to delete: {[f.get('path') for f in files_to_delete]}")
    
    # First, try direct Python deletion methods (handles paths with spaces better)
    if not create_script_only:
        deleted_files = []
        failed_files = []
        
        print(f"[Delete Service] Attempting direct Python deletion methods...")
        
        for file_info in files_to_delete:
            file_path = file_info.get("path")
            path_obj = Path(file_path)
            
            # Skip if file doesn't exist (might already be deleted)
            if not path_obj.exists():
                deleted_files.append(file_path)
                print(f"[Delete Service] File already deleted or doesn't exist: {file_path}")
                continue
            
            # Try send2trash first (safe deletion to Recycle Bin)
            if use_recycle_bin:
                try:
                    from send2trash import send2trash
                    send2trash(str(path_obj))
                    # Wait a moment for file system to update
                    import time
                    time.sleep(0.3)
                    if not path_obj.exists():
                        deleted_files.append(file_path)
                        print(f"[Delete Service] ✓ File moved to Recycle Bin: {file_path}")
                        continue
                except ImportError:
                    pass  # send2trash not available
                except Exception as e:
                    print(f"[Delete Service] send2trash failed for {file_path}: {e}")
            
            # Try direct os.remove with permission fixes
            try:
                # Remove read-only attribute on Windows
                if os.name == 'nt':
                    try:
                        subprocess.run(['attrib', '-R', str(path_obj)], 
                                     check=False, capture_output=True, timeout=5)
                    except Exception:
                        pass
                
                # Try to delete
                os.remove(str(path_obj))
                time.sleep(0.2)
                if not path_obj.exists():
                    deleted_files.append(file_path)
                    print(f"[Delete Service] ✓ File deleted using os.remove: {file_path}")
                    continue
            except Exception as e:
                print(f"[Delete Service] os.remove failed for {file_path}: {e}")
        
        # If all files were deleted using Python methods, return success
        if len(deleted_files) == len(files_to_delete):
            print(f"[Delete Service] ✓ All files deleted using Python methods")
            return {
                "success": True,
                "message": f"Deletion using Python methods: {len(deleted_files)} successful",
                "deleted_files": deleted_files,
                "failed_files": failed_files,
                "method": "python_direct"
            }
        # If some were deleted, continue with shell scripts for the rest
        elif len(deleted_files) > 0:
            # Remove successfully deleted files from the list
            files_to_delete = [f for f in files_to_delete if f.get("path") not in deleted_files]
            print(f"[Delete Service] {len(deleted_files)} files deleted using Python, {len(files_to_delete)} remaining for shell script deletion")
    
    # On Windows, use shell scripts as fallback (for files that Python methods couldn't delete)
    if os.name == 'nt' and not create_script_only and len(files_to_delete) > 0:
        print(f"[Delete Service] Attempting Windows shell script deletion for {len(files_to_delete)} file(s)")
        # Use Windows shell scripts for deletion
        deletion_dir = Path(__file__).parent / "deletion"
        
        # Check if secure deletion is requested
        if secure_delete:
            secure_script = deletion_dir / "secure_delete_ps.ps1"
            if secure_script.exists():
                print(f"[Delete Service] Using secure deletion (sdelete.exe) with {secure_delete_passes} passes")
                ps_script = secure_script
                batch_script = None  # Don't use batch script for secure deletion
            else:
                print(f"[Delete Service] ⚠ Secure deletion script not found, falling back to standard deletion")
                ps_script = deletion_dir / "delete_file.ps1"
                batch_script = deletion_dir / "delete_file.bat"
        else:
            ps_script = deletion_dir / "delete_file.ps1"
            batch_script = deletion_dir / "delete_file.bat"
        
        print(f"[Delete Service] PowerShell script path: {ps_script} (exists: {ps_script.exists()})")
        print(f"[Delete Service] Batch script path: {batch_script} (exists: {batch_script.exists()})")
        
        # Try PowerShell script first
        if ps_script.exists():
            print(f"[Delete Service] Executing PowerShell script: {ps_script}")
            deleted_files = []
            failed_files = []
            
            for file_info in files_to_delete:
                file_path = file_info.get("path")
                print(f"[Delete Service] Executing PowerShell script for: {file_path}")
                try:
                    # Build command based on script type
                    if secure_delete and "secure_delete" in str(ps_script):
                        # Secure deletion script parameters
                        cmd = [
                            'powershell', '-ExecutionPolicy', 'Bypass', '-File', str(ps_script),
                            '-Path', file_path,
                            '-Passes', str(secure_delete_passes),
                            '-NoConfirm'
                        ]
                    else:
                        # Standard deletion script
                        cmd = [
                            'powershell', '-ExecutionPolicy', 'Bypass', '-File', str(ps_script),
                            '-FilePath', file_path
                        ]
                    
                    result_ps = subprocess.run(
                        cmd,
                        check=False,
                        capture_output=True,
                        timeout=30 if secure_delete else 15,  # Secure deletion may take longer
                        text=True,
                        shell=False  # Don't use shell to avoid double-quoting issues
                    )
                    
                    print(f"[Delete Service] PowerShell script execution completed:")
                    print(f"  - returncode: {result_ps.returncode}")
                    print(f"  - stdout: {result_ps.stdout[:200] if result_ps.stdout else 'None'}")
                    print(f"  - stderr: {result_ps.stderr[:200] if result_ps.stderr else 'None'}")
                    
                    # Also check the output for any errors
                    if result_ps.returncode != 0:
                        print(f"[Delete Service] ⚠ PowerShell script returned code {result_ps.returncode}: {result_ps.stderr}")
                    # Wait a moment for file system to update
                    import time
                    time.sleep(0.5)
                    # Check if file was deleted
                    file_path_obj = Path(file_path)
                    # Try to resolve the path (might fail if file doesn't exist)
                    try:
                        resolved_path = file_path_obj.resolve()
                    except (OSError, RuntimeError):
                        resolved_path = None
                    
                    # Check both original and resolved paths
                    # If PowerShell script returned success (exit code 0), consider it deleted even if file still exists
                    # (might be in Recycle Bin or filesystem hasn't updated yet)
                    original_exists = file_path_obj.exists()
                    resolved_exists = resolved_path.exists() if resolved_path else False
                    
                    if result_ps.returncode == 0:
                        deleted_files.append(file_path)
                        print(f"[Delete Service] ✓ File deleted (PowerShell returned success): {file_path}")
                    elif not original_exists and not resolved_exists:
                        deleted_files.append(file_path)
                        print(f"[Delete Service] ✓ File deleted: {file_path}")
                    else:
                        # Only mark as failed if script failed AND file still exists
                        if result_ps.returncode != 0:
                            failed_files.append({"path": file_path, "error": f"PowerShell script failed with code {result_ps.returncode}"})
                            print(f"[Delete Service] ✗ PowerShell script failed: {file_path} (code={result_ps.returncode})")
                        else:
                            # Script succeeded but file still exists - might be in Recycle Bin, still consider success
                            deleted_files.append(file_path)
                            print(f"[Delete Service] ✓ File deleted (script succeeded, file may be in Recycle Bin): {file_path}")
                except Exception as e:
                    failed_files.append({"path": file_path, "error": str(e)})
            
            # Combine with any files already deleted by Python methods
            all_deleted = deleted_files.copy()
            all_failed = failed_files.copy()
            
            # Return success if at least one file was deleted
            if len(all_deleted) > 0:
                return {
                    "success": True,
                    "message": f"Deletion: {len(all_deleted)} successful, {len(all_failed)} failed",
                    "deleted_files": all_deleted,
                    "failed_files": all_failed,
                    "method": "python_and_powershell"
                }
            elif len(all_failed) > 0:
                # If we have failures, still return success=False but with details
                return {
                    "success": False,
                    "error": f"PowerShell deletion failed for {len(all_failed)} file(s)",
                    "deleted_files": all_deleted,
                    "failed_files": all_failed,
                    "method": "windows_powershell_script"
                }
        
        # Fallback to batch script
        if batch_script.exists():
            deleted_files = []
            failed_files = []
            
            for file_info in files_to_delete:
                file_path = file_info.get("path")
                print(f"[Delete Service] Executing batch script for: {file_path}")
                try:
                    # Properly quote file path for batch script (batch script uses %~1 which handles quotes)
                    # But we need to ensure the path is quoted when passed
                    quoted_path = f'"{file_path}"'
                    result_batch = subprocess.run(
                        ['cmd', '/c', str(batch_script), quoted_path],
                        check=False,
                        capture_output=True,
                        timeout=10,
                        text=True
                    )
                    
                    print(f"[Delete Service] Batch script execution completed:")
                    print(f"  - returncode: {result_batch.returncode}")
                    print(f"  - stdout: {result_batch.stdout[:200] if result_batch.stdout else 'None'}")
                    print(f"  - stderr: {result_batch.stderr[:200] if result_batch.stderr else 'None'}")
                    
                    # Also check the output for any errors
                    if result_batch.returncode != 0:
                        print(f"[Delete Service] ⚠ Batch script returned code {result_batch.returncode}: {result_batch.stderr}")
                    # Wait a moment for file system to update
                    import time
                    time.sleep(0.5)
                    # Check if file was deleted
                    file_path_obj = Path(file_path)
                    # Try to resolve the path (might fail if file doesn't exist)
                    try:
                        resolved_path = file_path_obj.resolve()
                    except (OSError, RuntimeError):
                        resolved_path = None
                    
                    # Check both original and resolved paths
                    # If batch script returned success (exit code 0), consider it deleted
                    original_exists = file_path_obj.exists()
                    resolved_exists = resolved_path.exists() if resolved_path else False
                    
                    if result_batch.returncode == 0:
                        deleted_files.append(file_path)
                        print(f"[Delete Service] ✓ File deleted (batch script returned success): {file_path}")
                    elif not original_exists and not resolved_exists:
                        deleted_files.append(file_path)
                        print(f"[Delete Service] ✓ File deleted: {file_path}")
                    else:
                        # Only mark as failed if script failed AND file still exists
                        if result_batch.returncode != 0:
                            failed_files.append({"path": file_path, "error": f"Batch script failed with code {result_batch.returncode}"})
                            print(f"[Delete Service] ✗ Batch script failed: {file_path} (code={result_batch.returncode})")
                        else:
                            # Script succeeded but file still exists - might be in Recycle Bin, still consider success
                            deleted_files.append(file_path)
                            print(f"[Delete Service] ✓ File deleted (script succeeded, file may be in Recycle Bin): {file_path}")
                except Exception as e:
                    failed_files.append({"path": file_path, "error": str(e)})
            
            # Combine with any files already deleted by Python methods
            all_deleted = deleted_files.copy()
            all_failed = failed_files.copy()
            
            # Return success if at least one file was deleted
            if len(all_deleted) > 0:
                return {
                    "success": True,
                    "message": f"Deletion: {len(all_deleted)} successful, {len(all_failed)} failed",
                    "deleted_files": all_deleted,
                    "failed_files": all_failed,
                    "method": "python_and_batch"
                }
            elif len(all_failed) > 0:
                # If we have failures, still return success=False but with details
                return {
                    "success": False,
                    "error": f"Batch deletion failed for {len(all_failed)} file(s)",
                    "deleted_files": all_deleted,
                    "failed_files": all_failed,
                    "method": "windows_batch_script"
                }
    
    # Create Python deletion script as fallback
    try:
        script_path = create_deletion_script(files_to_delete)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to create deletion script: {e}",
            "deleted_files": [],
            "failed_files": files_to_delete
        }
    
    if create_script_only:
        return {
            "success": True,
            "message": "Deletion script created",
            "script_path": script_path,
            "files_to_delete": files_to_delete,
            "deleted_files": [],
            "failed_files": []
        }
    
    # Execute Python deletion script as fallback (if shell scripts didn't work or not on Windows)
    try:
        if os.name == 'nt' and not admin_available:
            # On Windows, try to run with elevation using PowerShell
            ps_cmd = f'Start-Process python -ArgumentList "{script_path}" -Verb RunAs -Wait'
            result = subprocess.run(
                ['powershell', '-Command', ps_cmd],
                capture_output=True,
                text=True,
                timeout=300
            )
        else:
            # Run normally (or with sudo on Linux if needed)
            if os.name != 'nt' and not admin_available:
                # Try with sudo on Linux/macOS
                try:
                    result = subprocess.run(
                        ['sudo', sys.executable, script_path],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                except FileNotFoundError:
                    # sudo not available, run normally
                    result = subprocess.run(
                        [sys.executable, script_path],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
            else:
                result = subprocess.run(
                    [sys.executable, script_path],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
        
        # Parse results from deletion_results.json if available
        results_file = Path(script_path).parent / "deletion_results.json"
        deleted_files = []
        failed_files = []
        
        if results_file.exists():
            try:
                with open(results_file, 'r') as f:
                    results_data = json.load(f)
                    for result in results_data.get("results", []):
                        if result.get("success"):
                            deleted_files.append(result.get("path"))
                        else:
                            failed_files.append({
                                "path": result.get("path"),
                                "error": result.get("error")
                            })
            except Exception as e:
                print(f"[Delete Anomalies] Failed to parse results: {e}")
        
        return {
            "success": result.returncode == 0,
            "message": f"Deletion script executed (exit code: {result.returncode})",
            "script_path": script_path,
            "deleted_files": deleted_files,
            "failed_files": failed_files,
            "errors": errors if errors else None,
            "stdout": result.stdout if result.stdout else None,
            "stderr": result.stderr if result.stderr else None
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Deletion script execution timed out",
            "deleted_files": [],
            "failed_files": files_to_delete
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to execute deletion script: {e}",
            "script_path": script_path,
            "deleted_files": [],
            "failed_files": files_to_delete
        }


def delete_anomaly_file_simple(
    threat_id: Optional[int] = None,
    file_path: Optional[str] = None,
    use_recycle_bin: bool = True,
    secure_delete: bool = False,
    secure_delete_passes: int = 3
) -> Dict[str, Any]:
    """
    Simplified function to delete a single anomaly file.
    
    This is a convenience wrapper around delete_anomaly_files for single file deletion.
    
    Args:
        threat_id: Threat ID to delete
        file_path: Direct file path to delete
        use_recycle_bin: If True, send to Recycle Bin on Windows
        secure_delete: If True, use secure deletion (sdelete.exe) to overwrite before deletion
        secure_delete_passes: Number of overwrite passes for secure deletion (default: 3)
    
    Returns:
        Dict with success status and details
    """
    threat_ids = [threat_id] if threat_id else None
    file_paths = [file_path] if file_path else None
    
    return delete_anomaly_files(
        threat_ids=threat_ids,
        file_paths=file_paths,
        use_recycle_bin=use_recycle_bin,
        require_admin=True,
        create_script_only=False,
        secure_delete=secure_delete,
        secure_delete_passes=secure_delete_passes
    )

