"""
threat_actions.py - Threat action handlers for quarantine and deletion.

This module provides functions for:
- Quarantining threat files (using quarantine_manager.py)
- Deleting threat files (using delete_anomalies_service.py)
- Restricting file permissions
- Listing and restoring quarantined files

Run check_threat_actions.py to verify this file has no errors.
"""

from pathlib import Path
import os
import shutil
import hashlib
import json
import time
import stat
import subprocess
import logging
from typing import Optional, Dict, Any
from datetime import datetime
from sqlmodel import Session
from ..store import DB, Threat

# Safe deletion support (cross-platform - uses send2trash)
SEND2TRASH_AVAILABLE = False
try:
    from send2trash import send2trash
    SEND2TRASH_AVAILABLE = True
except ImportError:
    SEND2TRASH_AVAILABLE = False
    print("[Delete] send2trash not installed - will use permanent deletion. Install with: pip install send2trash")

# Windows Recycle Bin support (fallback - requires pywin32)
WINDOWS_RECYCLE_BIN_AVAILABLE = False
if os.name == 'nt':
    try:
        from win32com.shell import shell, shellcon
        WINDOWS_RECYCLE_BIN_AVAILABLE = True
    except ImportError:
        WINDOWS_RECYCLE_BIN_AVAILABLE = False

def _generate_quarantine_filename(original_path: Path, file_hash: str) -> str:
    """Generate an obfuscated quarantine filename.
    
    Format: Q{hash_prefix}_{timestamp}.quarantine
    Example: Qa3f2b1c_1704067200.quarantine
    """
    timestamp = int(time.time())
    hash_prefix = file_hash[:8]  # First 8 chars of hash
    return f"Q{hash_prefix}_{timestamp}.quarantine"

def _set_restrictive_permissions(file_path: Path, level: str = "standard") -> bool:
    """Set restrictive OS-level permissions to prevent execution and modification.
    
    Args:
        file_path: Path to the file
        level: Permission restriction level
            - "standard": Read-only, no execute (default)
            - "strict": No permissions at all (000 on Unix, maximum restrictions on Windows)
            - "moderate": Read-only with minimal restrictions
    
    Windows: Remove execute permissions, set read-only
    Linux/macOS: Remove execute and write permissions (chmod 444 or 000)
    
    Returns True if successful, False otherwise.
    """
    try:
        if os.name == 'nt':  # Windows
            # Remove read-only attribute first to allow modification
            try:
                subprocess.run(['attrib', '-R', str(file_path)], 
                             check=False, capture_output=True, timeout=5)
            except Exception:
                pass
            
            if level == "strict":
                # Maximum restrictions: read-only + deny all execute
                try:
                    subprocess.run(['attrib', '+R', str(file_path)], 
                                 check=False, capture_output=True, timeout=5)
                    # Deny execute for all users
                    subprocess.run(['icacls', str(file_path), '/deny', 'Everyone:(X)'], 
                                 check=False, capture_output=True, timeout=5)
                    # Deny write for all users
                    subprocess.run(['icacls', str(file_path), '/deny', 'Everyone:(W)'], 
                                 check=False, capture_output=True, timeout=5)
                except Exception:
                    pass
            elif level == "moderate":
                # Moderate: read-only only
                try:
                    subprocess.run(['attrib', '+R', str(file_path)], 
                                 check=False, capture_output=True, timeout=5)
                except Exception:
                    pass
            else:  # standard
                # Set read-only (removes write permission)
                try:
                    subprocess.run(['attrib', '+R', str(file_path)], 
                                 check=False, capture_output=True, timeout=5)
                except Exception:
                    pass
                
                # Remove execute permission using icacls (if available)
                try:
                    # Deny execute permission for all users
                    subprocess.run(['icacls', str(file_path), '/deny', 'Everyone:(X)'], 
                                 check=False, capture_output=True, timeout=5)
                except Exception:
                    # Fallback: Use Python stat to remove execute bits
                    try:
                        current_mode = os.stat(str(file_path)).st_mode
                        # Remove execute permissions: S_IXUSR, S_IXGRP, S_IXOTH
                        new_mode = current_mode & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                        os.chmod(str(file_path), new_mode)
                    except Exception:
                        pass
            
            return True
        else:  # Linux/macOS
            if level == "strict":
                # Maximum security: no permissions at all (000)
                try:
                    os.chmod(str(file_path), 0)
                    return True
                except Exception as e:
                    print(f"[Permissions] Failed to set strict permissions on {file_path}: {e}")
                    return False
            elif level == "moderate":
                # Moderate: read-only for owner only (400)
                try:
                    os.chmod(str(file_path), stat.S_IRUSR)
                    return True
                except Exception as e:
                    print(f"[Permissions] Failed to set moderate permissions on {file_path}: {e}")
                    return False
            else:  # standard
                # Set permissions to 444 (read-only, no execute, no write)
                try:
                    os.chmod(str(file_path), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
                    return True
                except Exception as e:
                    print(f"[Permissions] Failed to set permissions on {file_path}: {e}")
                    return False
    except Exception as e:
        print(f"[Permissions] Error setting restrictive permissions: {e}")
        return False


def restrict_anomaly_file_permissions(file_path: str, level: str = "standard") -> Dict[str, Any]:
    """Manually restrict permissions on an anomaly file without quarantining it.
    
    This function allows manual permission restriction on files detected as anomalies
    (high risk, suspicious, or malicious files) without moving them to quarantine.
    Useful for in-place protection of suspicious files.
    
    Args:
        file_path: Path to the anomaly file
        level: Permission restriction level
            - "standard": Read-only, no execute (default)
            - "strict": Maximum restrictions (no permissions on Unix, all denies on Windows)
            - "moderate": Read-only with minimal restrictions
    
    Returns:
        Dictionary with operation result:
        {
            "success": bool,
            "message": str,
            "file_path": str,
            "level": str,
            "permissions_before": str (optional),
            "permissions_after": str (optional)
        }
    """
    p = Path(file_path)
    
    if not p.exists() or not p.is_file():
        return {
            "success": False,
            "message": "File not found",
            "file_path": file_path,
            "level": level
        }
    
    try:
        # Get current permissions for logging
        permissions_before = None
        permissions_after = None
        
        if os.name == 'nt':  # Windows
            try:
                result = subprocess.run(['icacls', str(p)], 
                                      check=False, capture_output=True, timeout=5, text=True)
                permissions_before = result.stdout.strip() if result.returncode == 0 else "unknown"
            except Exception:
                pass
        else:  # Linux/macOS
            try:
                current_mode = os.stat(str(p)).st_mode
                permissions_before = oct(current_mode & 0o777)
            except Exception:
                pass
        
        # Make file writable temporarily to allow permission changes
        try:
            if os.name == 'nt':  # Windows
                subprocess.run(['attrib', '-R', str(p)], 
                             check=False, capture_output=True, timeout=5)
            else:  # Linux/macOS
                current_mode = os.stat(str(p)).st_mode
                os.chmod(str(p), current_mode | stat.S_IWRITE)
        except Exception as e:
            print(f"[Permissions] Warning: Could not make file writable temporarily: {e}")
        
        # Set restrictive permissions
        success = _set_restrictive_permissions(p, level)
        
        if success:
            # Get permissions after change
            if os.name == 'nt':  # Windows
                try:
                    result = subprocess.run(['icacls', str(p)], 
                                          check=False, capture_output=True, timeout=5, text=True)
                    permissions_after = result.stdout.strip() if result.returncode == 0 else "unknown"
                except Exception:
                    pass
            else:  # Linux/macOS
                try:
                    current_mode = os.stat(str(p)).st_mode
                    permissions_after = oct(current_mode & 0o777)
                except Exception:
                    pass
            
            print(f"[Permissions] Successfully restricted permissions on {file_path} (level: {level})")
            return {
                "success": True,
                "message": f"Permissions restricted successfully (level: {level})",
                "file_path": file_path,
                "level": level,
                "permissions_before": permissions_before,
                "permissions_after": permissions_after
            }
        else:
            return {
                "success": False,
                "message": "Failed to set restrictive permissions",
                "file_path": file_path,
                "level": level,
                "permissions_before": permissions_before
            }
    
    except Exception as e:
        print(f"[Permissions] Error restricting permissions on {file_path}: {e}")
        import traceback
        traceback.print_exc()
        return {
            "success": False,
            "message": f"Error: {str(e)}",
            "file_path": file_path,
            "level": level
        }

def _save_quarantine_metadata(quarantine_dir: Path, original_path: Path, 
                              obfuscated_name: str, threat: Threat) -> bool:
    """Save metadata about the quarantined file for recovery purposes.
    
    Creates a JSON file with original filename, path, timestamp, and threat info.
    """
    try:
        metadata_file = quarantine_dir / f"{Path(obfuscated_name).stem}.meta.json"
        metadata = {
            "original_filename": original_path.name,
            "original_path": str(original_path),
            "original_extension": original_path.suffix,
            "quarantined_filename": obfuscated_name,
            "quarantine_timestamp": datetime.now().isoformat(),
            "threat_id": threat.id,
            "threat_severity": threat.severity,
            "threat_source": threat.source,
            "threat_description": threat.description,
            "file_size": original_path.stat().st_size if original_path.exists() else 0,
            "actions": [{
                "action": "quarantined",
                "timestamp": datetime.now().isoformat(),
                "description": f"File quarantined with obfuscated name and .quarantine extension"
            }]
        }
        
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        # Also set restrictive permissions on metadata file (standard level)
        _set_restrictive_permissions(metadata_file, level="standard")
        return True
    except Exception as e:
        print(f"[Quarantine] Failed to save metadata: {e}")
        return False


def _add_quarantine_action(quarantine_dir: Path, quarantined_filename: str, 
                           action: str, description: str) -> bool:
    """Add an action to the quarantine metadata file."""
    try:
        metadata_file = quarantine_dir / f"{Path(quarantined_filename).stem}.meta.json"
        if not metadata_file.exists():
            return False
        
        # Read existing metadata
        with open(metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        
        # Add action
        if "actions" not in metadata:
            metadata["actions"] = []
        
        metadata["actions"].append({
            "action": action,
            "timestamp": datetime.now().isoformat(),
            "description": description
        })
        
        # Keep only last 50 actions
        metadata["actions"] = metadata["actions"][-50:]
        
        # Write back
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        return True
    except Exception as e:
        print(f"[Quarantine] Failed to add action: {e}")
        return False

def _compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        # Fallback: use filename and timestamp if file can't be read
        return hashlib.sha256(f"{file_path}_{time.time()}".encode()).hexdigest()

def _is_admin() -> bool:
    """Check if running with admin privileges."""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/macOS
            return os.geteuid() == 0
    except Exception:
        return False


def _request_admin_elevation_for_quarantine(file_path: str) -> bool:
    """Request admin elevation for quarantine operation."""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            if not _is_admin():
                # Use PowerShell to run with elevation
                import sys
                ps_script = f'''
                Start-Process python -ArgumentList "-c", "import sys; sys.path.insert(0, r'{Path(__file__).parent.parent.parent}'); from app.services import threat_actions; from app.store import DB, Threat; from sqlmodel import Session; s = Session(DB.engine); t = s.query(Threat).filter_by(filePath=r'{file_path}').first(); threat_actions.quarantine_file(t) if t else None" -Verb RunAs
                '''
                subprocess.run(['powershell', '-Command', ps_script], check=False, timeout=10)
                return True
        else:  # Linux/macOS
            if not _is_admin():
                # Would need sudo, but this is complex - just try without for now
                pass
    except Exception as e:
        print(f"[Quarantine] Failed to request admin elevation: {e}")
    return False


def quarantine_file(threat: Threat) -> bool:
    """Enhanced quarantine algorithm using quarantine_manager.py script.
    
    This function uses the quarantine_manager.py script which:
    1. Moves file to quarantine directory (~/.quarantine)
    2. Computes and stores SHA256 hash
    3. Obfuscates filename with timestamp and hash
    4. Changes extension to .quarantine to prevent execution
    5. Locks file permissions (Windows icacls, POSIX chmod/chattr)
    6. Stores metadata in SQLite database
    7. Tracks user, timestamp, and reason
    
    Returns True if successful, False otherwise.
    """
    if not threat or not threat.filePath:
        return False
    
    src = Path(threat.filePath)
    threat_id = threat.id
    
    # Try using quarantine_manager.py script first (preferred method)
    try:
        import sys
        import importlib.util
        from pathlib import Path as PathLib
        
        print(f"[Quarantine] Attempting to use quarantine_manager.py for threat {threat_id}, file: {src}")
        
        # Import quarantine_manager from services/quarantine directory
        services_dir = PathLib(__file__).parent
        quarantine_dir = services_dir / "quarantine"
        quarantine_manager_path = quarantine_dir / "quarantine_manager.py"
        
        print(f"[Quarantine] Looking for quarantine_manager at: {quarantine_manager_path}")
        
        if not quarantine_manager_path.exists():
            raise ImportError(f"quarantine_manager.py not found at {quarantine_manager_path}")
        
        spec = importlib.util.spec_from_file_location(
            "quarantine_manager",
            quarantine_manager_path
        )
        if not spec or not spec.loader:
            raise ImportError(f"Failed to create spec for quarantine_manager")
        
        quarantine_manager_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(quarantine_manager_module)
        quarantine_manager_quarantine = quarantine_manager_module.quarantine
        
        print(f"[Quarantine] Successfully imported quarantine_manager module")
        
        # Prepare metadata
        metadata = {
            "severity": threat.severity,
            "source": threat.source,
            "description": threat.description,
            "threat_id": threat_id
        }
        
        # Quarantine using quarantine_manager
        print(f"[Quarantine] Calling quarantine_manager.quarantine() for: {src}")
        result = quarantine_manager_quarantine(
            path_str=str(src),
            reason=f"Threat detected: {threat.description or 'Unknown threat'}",
            threat_id=threat_id,
            metadata=metadata
        )
        
        print(f"[Quarantine] quarantine_manager.quarantine() returned: {result}")
        
        if result:
            # Update threat in database
            with Session(DB.engine) as s:
                obj = s.get(Threat, threat_id)
                if obj:
                    obj.action = "quarantined"
                    # Update filePath to point to quarantine location
                    from pathlib import Path as PathLib
                    quarantine_path = str(PathLib.home() / ".quarantine" / result.get("stored_name", ""))
                    obj.filePath = quarantine_path if result.get("stored_name") else str(src)
                    s.add(obj)
                    s.commit()
                    print(f"[Quarantine] ✓ Successfully quarantined using quarantine_manager.py")
                    print(f"  - stored_name: {result.get('stored_name')}")
                    print(f"  - quarantine_path: {quarantine_path}")
                    print(f"  - threat_id: {threat_id} updated in database")
                    return True
        else:
            print("[Quarantine] quarantine_manager.py returned None, falling back to standard method")
    except ImportError as e:
        print(f"[Quarantine] quarantine_manager not available: {e}, using fallback")
    except Exception as e:
        print(f"[Quarantine] Error using quarantine_manager.py: {e}, using fallback")
        import traceback
        traceback.print_exc()
    
    # Fallback to standard quarantine method
    file_moved = False
    file_hash = ""
    
    # Check if admin is needed and request if necessary
    admin_available = _is_admin()
    if not admin_available:
        print("[Quarantine] Warning: Not running with admin privileges. Some operations may fail.")
    
    try:
        qdir = Path("backend") / "quarantine"
        qdir.mkdir(parents=True, exist_ok=True)
        
        if src.exists() and src.is_file():
            # Step 1: Compute file hash for obfuscated naming
            try:
                file_hash = _compute_file_hash(src)
            except Exception as e:
                print(f"[Quarantine] Warning: Could not compute hash, using fallback: {e}")
                file_hash = hashlib.sha256(f"{src}_{time.time()}".encode()).hexdigest()
            
            # Step 2: Generate obfuscated filename with .quarantine extension
            obfuscated_name = _generate_quarantine_filename(src, file_hash)
            dst = qdir / obfuscated_name
            
            # Step 3: Ensure unique filename (in case of hash collision)
            counter = 1
            original_dst = dst
            while dst.exists():
                stem = original_dst.stem
                dst = qdir / f"{stem}_{counter}.quarantine"
                counter += 1
                if counter > 1000:  # Safety limit
                    raise Exception("Too many filename collisions")
            
            # Step 4: Make source file writable if needed (to allow move)
            try:
                if os.name == 'nt':  # Windows
                    try:
                        # Remove read-only attribute temporarily
                        subprocess.run(['attrib', '-R', str(src)], 
                                     check=False, capture_output=True, timeout=5)
                        os.chmod(str(src), stat.S_IWRITE | stat.S_IREAD)
                    except Exception:
                        pass
                else:  # Linux/macOS
                    try:
                        # Make writable temporarily
                        current_mode = os.stat(str(src)).st_mode
                        os.chmod(str(src), current_mode | stat.S_IWRITE)
                    except Exception:
                        pass
            except Exception as e:
                print(f"[Quarantine] Warning: Could not modify source permissions: {e}")
            
            # Step 5: Move file to quarantine directory
            try:
                shutil.move(str(src), str(dst))
                file_moved = True
                print(f"[Quarantine] Moved file: {src.name} -> {dst.name}")
            except PermissionError:
                # On Windows, try to force move using elevated permissions
                if os.name == 'nt':
                    try:
                        subprocess.run(['attrib', '-R', str(src)], 
                                     check=False, capture_output=True, timeout=5)
                        shutil.move(str(src), str(dst))
                        file_moved = True
                        print(f"[Quarantine] Moved file with elevated permissions: {src.name} -> {dst.name}")
                    except Exception as e:
                        print(f"[Quarantine] Failed to move file with elevated permissions: {e}")
                        return False
                else:
                    print(f"[Quarantine] Permission denied moving file: {src}")
                    return False
            except Exception as e:
                print(f"[Quarantine] Error moving file: {e}")
                return False
            
            # Step 6: Set restrictive permissions on quarantined file (use strict level for quarantined files)
            if file_moved and dst.exists():
                perm_success = _set_restrictive_permissions(dst, level="strict")
                if perm_success:
                    print(f"[Quarantine] Set restrictive permissions on: {dst.name}")
                else:
                    print(f"[Quarantine] Warning: Could not set all restrictive permissions on: {dst.name}")
                
                # Step 7: Save metadata for recovery
                _save_quarantine_metadata(qdir, src, dst.name, threat)
        
        # Step 8: Update threat action in database (don't delete, mark as quarantined)
        with Session(DB.engine) as s:
            obj = s.get(Threat, threat_id)
            if obj:
                obj.action = "quarantined"
                obj.filePath = str(dst)  # Update path to quarantined location
                s.add(obj)
                s.commit()
                print(f"[Quarantine] Updated threat {threat_id} action to 'quarantined'")
        
        return file_moved or not src.exists()  # Success if file was moved or no longer exists
    
    except Exception as e:
        print(f"[Quarantine] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False

def list_quarantined_files() -> list[Dict[str, Any]]:
    """List all files in the quarantine directory with their metadata.
    
    Uses quarantine_manager.py to get quarantined files from SQLite database.
    Falls back to old method if quarantine_manager is not available.
    
    Returns a list of dictionaries containing:
    - quarantined_filename: The obfuscated filename
    - original_filename: The original filename
    - original_path: The original file path
    - quarantine_timestamp: When the file was quarantined
    - threat_severity: Severity of the threat
    - file_size: Size of the file in bytes
    """
    # Try using quarantine_manager.py first (preferred method)
    try:
        import sys
        from pathlib import Path as PathLib
        
        # Import quarantine_manager from services/quarantine directory
        services_dir = PathLib(__file__).parent
        quarantine_dir = services_dir / "quarantine"
        sys.path.insert(0, str(quarantine_dir))
        
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "quarantine_manager",
            quarantine_dir / "quarantine_manager.py"
        )
        if spec and spec.loader:
            quarantine_manager_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(quarantine_manager_module)
            list_quarantined_func = quarantine_manager_module.list_quarantined
            
            # Get quarantined items from SQLite database
            items = list_quarantined_func()
            
            # Convert to expected format
            quarantined_files = []
            for item in items:
                # Skip if already purged or restored (only show active quarantined items)
                state = item.get("state")
                if state and state not in ("quarantined", None):
                    continue
                
                stored_name = item.get("stored_name", "")
                original_path = item.get("original_path", "")
                
                # Parse metadata (it might be a dict or JSON string)
                metadata_dict = {}
                metadata_raw = item.get("metadata")
                if metadata_raw:
                    if isinstance(metadata_raw, dict):
                        metadata_dict = metadata_raw
                    elif isinstance(metadata_raw, str):
                        try:
                            import json
                            metadata_dict = json.loads(metadata_raw)
                        except Exception:
                            pass
                
                # Build file info
                file_info = {
                    "quarantined_filename": stored_name,
                    "quarantined_path": str(PathLib.home() / ".quarantine" / stored_name),
                    "original_filename": PathLib(original_path).name if original_path else None,
                    "original_path": original_path,
                    "quarantine_timestamp": item.get("timestamp", ""),
                    "threat_severity": metadata_dict.get("severity", "unknown") if metadata_dict else "unknown",
                    "file_size": item.get("size", 0),
                    "permission_level": "strict",
                    "actions": [
                        {
                            "action": "quarantined",
                            "timestamp": item.get("timestamp", ""),
                            "description": item.get("reason", "File quarantined")
                        }
                    ]
                }
                
                quarantined_files.append(file_info)
            
            # Sort by timestamp (newest first)
            quarantined_files.sort(
                key=lambda x: x.get("quarantine_timestamp", ""), 
                reverse=True
            )
            
            print(f"[Quarantine] Listed {len(quarantined_files)} quarantined files from quarantine_manager")
            return quarantined_files
    except ImportError as e:
        print(f"[Quarantine] quarantine_manager not available: {e}, using fallback")
    except Exception as e:
        print(f"[Quarantine] Error using quarantine_manager: {e}, using fallback")
        import traceback
        traceback.print_exc()
    
    # Fallback to old method (check backend/quarantine directory)
    qdir = Path("backend") / "quarantine"
    if not qdir.exists():
        return []
    
    quarantined_files = []
    
    try:
        # Find all .quarantine files
        for file_path in qdir.glob("*.quarantine"):
            metadata_file = qdir / f"{file_path.stem}.meta.json"
            
            metadata = {
                "quarantined_filename": file_path.name,
                "quarantined_path": str(file_path),
                "file_size": file_path.stat().st_size if file_path.exists() else 0,
            }
            
            # Load metadata if available
            if metadata_file.exists():
                try:
                    with open(metadata_file, 'r', encoding='utf-8') as f:
                        file_metadata = json.load(f)
                        metadata.update(file_metadata)
                except Exception as e:
                    print(f"[Quarantine] Failed to load metadata for {file_path.name}: {e}")
            
            quarantined_files.append(metadata)
        
        # Sort by quarantine timestamp (newest first)
        quarantined_files.sort(
            key=lambda x: x.get("quarantine_timestamp", ""), 
            reverse=True
        )
        
    except Exception as e:
        print(f"[Quarantine] Error listing quarantined files: {e}")
    
    return quarantined_files

def restore_quarantined_file(quarantined_filename: str, restore_path: Optional[str] = None) -> bool:
    """Restore a quarantined file to its original location or a specified path.
    
    Uses quarantine_manager.py if available, otherwise falls back to old method.
    
    Args:
        quarantined_filename: The obfuscated filename in quarantine
        restore_path: Optional path to restore to (if not provided, uses original path)
    
    Returns:
        True if successful, False otherwise
    """
    # Try using quarantine_manager.py first (preferred method)
    try:
        import sys
        from pathlib import Path as PathLib
        
        # Import quarantine_manager from services/quarantine directory
        services_dir = PathLib(__file__).parent
        quarantine_dir = services_dir / "quarantine"
        sys.path.insert(0, str(quarantine_dir))
        
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "quarantine_manager",
            quarantine_dir / "quarantine_manager.py"
        )
        if spec and spec.loader:
            quarantine_manager_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(quarantine_manager_module)
            restore_func = quarantine_manager_module.restore
            
            # Restore using quarantine_manager
            success = restore_func(quarantined_filename, restore_path)
            if success:
                print(f"[Quarantine] Successfully restored {quarantined_filename} using quarantine_manager")
                return True
            else:
                print(f"[Quarantine] quarantine_manager restore failed for {quarantined_filename}, using fallback")
    except ImportError as e:
        print(f"[Quarantine] quarantine_manager not available: {e}, using fallback")
    except Exception as e:
        print(f"[Quarantine] Error using quarantine_manager restore: {e}, using fallback")
        import traceback
        traceback.print_exc()
    
    # Fallback to old method (check backend/quarantine directory)
    qdir = Path("backend") / "quarantine"
    quarantined_file = qdir / quarantined_filename
    
    if not quarantined_file.exists():
        print(f"[Quarantine] File not found: {quarantined_filename}")
        return False
    
    # Load metadata
    metadata_file = qdir / f"{quarantined_file.stem}.meta.json"
    if not metadata_file.exists():
        print(f"[Quarantine] Metadata not found for: {quarantined_filename}")
        return False
    
    try:
        with open(metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        
        original_path = Path(metadata.get("original_path", ""))
        if not original_path and not restore_path:
            print(f"[Quarantine] No original path in metadata and no restore path provided")
            return False
        
        # Determine restore destination
        if restore_path:
            restore_dest = Path(restore_path)
        else:
            restore_dest = original_path
        
        # Create parent directory if it doesn't exist
        restore_dest.parent.mkdir(parents=True, exist_ok=True)
        
        # Check if destination already exists
        if restore_dest.exists():
            print(f"[Quarantine] Destination already exists: {restore_dest}")
            return False
        
        # Add restore action to metadata
        _add_quarantine_action(qdir, quarantined_filename, "restore_initiated", 
                               f"Restore initiated to: {restore_dest}")
        
        # Restore file permissions first (make writable)
        try:
            if os.name == 'nt':  # Windows
                subprocess.run(['attrib', '-R', str(quarantined_file)], 
                             check=False, capture_output=True, timeout=5)
                os.chmod(str(quarantined_file), stat.S_IWRITE | stat.S_IREAD)
            else:  # Linux/macOS
                current_mode = os.stat(str(quarantined_file)).st_mode
                os.chmod(str(quarantined_file), current_mode | stat.S_IWRITE | stat.S_IXUSR)
        except Exception as e:
            print(f"[Quarantine] Warning: Could not restore permissions before move: {e}")
        
        # Move file back
        try:
            shutil.move(str(quarantined_file), str(restore_dest))
            
            # Restore original extension if different
            if restore_path is None and original_path.suffix != restore_dest.suffix:
                # File was moved, now rename to restore original extension
                final_path = restore_dest.with_suffix(original_path.suffix)
                if not final_path.exists():
                    restore_dest.rename(final_path)
                    restore_dest = final_path
            
            # Restore normal permissions (read/write for user)
            try:
                if os.name == 'nt':  # Windows
                    subprocess.run(['attrib', '-R', str(restore_dest)], 
                                 check=False, capture_output=True, timeout=5)
                    os.chmod(str(restore_dest), stat.S_IWRITE | stat.S_IREAD)
                else:  # Linux/macOS
                    os.chmod(str(restore_dest), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
            except Exception as e:
                print(f"[Quarantine] Warning: Could not restore normal permissions: {e}")
            
            _add_quarantine_action(qdir, quarantined_filename, "restore_completed", 
                                 f"File successfully restored to: {restore_dest}")
            
            # Delete metadata file
            try:
                metadata_file.unlink()
            except Exception:
                pass
            
            print(f"[Quarantine] Restored file: {quarantined_filename} -> {restore_dest}")
            return True
            
        except Exception as e:
            print(f"[Quarantine] Failed to restore file: {e}")
            return False
    
    except Exception as e:
        print(f"[Quarantine] Error restoring file: {e}")
        import traceback
        traceback.print_exc()
        return False

def _delete_to_recycle_bin(file_path: Path) -> bool:
    """Move file to Recycle Bin/Trash (cross-platform).
    
    Uses send2trash for cross-platform support (Windows, Linux, macOS).
    Falls back to pywin32 on Windows if send2trash is unavailable.
    
    Returns True if successful, False otherwise.
    """
    # Method 1: Use send2trash (preferred - cross-platform)
    if SEND2TRASH_AVAILABLE:
        try:
            from send2trash import send2trash
            send2trash(str(file_path))
            return True
        except Exception as e:
            print(f"[Delete] send2trash failed: {e}, trying fallback...")
    
    # Method 2: Fallback to pywin32 on Windows
    if os.name == 'nt' and WINDOWS_RECYCLE_BIN_AVAILABLE:
        try:
            file_path_str = str(file_path.absolute())
            # Use Windows Shell API to move to Recycle Bin
            result = shell.SHFileOperation((
                0,
                shellcon.FO_DELETE,
                file_path_str,
                None,
                shellcon.FOF_ALLOWUNDO | shellcon.FOF_NOCONFIRMATION | shellcon.FOF_NOERRORUI,
                None,
                None
            ))
            return result[0] == 0  # 0 means success
        except Exception as e:
            print(f"[Delete] Failed to move to Recycle Bin: {e}")
            return False
    
    return False


def _permanently_delete_file(file_path: Path) -> bool:
    """Permanently delete a file or directory from the filesystem.
    
    Uses shutil.rmtree() for directories and os.remove() for files.
    
    Returns True if successful, False otherwise.
    """
    try:
        if not file_path.exists():
            return True  # Already deleted
        
        # Make file/directory writable if it's read-only
        if os.name == 'nt':  # Windows
            try:
                # Remove read-only attribute
                subprocess.run(['attrib', '-R', str(file_path)], 
                             check=False, capture_output=True, timeout=5)
                # For directories, also remove read-only from contents
                if file_path.is_dir():
                    subprocess.run(['attrib', '-R', f'{file_path}\\*.*', '/s', '/d'], 
                                 check=False, capture_output=True, timeout=10)
                # Remove any deny permissions that might block deletion
                try:
                    subprocess.run(['icacls', str(file_path), '/remove', 'Everyone'], 
                                 check=False, capture_output=True, timeout=5)
                except Exception:
                    pass
            except Exception:
                pass
        else:  # Linux/macOS
            try:
                # Make file/directory writable
                if file_path.is_dir():
                    os.chmod(str(file_path), stat.S_IWRITE | stat.S_IREAD | stat.S_IXUSR)
                else:
                    os.chmod(str(file_path), stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass
        
        # Delete using shutil for directories, os for files
        if file_path.is_dir():
            # Use shutil.rmtree() for directories (recursive deletion)
            shutil.rmtree(str(file_path), ignore_errors=True)
            print(f"[Delete] Deleted directory using shutil.rmtree(): {file_path}")
        else:
            # Use os.remove() for files
            os.remove(str(file_path))
            print(f"[Delete] Deleted file using os.remove(): {file_path}")
        
        return not file_path.exists()  # Verify deletion
    except PermissionError as e:
        print(f"[Delete] Permission denied deleting {file_path}: {e}")
        # Try with elevated permissions on Windows
        if os.name == 'nt':
            try:
                subprocess.run(['attrib', '-R', str(file_path)], 
                             check=False, capture_output=True, timeout=5)
                if file_path.is_dir():
                    # Use shutil.rmtree with elevated permissions
                    subprocess.run(['attrib', '-R', f'{file_path}\\*.*', '/s', '/d'], 
                                 check=False, capture_output=True, timeout=10)
                    shutil.rmtree(str(file_path), ignore_errors=True)
                    # Fallback to Windows command
                    if file_path.exists():
                        subprocess.run(['rmdir', '/s', '/q', str(file_path)], 
                                     check=False, capture_output=True, timeout=10, shell=True)
                else:
                    # Use os.remove with elevated permissions
                    os.remove(str(file_path))
                    # Fallback to Windows command
                    if file_path.exists():
                        subprocess.run(['del', '/f', '/q', str(file_path)], 
                                     check=False, capture_output=True, timeout=5, shell=True)
                return not file_path.exists()
            except Exception as e2:
                print(f"[Delete] Elevated deletion failed: {e2}")
                pass
        return False
    except Exception as e:
        print(f"[Delete] Error deleting {file_path}: {e}")
        return False


def delete_anomaly_immediately(file_path: str, is_directory: bool = False) -> Dict[str, Any]:
    """
    Immediately delete a file or directory when an anomaly is detected.
    
    Uses shutil.rmtree() for directories and os.remove() for files.
    This is called automatically when high-severity anomalies are detected.
    
    Args:
        file_path: Path to the file or directory to delete
        is_directory: True if the path is a directory, False for a file
    
    Returns:
        Dictionary with deletion result:
        {
            "success": bool,
            "message": str,
            "file_path": str,
            "method": str ("shutil.rmtree" for directories, "os.remove" for files),
            "item_type": str ("file" or "directory"),
            "error": str (if failed)
        }
    """
    logger = logging.getLogger("ai_shield.threat_actions")
    
    path = Path(file_path)
    
    if not path.exists():
        logger.info(f"[Anomaly Delete] File/directory already deleted: {file_path}")
        return {
            "success": True,
            "message": "File/directory already deleted",
            "file_path": file_path,
            "method": "already_deleted",
            "item_type": "unknown"
        }
    
    # Determine if it's actually a directory
    actual_is_dir = path.is_dir()
    if is_directory and not actual_is_dir:
        logger.warning(f"[Anomaly Delete] Path marked as directory but is a file: {file_path}")
    if actual_is_dir:
        is_directory = True
    
    method = None
    item_type = None
    
    try:
        if is_directory or actual_is_dir:
            # Use shutil.rmtree() for directories
            item_type = "directory"
            method = "shutil.rmtree"
            
            logger.info(f"[Anomaly Delete] Attempting to delete directory using shutil.rmtree(): {file_path}")
            
            # First, make sure we can delete it by removing read-only attributes
            if os.name == 'nt':  # Windows
                try:
                    # Remove read-only attributes recursively from all files and directories
                    subprocess.run(['attrib', '-R', f'{path}\\*.*', '/s', '/d'], 
                                 check=False, capture_output=True, timeout=10)
                    # Also remove read-only from the directory itself
                    subprocess.run(['attrib', '-R', str(path), '/d'], 
                                 check=False, capture_output=True, timeout=5)
                except Exception as e:
                    logger.warning(f"[Anomaly Delete] Could not remove read-only attributes: {e}")
            else:  # Linux/macOS
                try:
                    # Make directory and contents writable
                    os.chmod(str(path), stat.S_IWRITE | stat.S_IREAD | stat.S_IXUSR)
                    # Use os.walk to make all files writable
                    for root, dirs, files in os.walk(str(path)):
                        for d in dirs:
                            try:
                                os.chmod(os.path.join(root, d), stat.S_IWRITE | stat.S_IREAD | stat.S_IXUSR)
                            except Exception:
                                pass
                        for f in files:
                            try:
                                os.chmod(os.path.join(root, f), stat.S_IWRITE | stat.S_IREAD)
                            except Exception:
                                pass
                except Exception as e:
                    logger.warning(f"[Anomaly Delete] Could not modify permissions: {e}")
            
            # Delete directory using shutil.rmtree()
            shutil.rmtree(str(path), ignore_errors=False)
            logger.info(f"[Anomaly Delete] Directory deleted using shutil.rmtree(): {file_path}")
            
        else:
            # Use os.remove() for files
            item_type = "file"
            method = "os.remove"
            
            logger.info(f"[Anomaly Delete] Attempting to delete file using os.remove(): {file_path}")
            
            # Make file writable if needed
            if os.name == 'nt':  # Windows
                try:
                    # Remove read-only attribute
                    subprocess.run(['attrib', '-R', str(path)], 
                                 check=False, capture_output=True, timeout=5)
                    # Also try to remove any deny permissions
                    try:
                        subprocess.run(['icacls', str(path), '/remove', 'Everyone'], 
                                     check=False, capture_output=True, timeout=5)
                    except Exception:
                        pass
                except Exception as e:
                    logger.warning(f"[Anomaly Delete] Could not remove read-only attribute: {e}")
            else:  # Linux/macOS
                try:
                    # Make file writable
                    os.chmod(str(path), stat.S_IWRITE | stat.S_IREAD)
                except Exception as e:
                    logger.warning(f"[Anomaly Delete] Could not modify file permissions: {e}")
            
            # Delete file using os.remove()
            os.remove(str(path))
            logger.info(f"[Anomaly Delete] File deleted using os.remove(): {file_path}")
        
        # Verify deletion
        if not path.exists():
            print(f"[Anomaly Delete] ✓ Successfully deleted {item_type} using {method}: {file_path}")
            logger.info(f"[Anomaly Delete] Successfully deleted {item_type}: {file_path}")
            return {
                "success": True,
                "message": f"Successfully deleted {item_type}",
                "file_path": file_path,
                "method": method,
                "item_type": item_type
            }
        else:
            error_msg = f"Deletion appeared to succeed but {item_type} still exists"
            logger.error(f"[Anomaly Delete] {error_msg}: {file_path}")
            return {
                "success": False,
                "message": error_msg,
                "file_path": file_path,
                "method": method,
                "item_type": item_type,
                "error": "Verification failed"
            }
            
    except PermissionError as e:
        error_msg = f"Permission denied: {e}"
        logger.error(f"[Anomaly Delete] {error_msg}: {file_path}")
        print(f"[Anomaly Delete] Permission denied: {e}")
        
        # Try with elevated permissions and error handling
        try:
            if is_directory or actual_is_dir:
                # Try shutil.rmtree with ignore_errors=True
                logger.info(f"[Anomaly Delete] Retrying directory deletion with ignore_errors: {file_path}")
                shutil.rmtree(str(path), ignore_errors=True)
                if not path.exists():
                    logger.info(f"[Anomaly Delete] Directory deleted with ignore_errors: {file_path}")
                    return {
                        "success": True,
                        "message": "Directory deleted with ignore_errors",
                        "file_path": file_path,
                        "method": "shutil.rmtree (ignore_errors)",
                        "item_type": "directory"
                    }
            else:
                # Try os.remove after fixing permissions more aggressively
                logger.info(f"[Anomaly Delete] Retrying file deletion with permission fix: {file_path}")
                if os.name == 'nt':
                    # Try takeown and icacls on Windows
                    try:
                        subprocess.run(['takeown', '/f', str(path)], 
                                     check=False, capture_output=True, timeout=5)
                        subprocess.run(['icacls', str(path), '/grant', 'Everyone:F'], 
                                     check=False, capture_output=True, timeout=5)
                    except Exception:
                        pass
                    subprocess.run(['attrib', '-R', str(path)], 
                                 check=False, capture_output=True, timeout=5)
                else:
                    # Try with sudo on Linux/macOS (if available)
                    try:
                        subprocess.run(['sudo', 'rm', '-f', str(path)], 
                                     check=False, capture_output=True, timeout=10)
                        if not path.exists():
                            return {
                                "success": True,
                                "message": "File deleted with sudo",
                                "file_path": file_path,
                                "method": "os.remove (sudo)",
                                "item_type": "file"
                            }
                    except Exception:
                        pass
                
                os.remove(str(path))
                if not path.exists():
                    logger.info(f"[Anomaly Delete] File deleted after permission fix: {file_path}")
                    return {
                        "success": True,
                        "message": "File deleted after permission fix",
                        "file_path": file_path,
                        "method": "os.remove (after permissions)",
                        "item_type": "file"
                    }
        except Exception as e2:
            logger.error(f"[Anomaly Delete] Retry also failed: {e2}")
            pass
        
        return {
            "success": False,
            "message": error_msg,
            "file_path": file_path,
            "method": method if method else "unknown",
            "item_type": item_type if item_type else "unknown",
            "error": str(e)
        }
    except Exception as e:
        error_msg = f"Deletion failed: {e}"
        logger.error(f"[Anomaly Delete] {error_msg}: {file_path}")
        print(f"[Anomaly Delete] Error deleting {file_path}: {e}")
        return {
            "success": False,
            "message": error_msg,
            "file_path": file_path,
            "method": method if method else "unknown",
            "item_type": item_type if item_type else "unknown",
            "error": str(e)
        }


def delete_file(threat: Threat, use_recycle_bin: bool = True) -> Optional[Threat]:
    """
    Delete a file associated with a threat and remove the threat record from the database.
    
    Args:
        threat: The threat object containing file path
        use_recycle_bin: If True (default), send to Recycle Bin on Windows, 
                        otherwise permanently delete. On Linux/macOS, always permanent.
    
    Returns:
        None if successfully deleted, or the threat object if deletion failed.
    """
    if not threat or not threat.filePath:
        return None
    
    src = Path(threat.filePath)
    threat_id = threat.id
    file_deleted = False
    
    try:
        if src.exists():
            # Try to delete the file at OS level
            if os.name == 'nt' and use_recycle_bin and WINDOWS_RECYCLE_BIN_AVAILABLE:
                # Windows: Send to Recycle Bin
                file_deleted = _delete_to_recycle_bin(src)
                if not file_deleted:
                    # Fallback to permanent deletion if Recycle Bin fails
                    print(f"[Delete] Recycle Bin failed for {src}, attempting permanent deletion")
                    file_deleted = _permanently_delete_file(src)
            else:
                # Linux/macOS or permanent deletion requested
                file_deleted = _permanently_delete_file(src)
        else:
            # File doesn't exist, consider it deleted
            file_deleted = True
        
        # Delete threat record from database
        with Session(DB.engine) as s:
            obj = s.get(Threat, threat_id)
            if obj:
                s.delete(obj)
                s.commit()
                print(f"[Delete] Threat {threat_id} deleted from database. File deleted: {file_deleted}")
                return None  # Return None to indicate successful deletion
    except Exception as e:
        print(f"[Delete] Error deleting threat {threat_id}: {e}")
        # Even if file deletion failed, remove from database
        try:
            with Session(DB.engine) as s:
                obj = s.get(Threat, threat_id)
                if obj:
                    s.delete(obj)
                    s.commit()
                    print(f"[Delete] Threat {threat_id} removed from database despite file deletion error")
                    return None
        except Exception as inner_e:
            print(f"[Delete] Error removing threat from database: {inner_e}")
            pass
    
    return None
