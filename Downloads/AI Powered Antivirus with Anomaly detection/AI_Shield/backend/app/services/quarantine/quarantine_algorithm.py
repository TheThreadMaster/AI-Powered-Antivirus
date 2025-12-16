#!/usr/bin/env python3
"""
AI Shield - Async Quarantine Algorithm Script

This script is specifically designed for the quarantine algorithm operations:
- Changing file extensions to .quarantine
- Obfuscating filenames
- Setting restrictive permissions
- Invoking admin authorization when required

Usage:
    python quarantine_algorithm.py --file-path /path/to/file.exe [--action quarantine|restore|change-extension]
"""

import os
import sys
import asyncio
import subprocess
import json
import hashlib
import time
import stat
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
import argparse

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from app.store import DB, Threat
    from sqlmodel import Session
    DB_AVAILABLE = True
except ImportError as e:
    print(f"[Warning] Database not available: {e}")
    DB_AVAILABLE = False


def is_admin() -> bool:
    """Check if the script is running with administrator/elevated privileges."""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/macOS
            return os.geteuid() == 0
    except Exception:
        return False


async def request_admin_elevation_async(script_path: str, args: List[str]) -> bool:
    """
    Request administrator/elevated privileges asynchronously.
    
    Returns True if elevation was requested, False otherwise.
    """
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            if not is_admin():
                print("[Admin] Requesting administrator privileges...")
                # Use ShellExecuteW for async elevation
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",  # Request elevation
                    sys.executable,
                    f'"{script_path}" {" ".join(args)}',
                    None,
                    1  # SW_SHOWNORMAL
                )
                return True
        else:  # Linux/macOS
            if not is_admin():
                print("[Admin] Requesting root privileges...")
                # Run with sudo
                process = await asyncio.create_subprocess_exec(
                    'sudo', sys.executable, script_path, *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                return True
    except Exception as e:
        print(f"[Error] Failed to request elevation: {e}")
    return False


async def change_file_extension_async(file_path: Path, new_extension: str, 
                                      require_admin: bool = False) -> Dict[str, Any]:
    """
    Asynchronously change file extension with admin authorization if required.
    
    Args:
        file_path: Path to the file
        new_extension: New extension (e.g., '.quarantine')
        require_admin: Whether to require admin privileges
    
    Returns:
        Dict with success status and details
    """
    result = {
        "success": False,
        "file_path": str(file_path),
        "original_extension": file_path.suffix,
        "new_extension": new_extension,
        "new_path": None,
        "error": None,
        "admin_required": False,
        "admin_granted": False
    }
    
    try:
        if not file_path.exists():
            result["error"] = "File does not exist"
            return result
        
        # Check if admin is required
        if require_admin and not is_admin():
            result["admin_required"] = True
            result["error"] = "Admin privileges required but not available"
            return result
        
        if is_admin():
            result["admin_granted"] = True
        
        # Generate new filename with new extension
        new_path = file_path.with_suffix(new_extension)
        
        # Handle name collision
        counter = 1
        original_new_path = new_path
        while new_path.exists():
            stem = original_new_path.stem
            new_path = file_path.parent / f"{stem}_{counter}{new_extension}"
            counter += 1
            if counter > 1000:
                result["error"] = "Too many filename collisions"
                return result
        
        # Make file writable if needed
        if os.name == 'nt':  # Windows
            try:
                # Remove read-only attribute
                await asyncio.to_thread(
                    subprocess.run,
                    ['attrib', '-R', str(file_path)],
                    check=False,
                    capture_output=True,
                    timeout=5
                )
                # Remove deny permissions if admin
                if is_admin():
                    try:
                        await asyncio.to_thread(
                            subprocess.run,
                            ['icacls', str(file_path), '/remove', 'Everyone'],
                            check=False,
                            capture_output=True,
                            timeout=5
                        )
                    except Exception:
                        pass
            except Exception:
                pass
        else:  # Linux/macOS
            try:
                current_mode = os.stat(str(file_path)).st_mode
                await asyncio.to_thread(os.chmod, str(file_path), current_mode | stat.S_IWRITE)
            except Exception:
                pass
        
        # Rename file (change extension)
        await asyncio.to_thread(file_path.rename, new_path)
        
        result["success"] = True
        result["new_path"] = str(new_path)
        print(f"[Quarantine] Changed extension: {file_path.name} -> {new_path.name}")
        
    except PermissionError as e:
        result["error"] = f"Permission denied: {e}"
        result["admin_required"] = True
    except Exception as e:
        result["error"] = str(e)
        print(f"[Quarantine] Error changing extension: {e}")
    
    return result


async def obfuscate_filename_async(file_path: Path, file_hash: Optional[str] = None) -> Dict[str, Any]:
    """
    Asynchronously obfuscate filename using hash and timestamp.
    
    Format: Q{hash_prefix}_{timestamp}.{original_extension}
    """
    result = {
        "success": False,
        "original_path": str(file_path),
        "obfuscated_path": None,
        "obfuscated_name": None,
        "error": None
    }
    
    try:
        if not file_path.exists():
            result["error"] = "File does not exist"
            return result
        
        # Compute hash if not provided
        if not file_hash:
            sha256 = hashlib.sha256()
            async def read_file_chunks():
                with open(file_path, 'rb') as f:
                    while True:
                        chunk = await asyncio.to_thread(f.read, 8192)
                        if not chunk:
                            break
                        sha256.update(chunk)
            await read_file_chunks()
            file_hash = sha256.hexdigest()
        
        # Generate obfuscated name
        timestamp = int(time.time())
        hash_prefix = file_hash[:8]
        original_ext = file_path.suffix
        obfuscated_name = f"Q{hash_prefix}_{timestamp}{original_ext}"
        obfuscated_path = file_path.parent / obfuscated_name
        
        # Handle collision
        counter = 1
        original_obfuscated = obfuscated_path
        while obfuscated_path.exists():
            stem = original_obfuscated.stem
            obfuscated_path = file_path.parent / f"{stem}_{counter}{original_ext}"
            counter += 1
            if counter > 1000:
                result["error"] = "Too many filename collisions"
                return result
        
        # Rename file
        await asyncio.to_thread(file_path.rename, obfuscated_path)
        
        result["success"] = True
        result["obfuscated_path"] = str(obfuscated_path)
        result["obfuscated_name"] = obfuscated_path.name
        print(f"[Quarantine] Obfuscated filename: {file_path.name} -> {obfuscated_path.name}")
        
    except PermissionError as e:
        result["error"] = f"Permission denied: {e}"
    except Exception as e:
        result["error"] = str(e)
        print(f"[Quarantine] Error obfuscating filename: {e}")
    
    return result


async def set_restrictive_permissions_async(file_path: Path, level: str = "standard", 
                                           require_admin: bool = False) -> Dict[str, Any]:
    """
    Asynchronously set restrictive OS-level permissions.
    
    Args:
        file_path: Path to the file
        level: Permission level (standard, moderate, strict)
        require_admin: Whether to require admin privileges
    """
    result = {
        "success": False,
        "file_path": str(file_path),
        "level": level,
        "error": None,
        "admin_required": False,
        "admin_granted": False
    }
    
    try:
        if not file_path.exists():
            result["error"] = "File does not exist"
            return result
        
        if require_admin and not is_admin():
            result["admin_required"] = True
            result["error"] = "Admin privileges required but not available"
            return result
        
        if is_admin():
            result["admin_granted"] = True
        
        if os.name == 'nt':  # Windows
            # Remove read-only first
            try:
                await asyncio.to_thread(
                    subprocess.run,
                    ['attrib', '-R', str(file_path)],
                    check=False,
                    capture_output=True,
                    timeout=5
                )
            except Exception:
                pass
            
            if level == "strict":
                # Maximum restrictions
                try:
                    await asyncio.to_thread(
                        subprocess.run,
                        ['attrib', '+R', str(file_path)],
                        check=False,
                        capture_output=True,
                        timeout=5
                    )
                    await asyncio.to_thread(
                        subprocess.run,
                        ['icacls', str(file_path), '/deny', 'Everyone:(X)'],
                        check=False,
                        capture_output=True,
                        timeout=5
                    )
                    await asyncio.to_thread(
                        subprocess.run,
                        ['icacls', str(file_path), '/deny', 'Everyone:(W)'],
                        check=False,
                        capture_output=True,
                        timeout=5
                    )
                except Exception:
                    pass
            else:  # standard or moderate
                try:
                    await asyncio.to_thread(
                        subprocess.run,
                        ['attrib', '+R', str(file_path)],
                        check=False,
                        capture_output=True,
                        timeout=5
                    )
                    if is_admin():
                        await asyncio.to_thread(
                            subprocess.run,
                            ['icacls', str(file_path), '/deny', 'Everyone:(X)'],
                            check=False,
                            capture_output=True,
                            timeout=5
                        )
                except Exception:
                    pass
        else:  # Linux/macOS
            if level == "strict":
                await asyncio.to_thread(os.chmod, str(file_path), 0)
            elif level == "moderate":
                await asyncio.to_thread(os.chmod, str(file_path), stat.S_IRUSR)
            else:  # standard
                await asyncio.to_thread(os.chmod, str(file_path), 
                                        stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        
        result["success"] = True
        print(f"[Quarantine] Set {level} permissions on: {file_path.name}")
        
    except PermissionError as e:
        result["error"] = f"Permission denied: {e}"
        result["admin_required"] = True
    except Exception as e:
        result["error"] = str(e)
        print(f"[Quarantine] Error setting permissions: {e}")
    
    return result


async def quarantine_file_async(file_path: str, threat_id: Optional[int] = None,
                               require_admin: bool = True) -> Dict[str, Any]:
    """
    Asynchronously quarantine a file using the full quarantine algorithm.
    
    Steps:
    1. Compute file hash
    2. Obfuscate filename
    3. Change extension to .quarantine
    4. Move to quarantine directory
    5. Set restrictive permissions
    6. Save metadata
    
    Args:
        file_path: Path to file to quarantine
        threat_id: Optional threat ID from database
        require_admin: Whether to require admin privileges
    
    Returns:
        Dict with quarantine operation results
    """
    result = {
        "success": False,
        "file_path": file_path,
        "quarantined_path": None,
        "quarantined_filename": None,
        "actions_taken": [],
        "error": None,
        "admin_required": False,
        "admin_granted": False
    }
    
    try:
        src = Path(file_path)
        if not src.exists():
            result["error"] = "File does not exist"
            return result
        
        # Check admin status
        if require_admin and not is_admin():
            result["admin_required"] = True
            result["error"] = "Admin privileges required but not available"
            return result
        
        if is_admin():
            result["admin_granted"] = True
        
        # Step 1: Compute file hash
        print(f"[Quarantine] Computing hash for: {src.name}")
        sha256 = hashlib.sha256()
        async def compute_hash():
            with open(src, 'rb') as f:
                while True:
                    chunk = await asyncio.to_thread(f.read, 8192)
                    if not chunk:
                        break
                    sha256.update(chunk)
        await compute_hash()
        file_hash = sha256.hexdigest()
        result["actions_taken"].append({
            "action": "hash_computed",
            "hash": file_hash,
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 2: Create quarantine directory
        qdir = Path("backend") / "quarantine"
        await asyncio.to_thread(qdir.mkdir, parents=True, exist_ok=True)
        
        # Step 3: Generate obfuscated filename with .quarantine extension
        timestamp = int(time.time())
        hash_prefix = file_hash[:8]
        obfuscated_name = f"Q{hash_prefix}_{timestamp}.quarantine"
        dst = qdir / obfuscated_name
        
        # Handle collision
        counter = 1
        original_dst = dst
        while dst.exists():
            stem = original_dst.stem
            dst = qdir / f"{stem}_{counter}.quarantine"
            counter += 1
            if counter > 1000:
                result["error"] = "Too many filename collisions"
                return result
        
        # Step 4: Make source writable
        if os.name == 'nt':
            try:
                await asyncio.to_thread(
                    subprocess.run,
                    ['attrib', '-R', str(src)],
                    check=False,
                    capture_output=True,
                    timeout=5
                )
            except Exception:
                pass
        else:
            try:
                current_mode = os.stat(str(src)).st_mode
                await asyncio.to_thread(os.chmod, str(src), current_mode | stat.S_IWRITE)
            except Exception:
                pass
        
        # Step 5: Move file to quarantine directory
        print(f"[Quarantine] Moving file to quarantine: {src.name} -> {dst.name}")
        await asyncio.to_thread(shutil.move, str(src), str(dst))
        result["actions_taken"].append({
            "action": "file_moved",
            "from": str(src),
            "to": str(dst),
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 6: Change extension is already done (filename includes .quarantine)
        result["actions_taken"].append({
            "action": "extension_changed",
            "original_extension": src.suffix,
            "new_extension": ".quarantine",
            "timestamp": datetime.now().isoformat()
        })
        
        # Step 7: Set restrictive permissions
        perm_result = await set_restrictive_permissions_async(dst, level="strict", require_admin=require_admin)
        if perm_result["success"]:
            result["actions_taken"].append({
                "action": "permissions_set",
                "level": "strict",
                "timestamp": datetime.now().isoformat()
            })
        else:
            result["actions_taken"].append({
                "action": "permissions_set",
                "level": "strict",
                "status": "failed",
                "error": perm_result.get("error"),
                "timestamp": datetime.now().isoformat()
            })
        
        # Step 8: Save metadata
        if threat_id and DB_AVAILABLE:
            try:
                with Session(DB.engine) as s:
                    threat = s.get(Threat, threat_id)
                    if threat:
                        metadata = {
                            "original_filename": src.name,
                            "original_path": str(src),
                            "original_extension": src.suffix,
                            "quarantined_filename": dst.name,
                            "quarantine_timestamp": datetime.now().isoformat(),
                            "threat_id": threat.id,
                            "threat_severity": threat.severity,
                            "threat_source": threat.source,
                            "threat_description": threat.description,
                            "file_size": dst.stat().st_size if dst.exists() else 0,
                            "actions": result["actions_taken"]
                        }
                        metadata_file = qdir / f"{dst.stem}.meta.json"
                        await asyncio.to_thread(
                            lambda: json.dump(metadata, open(metadata_file, 'w', encoding='utf-8'), indent=2, ensure_ascii=False)
                        )
                        result["actions_taken"].append({
                            "action": "metadata_saved",
                            "metadata_file": str(metadata_file),
                            "timestamp": datetime.now().isoformat()
                        })
            except Exception as e:
                print(f"[Quarantine] Failed to save metadata: {e}")
        
        result["success"] = True
        result["quarantined_path"] = str(dst)
        result["quarantined_filename"] = dst.name
        print(f"[Quarantine] Successfully quarantined: {src.name} -> {dst.name}")
        
    except PermissionError as e:
        result["error"] = f"Permission denied: {e}"
        result["admin_required"] = True
    except Exception as e:
        result["error"] = str(e)
        print(f"[Quarantine] Error quarantining file: {e}")
        import traceback
        traceback.print_exc()
    
    return result


async def main():
    """Main async function."""
    parser = argparse.ArgumentParser(
        description="Async Quarantine Algorithm - Change extensions and quarantine files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quarantine a file
  python quarantine_algorithm.py --file-path /path/to/file.exe --action quarantine
  
  # Change extension only
  python quarantine_algorithm.py --file-path /path/to/file.exe --action change-extension
  
  # Restore file (remove .quarantine extension)
  python quarantine_algorithm.py --file-path /path/to/file.quarantine --action restore
        """
    )
    
    parser.add_argument('--file-path', type=str, required=True, help='Path to file to process')
    parser.add_argument('--action', choices=['quarantine', 'change-extension', 'restore', 'obfuscate'],
                       default='quarantine', help='Action to perform')
    parser.add_argument('--threat-id', type=int, help='Threat ID from database')
    parser.add_argument('--new-extension', type=str, default='.quarantine', 
                       help='New extension for change-extension action')
    parser.add_argument('--require-admin', action='store_true', default=True,
                       help='Require admin privileges (default: True)')
    parser.add_argument('--no-admin', action='store_true',
                       help='Do not require admin privileges')
    
    args = parser.parse_args()
    
    if args.no_admin:
        args.require_admin = False
    
    print("=" * 70)
    print("AI Shield - Async Quarantine Algorithm")
    print("=" * 70)
    print()
    
    # Check admin status
    admin_status = is_admin()
    print(f"[Status] Admin/Elevated privileges: {'Yes' if admin_status else 'No'}")
    
    if args.require_admin and not admin_status:
        print("[Warning] Admin privileges required but not available.")
        response = input("Request administrator privileges? (y/n): ").strip().lower()
        if response == 'y':
            script_args = sys.argv[1:]
            if await request_admin_elevation_async(__file__, script_args):
                print("[Info] Elevation requested. Please approve in the UAC prompt.")
                return 0
        else:
            print("[Error] Cannot proceed without admin privileges.")
            return 1
    
    file_path = Path(args.file_path)
    
    if not file_path.exists():
        print(f"[Error] File not found: {file_path}")
        return 1
    
    print(f"[Info] Processing file: {file_path}")
    print(f"[Info] Action: {args.action}")
    print()
    
    try:
        if args.action == "quarantine":
            result = await quarantine_file_async(
                str(file_path),
                threat_id=args.threat_id,
                require_admin=args.require_admin
            )
            
            if result["success"]:
                print(f"[Success] File quarantined: {result['quarantined_filename']}")
                print(f"[Success] Actions taken: {len(result['actions_taken'])}")
                for action in result["actions_taken"]:
                    print(f"  - {action['action']}: {action.get('description', '')}")
            else:
                print(f"[Error] Quarantine failed: {result['error']}")
                if result.get("admin_required"):
                    print("[Error] Admin privileges required. Run with elevated permissions.")
                return 1
        
        elif args.action == "change-extension":
            result = await change_file_extension_async(
                file_path,
                args.new_extension,
                require_admin=args.require_admin
            )
            
            if result["success"]:
                print(f"[Success] Extension changed: {result['original_extension']} -> {result['new_extension']}")
                print(f"[Success] New path: {result['new_path']}")
            else:
                print(f"[Error] Extension change failed: {result['error']}")
                if result.get("admin_required"):
                    print("[Error] Admin privileges required. Run with elevated permissions.")
                return 1
        
        elif args.action == "obfuscate":
            result = await obfuscate_filename_async(file_path)
            
            if result["success"]:
                print(f"[Success] Filename obfuscated: {result['obfuscated_name']}")
                print(f"[Success] New path: {result['obfuscated_path']}")
            else:
                print(f"[Error] Obfuscation failed: {result['error']}")
                return 1
        
        elif args.action == "restore":
            # Restore: remove .quarantine extension
            if file_path.suffix != ".quarantine":
                print(f"[Error] File does not have .quarantine extension: {file_path.suffix}")
                return 1
            
            # Try to restore original extension from metadata
            qdir = file_path.parent
            metadata_file = qdir / f"{file_path.stem}.meta.json"
            original_ext = None
            
            if metadata_file.exists():
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        original_ext = metadata.get("original_extension", "")
                except Exception:
                    pass
            
            new_ext = original_ext if original_ext else ".restored"
            result = await change_file_extension_async(
                file_path,
                new_ext,
                require_admin=args.require_admin
            )
            
            if result["success"]:
                print(f"[Success] File restored: {file_path.name} -> {Path(result['new_path']).name}")
            else:
                print(f"[Error] Restore failed: {result['error']}")
                return 1
        
        return 0
        
    except Exception as e:
        print(f"[Error] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

