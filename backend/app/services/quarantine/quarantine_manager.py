#!/usr/bin/env python3
"""
Quarantine Manager - Enhanced for AI Shield
Python 3.8+

Features:
 - Move file to quarantine directory
 - Compute and store metadata (sha256, size, original path, timestamp, user)
 - Lock file by removing permissions (POSIX) or using icacls (Windows)
 - Optionally change extension to .quarantine
 - Restore or permanently delete (with audit)
 - SQLite database for tracking

Dependencies: sqlite3 (stdlib), cryptography (optional)
"""

import os
import sys
import shutil
import hashlib
import sqlite3
import getpass
import json
from datetime import datetime
from pathlib import Path
import platform
import stat
import subprocess
from typing import Optional, Dict, Any, List

# Configuration
QUARANTINE_DIR = Path.home() / ".quarantine"
DB_PATH = QUARANTINE_DIR / "quarantine.db"
CHANGE_EXT = True  # Add .quarantine extension to files
ENCRYPT = False  # Optional: encrypt quarantined file (not implemented here)
REMOVE_PERMS = True  # Remove permissions after copying (or apply Windows icacls)


def ensure_env():
    """Ensure quarantine directory and database exist."""
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stored_name TEXT UNIQUE,
        original_path TEXT,
        sha256 TEXT,
        size INTEGER,
        user TEXT,
        timestamp TEXT,
        reason TEXT,
        state TEXT DEFAULT 'quarantined',
        threat_id INTEGER,
        metadata TEXT
    )""")
    conn.commit()
    conn.close()


def sha256_of_file(p: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def lock_permissions(p: Path) -> bool:
    """Lock file permissions to prevent access.
    
    On Windows: Uses icacls to deny read/write access
    On POSIX: Removes all permissions and optionally sets immutable flag
    """
    system = platform.system()
    if system == "Windows":
        # Remove all access for Everyone (requires admin for some ACL operations)
        try:
            # First, take ownership if needed
            subprocess.check_call(
                ["takeown", "/f", str(p)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
        except Exception:
            pass
        
        try:
            # Deny read/write access
            subprocess.check_call(
                ["icacls", str(p), "/deny", "Everyone:(R,W)"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            return True
        except Exception as e:
            print(f"Warning: couldn't run icacls: {e}")
            return False
    else:
        # POSIX: Remove all perms
        try:
            p.chmod(0)
            # Also set immutable if possible (Linux chattr +i) - best-effort
            if shutil.which("chattr"):
                try:
                    subprocess.check_call(
                        ["chattr", "+i", str(p)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5
                    )
                except Exception:
                    pass
            return True
        except Exception as e:
            print(f"Warning: couldn't lock permissions: {e}")
            return False


def unlock_permissions(p: Path) -> bool:
    """Unlock file permissions to allow access."""
    system = platform.system()
    if system == "Windows":
        try:
            # Remove deny ACL
            subprocess.check_call(
                ["icacls", str(p), "/remove:d", "Everyone"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            return True
        except Exception as e:
            print(f"Warning: couldn't unlock permissions: {e}")
            return False
    else:
        # Remove immutable then set to 0644
        if shutil.which("chattr"):
            try:
                subprocess.check_call(
                    ["chattr", "-i", str(p)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
            except Exception:
                pass
        try:
            p.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
            return True
        except Exception as e:
            print(f"Warning: couldn't unlock permissions: {e}")
            return False


def store_metadata(
    stored_name: str,
    original_path: str,
    sha: str,
    size: int,
    user: str,
    reason: str,
    threat_id: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> int:
    """Store quarantine metadata in database. Returns the inserted row ID."""
    ensure_env()
    conn = sqlite3.connect(DB_PATH)
    metadata_json = json.dumps(metadata) if metadata else None
    cursor = conn.execute(
        """INSERT INTO items 
           (stored_name, original_path, sha256, size, user, timestamp, reason, state, threat_id, metadata) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            stored_name,
            original_path,
            sha,
            size,
            user,
            datetime.utcnow().isoformat(),
            reason,
            "quarantined",
            threat_id,
            metadata_json
        )
    )
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def quarantine(
    path_str: str,
    reason: str = "manual quarantine",
    threat_id: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """
    Quarantine a file.
    
    Args:
        path_str: Path to file to quarantine
        reason: Reason for quarantine
        threat_id: Optional threat ID from database
        metadata: Optional additional metadata
    
    Returns:
        Dict with quarantine info or None if failed
    """
    p = Path(path_str).expanduser().resolve()
    if not p.exists():
        print(f"Not found: {p}")
        return None
    
    if not p.is_file():
        print(f"Not a file: {p}")
        return None
    
    ensure_env()
    
    try:
        size = p.stat().st_size
        sha = sha256_of_file(p)
        user = getpass.getuser()
        timestamp = datetime.utcnow()
        stored_name = f"{timestamp.strftime('%Y%m%dT%H%M%S')}_{sha[:12]}_{p.name}"
        if CHANGE_EXT:
            stored_name += ".quarantine"
        
        dest = QUARANTINE_DIR / stored_name
        
        # Move file (keeping original removed). Using move gives atomic rename if same fs; else copy+unlink
        try:
            shutil.move(str(p), str(dest))
        except Exception as e:
            print(f"Move failed, trying copy+delete: {e}")
            shutil.copy2(str(p), str(dest))
            p.unlink()
        
        # Lock permissions on the quarantined copy
        if REMOVE_PERMS:
            try:
                lock_permissions(dest)
            except Exception as e:
                print(f"Warning: couldn't remove permissions: {e}")
        
        # Store metadata
        row_id = store_metadata(
            stored_name,
            str(p),
            sha,
            size,
            user,
            reason,
            threat_id,
            metadata
        )
        
        result = {
            "id": row_id,
            "stored_name": stored_name,
            "original_path": str(p),
            "quarantine_path": str(dest),
            "sha256": sha,
            "size": size,
            "user": user,
            "timestamp": timestamp.isoformat(),
            "reason": reason,
            "state": "quarantined"
        }
        
        print(f"Quarantined: {dest}")
        return result
    except Exception as e:
        print(f"Error quarantining file: {e}")
        import traceback
        traceback.print_exc()
        return None


def restore(stored_name: str, restore_path: Optional[str] = None) -> bool:
    """Restore a quarantined file."""
    ensure_env()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "SELECT stored_name, original_path, state FROM items WHERE stored_name = ?",
        (stored_name,)
    )
    row = cur.fetchone()
    if not row:
        print(f"Not found in DB: {stored_name}")
        conn.close()
        return False
    
    if row[2] != "quarantined":
        print(f"Item not in quarantined state: {row[2]}")
        conn.close()
        return False
    
    src = QUARANTINE_DIR / row[0]
    target = Path(restore_path) if restore_path else Path(row[1])
    
    if not src.exists():
        print(f"Stored file missing: {src}")
        conn.close()
        return False
    
    # Unlock permissions
    try:
        unlock_permissions(src)
    except Exception as e:
        print(f"Warning: couldn't unlock permissions: {e}")
    
    # Move back
    try:
        target_parent = target.parent
        target_parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(target))
        conn.execute(
            "UPDATE items SET state = ? WHERE stored_name = ?",
            ("restored", stored_name)
        )
        conn.commit()
        conn.close()
        print(f"Restored to: {target}")
        return True
    except Exception as e:
        print(f"Error restoring file: {e}")
        conn.close()
        return False


def purge(stored_name: str, force: bool = False) -> bool:
    """Permanently remove quarantined copy (destructive)."""
    ensure_env()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "SELECT stored_name, state FROM items WHERE stored_name = ?",
        (stored_name,)
    )
    row = cur.fetchone()
    if not row:
        print(f"Not found in DB: {stored_name}")
        conn.close()
        return False
    
    if row[1] == "purged":
        print("Already purged")
        conn.close()
        return False
    
    src = QUARANTINE_DIR / row[0]
    if src.exists():
        # Attempt to remove immutable or ACL then delete
        try:
            unlock_permissions(src)
            src.unlink()
        except Exception as e:
            print(f"Error deleting file: {e}")
            conn.close()
            return False
    
    conn.execute(
        "UPDATE items SET state = ? WHERE stored_name = ?",
        ("purged", stored_name)
    )
    conn.commit()
    conn.close()
    print(f"Purged: {stored_name}")
    return True


def list_quarantined() -> List[Dict[str, Any]]:
    """List all quarantined items."""
    ensure_env()
    conn = sqlite3.connect(DB_PATH)
    items = []
    for row in conn.execute(
        """SELECT id, stored_name, original_path, sha256, size, user, timestamp, reason, state, threat_id, metadata 
           FROM items ORDER BY id DESC"""
    ):
        items.append({
            "id": row[0],
            "stored_name": row[1],
            "original_path": row[2],
            "sha256": row[3],
            "size": row[4],
            "user": row[5],
            "timestamp": row[6],
            "reason": row[7],
            "state": row[8],
            "threat_id": row[9],
            "metadata": json.loads(row[10]) if row[10] else None
        })
    conn.close()
    return items


def get_quarantine_info(stored_name: str) -> Optional[Dict[str, Any]]:
    """Get information about a quarantined item."""
    ensure_env()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        """SELECT id, stored_name, original_path, sha256, size, user, timestamp, reason, state, threat_id, metadata 
           FROM items WHERE stored_name = ?""",
        (stored_name,)
    )
    row = cur.fetchone()
    conn.close()
    
    if not row:
        return None
    
    return {
        "id": row[0],
        "stored_name": row[1],
        "original_path": row[2],
        "sha256": row[3],
        "size": row[4],
        "user": row[5],
        "timestamp": row[6],
        "reason": row[7],
        "state": row[8],
        "threat_id": row[9],
        "metadata": json.loads(row[10]) if row[10] else None
    }


# CLI
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: quarantine_manager.py <quarantine|restore|purge|list|info> [args]")
        sys.exit(1)
    
    cmd = sys.argv[1].lower()
    
    if cmd == "quarantine":
        if len(sys.argv) < 3:
            print("Provide path to quarantine")
            sys.exit(1)
        reason = sys.argv[3] if len(sys.argv) > 3 else "manual"
        result = quarantine(sys.argv[2], reason=reason)
        if result:
            print(json.dumps(result, indent=2))
    elif cmd == "restore":
        if len(sys.argv) < 3:
            print("Provide stored_name to restore (see list)")
            sys.exit(1)
        restore_path = sys.argv[3] if len(sys.argv) > 3 else None
        restore(sys.argv[2], restore_path=restore_path)
    elif cmd == "purge":
        if len(sys.argv) < 3:
            print("Provide stored_name to purge")
            sys.exit(1)
        purge(sys.argv[2])
    elif cmd == "list":
        items = list_quarantined()
        print(json.dumps(items, indent=2))
    elif cmd == "info":
        if len(sys.argv) < 3:
            print("Provide stored_name to get info")
            sys.exit(1)
        info = get_quarantine_info(sys.argv[2])
        if info:
            print(json.dumps(info, indent=2))
        else:
            print("Not found")
    else:
        print(f"Unknown command: {cmd}")

