#!/usr/bin/env python3
"""
AI Shield - Safe File Deletion Utility

This script provides safe file deletion with Recycle Bin/Trash support
and logging functionality. It uses send2trash for cross-platform compatibility.

Usage:
    python delete_safe.py <path> [--permanent] [--no-confirm]
"""

import os
import sys
import argparse
from pathlib import Path
from datetime import datetime
import logging

try:
    from send2trash import send2trash
    SEND2TRASH_AVAILABLE = True
except ImportError:
    print("[Error] send2trash not installed. Install with: pip install send2trash")
    SEND2TRASH_AVAILABLE = False
    sys.exit(1)

# Setup logging
LOG_FILE = "delete_log.txt"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


def confirm(prompt: str, default_no: bool = True) -> bool:
    """Prompt user for confirmation."""
    if default_no:
        ans = input(f"{prompt} [y/N]: ").strip().lower()
        return ans in ('y', 'yes')
    else:
        ans = input(f"{prompt} [Y/n]: ").strip().lower()
        return ans not in ('n', 'no')


def get_file_size(path: Path) -> str:
    """Get human-readable file size."""
    try:
        if path.is_file():
            size = path.stat().st_size
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} TB"
        elif path.is_dir():
            # Count files in directory
            count = sum(1 for _ in path.rglob('*') if _.is_file())
            return f"{count} files"
    except Exception:
        pass
    return "unknown size"


def delete_path(path: str, permanent: bool = False, no_confirm: bool = False) -> bool:
    """
    Delete a file or directory safely.
    
    Args:
        path: Path to file or directory
        permanent: If True, permanently delete (bypass Recycle Bin/Trash)
        no_confirm: If True, skip confirmation prompt
    
    Returns:
        True if deletion was successful, False otherwise
    """
    path_obj = Path(path)
    
    if not path_obj.exists():
        print(f"[Info] Path not found: {path}")
        logging.info(f"path_not_found: {path}")
        return False
    
    # Get file/directory info
    size_info = get_file_size(path_obj)
    item_type = "Directory" if path_obj.is_dir() else "File"
    
    print(f"\n[Target] {item_type}: {path}")
    print(f"[Size] {size_info}")
    
    # Confirmation
    if not no_confirm:
        action = "permanently delete" if permanent else "move to Trash/Recycle Bin"
        if not confirm(f"Proceed with {action}?"):
            print("[Cancelled] Deletion cancelled by user")
            logging.info(f"cancelled: {path}")
            return False
    
    try:
        if permanent:
            # Permanent delete (use carefully)
            if path_obj.is_file():
                os.remove(str(path_obj))
            else:
                import shutil
                shutil.rmtree(str(path_obj))
            print(f"[Success] Permanently deleted: {path}")
            logging.info(f"permanent_deleted: {path} ({size_info})")
        else:
            # Safe delete (Recycle Bin/Trash)
            if not SEND2TRASH_AVAILABLE:
                print("[Error] send2trash not available")
                logging.error(f"send2trash_unavailable: {path}")
                return False
            
            send2trash(str(path_obj))
            print(f"[Success] Moved to Trash/Recycle Bin: {path}")
            logging.info(f"trashed: {path} ({size_info})")
        
        return True
    except PermissionError as e:
        print(f"[Error] Permission denied: {e}")
        logging.error(f"permission_denied: {path} - {e}")
        return False
    except Exception as e:
        print(f"[Error] Deletion failed: {e}")
        logging.exception(f"delete_error: {path} - {e}")
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AI Shield - Safe File Deletion Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python delete_safe.py file.txt              # Move to Trash/Recycle Bin
  python delete_safe.py file.txt --permanent  # Permanently delete
  python delete_safe.py file.txt --no-confirm # Skip confirmation
        """
    )
    parser.add_argument(
        "path",
        help="Path to file or directory to delete"
    )
    parser.add_argument(
        "--permanent",
        action="store_true",
        help="Permanently delete (bypass Recycle Bin/Trash)"
    )
    parser.add_argument(
        "--no-confirm",
        action="store_true",
        help="Skip confirmation prompt (use with caution)"
    )
    
    args = parser.parse_args()
    
    if not SEND2TRASH_AVAILABLE:
        print("[Error] send2trash library not installed.")
        print("Install with: pip install send2trash")
        sys.exit(1)
    
    success = delete_path(args.path, permanent=args.permanent, no_confirm=args.no_confirm)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

