# Deletion Service Module

This directory contains all files related to file deletion operations.

## Files

- `delete_anomalies.py` - Main deletion script with admin authorization and multiple deletion methods
- `delete_safe.py` - Safe deletion utility using send2trash (Recycle Bin/Trash support)
- `delete_file.bat` - Windows batch script for file deletion
- `delete_file.ps1` - PowerShell script for file deletion
- `secure_delete_ps.ps1` - PowerShell script for secure file deletion using `sdelete.exe` (Sysinternals)
- `delete_log.txt` - Log file for deletion operations

## Usage

These scripts are used by the `delete_anomalies_service.py` module, which provides programmatic access to deletion functionality.

## Secure Deletion

The `secure_delete_ps.ps1` script provides secure file deletion using `sdelete.exe` from Sysinternals Suite. It:
- Securely overwrites files before deletion using multiple passes
- Requires `sdelete.exe` to be installed (download from Microsoft Sysinternals)
- Can be enabled by setting `secure_delete=True` in the deletion service

### Requirements for Secure Deletion
- Windows OS
- `sdelete.exe` from Sysinternals Suite (https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete)
- Admin privileges (for some file locations)

### Usage Example
```python
from app.services import delete_anomalies_service

result = delete_anomalies_service.delete_anomaly_file_simple(
    file_path="C:\\path\\to\\file.txt",
    secure_delete=True,
    secure_delete_passes=3  # Number of overwrite passes
)
```

## Features

- Cross-platform support (Windows, Linux, macOS)
- Admin authorization handling
- Multiple deletion methods with fallbacks
- Recycle Bin/Trash support
- Secure deletion option (Windows only, requires sdelete.exe)
- Comprehensive logging

