from __future__ import annotations

from pathlib import Path
import mimetypes


def analyze_path(path: str):
    """Analyze file path and return sandbox simulation results based on file type."""
    p = Path(path)
    ext = p.suffix.lower()
    mime = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
    
    # Detect file type from header
    header = b""
    try:
        with open(p, "rb") as f:
            header = f.read(32)
    except Exception:
        pass
    
    is_image = (ext in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg", ".ico"} or
                mime.startswith("image/"))
    is_pdf = (ext == ".pdf" or mime == "application/pdf" or header.startswith(b"%PDF"))
    is_text = (ext in {".txt", ".md", ".csv", ".json", ".xml", ".html", ".css"} or mime.startswith("text/"))
    is_executable = (ext in {".exe", ".dll", ".scr", ".sys", ".bat", ".cmd", ".ps1", ".js", ".vbs"} or
                     header.startswith(b"MZ") or header.startswith(b"\x7FELF"))
    is_script = (ext in {".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".js"})
    
    # Context-aware sandbox verdict
    if is_image:
        # Images typically don't execute, so they're benign in sandbox context
        verdict = "benign"
        syscalls = []
        registry = []
        network = []
    elif is_pdf:
        # PDFs can contain scripts but typically just display content
        verdict = "benign"
        syscalls = ["ReadFile"]
        registry = []
        network = []
    elif is_text:
        # Text files are passive
        verdict = "benign"
        syscalls = []
        registry = []
        network = []
    elif is_executable or is_script:
        # Executables and scripts have behavior
        verdict = "suspicious"  # Default to suspicious for executables
        syscalls = ["CreateFile", "ReadFile", "WriteFile", "CreateProcess"]
        registry = ["HKCU\\Software"]
        network = []
    else:
        # Unknown file types
        verdict = "suspicious"
        syscalls = ["CreateFile", "ReadFile"]
        registry = []
        network = []
    
    return {
        "path": str(p),
        "syscalls": syscalls,
        "registry": registry,
        "network": network,
        "verdict": verdict.lower(),  # Ensure lowercase for consistency
    }