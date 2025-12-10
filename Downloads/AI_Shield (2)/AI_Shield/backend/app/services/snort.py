from __future__ import annotations

from pathlib import Path


def read_alerts(path: str | None = None):
    # Try common snort alert file if none provided.
    candidates = [
        Path(path) if path else None,
        Path("/var/log/snort/alert"),
        Path("C:/Snort/log/alert"),
    ]
    for c in candidates:
        if c and c.exists():
            try:
                with open(c, "r", errors="ignore") as f:
                    lines = f.readlines()[-200:]
                return [{"raw": ln.strip()} for ln in lines]
            except Exception:
                pass
    # Fallback sample
    return [{"raw": "[sample] Snort not configured yet."}]