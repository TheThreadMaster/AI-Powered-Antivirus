from __future__ import annotations

import asyncio
import os
import tempfile
import random
import time
from typing import List, Optional
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form, Request
from pathlib import Path
import mimetypes
import zipfile
import hashlib
import json
import math
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .store import DB, ThreatIn, Threat, AllowedFile, BlockedUrl, ScanJob
from .services import anomaly, sandbox, webshield, snort
from .services import threat_actions, background
from .services.cloud_protection import get_cloud_service
from .routers import anomaly as anomaly_router, webshield as webshield_router
from .routers import sandbox as sandbox_router, snort as snort_router
from .routers import threat_actions as threat_actions_router, scanner as scanner_router
from .routers import cloud_protection as cloud_protection_router


class Overview(BaseModel):
    threatLevel: int
    threatIndex: int
    activeThreats: int
    filesScanned: int
    networkAlerts: int
    protection: dict


class ConnectionInfo(BaseModel):
    pid: int
    process: str
    remote: str
    bytes: int


class WSManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, message: dict):
        dead: List[WebSocket] = []
        for ws in self.connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for d in dead:
            self.disconnect(d)


app = FastAPI(title="AI Shield Backend")

origins = [
    os.getenv("FRONTEND_ORIGIN", "http://localhost:3000"),
    "http://127.0.0.1:3000",
    "http://192.168.1.11:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ws_manager = WSManager()

# Include security module routers
app.include_router(anomaly_router.router)
app.include_router(webshield_router.router)
app.include_router(sandbox_router.router)
app.include_router(snort_router.router)
app.include_router(threat_actions_router.router)
app.include_router(cloud_protection_router.router)

# Initialize scanner router with dependencies (after LIVE_SCAN_STATE is created)
# This will be done after LIVE_SCAN_STATE initialization

# Sandbox jobs store (stub)
class SandboxJob(BaseModel):
    job_id: str
    target: str | None = None
    status: str = "queued"  # queued, running, done
    percent: int = 0
    verdict: str | None = None
    calls: list[str] | None = None
    score: float | None = None  # Anomaly score (0.0 to 1.0, higher = more suspicious)

DB.state.setdefault("sandbox_jobs", [])

# Live background scan status (enhanced)
# Get threat report interval from environment variable (default: 1 minute)
_DEFAULT_THREAT_REPORT_INTERVAL = float(os.getenv("BACKGROUND_SCAN_THREAT_REPORT_INTERVAL", "1.0"))

class LiveScanStatus(BaseModel):
    enabled: bool
    paths: list[str]
    recent_quarantine: list[str]
    exclude_patterns: list[str] = []
    scan_delay: float = 1.0
    auto_quarantine: bool = True  # Enabled by default for automatic threat protection
    threat_report_interval: float = _DEFAULT_THREAT_REPORT_INTERVAL  # Threat reporting interval in minutes (configurable via env var)
    stats: Optional[dict] = None
    recent_threats: list[dict] = []
    scan_progress: Optional[dict] = None

LIVE_SCAN_STATE: LiveScanStatus = LiveScanStatus(
    enabled=True,
    paths=["C:/Users", "C:/Users/Public"] if os.name == "nt" else ["/home", "/tmp"],
    recent_quarantine=[],
    exclude_patterns=[
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "AppData\\Local\\Temp",
        "/tmp",
        "/var/tmp",
    ],
    scan_delay=1.0,
    auto_quarantine=True,  # Enabled by default - automatically quarantines malicious and suspicious files
    threat_report_interval=_DEFAULT_THREAT_REPORT_INTERVAL,  # Configurable via BACKGROUND_SCAN_THREAT_REPORT_INTERVAL env var
)


@app.get("/api/overview", response_model=Overview)
def get_overview():
    threats = DB.list_threats(limit=100)
    return Overview(
        threatLevel=DB.state.get("threatLevel", 15),
        threatIndex=DB.state.get("threatIndex", 42),
        activeThreats=sum(1 for t in threats if t.action is None),
        filesScanned=DB.state.get("filesScanned", 0),
        networkAlerts=DB.state.get("networkAlerts", 0),
        protection=DB.state.get("protection", {"scan": True, "webshield": True, "snort": True}),
    )


@app.get("/api/threats", response_model=list[Threat])
def list_threats(limit: int = 100, severity: str | None = None, source: str | None = None, action: str | None = None):
    return DB.list_threats(limit=limit, severity=severity, source=source, action=action)


@app.get("/api/threats/{tid}", response_model=Threat)
def get_threat(tid: int):
    from sqlmodel import Session
    with Session(DB.engine) as s:
        obj = s.get(Threat, tid)
        return obj


class BulkActionReq(BaseModel):
    ids: list[int]
    action: str  # quarantine | delete | allow


@app.post("/api/threats/bulk-action")
def threats_bulk(req: BulkActionReq):
    from sqlmodel import Session
    updated = 0
    deleted_ids = []
    out = []
    with Session(DB.engine) as s:
        for tid in req.ids:
            obj = s.get(Threat, tid)
            if not obj:
                continue
            
            res = None
            res = None
            if req.action == "quarantine":
                print(f"[Bulk Quarantine] Attempting to quarantine threat {tid}, file: {obj.filePath if obj else 'None'}")
                success = threat_actions.quarantine_file(obj)
                print(f"[Bulk Quarantine] quarantine_file() returned: {success}")
                if success:
                    # Quarantine successful - threat is moved to quarantine
                    updated += 1
                    # Refresh the threat object to get updated action
                    s.refresh(obj)
                    # Update action to quarantined (don't delete from list, just mark as quarantined)
                    obj.action = "quarantined"
                    s.add(obj)
                    s.commit()
                    res = obj
                    try:
                        asyncio.create_task(ws_manager.broadcast({
                            "type": "threat_updated", 
                            "id": tid,
                            "action": "quarantined"
                        }))
                    except Exception:
                        pass
            elif req.action == "delete":
                # Use delete_anomalies.py script for enhanced deletion with admin auth
                file_deleted = False
                try:
                    from ..services import delete_anomalies_service
                    
                    # Get file path from threat before deletion
                    file_path = obj.filePath if obj and obj.filePath else None
                    print(f"[Bulk Delete] Attempting to delete threat {tid}, file: {file_path}")
                    
                    # Pass both threat_id and file_path for redundancy
                    delete_result = delete_anomalies_service.delete_anomaly_file_simple(
                        threat_id=tid,
                        file_path=file_path,  # Pass file path directly as well
                        use_recycle_bin=True
                    )
                    
                    print(f"[Bulk Delete] Delete result for threat {tid}:")
                    print(f"  - success: {delete_result.get('success')}")
                    print(f"  - deleted_files: {delete_result.get('deleted_files')}")
                    print(f"  - failed_files: {delete_result.get('failed_files')}")
                    print(f"  - error: {delete_result.get('error')}")
                    print(f"  - method: {delete_result.get('method')}")
                    print(f"  - file_path from threat: {file_path}")
                    
                    if delete_result.get("success"):
                        # Check if file was actually deleted
                        deleted_files = delete_result.get("deleted_files", [])
                        # Normalize paths for comparison (handle Windows path separators)
                        normalized_file_path = str(Path(file_path).resolve()) if file_path else None
                        normalized_deleted_files = [str(Path(f).resolve()) for f in deleted_files]
                        
                        # Check if file path is in deleted_files list or file no longer exists
                        file_path_deleted = False
                        if normalized_file_path and normalized_file_path in normalized_deleted_files:
                            file_path_deleted = True
                            print(f"[Bulk Delete] File path found in deleted_files list")
                        elif file_path:
                            file_path_obj = Path(file_path)
                            # Try both original path and resolved path
                            if not file_path_obj.exists() and not Path(file_path).resolve().exists():
                                file_path_deleted = True
                                print(f"[Bulk Delete] File {file_path} confirmed deleted (no longer exists)")
                        
                        # If deletion service reported success OR files were deleted, consider it a success
                        # (The deletion script might have moved file to recycle bin, which is still success)
                        service_success = delete_result.get("success", False)
                        has_deleted_files = len(deleted_files) > 0
                        
                        print(f"[Bulk Delete] Evaluation for threat {tid}:")
                        print(f"  - service_success: {service_success}")
                        print(f"  - has_deleted_files: {has_deleted_files} (count: {len(deleted_files)})")
                        print(f"  - file_path_deleted: {file_path_deleted}")
                        print(f"  - file_path: {file_path}")
                        
                        # If deletion service reported success OR files were in deleted_files list, mark as deleted
                        # Note: send2trash moves files to recycle bin, so file might still exist at original location
                        # but that's still considered a successful deletion. Also, PowerShell/batch scripts might
                        # succeed even if file appears to still exist (filesystem delay or Recycle Bin)
                        if service_success or has_deleted_files or file_path_deleted:
                            # Always mark as deleted if service reported success or files were deleted
                            # Don't do another existence check - trust the deletion service
                            # File successfully deleted using delete_anomalies.py
                            file_deleted = True
                            # Remove threat from database
                            s.delete(obj)
                            s.commit()
                            updated += 1
                            deleted_ids.append(tid)
                            print(f"[Bulk Delete] ✓ Successfully deleted file and threat {tid} using delete_anomalies.py")
                            try:
                                asyncio.create_task(ws_manager.broadcast({
                                    "type": "threat_deleted", 
                                    "id": tid,
                                    "method": "delete_anomalies_script"
                                }))
                            except Exception:
                                pass
                            continue
                        else:
                            # Deletion reported success but no files in deleted list - try fallback
                            print(f"[Bulk Delete] ⚠ delete_anomalies.py reported success but no files deleted: {file_path}, trying fallback")
                    else:
                        # Fallback to standard deletion if delete_anomalies.py fails
                        error_msg = delete_result.get("error", "Unknown error")
                        print(f"[Bulk Delete] ⚠ delete_anomalies.py failed for threat {tid}: {error_msg}, using fallback")
                except ImportError:
                    # delete_anomalies_service not available, use fallback
                    print(f"[Bulk Delete] ⚠ delete_anomalies_service not available, using fallback")
                except Exception as e:
                    print(f"[Bulk Delete] ⚠ Error using delete_anomalies.py: {e}, using fallback")
                    import traceback
                    traceback.print_exc()
                
                # Fallback to standard deletion method if delete_anomalies.py didn't work
                if not file_deleted:
                    print(f"[Bulk Delete] Using fallback deletion method for threat {tid}")
                    res = threat_actions.delete_file(obj, use_recycle_bin=True)
                    if res is None:
                        # Successfully deleted from database and filesystem
                        updated += 1
                        deleted_ids.append(tid)
                        print(f"[Bulk Delete] ✓ Successfully deleted threat {tid} using fallback method")
                        try:
                            asyncio.create_task(ws_manager.broadcast({"type": "threat_deleted", "id": tid}))
                        except Exception:
                            pass
                        # Don't add to output - threat is gone
                        continue
                    # If res is not None, something went wrong (shouldn't happen with current implementation)
                    else:
                        # Still remove from database even if file deletion had issues
                        s.delete(obj)
                        s.commit()
                        updated += 1
                        deleted_ids.append(tid)
                        print(f"[Bulk Delete] ⚠ Removed threat {tid} from database (file deletion may have failed)")
                        try:
                            asyncio.create_task(ws_manager.broadcast({"type": "threat_deleted", "id": tid}))
                        except Exception:
                            pass
                        continue
            elif req.action == "allow":
                res = DB.allow_file(tid)
            
            # Only add to output if we have a result and it's not a delete action
            if res and req.action != "delete":
                updated += 1
                out.append(res.model_dump())
                try:
                    td = res.model_dump()
                    try:
                        if getattr(res, "time", None):
                            td["time"] = res.time.astimezone().isoformat()
                    except Exception:
                        pass
                    asyncio.create_task(ws_manager.broadcast({"type": "threat_updated", "threat": td}))
                except Exception:
                    pass
    
    return {
        "ok": True, 
        "updated": updated, 
        "status": req.action, 
        "items": out, 
        "deleted_ids": deleted_ids,
        "message": f"Processed {len(req.ids)} threat(s): {updated} updated, {len(deleted_ids)} deleted"
    }


@app.get("/api/threats/{tid}/analyze")
def analyze_threat(tid: int):
    """Comprehensive threat analysis endpoint."""
    from sqlmodel import Session
    import hashlib
    import mimetypes
    from pathlib import Path
    
    with Session(DB.engine) as s:
        threat = s.get(Threat, tid)
        if not threat:
            return {"error": "Threat not found"}
        
        analysis = {
            "threat_id": tid,
            "timestamp": threat.time.isoformat() if hasattr(threat.time, 'isoformat') else str(threat.time),
            "severity": threat.severity,
            "source": threat.source,
            "description": threat.description,
            "action": threat.action,
            "location": {},
            "signature": {},
            "behavior": {},
            "risk_assessment": {},
        }
        
        # Location Information
        if threat.filePath:
            p = Path(threat.filePath)
            analysis["location"] = {
                "type": "file",
                "path": threat.filePath,
                "filename": p.name,
                "directory": str(p.parent),
                "exists": p.exists(),
            }
            if p.exists():
                try:
                    stat = p.stat()
                    analysis["location"]["size"] = stat.st_size
                    analysis["location"]["created"] = stat.st_ctime
                    analysis["location"]["modified"] = stat.st_mtime
                except Exception:
                    pass
        elif threat.url:
            analysis["location"] = {
                "type": "url",
                "url": threat.url,
            }
            try:
                from urllib.parse import urlparse
                parsed = urlparse(threat.url)
                analysis["location"]["domain"] = parsed.netloc
                analysis["location"]["scheme"] = parsed.scheme
                analysis["location"]["path"] = parsed.path
            except Exception:
                pass
        
        # Signature Analysis (for files)
        if threat.filePath:
            try:
                p = Path(threat.filePath)
                if p.exists() and p.is_file():
                    ext = p.suffix.lower()
                    mime = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
                    
                    # Read file header
                    header = b""
                    body_sample = b""
                    try:
                        with open(p, "rb") as f:
                            header = f.read(16)
                            body_sample = f.read(256 * 1024)  # 256KB sample
                    except Exception:
                        pass
                    
                    # File type detection
                    file_type = "unknown"
                    if header.startswith(b"MZ"):
                        file_type = "PE (Portable Executable - Windows)"
                    elif header.startswith(b"\x7FELF"):
                        file_type = "ELF (Executable and Linkable Format - Linux)"
                    elif header.startswith(b"%PDF"):
                        file_type = "PDF Document"
                    elif header.startswith(b"PK\x03\x04"):
                        file_type = "ZIP Archive"
                    elif header.startswith(b"\x89PNG"):
                        file_type = "PNG Image"
                    elif header.startswith(b"\xff\xd8\xff"):
                        file_type = "JPEG Image"
                    
                    # Compute hash
                    file_hash = ""
                    try:
                        h = hashlib.sha256()
                        with open(p, "rb") as f:
                            for chunk in iter(lambda: f.read(8192), b""):
                                h.update(chunk)
                        file_hash = h.hexdigest()
                    except Exception:
                        pass
                    
                    # Entropy calculation
                    entropy = 0.0
                    if body_sample:
                        counts = [0] * 256
                        for b in body_sample:
                            counts[b] += 1
                        length = len(body_sample)
                        for c in counts:
                            if c:
                                p_val = c / length
                                entropy -= p_val * math.log2(p_val)
                    
                    # Suspicious strings detection
                    suspicious_strings = [
                        "CreateRemoteThread", "VirtualAlloc", "RegSetValue",
                        "RegCreateKey", "WinExec", "ShellExecute", "powershell",
                        "-EncodedCommand", "FromBase64String", "cmd.exe",
                        "wget ", "curl ", "AutoIt"
                    ]
                    found_strings = []
                    try:
                        text_sample = body_sample.decode(errors="ignore")
                        for s in suspicious_strings:
                            if s in text_sample:
                                found_strings.append(s)
                    except Exception:
                        pass
                    
                    analysis["signature"] = {
                        "file_type": file_type,
                        "extension": ext,
                        "mime_type": mime,
                        "sha256": file_hash,
                        "entropy": round(entropy, 2),
                        "header_magic": header.hex()[:32] if header else None,
                        "suspicious_strings_found": found_strings,
                        "risk_indicators": {
                            "packed_obfuscated": entropy > 7.2 and ext in {".exe", ".dll", ".scr"},
                            "executable": ext in {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs"},
                            "high_entropy": entropy > 7.5,
                            "suspicious_strings": len(found_strings) > 0,
                        }
                    }
            except Exception as e:
                analysis["signature"]["error"] = str(e)
        
        # URL Analysis
        if threat.url:
            try:
                url_analysis = webshield.score_url(threat.url)
                analysis["signature"] = {
                    "type": "url",
                    "risk_score": url_analysis.get("score", 0),
                    "category": url_analysis.get("category", "unknown"),
                    "domain": analysis["location"].get("domain", ""),
                    "risk_indicators": {
                        "suspicious_keywords": url_analysis.get("score", 0) > 0.3,
                        "risky_tld": any(tld in threat.url.lower() for tld in [".ru", ".cn", ".cc", ".xyz"]),
                        "ip_address": "." in (analysis["location"].get("domain", "") or "").split(".")[0] if "." in (analysis["location"].get("domain", "") or "") else False,
                    }
                }
            except Exception:
                pass
        
        # Behavior Analysis
        if threat.deep_analysis:
            try:
                import json
                deep_data = json.loads(threat.deep_analysis) if isinstance(threat.deep_analysis, str) else threat.deep_analysis
                analysis["behavior"] = {
                    "sandbox_verdict": deep_data.get("verdict", "unknown"),
                    "sandbox_score": deep_data.get("score", 0),
                    "syscalls": deep_data.get("calls", []),
                    "system_interactions": len(deep_data.get("calls", [])) if isinstance(deep_data.get("calls"), list) else 0,
                }
            except Exception:
                pass
        
        # ML/Anomaly Analysis (for files)
        if threat.filePath:
            try:
                ml_analysis = anomaly.score_path(threat.filePath)
                analysis["behavior"]["ml_analysis"] = {
                    "risk_score": ml_analysis.get("risk", 0),
                    "verdict": ml_analysis.get("verdict", "unknown"),
                    "anomaly_detected": ml_analysis.get("risk", 0) > 0.5,
                }
            except Exception:
                pass
            
            # Sandbox behavior (if available)
            try:
                sandbox_result = sandbox.analyze_path(threat.filePath)
                analysis["behavior"]["sandbox_analysis"] = {
                    "syscalls": sandbox_result.get("syscalls", []),
                    "registry_access": sandbox_result.get("registry", []),
                    "network_activity": sandbox_result.get("network", []),
                    "verdict": sandbox_result.get("verdict", "unknown"),
                }
            except Exception:
                pass
        
        # Risk Assessment Summary
        risk_level = "low"
        risk_score = 0.0
        
        if threat.severity == "critical":
            risk_score = 0.95
            risk_level = "critical"
        elif threat.severity == "high":
            risk_score = 0.8
            risk_level = "high"
        elif threat.severity == "medium":
            risk_score = 0.6
            risk_level = "medium"
        else:
            risk_score = 0.3
            risk_level = "low"
        
        # Adjust based on signature and behavior
        if analysis.get("signature", {}).get("risk_indicators", {}):
            sig_risks = analysis["signature"]["risk_indicators"]
            if sig_risks.get("packed_obfuscated") or sig_risks.get("suspicious_strings"):
                risk_score = min(1.0, risk_score + 0.1)
            if sig_risks.get("executable") and threat.source == "ML":
                risk_score = min(1.0, risk_score + 0.15)
        
        if analysis.get("behavior", {}).get("sandbox_verdict") == "malicious":
            risk_score = min(1.0, risk_score + 0.2)
        
        analysis["risk_assessment"] = {
            "overall_risk": round(risk_score, 2),
            "risk_level": risk_level,
            "threat_category": threat.source,
            "confidence": "high" if risk_score > 0.7 else ("medium" if risk_score > 0.4 else "low"),
            "recommendations": [
                "Immediately quarantine the threat" if risk_score > 0.7 else "Monitor closely",
                "Review file behavior in sandbox" if threat.filePath else "Block URL access",
                "Check for related threats in system" if risk_score > 0.6 else "Verify threat signature",
            ]
        }
        
        return analysis


@app.get("/api/webshield/blocked")
def blocked_urls():
    """Get list of blocked URLs with full history from database."""
    blocked = DB.list_blocked_urls(limit=1000)
    return [
        {
            "id": b.id,
            "url": b.url,
            "host": b.host,
            "score": b.score,
            "category": b.category,
            "os_blocked": b.os_blocked,
            "created": b.created.isoformat() if hasattr(b.created, 'isoformat') else str(b.created),
        }
        for b in blocked
    ]


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await asyncio.sleep(1.0)
            # emit a metric point
            t = int(time.time() * 1000)
            metric = {
                "t": t,
                "cpu": random.randint(5, 95),
                "mem": random.randint(5, 95),
                "disk": random.randint(0, 100),
                "netUp": random.randint(10, 300),
                "netDown": random.randint(10, 300),
            }
            await ws_manager.broadcast({"type": "metric", "data": metric})
            # push a log line occasionally
            if random.random() < 0.3:
                from datetime import datetime
                log = {"time": datetime.now().astimezone().isoformat(), "level": random.choice(["INFO","WARN","ERROR"]), "msg": random.choice(["Scan completed","Connection blocked","Sandbox job started"]) }
                DB.state.setdefault("logs", []).insert(0, log)
                await ws_manager.broadcast({"type": "log", "level": log["level"], "msg": log["msg"], "timestamp": log["time"]})
            # occasionally emit synthetic threat
            if random.random() < 0.2:
                titem = DB.add_threat(
                    ThreatIn(
                        severity=random.choice(["low", "medium", "high", "critical"]),
                        description=random.choice([
                            "Suspicious process behavior detected",
                            "Malware signature match",
                            "Anomalous network activity",
                            "Risky URL blocked",
                        ]),
                        source=random.choice(["ML", "Snort", "WebShield", "Sandbox"]),
                    )
                )
                th = titem.model_dump()
                try:
                    th_time = getattr(titem, "time", None)
                    if th_time:
                        th["time"] = th_time.astimezone().isoformat()
                except Exception:
                    pass
                await ws_manager.broadcast({"type": "threat", "data": th})
                # small change to threat level
                DB.state["threatLevel"] = max(0, min(100, DB.state.get("threatLevel", 15) + random.randint(-2, 5)))
                await ws_manager.broadcast({"type": "threatLevel", "data": DB.state["threatLevel"]})
            # network connection update
            if random.random() < 0.3:
                from datetime import datetime
                await ws_manager.broadcast({
                    "type": "connection_update",
                    "pid": random.randint(1000, 5000),
                    "process": random.choice(["chrome.exe", "python.exe", "code.exe", "snort.exe", "node.exe"]),
                    "remote": random.choice(["8.8.8.8:443", "1.1.1.1:53", "github.com:443", "bad.example:80"]),
                    "bytes_sec": random.randint(100, 5000),
                    "timestamp": datetime.now().astimezone().isoformat(),
                })
            # snort alert (only if snort protection is enabled)
            if random.random() < 0.2:
                protection = DB.state.get("protection", {})
                if protection.get("snort", True):
                    from datetime import datetime
                    await ws_manager.broadcast({
                        "type": "snort_alert",
                        "sid": random.randint(200000, 201000),
                        "msg": random.choice(["SQLi attempt", "Port scan detected", "DNS tunneling"]),
                        "src": random.choice(["10.0.0.5", "1.2.3.4", "192.168.1.10"]),
                        "dst": random.choice(["8.8.8.8", "5.6.7.8", "192.168.1.1"]),
                        "time": datetime.now().astimezone().isoformat(),
                    })
            # Active URL checking and blocking (if webshield enabled)
            if random.random() < 0.15:
                protection = DB.state.get("protection", {})
                if protection.get("webshield", True):
                    # Simulate checking a risky URL and auto-blocking
                    test_urls = [
                        "http://malicious-phishing-site.ru/login",
                        "https://suspicious-giveaway-free.win/claim",
                        "http://192.168.1.100/suspicious",
                        "https://free-bitcoin-claim.cc/verify",
                    ]
                    test_url = random.choice(test_urls)
                    result = webshield.check_and_block_url(test_url, auto_block_threshold=0.5, db=DB)
                    # Only add alert if URL was actually blocked (WebShield must be enabled for this)
                    if result.get("blocked") and result.get("action") != "allowed":
                        from datetime import datetime
                        alert = {
                            "type": "webshield_alert",
                            "url": test_url,
                            "score": result["score"],
                            "category": result["category"],
                            "action": result["action"],
                            "timestamp": datetime.now().astimezone().isoformat(),
                            "os_blocked": result.get("os_blocked", False),
                        }
                        DB.state.setdefault("webshield_alerts", []).insert(0, alert)
                        DB.state["webshield_alerts"] = DB.state["webshield_alerts"][:500]
                        await ws_manager.broadcast({
                            "type": "webshield_alert",
                            "url": alert["url"],
                            "score": alert["score"],
                            "category": alert["category"],
                            "action": alert["action"],
                            "timestamp": alert["timestamp"],
                            "os_blocked": alert["os_blocked"],
                        })
            
            # webshield alert
            if random.random() < 0.2:
                from datetime import datetime
                ws_alert = {
                    "type": "webshield_alert",
                    "url": random.choice(["http://bad.example", "http://phish.ru", "http://free-giveaway.cn"]),
                    "score": round(random.uniform(0.5, 0.99), 2),
                    "category": random.choice(["phishing", "malware", "scam"]),
                    "action": "blocked",
                    "timestamp": datetime.now().astimezone().isoformat(),
                }
                await ws_manager.broadcast(ws_alert)
            # background scan status/event
            if random.random() < 0.2:
                from datetime import datetime
                await ws_manager.broadcast({
                    "type": "scan_status",
                    "enabled": LIVE_SCAN_STATE.enabled,
                    "paths": LIVE_SCAN_STATE.paths,
                    "timestamp": datetime.now().astimezone().isoformat(),
                })
            if random.random() < 0.2:
                from datetime import datetime
                await ws_manager.broadcast({
                    "type": "scan_event",
                    "job_id": f"s-{random.randint(1, 9)}",
                    "percent": random.randint(0, 100),
                    "scanned": random.randint(10, 500),
                    "timestamp": datetime.now().astimezone().isoformat(),
                })
            # sandbox progress/result
            if random.random() < 0.25:
                jobs: list[SandboxJob] = [SandboxJob(**j) for j in DB.state.get("sandbox_jobs", [])]
                if jobs:
                    j = random.choice(jobs)
                    if j.status != "done":
                        j.status = "running"
                        j.percent = min(100, j.percent + random.randint(5, 25))
                        if j.percent >= 100:
                            j.status = "done"
                            j.verdict = random.choice(["benign", "suspicious", "malicious"])
                            j.calls = ["CreateFile", "ReadFile", "WriteFile"]
                            sr_score = round(random.uniform(0.5, 0.99), 2)
                            from datetime import datetime
                            await ws_manager.broadcast({
                                "type": "sandbox_result",
                                "job_id": j.job_id,
                                "verdict": j.verdict,
                                "calls": j.calls,
                                "score": sr_score,
                                "target": j.target,
                                "timestamp": datetime.now().astimezone().isoformat(),
                            })
                            try:
                                from sqlmodel import Session, select
                                with Session(DB.engine) as s:
                                    q = s.exec(select(Threat).where((Threat.filePath == j.target) | (Threat.url == j.target))).first()
                                    if q:
                                        q.deep_analysis = json.dumps({"calls": j.calls or [], "score": sr_score, "verdict": j.verdict})
                                        q.action = "analyzed"
                                        s.add(q)
                                        s.commit()
                                        s.refresh(q)
                                        try:
                                            qd = q.model_dump()
                                            try:
                                                if getattr(q, "time", None):
                                                    qd["time"] = q.time.astimezone().isoformat()
                                            except Exception:
                                                pass
                                            await ws_manager.broadcast({"type": "threat_updated", "threat": qd})
                                        except Exception:
                                            pass
                            except Exception:
                                pass
                        else:
                            from datetime import datetime
                            await ws_manager.broadcast({
                                "type": "sandbox_progress",
                                "job_id": j.job_id,
                                "percent": j.percent,
                                "timestamp": datetime.now().astimezone().isoformat(),
                            })
                        # persist back
                        DB.state["sandbox_jobs"] = [jj.model_dump() if isinstance(jj, SandboxJob) else jj for jj in jobs]
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


@app.post("/api/scan/url")
def scan_url(url: str):
    """Scan URL and automatically block if risky. Active blocking enabled."""
    protection = DB.state.get("protection", {})
    webshield_enabled = protection.get("webshield", True)
    
    # Cloud protection check for URL
    cloud_result = None
    try:
        cloud_service = get_cloud_service()
        if cloud_service.enabled:
            cloud_result = cloud_service.check_url(url)
            # If cloud detects threat, enhance blocking decision
            if cloud_result.get("threat_detected"):
                # Force block if cloud confirms malicious
                if cloud_result.get("cloud_reputation") == "malicious":
                    webshield.block_url(url, force=True)
                    DB.add_blocked_url(url, url, 1.0, "malicious", True)
    except Exception as e:
        print(f"[Scan] Cloud protection URL check error: {e}")
    
    if webshield_enabled:
        # Active blocking: check and auto-block risky URLs
        result = webshield.check_and_block_url(url, auto_block_threshold=0.5, db=DB)
        
        # Only add alert if URL was actually blocked (WebShield must be enabled for this)
        if result.get("blocked") and result.get("action") != "allowed":
            from datetime import datetime
            alert = {
                "type": "webshield_alert",
                "url": url,
                "score": result["score"],
                "category": result["category"],
                "action": result["action"],
                "timestamp": datetime.now().astimezone().isoformat(),
                "os_blocked": result.get("os_blocked", False),
            }
            DB.state.setdefault("webshield_alerts", []).insert(0, alert)
            # Keep only last 500 alerts
            DB.state["webshield_alerts"] = DB.state["webshield_alerts"][:500]
            
            try:
                asyncio.create_task(ws_manager.broadcast({
                    "type": "webshield_alert",
                    "url": alert["url"],
                    "score": alert["score"],
                    "category": alert["category"],
                    "action": alert["action"],
                    "timestamp": alert["timestamp"],
                    "os_blocked": alert["os_blocked"],
                }))
            except Exception:
                pass
            
            # Add threat record only if blocked
            sev = "high" if result["category"] == "phishing" else ("medium" if result["score"] >= 0.5 else "low")
            try:
                DB.add_threat(ThreatIn(
                    severity=sev,
                    description=f"WebShield auto-blocked risky URL: {url}",
                    source="WebShield",
                    url=url
                ))
            except Exception:
                pass
        
        return result
    else:
        # If WebShield is disabled, just return scoring info without blocking, alerting, or adding threats
        result = webshield.score_url(url)
        return {
            "url": url,
            "score": result.get("score", 0.0),
            "category": result.get("category", "benign"),
            "blocked": False,
            "action": "allowed",
            "os_blocked": False,
        }


async def _process_scan_job(job_id: str):
    """Background task to process a scan job asynchronously."""
    try:
        job = DB.get_scan_job(job_id)
        if not job:
            return
        
        # Update status to processing
        DB.update_scan_job(job_id, status="processing", progress=10)
        
        p = Path(job.file_path)
        if not p.exists() or not p.is_file():
            DB.update_scan_job(job_id, status="failed", error="File not found")
            return
        
        # Read file data
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except Exception as e:
            DB.update_scan_job(job_id, status="failed", error=f"Failed to read file: {str(e)}")
            return
        
        DB.update_scan_job(job_id, progress=20)
        
        # Compute file properties
        def _entropy(b: bytes) -> float:
            if not b:
                return 0.0
            counts = [0] * 256
            for x in b:
                counts[x] += 1
            e = 0.0
            n = len(b)
            for c in counts:
                if c:
                    p = c / n
                    e -= p * math.log2(p)
            return e
        
        def _filetype(b: bytes, name: str) -> str:
            if b.startswith(b"MZ"):
                return "pe"
            if b.startswith(b"\x7FELF"):
                return "elf"
            if b.startswith(b"%PDF"):
                return "pdf"
            if b.startswith(b"PK\x03\x04"):
                return "zip"
            ext = Path(name).suffix.lower()
            if ext in {".ps1", ".psm1", ".bat", ".cmd"}:
                return "script"
            if ext in {".js", ".vbs"}:
                return "script"
            return "unknown"
        
        sha256 = hashlib.sha256(data).hexdigest()
        ent = _entropy(data)
        ftype = _filetype(data, p.name)
        
        DB.update_scan_job(job_id, progress=40)
        
        # YARA matching
        yara_matches: list[str] = []
        try:
            import yara
            rules_src = "rule R1 { strings: $a = \"powershell\" wide ascii $b = /FromBase64String/ wide ascii $c = /cmd\\.exe/ ascii condition: any of them } rule R2 { strings: $mz = {4D 5A} $alloc = /VirtualAlloc/ ascii condition: $mz and $alloc }"
            rs = yara.compile(source=rules_src)
            r = rs.match(data=data)
            yara_matches = [m.rule for m in r]
        except Exception:
            pass
        
        DB.update_scan_job(job_id, progress=50)
        
        # ML scoring
        if DB.is_allowed_path(str(p)):
            score = {"path": str(p), "risk": 0.0, "verdict": "allowed", "mime": job.file_mime, "size": job.file_size}
        else:
            # Pass YARA matches to anomaly scoring for better detection
            score = anomaly.score_path(str(p), yara_matches=yara_matches)
        
        score["hash"] = sha256
        score["filetype"] = ftype
        score["entropy"] = ent
        # YARA matches are now included in score from anomaly.py
        if "yara_matches" not in score:
            score["yara"] = yara_matches
        
        DB.update_scan_job(job_id, progress=70)
        
        # Cloud protection check
        cloud_result = None
        try:
            cloud_service = get_cloud_service()
            if cloud_service.enabled:
                cloud_result = cloud_service.check_file(str(p))
                # Enhance risk score if cloud detects threat
                if cloud_result.get("threat_detected"):
                    cloud_score = cloud_result.get("cloud_score", 0.0)
                    # Boost risk if cloud confirms threat
                    current_risk = score.get("risk", 0.0)
                    score["risk"] = min(1.0, max(current_risk, cloud_score))
                    if cloud_result.get("cloud_verdict") in ("malicious", "suspicious"):
                        score["verdict"] = cloud_result.get("cloud_verdict")
        except Exception as e:
            print(f"[Scan] Cloud protection check error: {e}")
        
        # Sandbox analysis
        sand = sandbox.analyze_path(str(p))
        
        DB.update_scan_job(job_id, progress=85)
        
        # Prepare metadata
        is_dir = p.is_dir()
        entries: list[str] = []
        if not is_dir:
            try:
                if zipfile.is_zipfile(str(p)):
                    with zipfile.ZipFile(str(p)) as zf:
                        entries = [i.filename for i in zf.infolist()[:50]]
            except Exception:
                entries = []
        
        meta = {
            "path": str(p),
            "name": p.name,
            "size": job.file_size,
            "mime": job.file_mime,
            "hash": sha256,
            "filetype": ftype,
            "entropy": ent,
            "yara": yara_matches,
            "structure": {
                "is_dir": is_dir,
                "entries": entries,
            },
        }
        
        r = float(score.get("risk", 0) or 0)
        v = str(score.get("verdict", "benign")).lower()
        
        # Severity mapping
        if v == "malicious":
            severity = "high"
        elif v == "suspicious":
            severity = "medium"
        else:
            severity = "low"
        
        res = {"ml": score, "sandbox": sand, "meta": meta, "severity": severity}
        if cloud_result:
            res["cloud"] = cloud_result
        
        DB.update_scan_job(job_id, progress=90)
        
        # Auto-submit to cloud platforms if threat detected
        if v in ("malicious", "suspicious") or severity in ("high", "medium"):
            try:
                cloud_service = get_cloud_service()
                if cloud_service.enabled and cloud_service.auto_submit_enabled:
                    submission_result = cloud_service.submit_threat_sample(str(p), v, severity)
                    if submission_result.get("submitted"):
                        print(f"[Manual Scanner] Auto-submitted {p.name} to {len(submission_result.get('platforms', []))} cloud platform(s)")
                        res["cloud_submission"] = submission_result
            except Exception as e:
                print(f"[Manual Scanner] Error during auto-submission: {e}")
        
        # Update scan history (keep in-memory for backward compatibility)
        seq = DB.state.get("scan_seq", 0) + 1
        DB.state["scan_seq"] = seq
        entry = {
            "id": seq,
            "path": str(p),
            "name": p.name,
            "mime": job.file_mime,
            "size": job.file_size,
            "severity": severity,
            "risk": r,
            "verdict_ml": score.get("verdict"),
            "time": datetime.now().astimezone().isoformat(),
            "is_uploaded": job.is_uploaded,
            "temp_path": job.temp_path,
        }
        scanned_files = DB.state.setdefault("scanned_files", [])
        scanned_files.insert(0, entry)
        from datetime import timedelta
        cutoff_time = (datetime.now().astimezone() - timedelta(days=30)).isoformat()
        scanned_files = [f for f in scanned_files if f.get("time", "") >= cutoff_time]
        DB.state["scanned_files"] = scanned_files[:200]
        DB.state["filesScanned"] = DB.state.get("filesScanned", 0) + 1
        
        # Create threat record (retain in database)
        threat_id = None
        try:
            titem = DB.add_threat(ThreatIn(
                severity=severity, 
                description=f"File scanned: {p.name}", 
                source="Manual Scanner", 
                filePath=str(p)
            ))
            threat_id = titem.id
            td = titem.model_dump()
            try:
                if getattr(titem, "time", None):
                    td["time"] = titem.time.astimezone().isoformat()
            except Exception:
                pass
            asyncio.create_task(ws_manager.broadcast({"type": "threat", "data": td}))
        except Exception as e:
            print(f"[Scan Job] Failed to create threat: {e}")
        
        # Mark job as completed
        DB.update_scan_job(job_id, status="completed", progress=100, result=res, threat_id=threat_id)
        
        # Broadcast scan completion
        try:
            asyncio.create_task(ws_manager.broadcast({
                "type": "scan_completed",
                "job_id": job_id,
                "result": res
            }))
        except Exception:
            pass
        
    except Exception as e:
        print(f"[Scan Job] Error processing job {job_id}: {e}")
        import traceback
        traceback.print_exc()
        DB.update_scan_job(job_id, status="failed", error=str(e))


@app.post("/api/scan/file")
async def scan_file(request: Request, file: UploadFile | None = File(None), path: str | None = Form(None)):
    """Asynchronous file scanning - returns job ID immediately.
    Note: Manual scans always work regardless of protection.scan setting.
    The protection.scan setting only controls the background/live scanner.
    """
    use_path = path
    temp_path = None
    file_name = None
    file_size = 0
    file_mime = "application/octet-stream"
    
    if file is not None:
        data = await file.read()
        file_name = file.filename or "uploaded_file"
        file_size = len(data)
        file_mime = file.content_type or mimetypes.guess_type(file_name)[0] or "application/octet-stream"
        fd, temp_path = tempfile.mkstemp(prefix="upload_", suffix=os.path.splitext(file_name)[1])
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        use_path = temp_path
    else:
        data = None
    
    # Accept JSON body or query param path when not provided as Form
    if not use_path:
        try:
            js = await request.json()
            use_path = js.get("path") if isinstance(js, dict) else None
        except Exception:
            use_path = use_path
    if not use_path:
        try:
            qp = request.query_params.get("path")
            use_path = qp or use_path
        except Exception:
            pass
    
    if not use_path:
        return {"error": "no_input"}
    
    p = Path(use_path)
    if not p.exists() or not p.is_file():
        return {"error": "file_not_found"}
    
    # Get file info if not already known
    if file_name is None:
        file_name = p.name
    if file_size == 0:
        try:
            file_size = p.stat().st_size
        except Exception:
            file_size = 0
    if file_mime == "application/octet-stream":
        file_mime = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
    
    # Generate unique job ID
    job_id = f"scan_{int(time.time())}_{hashlib.md5(f'{p}_{time.time()}'.encode()).hexdigest()[:8]}"
    
    # Create scan job
    is_uploaded = temp_path is not None and temp_path == str(p)
    job = DB.create_scan_job(
        job_id=job_id,
        file_path=str(p),
        file_name=file_name,
        file_size=file_size,
        file_mime=file_mime,
        is_uploaded=is_uploaded,
        temp_path=temp_path if is_uploaded else None
    )
    
    # Start background processing
    asyncio.create_task(_process_scan_job(job_id))
    
    # Return job info immediately
    return {
        "job_id": job_id,
        "status": "queued",
        "file_name": file_name,
        "file_path": str(p),
        "message": "Scan job queued. Use /api/scan/status/{job_id} to check status."
    }


def _threat_callback(file_path: str, result: dict):
    """Callback when a threat is detected during background scanning."""
    try:
        verdict = result.get("verdict", "benign")
        risk = float(result.get("risk", 0) or 0)
        severity = "high" if verdict == "malicious" else ("medium" if verdict == "suspicious" else "low")
        
        # Add threat to database
        threat = DB.add_threat(ThreatIn(
            severity=severity,
            description=f"Background scanner detected {verdict} file: {Path(file_path).name}",
            source="Background Scanner",
            filePath=file_path,
        ))
        
        # Auto-submit to cloud platforms if enabled
        try:
            cloud_service = get_cloud_service()
            if cloud_service.enabled and cloud_service.auto_submit_enabled:
                submission_result = cloud_service.submit_threat_sample(file_path, verdict, severity)
                if submission_result.get("submitted"):
                    print(f"[Background Scanner] Auto-submitted {Path(file_path).name} to {len(submission_result.get('platforms', []))} cloud platform(s)")
        except Exception as e:
            print(f"[Background Scanner] Error during auto-submission: {e}")
        
        # Auto-quarantine if enabled
        if LIVE_SCAN_STATE.auto_quarantine and verdict in ("malicious", "suspicious"):
            try:
                print(f"[Background Scanner] Auto-quarantining {verdict} file: {file_path}")
                success = threat_actions.quarantine_file(threat)
                if success:
                    print(f"[Background Scanner] Successfully quarantined: {file_path}")
                    if file_path not in LIVE_SCAN_STATE.recent_quarantine:
                        LIVE_SCAN_STATE.recent_quarantine.insert(0, file_path)
                        # Keep only last 50 quarantine entries for optimization
                        LIVE_SCAN_STATE.recent_quarantine = LIVE_SCAN_STATE.recent_quarantine[:50]
                else:
                    print(f"[Background Scanner] Warning: Failed to quarantine {file_path} - file may still be accessible")
            except Exception as e:
                print(f"[Background Scanner] Error during auto-quarantine: {e}")
                import traceback
                traceback.print_exc()
        
        # Broadcast via WebSocket
        try:
            asyncio.create_task(ws_manager.broadcast({
                "type": "background_scan_threat",
                "path": file_path,
                "verdict": verdict,
                "risk": risk,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }))
        except Exception:
            pass
    except Exception:
        pass


# Initialize scanner router with dependencies (after _threat_callback is defined)
scanner_router.init_scanner_router(LIVE_SCAN_STATE, _threat_callback, ws_manager)
app.include_router(scanner_router.router)


@app.get("/api/scan/live/status", response_model=LiveScanStatus)
def live_scan_status():
    """Get live scan status with statistics."""
    scanner = background.get_scanner()
    stats = scanner.get_stats()
    recent_threats = scanner.get_recent_threats(limit=15)  # Reduced from 20 to 15 for optimization
    scan_progress = scanner.get_scan_progress()
    
    LIVE_SCAN_STATE.stats = stats
    LIVE_SCAN_STATE.recent_threats = recent_threats
    LIVE_SCAN_STATE.scan_progress = scan_progress
    return LIVE_SCAN_STATE


class ToggleReq(BaseModel):
    enabled: bool


@app.post("/api/scan/live/toggle", response_model=LiveScanStatus)
def live_scan_toggle(req: ToggleReq):
    """Toggle background scanning on/off."""
    LIVE_SCAN_STATE.enabled = req.enabled
    scanner = background.get_scanner()
    
    def progress_callback(progress_data: dict):
        """Callback for scan progress updates."""
        try:
            asyncio.create_task(ws_manager.broadcast(progress_data))
        except Exception:
            pass
    
    if req.enabled:
        scanner.start_monitoring(
            paths=LIVE_SCAN_STATE.paths,
            scan_callback=_threat_callback,
            exclude_patterns=LIVE_SCAN_STATE.exclude_patterns,
            scan_delay=LIVE_SCAN_STATE.scan_delay,
            threat_report_interval=LIVE_SCAN_STATE.threat_report_interval * 60,  # Convert minutes to seconds
            progress_callback=progress_callback,
        )
    else:
        scanner.stop_monitoring()
    
    return live_scan_status()


class PathReq(BaseModel):
    path: str


@app.post("/api/scan/live/add-path", response_model=LiveScanStatus)
def live_scan_add_path(req: PathReq):
    """Add a path to monitor."""
    if req.path not in LIVE_SCAN_STATE.paths:
        LIVE_SCAN_STATE.paths.append(req.path)
    
    # Restart monitoring with new paths
    scanner = background.get_scanner()
    
    def progress_callback(progress_data: dict):
        """Callback for scan progress updates."""
        try:
            asyncio.create_task(ws_manager.broadcast(progress_data))
        except Exception:
            pass
    
    if LIVE_SCAN_STATE.enabled:
        scanner.start_monitoring(
            paths=LIVE_SCAN_STATE.paths,
            scan_callback=_threat_callback,
            exclude_patterns=LIVE_SCAN_STATE.exclude_patterns,
            scan_delay=LIVE_SCAN_STATE.scan_delay,
            threat_report_interval=LIVE_SCAN_STATE.threat_report_interval * 60,
            progress_callback=progress_callback,
        )
    
    return live_scan_status()


@app.delete("/api/scan/live/remove-path", response_model=LiveScanStatus)
def live_scan_remove_path(req: PathReq):
    """Remove a path from monitoring."""
    LIVE_SCAN_STATE.paths = [p for p in LIVE_SCAN_STATE.paths if p != req.path]
    
    # Restart monitoring with updated paths
    scanner = background.get_scanner()
    
    def progress_callback(progress_data: dict):
        """Callback for scan progress updates."""
        try:
            asyncio.create_task(ws_manager.broadcast(progress_data))
        except Exception:
            pass
    
    if LIVE_SCAN_STATE.enabled:
        scanner.start_monitoring(
            paths=LIVE_SCAN_STATE.paths,
            scan_callback=_threat_callback,
            exclude_patterns=LIVE_SCAN_STATE.exclude_patterns,
            scan_delay=LIVE_SCAN_STATE.scan_delay,
            threat_report_interval=LIVE_SCAN_STATE.threat_report_interval * 60,
            progress_callback=progress_callback,
        )
    
    return live_scan_status()


class UpdateConfigReq(BaseModel):
    exclude_patterns: Optional[list[str]] = None
    scan_delay: Optional[float] = None
    auto_quarantine: Optional[bool] = None
    threat_report_interval: Optional[float] = None  # In minutes


@app.post("/api/scan/live/config", response_model=LiveScanStatus)
def live_scan_update_config(req: UpdateConfigReq):
    """Update background scanner configuration."""
    if req.exclude_patterns is not None:
        LIVE_SCAN_STATE.exclude_patterns = req.exclude_patterns
    if req.scan_delay is not None:
        LIVE_SCAN_STATE.scan_delay = max(0.1, min(10.0, req.scan_delay))
    if req.auto_quarantine is not None:
        LIVE_SCAN_STATE.auto_quarantine = req.auto_quarantine
    if req.threat_report_interval is not None:
        # Validate and set threat report interval (minimum 1 minute)
        LIVE_SCAN_STATE.threat_report_interval = max(1.0, min(1440.0, req.threat_report_interval))
        # Update scanner's interval (function expects minutes, not seconds)
        scanner = background.get_scanner()
        scanner.set_threat_report_interval(LIVE_SCAN_STATE.threat_report_interval)
    
    # Restart monitoring with new config
    scanner = background.get_scanner()
    
    def progress_callback(progress_data: dict):
        """Callback for scan progress updates."""
        try:
            asyncio.create_task(ws_manager.broadcast(progress_data))
        except Exception:
            pass
    
    if LIVE_SCAN_STATE.enabled:
        scanner.start_monitoring(
            paths=LIVE_SCAN_STATE.paths,
            scan_callback=_threat_callback,
            exclude_patterns=LIVE_SCAN_STATE.exclude_patterns,
            scan_delay=LIVE_SCAN_STATE.scan_delay,
            threat_report_interval=LIVE_SCAN_STATE.threat_report_interval * 60,  # Convert minutes to seconds
            progress_callback=progress_callback,
        )
    
    return live_scan_status()


@app.get("/api/network/connections")
def network_connections():
    return DB.state.setdefault("connections", [])


class BlockReq(BaseModel):
    remote: str


@app.post("/api/network/block")
def network_block(req: BlockReq):
    blocked = DB.state.setdefault("blocked_ips", [])
    if req.remote not in blocked:
        blocked.append(req.remote)
    DB.state["networkAlerts"] = DB.state.get("networkAlerts", 0) + 1
    return {"ok": True, "blocked": req.remote}


@app.get("/api/network/webshield/alerts")
def webshield_alerts():
    """Get WebShield alerts with history from database and recent state."""
    alerts = DB.state.get("webshield_alerts", [])
    # Also include blocked URLs from database as alerts
    blocked = DB.list_blocked_urls(limit=100)
    from datetime import datetime
    for b in blocked:
        # Add if not already in alerts
        if not any(a.get("url") == b.url for a in alerts):
            alerts.insert(0, {
                "type": "webshield_alert",
                "url": b.url,
                "score": b.score,
                "category": b.category,
                "action": "blocked" if b.os_blocked else "flagged",
                "timestamp": b.created.isoformat() if hasattr(b.created, 'isoformat') else str(b.created),
                "os_blocked": b.os_blocked,
            })
    # Sort by timestamp, most recent first
    alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return alerts[:200]  # Return last 200 alerts


@app.delete("/api/webshield/blocked/{url_id}")
def delete_blocked_url(url_id: int):
    """Remove URL from blocked list."""
    deleted = DB.delete_blocked_url(url_id)
    if deleted:
        return {"ok": True, "message": "URL unblocked"}
    return {"ok": False, "error": "URL not found"}


class WebShieldBlockReq(BaseModel):
    url: str


@app.post("/api/network/webshield/block")
def webshield_block(req: WebShieldBlockReq):
    """Manually block URL - forces permanent OS-level blocking."""
    # Force block at OS level
    res = webshield.block_url(req.url, force=True)
    os_ok = bool(res.get("updated", False)) or bool(res.get("ok", False))
    host = res.get("host")
    base = res.get("base")
    
    # Score the URL
    scored = webshield.score_url(req.url)
    score_val = float(scored.get("score", 0.75))
    category = str(scored.get("category", "suspicious"))
    
    # Save to database (persistent storage)
    if host:
        try:
            DB.add_blocked_url(req.url, base or host, score_val, category, os_ok)
        except Exception:
            pass
    
    from datetime import datetime
    alert = {
        "type": "webshield_alert",
        "url": req.url,
        "score": score_val,
        "category": category,
        "action": "manually_blocked",
        "timestamp": datetime.now().astimezone().isoformat(),
        "os_blocked": os_ok,
    }
    DB.state.setdefault("webshield_alerts", []).insert(0, alert)
    # Keep only last 500 alerts
    DB.state["webshield_alerts"] = DB.state["webshield_alerts"][:500]
    
    try:
        asyncio.create_task(ws_manager.broadcast({
            "type": "webshield_alert",
            "url": alert["url"],
            "score": alert["score"],
            "category": alert["category"],
            "action": alert["action"],
            "timestamp": alert["timestamp"],
            "os_blocked": alert["os_blocked"],
        }))
    except Exception:
        pass
    
    sev = "high" if category == "phishing" else ("medium" if score_val >= 0.5 else "low")
    try:
        DB.add_threat(ThreatIn(
            severity=sev,
            description=f"WebShield manually blocked URL: {req.url}",
            source="WebShield",
            url=req.url
        ))
    except Exception:
        pass
    
    return {
        "ok": True,
        "url": req.url,
        "os_block": os_ok,
        "host": host,
        "base": base,
        "updated": res.get("updated", False),
        "message": "URL permanently blocked" if os_ok else res.get("error", "Blocking may require admin privileges"),
    }


class WebShieldToggleReq(BaseModel):
    enabled: bool


@app.post("/api/network/webshield/toggle")
def webshield_toggle(req: WebShieldToggleReq):
    prot = DB.state.setdefault("protection", {"scan": True, "webshield": True, "snort": True})
    prot["webshield"] = req.enabled
    return {"ok": True, "enabled": req.enabled}


class ProtectionToggleReq(BaseModel):
    module: str  # "scan", "webshield", or "snort"
    enabled: bool


@app.post("/api/settings/protection")
def toggle_protection(req: ProtectionToggleReq):
    """Unified endpoint to toggle any protection module."""
    prot = DB.state.setdefault("protection", {"scan": True, "webshield": True, "snort": True})
    
    if req.module not in ["scan", "webshield", "snort"]:
        return {"ok": False, "error": f"Invalid module: {req.module}"}
    
    prot[req.module] = req.enabled
    
    # If toggling scan, also update the live scanner
    if req.module == "scan":
        scanner = background.get_scanner()
        if req.enabled:
            # Start monitoring if enabled
            def progress_callback(progress_data: dict):
                try:
                    asyncio.create_task(ws_manager.broadcast(progress_data))
                except Exception:
                    pass
            
            scanner.start_monitoring(
                paths=LIVE_SCAN_STATE.paths,
                scan_callback=_threat_callback,
                exclude_patterns=LIVE_SCAN_STATE.exclude_patterns,
                scan_delay=LIVE_SCAN_STATE.scan_delay,
                threat_report_interval=LIVE_SCAN_STATE.threat_report_interval * 60,
                progress_callback=progress_callback,
            )
            LIVE_SCAN_STATE.enabled = True
        else:
            # Stop monitoring if disabled
            scanner.stop_monitoring()
            LIVE_SCAN_STATE.enabled = False
    
    return {"ok": True, "module": req.module, "enabled": req.enabled, "protection": prot}


# Logs streaming
DB.state.setdefault("logs", [])
DB.state.setdefault("scanned_files", [])
DB.state.setdefault("scan_seq", 0)

@app.get("/api/logs")
def logs(limit: int = 100):
    items = DB.state.get("logs", [])
    return list(items[:limit])


@app.get("/api/logs/download")
def logs_download():
    try:
        items = DB.state.get("logs", [])
        if not items:
            return {"text": "No logs available.\n"}
        text = "\n".join(f"{i.get('time','')} [{i.get('level','INFO')}] {i.get('msg','')}" for i in items)
        return {"text": text}
    except Exception as e:
        return {"text": f"Error generating log file: {str(e)}\n"}


@app.get("/api/logs/report-summary")
def generate_report_summary():
    """Generate a comprehensive security report summary."""
    from sqlmodel import Session, select
    from datetime import datetime, timedelta
    
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("AI SHIELD - SECURITY REPORT SUMMARY")
    report_lines.append("=" * 80)
    report_lines.append(f"Generated: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}")
    report_lines.append("")
    
    # System Overview
    report_lines.append("SYSTEM OVERVIEW")
    report_lines.append("-" * 80)
    overview = DB.get_overview()
    report_lines.append(f"Threat Level: {overview.get('threatLevel', 0)}")
    report_lines.append(f"Threat Index: {overview.get('threatIndex', 0)}")
    report_lines.append(f"Files Scanned: {DB.state.get('filesScanned', 0)}")
    report_lines.append(f"Network Alerts: {DB.state.get('networkAlerts', 0)}")
    report_lines.append("")
    
    # Threat Statistics
    report_lines.append("THREAT STATISTICS")
    report_lines.append("-" * 80)
    with Session(DB.engine) as session:
        all_threats = session.exec(select(Threat)).all()
        total_threats = len(all_threats)
        
        # Count by severity
        severity_counts = {}
        source_counts = {}
        action_counts = {}
        recent_threats = []
        
        for threat in all_threats:
            # Severity counts
            sev = threat.severity or "unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            # Source counts
            src = threat.source or "unknown"
            source_counts[src] = source_counts.get(src, 0) + 1
            
            # Action counts
            act = threat.action or "none"
            action_counts[act] = action_counts.get(act, 0) + 1
            
            # Recent threats (last 24 hours)
            if threat.time:
                try:
                    threat_time = threat.time if isinstance(threat.time, datetime) else datetime.fromisoformat(str(threat.time))
                    if (datetime.now().astimezone() - threat_time).total_seconds() < 86400:
                        recent_threats.append(threat)
                except Exception:
                    pass
        
        report_lines.append(f"Total Threats Detected: {total_threats}")
        report_lines.append("")
        report_lines.append("By Severity:")
        for sev in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                report_lines.append(f"  {sev.upper()}: {count}")
        report_lines.append("")
        report_lines.append("By Source:")
        for src, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            report_lines.append(f"  {src}: {count}")
        report_lines.append("")
        report_lines.append("By Action:")
        for act, count in sorted(action_counts.items(), key=lambda x: x[1], reverse=True):
            report_lines.append(f"  {act}: {count}")
        report_lines.append("")
        report_lines.append(f"Recent Threats (Last 24 Hours): {len(recent_threats)}")
        report_lines.append("")
    
    # Network Activity
    report_lines.append("NETWORK ACTIVITY")
    report_lines.append("-" * 80)
    blocked_urls = DB.list_blocked_urls(limit=100)
    report_lines.append(f"Blocked URLs: {len(blocked_urls)}")
    if blocked_urls:
        category_counts = {}
        for url in blocked_urls:
            cat = url.category or "unknown"
            category_counts[cat] = category_counts.get(cat, 0) + 1
        report_lines.append("Blocked URL Categories:")
        for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            report_lines.append(f"  {cat}: {count}")
    report_lines.append("")
    
    # Scan Statistics
    report_lines.append("SCAN STATISTICS")
    report_lines.append("-" * 80)
    with Session(DB.engine) as session:
        scan_jobs = session.exec(select(ScanJob)).all()
        completed_jobs = [j for j in scan_jobs if j.status == "completed"]
        failed_jobs = [j for j in scan_jobs if j.status == "failed"]
        report_lines.append(f"Total Scan Jobs: {len(scan_jobs)}")
        report_lines.append(f"Completed: {len(completed_jobs)}")
        report_lines.append(f"Failed: {len(failed_jobs)}")
        report_lines.append(f"Pending/Processing: {len(scan_jobs) - len(completed_jobs) - len(failed_jobs)}")
    report_lines.append("")
    
    # Cloud Protection Statistics
    report_lines.append("CLOUD PROTECTION")
    report_lines.append("-" * 80)
    try:
        cloud_service = get_cloud_service()
        cloud_stats = cloud_service.get_stats()
        stats = cloud_stats.get("stats", {})
        report_lines.append(f"Status: {'Enabled' if cloud_service.enabled else 'Disabled'}")
        report_lines.append(f"Auto-Submit: {'Enabled' if cloud_service.auto_submit_enabled else 'Disabled'}")
        report_lines.append(f"File Checks: {stats.get('file_checks', 0)}")
        report_lines.append(f"URL Checks: {stats.get('url_checks', 0)}")
        report_lines.append(f"IP Checks: {stats.get('ip_checks', 0)}")
        report_lines.append(f"Threats Detected: {stats.get('threats_detected', 0)}")
        report_lines.append(f"Samples Submitted: {stats.get('samples_submitted', 0)}")
        report_lines.append(f"Successful Submissions: {stats.get('submissions_successful', 0)}")
        report_lines.append(f"Failed Submissions: {stats.get('submissions_failed', 0)}")
        report_lines.append(f"Cache Size: {cloud_stats.get('cache_size', 0)} entries")
    except Exception as e:
        report_lines.append(f"Error retrieving cloud protection stats: {e}")
    report_lines.append("")
    
    # Background Scanner Statistics
    report_lines.append("BACKGROUND SCANNER")
    report_lines.append("-" * 80)
    try:
        bg_scanner = background.get_scanner()
        bg_stats = bg_scanner.get_stats()
        report_lines.append(f"Files Scanned: {bg_stats.get('files_scanned', 0)}")
        report_lines.append(f"Threats Found: {bg_stats.get('threats_found', 0)}")
        report_lines.append(f"Bytes Scanned: {bg_stats.get('bytes_scanned', 0) / (1024*1024):.2f} MB")
        if bg_stats.get('scan_rate_per_second'):
            report_lines.append(f"Scan Rate: {bg_stats.get('scan_rate_per_second', 0):.2f} files/sec")
        if bg_stats.get('uptime_seconds'):
            uptime_hours = bg_stats.get('uptime_seconds', 0) / 3600
            report_lines.append(f"Uptime: {uptime_hours:.2f} hours")
    except Exception as e:
        report_lines.append(f"Error retrieving background scanner stats: {e}")
    report_lines.append("")
    
    # Recent Logs Summary
    report_lines.append("RECENT ACTIVITY SUMMARY")
    report_lines.append("-" * 80)
    logs = DB.state.get("logs", [])
    recent_logs = logs[-50:] if len(logs) > 50 else logs
    error_logs = [l for l in recent_logs if l.get('level', '').upper() in ['ERROR', 'CRITICAL', 'WARNING']]
    report_lines.append(f"Total Log Entries: {len(logs)}")
    report_lines.append(f"Recent Logs (Last 50): {len(recent_logs)}")
    report_lines.append(f"Errors/Warnings: {len(error_logs)}")
    if error_logs:
        report_lines.append("")
        report_lines.append("Recent Errors/Warnings:")
        for log in error_logs[-10:]:
            report_lines.append(f"  [{log.get('level', 'INFO')}] {log.get('msg', '')}")
    report_lines.append("")
    
    # Protection Status
    report_lines.append("PROTECTION STATUS")
    report_lines.append("-" * 80)
    protection = DB.state.get("protection", {})
    report_lines.append(f"Live Scan: {'Enabled' if protection.get('scan') else 'Disabled'}")
    report_lines.append(f"WebShield: {'Enabled' if protection.get('webshield') else 'Disabled'}")
    report_lines.append(f"Snort IDS: {'Enabled' if protection.get('snort') else 'Disabled'}")
    report_lines.append("")
    
    report_lines.append("=" * 80)
    report_lines.append("END OF REPORT")
    report_lines.append("=" * 80)
    
    report_text = "\n".join(report_lines)
    return {"text": report_text}


@app.get("/api/scan/status/{job_id}")
def get_scan_status(job_id: str):
    """Get the status of a scan job."""
    job = DB.get_scan_job(job_id)
    if not job:
        return {"error": "job_not_found"}
    
    result = None
    if job.result:
        try:
            import json
            result = json.loads(job.result)
        except Exception:
            pass
    
    return {
        "job_id": job.job_id,
        "status": job.status,
        "progress": job.progress,
        "file_name": job.file_name,
        "file_path": job.file_path,
        "error": job.error,
        "threat_id": job.threat_id,
        "created": job.created.isoformat() if job.created else None,
        "started": job.started.isoformat() if job.started else None,
        "completed": job.completed.isoformat() if job.completed else None,
        "result": result
    }


@app.get("/api/scan/history")
def scan_history():
    """Get scan history from both database (persistent) and in-memory (backward compatibility)."""
    # Get from database (persistent)
    db_jobs = DB.list_scan_jobs(limit=200, status="completed")
    db_history = []
    for job in db_jobs:
        if job.result:
            try:
                import json
                result = json.loads(job.result)
                db_history.append({
                    "id": job.id,
                    "job_id": job.job_id,
                    "path": job.file_path,
                    "name": job.file_name,
                    "mime": job.file_mime,
                    "size": job.file_size,
                    "severity": result.get("severity", "low"),
                    "risk": result.get("ml", {}).get("risk", 0),
                    "verdict_ml": result.get("ml", {}).get("verdict"),
                    "time": job.completed.isoformat() if job.completed else job.created.isoformat(),
                    "is_uploaded": job.is_uploaded,
                    "temp_path": job.temp_path,
                    "threat_id": job.threat_id,
                })
            except Exception:
                pass
    
    # Also include in-memory history for backward compatibility
    scanned_files = DB.state.get("scanned_files", [])
    from datetime import datetime, timedelta
    cutoff_time = (datetime.now().astimezone() - timedelta(days=30)).isoformat()
    recent = [f for f in scanned_files if f.get("time", "") >= cutoff_time]
    
    # Merge and deduplicate (prefer database entries)
    db_paths = {h["path"] for h in db_history}
    memory_history = [f for f in recent if f.get("path") not in db_paths]
    
    # Combine and sort by time
    all_history = db_history + memory_history
    all_history.sort(key=lambda x: x.get("time", ""), reverse=True)
    
    # Update store with cleaned data
    if len(recent) < len(scanned_files):
        DB.state["scanned_files"] = recent[:200]
    
    return all_history[:200]  # Return max 200 most recent


@app.delete("/api/scan/history/{sid}")
def scan_history_delete(sid: int):
    scanned_files = DB.state.get("scanned_files", [])
    item_to_delete = next((s for s in scanned_files if s.get("id") == sid), None)
    
    # Delete the actual file if it was an uploaded file
    if item_to_delete:
        file_path = item_to_delete.get("path")
        temp_path = item_to_delete.get("temp_path")
        is_uploaded = item_to_delete.get("is_uploaded", False)
        
        # Try to delete the file from filesystem if it was uploaded
        if is_uploaded and file_path:
            try:
                file_to_delete = Path(temp_path if temp_path else file_path)
                if file_to_delete.exists():
                    os.remove(str(file_to_delete))
            except Exception:
                pass  # File might already be deleted or inaccessible
    
    # Remove from scan history
    DB.state["scanned_files"] = [s for s in scanned_files if s.get("id") != sid]
    return {"ok": True}


@app.delete("/api/scan/history")
def scan_history_clear():
    # Delete all uploaded files before clearing history
    scanned_files = DB.state.get("scanned_files", [])
    for item in scanned_files:
        if item.get("is_uploaded", False):
            file_path = item.get("path")
            temp_path = item.get("temp_path")
            try:
                file_to_delete = Path(temp_path if temp_path else file_path)
                if file_to_delete.exists():
                    os.remove(str(file_to_delete))
            except Exception:
                pass  # File might already be deleted or inaccessible
    
    DB.state["scanned_files"] = []
    DB.state["scan_seq"] = 0
    return {"ok": True}


@app.get("/__ping")
def ping():
    return {"ok": True}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/")
def root():
    return {"message": "AI Shield API", "docs": "/docs"}


# Voice command
class VoiceReq(BaseModel):
    text: str


@app.post("/voice-command")
def voice_command(req: VoiceReq):
    text = (req.text or "").lower()
    if "toggle webshield" in text:
        prot = DB.state.setdefault("protection", {"scan": True, "webshield": True, "snort": True})
        prot["webshield"] = not prot.get("webshield", True)
        return {"reply": f"WebShield is now {'enabled' if prot['webshield'] else 'disabled'}"}
    if "scan downloads" in text:
        return {"reply": "Starting scan of Downloads folder"}
    return {"reply": "Command received"}


@app.get("/api/snort/alerts")
def snort_alerts():
    return snort.read_alerts()


# Simple health check (alias)
@app.get("/health")
def health():
    return {"ok": True}


# Sandbox REST
@app.get("/api/sandbox/jobs")
def list_jobs():
    """List sandbox jobs, filtered to show only anomalies (suspicious/malicious verdicts or high scores)."""
    all_jobs = [SandboxJob(**j) for j in DB.state.get("sandbox_jobs", [])]
    
    # Filter to only show anomalies:
    # - Jobs with verdict that is NOT "benign" (i.e., "suspicious", "malicious", etc.)
    # - OR jobs with score > 0.5 (indicating suspicious behavior)
    # - OR jobs that are still running/pending (to show active analysis)
    anomaly_jobs = []
    for job in all_jobs:
        is_anomaly = False
        
        # Check if verdict indicates anomaly
        if job.verdict:
            verdict_lower = job.verdict.lower()
            if verdict_lower in ("suspicious", "malicious", "threat", "dangerous"):
                is_anomaly = True
        
        # Check if score indicates anomaly (score > 0.5)
        if job.score is not None and job.score > 0.5:
            is_anomaly = True
        
        # Include running/pending jobs (active analysis)
        if job.status in ("running", "pending", "queued"):
            is_anomaly = True
        
        if is_anomaly:
            anomaly_jobs.append(job)
    
    return anomaly_jobs


class RunReq(BaseModel):
    target: str | None = None


@app.post("/api/sandbox/run")
def run_sandbox(req: RunReq):
    job_id = f"j{int(time.time()*1000)}"
    job = SandboxJob(job_id=job_id, target=req.target or "unknown", status="queued", percent=0)
    jobs = DB.state.setdefault("sandbox_jobs", [])
    jobs.insert(0, job.model_dump())
    return job


@app.get("/api/sandbox/{job_id}")
def get_job(job_id: str):
    for j in DB.state.get("sandbox_jobs", []):
        if j.get("job_id") == job_id:
            return SandboxJob(**j)
    return SandboxJob(job_id=job_id, status="unknown")
@app.on_event("startup")
async def startup_event():
    """Initialize background scanner on startup if enabled."""
    if LIVE_SCAN_STATE.enabled:
        scanner = background.get_scanner()
        
        def progress_callback(progress_data: dict):
            """Callback for scan progress updates."""
            try:
                asyncio.create_task(ws_manager.broadcast(progress_data))
            except Exception:
                pass
        
        scanner.start_monitoring(
            paths=LIVE_SCAN_STATE.paths,
            scan_callback=_threat_callback,
            exclude_patterns=LIVE_SCAN_STATE.exclude_patterns,
            scan_delay=LIVE_SCAN_STATE.scan_delay,
            threat_report_interval=LIVE_SCAN_STATE.threat_report_interval * 60,
            progress_callback=progress_callback,
        )
        print("[Startup] Background scanner initialized and started")


@app.get("/__ping")
def __ping():
    return {"ok": True}

@app.get("/__info")
def __info():
    return {"file": __file__, "routes": [getattr(r, "path", None) for r in app.routes]}
class NewThreatReq(BaseModel):
    severity: str | None = None
    description: str
    source: str
    filePath: str | None = None
    url: str | None = None
    risk: float | None = None
    ml: dict | None = None

@app.post("/api/threats")
def create_threat(req: NewThreatReq):
    sev = req.severity or "medium"
    t = DB.add_threat(ThreatIn(severity=sev, description=req.description, source=req.source, filePath=req.filePath, url=req.url))
    th = t.model_dump()
    try:
        if getattr(t, "time", None):
            th["time"] = t.time.astimezone().isoformat()
    except Exception:
        pass
    try:
        asyncio.create_task(ws_manager.broadcast({"type": "threat", "data": th}))
        asyncio.create_task(ws_manager.broadcast({**{"type": "threat"}, **th}))
    except Exception:
        pass
    from datetime import datetime
    return {
        "id": th.get("id"),
        "timestamp": datetime.now().astimezone().isoformat(),
        "source": th.get("source"),
        "severity": th.get("severity"),
        "message": th.get("description"),
        "risk": req.risk if req.risk is not None else None,
        "ml": req.ml if req.ml is not None else None,
        "threat": th,
    }
