from __future__ import annotations

import os
import sys
import time
import asyncio
import threading
from typing import Awaitable, Callable, Optional, Dict, Any, List, Set
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from . import anomaly

# Check Python version for watchdog compatibility
PYTHON_313_OR_HIGHER = sys.version_info >= (3, 13)

# Get default threat report interval from environment variable (default: 1 minute)
_DEFAULT_THREAT_REPORT_INTERVAL_SECONDS = float(os.getenv("BACKGROUND_SCAN_THREAT_REPORT_INTERVAL", "1.0")) * 60


class BackgroundScanHandler(FileSystemEventHandler):
    """File system event handler for real-time background scanning."""
    
    def __init__(
        self,
        scan_callback: Callable[[str], None],
        exclude_patterns: Optional[List[str]] = None,
        scan_delay: float = 1.0,
    ):
        self.scan_callback = scan_callback
        self.exclude_patterns = exclude_patterns or []
        self.scan_delay = scan_delay
        self._pending_scans: Dict[str, float] = {}
        self._lock = threading.Lock()
        
    def _should_scan(self, path: str) -> bool:
        """Check if path should be scanned based on exclude patterns."""
        path_lower = path.lower()
        for pattern in self.exclude_patterns:
            if pattern.lower() in path_lower:
                return False
        # Only scan files, not directories
        if os.path.isdir(path):
            return False
        # Skip very large files (>100MB) for performance
        try:
            if os.path.getsize(path) > 100 * 1024 * 1024:
                return False
        except Exception:
            return False
        return True
    
    def _schedule_scan(self, path: str):
        """Schedule a delayed scan to avoid scanning the same file multiple times quickly."""
        current_time = time.time()
        with self._lock:
            self._pending_scans[path] = current_time + self.scan_delay
        
        def delayed_scan():
            time.sleep(self.scan_delay)
            with self._lock:
                if path in self._pending_scans and self._pending_scans[path] <= time.time():
                    if self._should_scan(path):
                        self.scan_callback(path)
                    del self._pending_scans[path]
        
        threading.Thread(target=delayed_scan, daemon=True).start()
    
    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            try:
                self._schedule_scan(event.src_path)
            except Exception as e:
                print(f"[BackgroundScanHandler] Error handling file creation event: {e}")
    
    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            try:
                self._schedule_scan(event.src_path)
            except Exception as e:
                print(f"[BackgroundScanHandler] Error handling file modification event: {e}")
    
    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory and hasattr(event, 'dest_path'):
            try:
                self._schedule_scan(getattr(event, 'dest_path', event.src_path))
            except Exception as e:
                print(f"[BackgroundScanHandler] Error handling file move event: {e}")


class BackgroundScanner:
    """Enhanced background scanner with real-time file monitoring and continuous scanning."""
    
    def __init__(self):
        self.observer: Optional[Observer] = None
        self.handlers: Dict[str, BackgroundScanHandler] = {}
        self.stats = {
            "files_scanned": 0,
            "threats_found": 0,
            "bytes_scanned": 0,
            "scan_start_time": None,
            "last_scan_time": None,
        }
        self.recent_threats: List[Dict[str, Any]] = []
        self.scanned_files: Set[str] = set()
        self.continuous_scan_task: Optional[asyncio.Task] = None
        self.continuous_scan_running = False
        self.threat_report_interval: float = _DEFAULT_THREAT_REPORT_INTERVAL_SECONDS  # Configurable via BACKGROUND_SCAN_THREAT_REPORT_INTERVAL env var (default: 1 minute)
        self.last_threat_report_time: Optional[float] = None
        self.threats_since_last_report: List[Dict[str, Any]] = []
        self.scan_progress: Dict[str, Any] = {
            "is_scanning": False,
            "current_path": None,
            "files_scanned_in_session": 0,
            "session_start_time": None,
        }
        self.progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._health_check_thread: Optional[threading.Thread] = None
        self._monitored_paths: List[str] = []
        self._scan_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self._exclude_patterns: Optional[List[str]] = None
        self._scan_delay: float = 1.0
        self._last_health_check: float = time.time()
        self._consecutive_errors: int = 0
        self._max_consecutive_errors: int = 10
        
    def start_monitoring(
        self,
        paths: List[str],
        scan_callback: Callable[[str, Dict[str, Any]], None],
        exclude_patterns: Optional[List[str]] = None,
        scan_delay: float = 1.0,
        threat_report_interval: Optional[float] = None,  # If None, uses default from env var
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        """Start monitoring paths for file changes and continuous scanning."""
        self.stop_monitoring()
        
        if not paths:
            return
        
        # Store parameters for health check restart
        self._monitored_paths = paths.copy()
        self._scan_callback = scan_callback
        self._exclude_patterns = exclude_patterns
        self._scan_delay = scan_delay
        
        # Use provided interval or fall back to default from environment variable
        self.threat_report_interval = threat_report_interval if threat_report_interval is not None else _DEFAULT_THREAT_REPORT_INTERVAL_SECONDS
        self.progress_callback = progress_callback
        self.last_threat_report_time = time.time()
        self.threats_since_last_report = []
        self._last_health_check = time.time()
        self._consecutive_errors = 0
        
        self.observer = Observer()
        exclude_patterns = exclude_patterns or [
            "node_modules",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            "AppData\\Local\\Temp",
            "/tmp",
            "/var/tmp",
        ]
        
        def create_handler(path: str):
            def callback(file_path: str):
                result = self._scan_file(file_path)
                if result and result.get("verdict") in ("malicious", "suspicious"):
                    # Add to threats since last report
                    threat_info = {
                        "path": file_path,
                        "verdict": result.get("verdict"),
                        "risk": result.get("risk", 0),
                        "confidence": result.get("confidence", "low"),
                        "confidence_score": result.get("confidence_score", 0.0),  # Numeric confidence
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    self.threats_since_last_report.append(threat_info)
                    
                    # Auto-delete high/critical severity anomalies immediately
                    severity = result.get("severity", "low")
                    if severity in ("high", "critical"):
                        try:
                            from ..services import threat_actions
                            from pathlib import Path as PathLib
                            p = PathLib(file_path)
                            if p.exists():
                                is_directory = p.is_dir()
                                deletion_result = threat_actions.delete_anomaly_immediately(
                                    file_path, 
                                    is_directory=is_directory
                                )
                                if deletion_result.get("success"):
                                    print(f"[Background Scanner] ✓ Auto-deleted {deletion_result.get('item_type', 'item')}: {p.name} (method: {deletion_result.get('method')})")
                                    threat_info["auto_deleted"] = True
                                    threat_info["deletion_method"] = deletion_result.get("method")
                                else:
                                    print(f"[Background Scanner] ✗ Failed to auto-delete: {p.name} - {deletion_result.get('error', 'Unknown error')}")
                        except Exception as del_e:
                            print(f"[Background Scanner] Error during auto-deletion: {del_e}")
                    
                    scan_callback(file_path, result)
            
            handler = BackgroundScanHandler(callback, exclude_patterns, scan_delay)
            self.handlers[path] = handler
            return handler
        
        for path in paths:
            try:
                if os.path.exists(path) and os.path.isdir(path):
                    handler = create_handler(path)
                    self.observer.schedule(handler, path, recursive=True)
                elif os.path.exists(path) and os.path.isfile(path):
                    # Single file, scan it
                    result = self._scan_file(path)
                    if result and result.get("verdict") in ("malicious", "suspicious"):
                        # Auto-delete high/critical severity anomalies immediately
                        severity = result.get("severity", "low")
                        if severity in ("high", "critical"):
                            try:
                                from ..services import threat_actions
                                from pathlib import Path as PathLib
                                p = PathLib(path)
                                if p.exists():
                                    is_directory = p.is_dir()
                                    deletion_result = threat_actions.delete_anomaly_immediately(
                                        path, 
                                        is_directory=is_directory
                                    )
                                    if deletion_result.get("success"):
                                        print(f"[Background Scanner] ✓ Auto-deleted {deletion_result.get('item_type', 'item')}: {p.name} (method: {deletion_result.get('method')})")
                                    else:
                                        print(f"[Background Scanner] ✗ Failed to auto-delete: {p.name} - {deletion_result.get('error', 'Unknown error')}")
                            except Exception as del_e:
                                print(f"[Background Scanner] Error during auto-deletion: {del_e}")
                        scan_callback(path, result)
            except Exception:
                continue
        
        # Start observer if we have any handlers scheduled
        # Note: Python 3.13 has compatibility issues with watchdog, so we catch the error
        if self.observer and len(self.handlers) > 0:
            try:
                self.observer.start()
                self.stats["scan_start_time"] = time.time()
            except (TypeError, AttributeError) as e:
                # Python 3.13 compatibility issue with watchdog
                error_str = str(e)
                if ("'handle' must be a _ThreadHandle" in error_str or 
                    "handle" in error_str.lower() and "thread" in error_str.lower()):
                    if PYTHON_313_OR_HIGHER:
                        print(f"[BackgroundScanner] Warning: Watchdog library is not compatible with Python 3.13.")
                        print(f"[BackgroundScanner] Error: {e}")
                        print("[BackgroundScanner] Real-time file monitoring is disabled.")
                        print("[BackgroundScanner] Continuous scanning will still work for periodic full scans.")
                        print("[BackgroundScanner] Recommendation: Use Python 3.12 or earlier, or wait for watchdog update.")
                    else:
                        print(f"[BackgroundScanner] Warning: Watchdog failed to start. Error: {e}")
                    # Don't fail completely - continuous scanning will still work
                    self.observer = None
                    self.handlers.clear()
                else:
                    raise
        
        # Start continuous scanning task
        self._start_continuous_scanning(paths, scan_callback, exclude_patterns)
        
        # Start health check thread
        self._start_health_check()
    
    def stop_monitoring(self):
        """Stop monitoring file changes and continuous scanning."""
        # Set flag first to signal threads to stop
        self.continuous_scan_running = False
        
        # Clear monitored paths to signal health check to stop
        self._monitored_paths = []
        self._scan_callback = None
        
        if self.observer:
            try:
                if hasattr(self.observer, 'is_alive') and self.observer.is_alive():
                    self.observer.stop()
                    self.observer.join(timeout=5)
            except (TypeError, AttributeError) as e:
                # Handle Python 3.13 compatibility issues
                print(f"[BackgroundScanner] Warning: Error stopping observer: {e}")
            except Exception as e:
                print(f"[BackgroundScanner] Warning: Error stopping observer: {e}")
            finally:
                self.observer = None
        self.handlers.clear()
        
        # Stop continuous scanning
        if self.continuous_scan_task:
            try:
                self.continuous_scan_task.cancel()
            except Exception:
                pass
            self.continuous_scan_task = None
        
        # Wait for scan thread to finish (with timeout)
        if hasattr(self, '_scan_thread') and self._scan_thread and self._scan_thread.is_alive():
            try:
                self._scan_thread.join(timeout=2)
            except Exception:
                pass
        
        # Stop health check
        if hasattr(self, '_health_check_thread') and self._health_check_thread and self._health_check_thread.is_alive():
            # Health check will stop when _monitored_paths is empty
            try:
                self._health_check_thread.join(timeout=5)
            except Exception:
                pass
        
        self.scan_progress["is_scanning"] = False
        self.scan_progress["current_path"] = None
    
    def _scan_file(self, file_path: str, update_progress: bool = True) -> Optional[Dict[str, Any]]:
        """Scan a single file and return results."""
        try:
            # Update progress
            if update_progress:
                self.scan_progress["current_path"] = file_path
                self.scan_progress["files_scanned_in_session"] += 1
                if self.progress_callback:
                    try:
                        self.progress_callback({
                            "type": "scan_progress",
                            "current_path": file_path,
                            "files_scanned": self.scan_progress["files_scanned_in_session"],
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        })
                    except Exception:
                        pass
            
            # Skip if already scanned recently
            file_hash = self._get_file_hash(file_path)
            if file_hash in self.scanned_files:
                return None
            
            # Get YARA matches if available
            yara_matches = None
            try:
                import yara
                from pathlib import Path as PathLib
                rules_path = PathLib(__file__).resolve().parent.parent.parent / "rules" / "malware.yar"
                if rules_path.exists():
                    yara_rules = yara.compile(filepath=str(rules_path))
                    with open(file_path, "rb") as f:
                        data = f.read(256 * 1024)  # Read 256KB sample
                    matches = yara_rules.match(data=data)
                    yara_matches = [m.rule for m in matches]
            except Exception:
                pass
            
            result = anomaly.score_path(file_path, yara_matches=yara_matches)
            self.stats["files_scanned"] += 1
            
            try:
                file_size = os.path.getsize(file_path)
                self.stats["bytes_scanned"] += file_size
            except Exception:
                file_size = 0
            
            verdict = result.get("verdict", "benign")
            if verdict in ("malicious", "suspicious"):
                self.stats["threats_found"] += 1
                
                # Determine severity from verdict and risk score
                risk_score = result.get("risk", 0)
                if verdict == "malicious" or risk_score >= 0.8:
                    severity = "high" if risk_score >= 0.9 else "medium"
                else:
                    severity = "medium" if risk_score >= 0.6 else "low"
                
                # Auto-delete high/critical severity anomalies immediately
                if severity in ("high", "critical") and os.path.exists(file_path):
                    try:
                        from ..services import threat_actions
                        from pathlib import Path as PathLib
                        p = PathLib(file_path)
                        is_directory = p.is_dir()
                        deletion_result = threat_actions.delete_anomaly_immediately(
                            file_path, 
                            is_directory=is_directory
                        )
                        if deletion_result.get("success"):
                            print(f"[Background Scanner] ✓ Auto-deleted {deletion_result.get('item_type', 'item')} during scan: {p.name} (method: {deletion_result.get('method')})")
                            result["auto_deleted"] = True
                            result["deletion_method"] = deletion_result.get("method")
                        else:
                            print(f"[Background Scanner] ✗ Failed to auto-delete during scan: {p.name} - {deletion_result.get('error', 'Unknown error')}")
                    except Exception as del_e:
                        print(f"[Background Scanner] Error during auto-deletion in _scan_file: {del_e}")
                
                threat_info = {
                    "path": file_path,
                    "verdict": verdict,
                    "risk": result.get("risk", 0),
                    "severity": severity,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "size": file_size,
                }
                self.recent_threats.insert(0, threat_info)
                # Keep only last 30 threats and cleanup old ones (older than 7 days)
                from datetime import datetime, timedelta
                cutoff_date = datetime.now() - timedelta(days=7)
                cutoff_str = cutoff_date.strftime("%Y-%m-%d %H:%M:%S")
                self.recent_threats = [
                    t for t in self.recent_threats[:30] 
                    if t.get("timestamp", "") >= cutoff_str
                ]
            
            self.scanned_files.add(file_hash)
            # Optimized cache size - keep only last 3000 entries
            if len(self.scanned_files) > 3000:
                self.scanned_files = set(list(self.scanned_files)[-3000:])
            
            self.stats["last_scan_time"] = time.time()
            # Reset consecutive errors on successful scan
            if self._consecutive_errors > 0:
                self._consecutive_errors = max(0, self._consecutive_errors - 1)
            return result
        except Exception as e:
            self._consecutive_errors += 1
            print(f"[Background Scanner] Error scanning file {file_path}: {e}")
            return None
    
    def _get_file_hash(self, file_path: str) -> str:
        """Get a simple hash for tracking scanned files."""
        try:
            stat = os.stat(file_path)
            return f"{file_path}:{stat.st_mtime}:{stat.st_size}"
        except Exception:
            return file_path
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanning statistics."""
        uptime = 0
        if self.stats["scan_start_time"]:
            uptime = time.time() - self.stats["scan_start_time"]
        
        scan_rate = 0
        if uptime > 0:
            scan_rate = self.stats["files_scanned"] / uptime
        
        return {
            **self.stats,
            "uptime_seconds": uptime,
            "scan_rate_per_second": scan_rate,
            "recent_threats_count": len(self.recent_threats),
        }
    
    def get_recent_threats(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent threats found."""
        return self.recent_threats[:limit]
    
    def reset_stats(self):
        """Reset scanning statistics."""
        self.stats = {
            "files_scanned": 0,
            "threats_found": 0,
            "bytes_scanned": 0,
            "scan_start_time": self.stats.get("scan_start_time"),
            "last_scan_time": None,
        }
    
    def _start_continuous_scanning(
        self,
        paths: List[str],
        scan_callback: Callable[[str, Dict[str, Any]], None],
        exclude_patterns: Optional[List[str]] = None,
    ):
        """Start continuous asynchronous scanning of all files in monitored paths."""
        if self.continuous_scan_running:
            return
        
        self.continuous_scan_running = True
        self.scan_progress["is_scanning"] = True
        self.scan_progress["files_scanned_in_session"] = 0
        self.scan_progress["session_start_time"] = time.time()
        
        async def continuous_scan_loop():
            """Continuously scan all files in monitored paths."""
            consecutive_loop_errors = 0
            max_loop_errors = 5
            
            while self.continuous_scan_running:
                try:
                    # Reset loop error count on successful iteration
                    consecutive_loop_errors = 0
                    
                    # Collect all files to scan
                    all_files: List[str] = []
                    for path in paths:
                        if not self.continuous_scan_running:
                            break
                        if not os.path.exists(path):
                            continue
                        if os.path.isfile(path):
                            all_files.append(path)
                        elif os.path.isdir(path):
                            try:
                                for root, dirs, files in os.walk(path):
                                    if not self.continuous_scan_running:
                                        break
                                    # Skip excluded directories
                                    dirs[:] = [d for d in dirs if not any(
                                        pattern.lower() in os.path.join(root, d).lower()
                                        for pattern in (exclude_patterns or [])
                                    )]
                                    for file in files:
                                        if not self.continuous_scan_running:
                                            break
                                        file_path = os.path.join(root, file)
                                        # Check exclude patterns
                                        if exclude_patterns:
                                            if any(pattern.lower() in file_path.lower() for pattern in exclude_patterns):
                                                continue
                                        # Skip very large files
                                        try:
                                            if os.path.getsize(file_path) > 100 * 1024 * 1024:
                                                continue
                                        except Exception:
                                            continue
                                        all_files.append(file_path)
                            except Exception as e:
                                print(f"[Background Scanner] Error walking directory {path}: {e}")
                                continue
                    
                    # Scan files asynchronously
                    total_files = len(all_files)
                    scanned_count = 0
                    
                    for file_path in all_files:
                        if not self.continuous_scan_running:
                            break
                        
                        try:
                            # Scan file (non-blocking)
                            result = self._scan_file(file_path, update_progress=True)
                            scanned_count += 1
                            
                            # Check if we should report threats
                            current_time = time.time()
                            if current_time - self.last_threat_report_time >= self.threat_report_interval:
                                self._report_threats(scan_callback)
                                self.last_threat_report_time = current_time
                            
                            # Yield control periodically to avoid blocking
                            if scanned_count % 100 == 0:
                                await asyncio.sleep(0.1)
                        except Exception as e:
                            # Individual file scan errors shouldn't stop the loop
                            print(f"[Background Scanner] Error scanning file {file_path}: {e}")
                            continue
                    
                    # Report any remaining threats after scan cycle
                    if self.threats_since_last_report:
                        try:
                            self._report_threats(scan_callback)
                        except Exception as e:
                            print(f"[Background Scanner] Error reporting threats: {e}")
                    
                    # Wait before next scan cycle (scan continuously but with small delay)
                    await asyncio.sleep(60)  # Wait 1 minute before next full scan cycle
                    
                except asyncio.CancelledError:
                    print("[Background Scanner] Continuous scan loop cancelled")
                    break
                except Exception as e:
                    consecutive_loop_errors += 1
                    self._consecutive_errors += 1
                    print(f"[Background Scanner] Error in continuous scan loop (error #{consecutive_loop_errors}): {e}")
                    import traceback
                    traceback.print_exc()
                    
                    # If too many consecutive loop errors, break and let health check restart
                    if consecutive_loop_errors >= max_loop_errors:
                        print(f"[Background Scanner] Too many consecutive loop errors ({consecutive_loop_errors}), breaking loop for health check restart")
                        self.continuous_scan_running = False  # Signal that we need restart
                        break
                    
                    # If too many total consecutive errors, wait longer
                    wait_time = min(60, 10 * min(self._consecutive_errors, 5))
                    await asyncio.sleep(wait_time)
                    
                    # Don't break on individual errors, let health check handle it
        
        # Start the continuous scan task in a new thread with event loop
        def run_async_loop():
            """Run async loop in a separate thread."""
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                task = loop.create_task(continuous_scan_loop())
                loop.run_until_complete(task)
            except Exception as e:
                print(f"[Background Scanner] Error in async loop: {e}")
                import traceback
                traceback.print_exc()
                self.continuous_scan_running = False
                self.scan_progress["is_scanning"] = False
                self._consecutive_errors += 1
            finally:
                # Ensure loop is closed
                try:
                    loop.close()
                except Exception:
                    pass
        
        scan_thread = threading.Thread(target=run_async_loop, daemon=True)
        scan_thread.start()
        # Store thread reference for cleanup
        self._scan_thread = scan_thread
    
    def _start_health_check(self):
        """Start health check thread to monitor and restart scanner if needed."""
        if hasattr(self, '_health_check_thread') and self._health_check_thread and self._health_check_thread.is_alive():
            return
        
        def health_check_loop():
            """Periodically check scanner health and restart if needed."""
            consecutive_health_check_errors = 0
            max_health_check_errors = 10
            
            # Keep running as long as we should be monitoring
            while True:
                try:
                    # Check if we should still be monitoring
                    # Health check should continue if paths are monitored
                    should_monitor = (self._monitored_paths and self._scan_callback is not None)
                    
                    if not should_monitor:
                        # If monitoring was explicitly stopped, exit
                        print(f"[Background Scanner] Health check stopping: monitoring stopped at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                        break
                    
                    time.sleep(30)  # Check every 30 seconds
                    self._last_health_check = time.time()
                    consecutive_health_check_errors = 0  # Reset on successful check
                    
                    # Check if continuous scan thread is alive
                    scan_thread_dead = (self._scan_thread is None or 
                                       not self._scan_thread.is_alive())
                    
                    # Check if observer is alive (if it was started)
                    observer_dead = False
                    if self.observer is not None:
                        try:
                            observer_dead = not (hasattr(self.observer, 'is_alive') and 
                                                self.observer.is_alive())
                        except Exception:
                            observer_dead = True
                    
                    # Check if continuous scan is marked as running but thread is dead
                    continuous_scan_dead = (self.continuous_scan_running and scan_thread_dead)
                    
                    # Restart if needed
                    if continuous_scan_dead or observer_dead:
                        print(f"[Background Scanner] Health check detected issue at {time.strftime('%Y-%m-%d %H:%M:%S')}:")
                        print(f"  - Continuous scan thread alive: {not scan_thread_dead}")
                        print(f"  - Observer alive: {not observer_dead}")
                        print(f"  - Continuous scan running flag: {self.continuous_scan_running}")
                        print(f"  - Monitored paths: {len(self._monitored_paths)}")
                        print(f"[Background Scanner] Attempting to restart...")
                        
                        # Reset error count on restart attempt
                        self._consecutive_errors = 0
                        
                        # Restart continuous scanning if needed
                        if continuous_scan_dead and self._monitored_paths and self._scan_callback:
                            try:
                                # Reset the flag before restarting
                                self.continuous_scan_running = False
                                time.sleep(1)  # Brief pause to ensure cleanup
                                
                                self._start_continuous_scanning(
                                    self._monitored_paths,
                                    self._scan_callback,
                                    self._exclude_patterns
                                )
                                print(f"[Background Scanner] Continuous scan restarted successfully")
                            except Exception as e:
                                print(f"[Background Scanner] Failed to restart continuous scan: {e}")
                                import traceback
                                traceback.print_exc()
                        
                        # Restart observer if needed
                        if observer_dead and self._monitored_paths:
                            try:
                                # Clean up old observer first
                                if self.observer is not None:
                                    try:
                                        if hasattr(self.observer, 'is_alive') and self.observer.is_alive():
                                            self.observer.stop()
                                            self.observer.join(timeout=2)
                                    except Exception:
                                        pass
                                
                                # Recreate observer
                                self.observer = Observer()
                                self.handlers.clear()
                                
                                # Recreate handlers
                                exclude_patterns = self._exclude_patterns or [
                                    "node_modules", ".git", "__pycache__", ".venv", "venv",
                                    "AppData\\Local\\Temp", "/tmp", "/var/tmp",
                                ]
                                
                                def create_handler(path: str):
                                    def callback(file_path: str):
                                        result = self._scan_file(file_path)
                                        if result and result.get("verdict") in ("malicious", "suspicious"):
                                            threat_info = {
                                                "path": file_path,
                                                "verdict": result.get("verdict"),
                                                "risk": result.get("risk", 0),
                                                "confidence": result.get("confidence", "low"),
                                                "confidence_score": result.get("confidence_score", 0.0),
                                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                                            }
                                            self.threats_since_last_report.append(threat_info)
                                            if self._scan_callback:
                                                self._scan_callback(file_path, result)
                                    
                                    handler = BackgroundScanHandler(callback, exclude_patterns, self._scan_delay)
                                    self.handlers[path] = handler
                                    return handler
                                
                                # Schedule handlers
                                scheduled_count = 0
                                for path in self._monitored_paths:
                                    try:
                                        if os.path.exists(path) and os.path.isdir(path):
                                            handler = create_handler(path)
                                            self.observer.schedule(handler, path, recursive=True)
                                            scheduled_count += 1
                                    except Exception as e:
                                        print(f"[Background Scanner] Error scheduling handler for {path}: {e}")
                                
                                # Start observer
                                if scheduled_count > 0:
                                    try:
                                        self.observer.start()
                                        print(f"[Background Scanner] Observer restarted successfully with {scheduled_count} paths")
                                    except Exception as e:
                                        print(f"[Background Scanner] Failed to restart observer: {e}")
                                        import traceback
                                        traceback.print_exc()
                                        self.observer = None
                                else:
                                    print(f"[Background Scanner] No valid paths to monitor, observer not started")
                                    self.observer = None
                            except Exception as e:
                                print(f"[Background Scanner] Failed to restart observer: {e}")
                                import traceback
                                traceback.print_exc()
                                self.observer = None
                    
                    # Reset consecutive errors if everything is healthy
                    if not scan_thread_dead and not observer_dead:
                        if self._consecutive_errors > 0:
                            print(f"[Background Scanner] Scanner healthy, resetting error count")
                            self._consecutive_errors = 0
                            
                except Exception as e:
                    consecutive_health_check_errors += 1
                    print(f"[Background Scanner] Error in health check (error #{consecutive_health_check_errors}): {e}")
                    import traceback
                    traceback.print_exc()
                    
                    # If health check itself has too many errors, restart it
                    if consecutive_health_check_errors >= max_health_check_errors:
                        print(f"[Background Scanner] Health check thread has too many errors, restarting...")
                        time.sleep(5)
                        # Restart health check by calling it again
                        try:
                            self._start_health_check()
                        except Exception:
                            pass
                        break
                    
                    time.sleep(30)  # Wait before next check
        
        self._health_check_thread = threading.Thread(target=health_check_loop, daemon=True, name="BackgroundScannerHealthCheck")
        self._health_check_thread.start()
        print(f"[Background Scanner] Health check thread started (PID: {os.getpid()})")
    
    def _report_threats(self, scan_callback: Callable[[str, Dict[str, Any]], None]):
        """Report threats found since last report."""
        if not self.threats_since_last_report:
            return
        
        # Create threat report
        threat_report = {
            "type": "threat_report",
            "interval_minutes": self.threat_report_interval / 60,
            "threats_count": len(self.threats_since_last_report),
            "threats": self.threats_since_last_report.copy(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        # Broadcast via progress callback if available
        if self.progress_callback:
            try:
                self.progress_callback(threat_report)
            except Exception:
                pass
        
        # Clear threats since last report
        self.threats_since_last_report = []
    
    def set_threat_report_interval(self, interval_minutes: float):
        """Set the threat reporting interval in minutes."""
        # Convert minutes to seconds (minimum 1 minute = 60 seconds)
        self.threat_report_interval = max(60.0, interval_minutes * 60)
    
    def get_scan_progress(self) -> Dict[str, Any]:
        """Get current scan progress information."""
        return {
            **self.scan_progress,
            "threat_report_interval_minutes": self.threat_report_interval / 60,
            "next_report_in_seconds": max(0, self.threat_report_interval - (time.time() - (self.last_threat_report_time or time.time()))),
        }


# Global scanner instance
_scanner = BackgroundScanner()


def get_scanner() -> BackgroundScanner:
    """Get the global background scanner instance."""
    return _scanner


async def scan_directory(
    root: str,
    broadcast: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
    job_id: Optional[str] = None,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Scan a directory (original function, kept for compatibility)."""
    rid = job_id or f"s-{int(time.time()*1000)}"
    scanned = 0
    malicious = 0
    suspicious = 0
    bytes_scanned = 0
    risks: List[float] = []
    top: List[Dict[str, Any]] = []
    files: List[str] = []

    for dirpath, dirnames, filenames in os.walk(root):
        for fname in filenames:
            fp = os.path.join(dirpath, fname)
            files.append(fp)
            if limit and len(files) >= limit:
                break
        if limit and len(files) >= limit:
            break

    total = len(files)
    for i, fp in enumerate(files):
        try:
            # Get YARA matches if available
            yara_matches = None
            try:
                import yara
                from pathlib import Path as PathLib
                rules_path = PathLib(__file__).resolve().parent.parent.parent / "rules" / "malware.yar"
                if rules_path.exists():
                    yara_rules = yara.compile(filepath=str(rules_path))
                    with open(fp, "rb") as f:
                        data = f.read(256 * 1024)  # Read 256KB sample
                    matches = yara_rules.match(data=data)
                    yara_matches = [m.rule for m in matches]
            except Exception:
                pass
            
            res = anomaly.score_path(fp, yara_matches=yara_matches)
            scanned += 1
            r = float(res.get("risk", 0) or 0)
            risks.append(r)
            try:
                sz = Path(fp).stat().st_size
            except Exception:
                sz = 0
            bytes_scanned += sz
            sev = res.get("verdict")
            if sev == "malicious":
                malicious += 1
            elif sev == "suspicious":
                suspicious += 1
            top.append({"path": fp, "risk": r, "verdict": sev})
            top = sorted(top, key=lambda x: x["risk"], reverse=True)[:20]
        except Exception:
            pass

        percent = int((scanned / max(1, total)) * 100)
        if broadcast:
            try:
                await broadcast({
                    "type": "scan_event",
                    "job_id": rid,
                    "percent": percent,
                    "scanned": scanned,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                })
            except Exception:
                pass
        await asyncio.sleep(0)

    risk_avg = (sum(risks) / len(risks)) if risks else 0.0
    res = {
        "job_id": rid,
        "root": root,
        "total": total,
        "scanned": scanned,
        "malicious": malicious,
        "suspicious": suspicious,
        "bytes": bytes_scanned,
        "risk_avg": risk_avg,
        "top": top,
        "completed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    if broadcast:
        try:
            await broadcast({"type": "scan_result", "job_id": rid, "summary": res})
        except Exception:
            pass
    return res

