"""Cloud Delivered Protection - Cloud-based threat intelligence and reputation services."""

from __future__ import annotations

import os
import hashlib
import time
import httpx
from typing import Optional, Dict, Any, List
from pathlib import Path
from urllib.parse import urlparse
import json


# Configuration
CLOUD_PROTECTION_ENABLED = os.getenv("CLOUD_PROTECTION_ENABLED", "true").lower() == "true"
CLOUD_API_TIMEOUT = 5.0  # 5 seconds timeout for cloud API calls
CLOUD_CACHE_TTL = 3600  # Cache results for 1 hour
AUTO_SUBMIT_ENABLED = os.getenv("AUTO_SUBMIT_SAMPLES", "true").lower() == "true"  # Auto-submit threats to cloud
AUTO_SUBMIT_MAX_SIZE = int(os.getenv("AUTO_SUBMIT_MAX_SIZE", "32")) * 1024 * 1024  # Max file size: 32MB default


class CloudProtectionService:
    """Cloud-based threat intelligence and reputation service."""
    
    def __init__(self):
        self.enabled = CLOUD_PROTECTION_ENABLED
        self.auto_submit_enabled = AUTO_SUBMIT_ENABLED
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_timestamps: Dict[str, float] = {}
        self.submission_tracking: Dict[str, Dict[str, Any]] = {}  # Track file submissions
        self.stats = {
            "file_checks": 0,
            "url_checks": 0,
            "ip_checks": 0,
            "threats_detected": 0,
            "api_errors": 0,
            "samples_submitted": 0,
            "submissions_successful": 0,
            "submissions_failed": 0,
        }
    
    def _get_cache_key(self, check_type: str, identifier: str) -> str:
        """Generate cache key for a check."""
        return f"{check_type}:{identifier}"
    
    def _is_cached(self, key: str) -> bool:
        """Check if result is cached and still valid."""
        if key not in self.cache:
            return False
        timestamp = self.cache_timestamps.get(key, 0)
        return (time.time() - timestamp) < CLOUD_CACHE_TTL
    
    def _get_cached(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if available."""
        if self._is_cached(key):
            return self.cache[key]
        return None
    
    def _cache_result(self, key: str, result: Dict[str, Any]):
        """Cache a result."""
        self.cache[key] = result
        self.cache_timestamps[key] = time.time()
        # Limit cache size to 1000 entries
        if len(self.cache) > 1000:
            # Remove oldest entries
            sorted_keys = sorted(self.cache_timestamps.items(), key=lambda x: x[1])
            for old_key, _ in sorted_keys[:100]:
                del self.cache[old_key]
                del self.cache_timestamps[old_key]
    
    def _submit_file_virustotal(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Submit a file to VirusTotal for analysis."""
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            return None
        
        try:
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > AUTO_SUBMIT_MAX_SIZE:
                return {
                    "success": False,
                    "error": f"File too large ({file_size / 1024 / 1024:.1f}MB). Max size: {AUTO_SUBMIT_MAX_SIZE / 1024 / 1024:.1f}MB",
                    "source": "virustotal"
                }
            
            url = "https://www.virustotal.com/vtapi/v2/file/scan"
            
            with httpx.Client(timeout=30.0) as client:  # Longer timeout for file upload
                with open(file_path, "rb") as f:
                    files = {"file": (file_path.name, f, "application/octet-stream")}
                    data = {"apikey": api_key}
                    response = client.post(url, files=files, data=data)
                    
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("response_code") == 1:  # Success
                            return {
                                "success": True,
                                "source": "virustotal",
                                "scan_id": data.get("scan_id"),
                                "permalink": data.get("permalink"),
                                "sha256": data.get("sha256"),
                                "message": "File submitted successfully",
                            }
                        else:
                            return {
                                "success": False,
                                "error": data.get("verbose_msg", "Submission failed"),
                                "source": "virustotal"
                            }
                    else:
                        return {
                            "success": False,
                            "error": f"HTTP {response.status_code}: {response.text[:200]}",
                            "source": "virustotal"
                        }
        except Exception as e:
            print(f"[CloudProtection] VirusTotal submission error: {e}")
            self.stats["api_errors"] += 1
            return {
                "success": False,
                "error": str(e),
                "source": "virustotal"
            }
    
    def _submit_file_hybrid_analysis(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Submit a file to Hybrid Analysis for analysis."""
        api_key = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
        api_secret = os.getenv("HYBRID_ANALYSIS_API_SECRET", "")
        if not api_key or not api_secret:
            return None
        
        try:
            file_size = file_path.stat().st_size
            if file_size > AUTO_SUBMIT_MAX_SIZE:
                return {
                    "success": False,
                    "error": f"File too large ({file_size / 1024 / 1024:.1f}MB)",
                    "source": "hybrid_analysis"
                }
            
            # Hybrid Analysis API v2
            url = "https://www.hybrid-analysis.com/api/v2/submit/file"
            headers = {
                "api-key": api_key,
                "api-secret": api_secret,
                "user-agent": "AI-Shield/1.0"
            }
            
            with httpx.Client(timeout=30.0) as client:
                with open(file_path, "rb") as f:
                    files = {"file": (file_path.name, f, "application/octet-stream")}
                    data = {
                        "environment_id": "100",  # Windows 10
                        "no_share_third_party": "false",
                        "no_hash_lookup": "false",
                    }
                    response = client.post(url, files=files, data=data, headers=headers)
                    
                    if response.status_code in (200, 201):
                        data = response.json()
                        if data.get("job_id"):
                            return {
                                "success": True,
                                "source": "hybrid_analysis",
                                "job_id": data.get("job_id"),
                                "sha256": data.get("sha256"),
                                "message": "File submitted successfully",
                            }
                    return {
                        "success": False,
                        "error": f"HTTP {response.status_code}: {response.text[:200]}",
                        "source": "hybrid_analysis"
                    }
        except Exception as e:
            print(f"[CloudProtection] Hybrid Analysis submission error: {e}")
            self.stats["api_errors"] += 1
            return None
    
    def _check_file_hash_virustotal(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check file hash against VirusTotal (using public API, rate-limited)."""
        # Note: VirusTotal requires API key for full access
        # This is a simplified implementation that can be extended
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            # Without API key, we can't use VirusTotal
            return None
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                "apikey": api_key,
                "resource": file_hash,
            }
            
            with httpx.Client(timeout=CLOUD_API_TIMEOUT) as client:
                response = client.get(url, params=params)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("response_code") == 1:  # Found
                        positives = data.get("positives", 0)
                        total = data.get("total", 0)
                        return {
                            "source": "virustotal",
                            "detected": positives > 0,
                            "positives": positives,
                            "total": total,
                            "scan_date": data.get("scan_date"),
                            "permalink": data.get("permalink"),
                            "verdict": "malicious" if positives > 5 else ("suspicious" if positives > 0 else "clean"),
                        }
        except Exception as e:
            print(f"[CloudProtection] VirusTotal error: {e}")
            self.stats["api_errors"] += 1
        
        return None
    
    def _check_url_reputation(self, url: str) -> Optional[Dict[str, Any]]:
        """Check URL reputation using multiple cloud services."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            # Check against known malicious domains (can be extended with real API)
            # This is a placeholder that can integrate with AbuseIPDB, URLhaus, etc.
            malicious_domains = [
                "malware.com", "phishing.com", "suspicious-site.com"
            ]
            
            if any(md in domain.lower() for md in malicious_domains):
                return {
                    "source": "cloud_reputation",
                    "reputation": "malicious",
                    "confidence": 0.8,
                    "reason": "Known malicious domain",
                }
            
            # Placeholder for real cloud API integration
            # Can integrate with:
            # - Google Safe Browsing API
            # - URLhaus API
            # - AbuseIPDB
            # - VirusTotal URL scanner
            
        except Exception as e:
            print(f"[CloudProtection] URL reputation check error: {e}")
            self.stats["api_errors"] += 1
        
        return None
    
    def _check_ip_reputation(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP address reputation."""
        try:
            # Placeholder for real IP reputation API
            # Can integrate with:
            # - AbuseIPDB
            # - VirusTotal IP scanner
            # - Threat Intelligence feeds
            
            # Simple check for private/local IPs
            if ip.startswith(("127.", "192.168.", "10.", "172.")):
                return {
                    "source": "cloud_reputation",
                    "reputation": "local",
                    "confidence": 1.0,
                }
            
        except Exception as e:
            print(f"[CloudProtection] IP reputation check error: {e}")
            self.stats["api_errors"] += 1
        
        return None
    
    def check_file(self, file_path: str) -> Dict[str, Any]:
        """
        Check file against cloud threat intelligence.
        
        Returns:
            {
                "enabled": bool,
                "checked": bool,
                "cloud_verdict": str | None,
                "cloud_score": float,
                "cloud_sources": List[str],
                "threat_detected": bool,
                "details": Dict[str, Any],
            }
        """
        if not self.enabled:
            return {
                "enabled": False,
                "checked": False,
                "cloud_verdict": None,
                "cloud_score": 0.0,
                "cloud_sources": [],
                "threat_detected": False,
                "details": {},
            }
        
        try:
            p = Path(file_path)
            if not p.exists() or not p.is_file():
                return {
                    "enabled": True,
                    "checked": False,
                    "cloud_verdict": None,
                    "cloud_score": 0.0,
                    "cloud_sources": [],
                    "threat_detected": False,
                    "details": {"error": "File not found"},
                }
            
            # Compute file hash
            file_hash = self._compute_file_hash(p)
            cache_key = self._get_cache_key("file", file_hash)
            
            # Check cache
            cached = self._get_cached(cache_key)
            if cached:
                return cached
            
            self.stats["file_checks"] += 1
            
            # Check against cloud services
            cloud_results = []
            threat_detected = False
            max_score = 0.0
            verdict = None
            
            # VirusTotal check
            vt_result = self._check_file_hash_virustotal(file_hash)
            if vt_result:
                cloud_results.append(vt_result)
                if vt_result.get("detected"):
                    threat_detected = True
                    positives = vt_result.get("positives", 0)
                    total = vt_result.get("total", 1)
                    max_score = max(max_score, positives / max(total, 1))
                    if not verdict or vt_result.get("verdict") in ("malicious", "suspicious"):
                        verdict = vt_result.get("verdict")
            
            result = {
                "enabled": True,
                "checked": True,
                "cloud_verdict": verdict or "clean",
                "cloud_score": max_score,
                "cloud_sources": [r.get("source", "unknown") for r in cloud_results],
                "threat_detected": threat_detected,
                "details": {
                    "file_hash": file_hash,
                    "file_size": p.stat().st_size,
                    "cloud_results": cloud_results,
                },
            }
            
            # Cache result
            self._cache_result(cache_key, result)
            
            if threat_detected:
                self.stats["threats_detected"] += 1
            
            return result
            
        except Exception as e:
            print(f"[CloudProtection] File check error: {e}")
            self.stats["api_errors"] += 1
            return {
                "enabled": True,
                "checked": False,
                "cloud_verdict": None,
                "cloud_score": 0.0,
                "cloud_sources": [],
                "threat_detected": False,
                "details": {"error": str(e)},
            }
    
    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check URL against cloud reputation services.
        
        Returns:
            {
                "enabled": bool,
                "checked": bool,
                "cloud_reputation": str | None,
                "cloud_score": float,
                "cloud_sources": List[str],
                "threat_detected": bool,
                "details": Dict[str, Any],
            }
        """
        if not self.enabled:
            return {
                "enabled": False,
                "checked": False,
                "cloud_reputation": None,
                "cloud_score": 0.0,
                "cloud_sources": [],
                "threat_detected": False,
                "details": {},
            }
        
        try:
            cache_key = self._get_cache_key("url", url)
            
            # Check cache
            cached = self._get_cached(cache_key)
            if cached:
                return cached
            
            self.stats["url_checks"] += 1
            
            # Check URL reputation
            reputation_result = self._check_url_reputation(url)
            
            threat_detected = False
            reputation = None
            score = 0.0
            sources = []
            
            if reputation_result:
                reputation = reputation_result.get("reputation", "unknown")
                score = reputation_result.get("confidence", 0.0)
                sources.append(reputation_result.get("source", "unknown"))
                if reputation in ("malicious", "suspicious"):
                    threat_detected = True
            
            result = {
                "enabled": True,
                "checked": True,
                "cloud_reputation": reputation or "unknown",
                "cloud_score": score,
                "cloud_sources": sources,
                "threat_detected": threat_detected,
                "details": {
                    "url": url,
                    "reputation_result": reputation_result,
                },
            }
            
            # Cache result
            self._cache_result(cache_key, result)
            
            if threat_detected:
                self.stats["threats_detected"] += 1
            
            return result
            
        except Exception as e:
            print(f"[CloudProtection] URL check error: {e}")
            self.stats["api_errors"] += 1
            return {
                "enabled": True,
                "checked": False,
                "cloud_reputation": None,
                "cloud_score": 0.0,
                "cloud_sources": [],
                "threat_detected": False,
                "details": {"error": str(e)},
            }
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Check IP address against cloud reputation services.
        
        Returns:
            {
                "enabled": bool,
                "checked": bool,
                "cloud_reputation": str | None,
                "cloud_score": float,
                "cloud_sources": List[str],
                "threat_detected": bool,
                "details": Dict[str, Any],
            }
        """
        if not self.enabled:
            return {
                "enabled": False,
                "checked": False,
                "cloud_reputation": None,
                "cloud_score": 0.0,
                "cloud_sources": [],
                "threat_detected": False,
                "details": {},
            }
        
        try:
            cache_key = self._get_cache_key("ip", ip)
            
            # Check cache
            cached = self._get_cached(cache_key)
            if cached:
                return cached
            
            self.stats["ip_checks"] += 1
            
            # Check IP reputation
            reputation_result = self._check_ip_reputation(ip)
            
            threat_detected = False
            reputation = None
            score = 0.0
            sources = []
            
            if reputation_result:
                reputation = reputation_result.get("reputation", "unknown")
                score = reputation_result.get("confidence", 0.0)
                sources.append(reputation_result.get("source", "unknown"))
                if reputation in ("malicious", "suspicious"):
                    threat_detected = True
            
            result = {
                "enabled": True,
                "checked": True,
                "cloud_reputation": reputation or "unknown",
                "cloud_score": score,
                "cloud_sources": sources,
                "threat_detected": threat_detected,
                "details": {
                    "ip": ip,
                    "reputation_result": reputation_result,
                },
            }
            
            # Cache result
            self._cache_result(cache_key, result)
            
            if threat_detected:
                self.stats["threats_detected"] += 1
            
            return result
            
        except Exception as e:
            print(f"[CloudProtection] IP check error: {e}")
            self.stats["api_errors"] += 1
            return {
                "enabled": True,
                "checked": False,
                "cloud_reputation": None,
                "cloud_score": 0.0,
                "cloud_sources": [],
                "threat_detected": False,
                "details": {"error": str(e)},
            }
    
    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read in chunks to handle large files
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return ""
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cloud protection statistics."""
        return {
            "enabled": self.enabled,
            "auto_submit_enabled": self.auto_submit_enabled,
            "stats": self.stats.copy(),
            "cache_size": len(self.cache),
            "submissions_tracked": len(self.submission_tracking),
        }
    
    def enable(self):
        """Enable cloud protection."""
        self.enabled = True
    
    def disable(self):
        """Disable cloud protection."""
        self.enabled = False
    
    def enable_auto_submit(self):
        """Enable automatic sample submission."""
        self.auto_submit_enabled = True
    
    def disable_auto_submit(self):
        """Disable automatic sample submission."""
        self.auto_submit_enabled = False
    
    def clear_cache(self):
        """Clear the cache."""
        self.cache.clear()
        self.cache_timestamps.clear()
    
    def submit_threat_sample(self, file_path: str, verdict: str = "suspicious", severity: str = "medium") -> Dict[str, Any]:
        """
        Automatically submit a threat sample to cloud platforms for analysis.
        
        Args:
            file_path: Path to the file to submit
            verdict: Threat verdict (malicious, suspicious, etc.)
            severity: Threat severity (low, medium, high, critical)
        
        Returns:
            {
                "submitted": bool,
                "platforms": List[str],
                "results": Dict[str, Any],
                "errors": List[str],
            }
        """
        if not self.enabled or not self.auto_submit_enabled:
            return {
                "submitted": False,
                "platforms": [],
                "results": {},
                "errors": ["Cloud protection or auto-submit disabled"],
            }
        
        try:
            p = Path(file_path)
            if not p.exists() or not p.is_file():
                return {
                    "submitted": False,
                    "platforms": [],
                    "results": {},
                    "errors": ["File not found"],
                }
            
            # Check if already submitted
            file_hash = self._compute_file_hash(p)
            submission_key = f"submission:{file_hash}"
            
            if submission_key in self.submission_tracking:
                cached = self.submission_tracking[submission_key]
                return {
                    "submitted": True,
                    "platforms": cached.get("platforms", []),
                    "results": cached.get("results", {}),
                    "errors": cached.get("errors", []),
                    "cached": True,
                }
            
            # Only submit suspicious/malicious files
            if verdict not in ("malicious", "suspicious") and severity not in ("high", "critical", "medium"):
                return {
                    "submitted": False,
                    "platforms": [],
                    "results": {},
                    "errors": ["File not suspicious enough for submission"],
                }
            
            self.stats["samples_submitted"] += 1
            
            submission_results = {}
            platforms_used = []
            errors = []
            
            # Submit to VirusTotal
            vt_result = self._submit_file_virustotal(p)
            if vt_result:
                if vt_result.get("success"):
                    platforms_used.append("virustotal")
                    submission_results["virustotal"] = vt_result
                    self.stats["submissions_successful"] += 1
                else:
                    errors.append(f"VirusTotal: {vt_result.get('error', 'Unknown error')}")
                    self.stats["submissions_failed"] += 1
            
            # Submit to Hybrid Analysis (if API keys configured)
            ha_result = self._submit_file_hybrid_analysis(p)
            if ha_result:
                if ha_result.get("success"):
                    platforms_used.append("hybrid_analysis")
                    submission_results["hybrid_analysis"] = ha_result
                    self.stats["submissions_successful"] += 1
                else:
                    errors.append(f"Hybrid Analysis: {ha_result.get('error', 'Unknown error')}")
                    self.stats["submissions_failed"] += 1
            
            result = {
                "submitted": len(platforms_used) > 0,
                "platforms": platforms_used,
                "results": submission_results,
                "errors": errors,
                "file_hash": file_hash,
                "file_path": str(p),
                "timestamp": time.time(),
            }
            
            # Track submission
            self.submission_tracking[submission_key] = result
            # Limit tracking size
            if len(self.submission_tracking) > 500:
                oldest_key = min(self.submission_tracking.keys(), key=lambda k: self.submission_tracking[k].get("timestamp", 0))
                del self.submission_tracking[oldest_key]
            
            print(f"[CloudProtection] Submitted {p.name} to {len(platforms_used)} platform(s): {', '.join(platforms_used)}")
            
            return result
            
        except Exception as e:
            print(f"[CloudProtection] Sample submission error: {e}")
            self.stats["api_errors"] += 1
            return {
                "submitted": False,
                "platforms": [],
                "results": {},
                "errors": [str(e)],
            }
    
    def get_submission_status(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get submission status for a file."""
        try:
            p = Path(file_path)
            if not p.exists():
                return None
            
            file_hash = self._compute_file_hash(p)
            submission_key = f"submission:{file_hash}"
            
            return self.submission_tracking.get(submission_key)
        except Exception:
            return None
    
    def list_submissions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent file submissions."""
        submissions = list(self.submission_tracking.values())
        # Sort by timestamp (newest first)
        submissions.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return submissions[:limit]


# Global instance
_cloud_service: Optional[CloudProtectionService] = None


def get_cloud_service() -> CloudProtectionService:
    """Get the global cloud protection service instance."""
    global _cloud_service
    if _cloud_service is None:
        _cloud_service = CloudProtectionService()
    return _cloud_service

