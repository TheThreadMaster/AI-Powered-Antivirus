import re
import os
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlparse


RISKY_DOMAINS = [
    r"\.ru$",
    r"\.cn$",
    r"bitcoin|giveaway|free-|win-|claim-",
]

# Comprehensive suspicious keywords for phishing/malware detection
PHISHING_KEYWORDS = [
    "verify", "confirm", "validate", "authenticate", "account", "security", "suspended",
    "locked", "expired", "urgent", "immediate", "action required", "limited time",
    "click here", "update now", "reactivate", "restore", "unlock", "validate account",
    "secure account", "protect account", "verify identity", "confirm identity"
]

SCAM_KEYWORDS = [
    "free", "gift", "prize", "winner", "congratulations", "you won", "claim now",
    "limited offer", "act now", "click to claim", "claim reward", "cash prize",
    "lottery", "sweepstakes", "voucher", "bonus", "discount code", "promo code"
]

FINANCIAL_SCAM_KEYWORDS = [
    "bitcoin", "crypto", "cryptocurrency", "investment", "trading", "forex",
    "get rich", "make money", "earn money", "fast money", "quick cash",
    "paypal", "bank", "credit card", "debit card", "ssn", "social security",
    "tax refund", "irs", "refund", "payment", "invoice", "billing"
]

MALWARE_KEYWORDS = [
    "download", "install", "update", "patch", "fix", "crack", "keygen",
    "serial", "warez", "torrent", "free download", "download now"
]

BRAND_IMPERSONATION_PATTERNS = [
    r"microsoft-?online", r"apple-?support", r"google-?security", r"amazon-?verify",
    r"paypal-?secure", r"bankofamerica-?online", r"wellsfargo-?login",
    r"netflix-?account", r"facebook-?verify", r"twitter-?confirm"
]

# High-risk TLDs (known for abuse)
HIGH_RISK_TLDS = {"cc", "xyz", "ru", "top", "tk", "ml", "ga", "cf", "gq", "cn", "online", "site", "website"}
MEDIUM_RISK_TLDS = {"info", "biz", "click", "download", "loan", "review", "win"}

# URL shortener services (often used for obfuscation)
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "short.link", "is.gd", "ow.ly", "buff.ly"}


def _detect_homograph_attack(host: str) -> float:
    """Detect homograph attacks using Unicode characters that look like ASCII."""
    # Common homograph characters (Cyrillic, Greek, etc. that look like Latin)
    homograph_chars = set([
        'а', 'е', 'о', 'р', 'с', 'у', 'х',  # Cyrillic
        'α', 'ε', 'ο', 'ρ', 'τ', 'υ', 'χ',  # Greek
        'і', 'ⅼ', '１', '０', 'ｅ',  # Various Unicode
    ])
    if any(c in host.lower() for c in homograph_chars):
        return 0.4
    return 0.0


def _detect_typosquatting(host: str) -> float:
    """Detect typosquatting patterns (common domain variations)."""
    # Common typosquatting patterns
    suspicious_patterns = [
        r"^[a-z]+\d+[a-z]+",  # Mixed alphanumeric (like "amazon123store")
        r"^[a-z]+-[a-z]+\d+",  # Hyphenated with numbers
        r"\d+[a-z]+-[a-z]+",   # Numbers at start with hyphens
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, host):
            return 0.25
    return 0.0


def _analyze_subdomain(host: str) -> float:
    """Analyze subdomain patterns for suspicious activity."""
    parts = host.split(".")
    if len(parts) < 3:
        return 0.0  # No subdomain
    
    subdomain = parts[0]
    score = 0.0
    
    # Suspicious subdomain patterns
    if len(subdomain) > 20:  # Very long subdomains
        score += 0.15
    
    # Random-looking subdomains (high digit ratio)
    if subdomain:
        digit_ratio = sum(1 for c in subdomain if c.isdigit()) / len(subdomain)
        if digit_ratio > 0.3:
            score += 0.2
    
    # Multiple hyphens
    if subdomain.count("-") >= 3:
        score += 0.15
    
    return min(0.3, score)


def _analyze_path_patterns(path: str, query: str) -> float:
    """Analyze URL path and query parameters for suspicious patterns."""
    score = 0.0
    path_lower = path.lower()
    query_lower = query.lower()
    combined = path_lower + query_lower
    
    # Suspicious path patterns
    high_risk_paths = ["login", "verify", "authenticate", "confirm", "secure", "account", "update", "payment"]
    medium_risk_paths = ["download", "install", "update", "patch", "fix"]
    
    for pattern in high_risk_paths:
        if pattern in combined:
            score += 0.12
    
    for pattern in medium_risk_paths:
        if pattern in combined:
            score += 0.08
    
    # Multiple parameters (often used for tracking/phishing)
    if query:
        param_count = query.count("&") + 1
        if param_count > 5:
            score += 0.1
    
    # Suspicious parameter names
    suspicious_params = ["token", "key", "auth", "password", "pwd", "pin", "ssn"]
    for param in suspicious_params:
        if param in query_lower:
            score += 0.15
    
    return min(0.4, score)


def score_url(url: str):
    """Enhanced URL scoring with comprehensive risk detection."""
    try:
        p = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return {"url": url, "score": 0.8, "category": "suspicious", "normalized_score": 0.8}

    raw = url.lower()
    host = (p.netloc or "").lower().split(":")[0]  # Remove port
    path = (p.path or "").lower()
    query = (p.query or "").lower()
    scheme = (p.scheme or "").lower()
    
    # Start with base score
    score = 0.05
    
    # HTTPS vs HTTP (HTTP is riskier for sensitive operations)
    if scheme == "http" and any(kw in path + query for kw in ["login", "pay", "bank", "secure", "verify"]):
        score += 0.25
    elif scheme == "https":
        score -= 0.02  # Slight reduction for HTTPS
    
    # Extract TLD and domain parts
    host_parts = host.split(".")
    if len(host_parts) >= 2:
        tld = host_parts[-1]
        domain = host_parts[-2] if len(host_parts) >= 2 else ""
        full_domain = ".".join(host_parts[-2:])
    else:
        tld = host_parts[-1] if host_parts else ""
        domain = ""
        full_domain = host
    
    # TLD risk assessment
    if tld in HIGH_RISK_TLDS:
        score += 0.3
    elif tld in MEDIUM_RISK_TLDS:
        score += 0.15
    
    # URL shortener detection
    if full_domain in URL_SHORTENERS:
        score += 0.2  # Shorteners are often used for obfuscation
    
    # Brand impersonation
    for pattern in BRAND_IMPERSONATION_PATTERNS:
        if re.search(pattern, host):
            score += 0.35
            break
    
    # Homograph attack detection
    score += _detect_homograph_attack(host)
    
    # Typosquatting detection
    score += _detect_typosquatting(host)
    
    # Subdomain analysis
    score += _analyze_subdomain(host)
    
    # IP address detection (both IPv4 and IPv6)
    ip_present = False
    try:
        socket.inet_aton(host)
        ip_present = True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            ip_present = True
        except (socket.error, ValueError):
            pass
    
    if ip_present:
        score += 0.35  # Direct IP access is suspicious
    
    # Port in URL (non-standard ports)
    if ":" in p.netloc and len(p.netloc.split(":")) > 1:
        try:
            port = int(p.netloc.split(":")[-1])
            if port not in [80, 443, 8080]:  # Common ports
                score += 0.15
        except ValueError:
            pass
    
    # Comprehensive keyword analysis
    # Phishing keywords (highest weight)
    phishing_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in raw)
    score += min(0.35, 0.05 * phishing_hits)
    
    # Domain-only phishing keywords (even higher weight)
    domain_phishing = sum(1 for kw in PHISHING_KEYWORDS if kw in host)
    score += min(0.3, 0.08 * domain_phishing)
    
    # Scam keywords
    scam_hits = sum(1 for kw in SCAM_KEYWORDS if kw in raw)
    score += min(0.3, 0.04 * scam_hits)
    
    # Financial scam keywords
    financial_hits = sum(1 for kw in FINANCIAL_SCAM_KEYWORDS if kw in raw)
    score += min(0.35, 0.06 * financial_hits)
    
    # Malware keywords
    malware_hits = sum(1 for kw in MALWARE_KEYWORDS if kw in raw)
    score += min(0.25, 0.04 * malware_hits)
    
    # URL length heuristics
    url_length = len(raw)
    if url_length > 80:
        score += 0.12
    if url_length > 120:
        score += 0.18
    if url_length > 200:
        score += 0.25
    
    # Excessive digits (often used in malicious URLs)
    digits = sum(1 for c in raw if c.isdigit())
    digit_ratio = digits / max(1, url_length)
    if digits >= 6:
        score += 0.12
    if digit_ratio > 0.25:
        score += 0.15
    if digit_ratio > 0.4:
        score += 0.2
    
    # Path and query parameter analysis
    score += _analyze_path_patterns(path, query)
    
    # Excessive hyphens or underscores
    if host.count("-") >= 4:
        score += 0.1
    if host.count("_") >= 2:
        score += 0.08
    
    # Encoded characters (potential obfuscation)
    if "%" in raw or "\\u" in raw or "&#" in raw:
        score += 0.15
    
    # Suspicious domain patterns
    if re.search(r'\d{4,}', host):  # 4+ consecutive digits
        score += 0.15
    
    # Clamp and categorize
    score = max(0.0, min(1.0, score))
    
    # Enhanced categorization
    if score >= 0.7:
        category = "phishing"
    elif score >= 0.55:
        category = "malware"
    elif score >= 0.35:
        category = "suspicious"
    elif score >= 0.2:
        category = "low_risk"
    else:
        category = "benign"
    
    return {
        "url": url,
        "score": round(score, 4),
        "category": category,
        "normalized_score": round(score, 4),
        "risk_factors": {
            "high_risk_tld": tld in HIGH_RISK_TLDS,
            "ip_address": ip_present,
            "url_shortener": full_domain in URL_SHORTENERS,
            "brand_impersonation": any(re.search(p, host) for p in BRAND_IMPERSONATION_PATTERNS),
            "has_phishing_keywords": phishing_hits > 0,
            "has_scam_keywords": scam_hits > 0,
            "has_financial_keywords": financial_hits > 0,
        }
    }


def _extract_host(url: str) -> tuple[str | None, str | None]:
    """Extract host and base domain from URL. Returns (host, base_domain)."""
    try:
        raw = (url or "").strip().lower()
        h = raw
        if "://" in h:
            try:
                h = urlparse(h).netloc.lower()
            except Exception:
                return None, None
        else:
            if "/" in h:
                try:
                    h = urlparse("http://" + h).netloc.lower()
                except Exception:
                    return None, None
        if not h:
            return None, None
        if ":" in h:
            h = h.split(":")[0]
        # Validate it's not an IP address
        try:
            socket.inet_aton(h)
            return None, None  # IP addresses not supported
        except Exception:
            pass
        if not re.fullmatch(r"[a-z0-9.-]+", h):
            return None, None
        # Determine base/root domain
        labels = h.split(".")
        base = ".".join(labels[-2:]) if len(labels) >= 2 else h
        return h, base
    except Exception:
        return None, None


def block_url(url: str, force: bool = True):
    """
    Block URL at OS level by modifying hosts file.
    Works on Windows, Linux, and macOS.
    Returns dict with ok, host, base, updated, and error fields.
    """
    try:
        host, base = _extract_host(url)
        if not host or not base:
            return {"ok": False, "error": "invalid_host", "host": None, "base": None, "updated": False}
        
        # Determine hosts file path based on OS
        if os.name == "nt":  # Windows
            hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")
            flush_cmd = ["ipconfig", "/flushdns"]
            block_ip = "127.0.0.1"
            needs_elevation = True
        elif os.name == "posix":  # Linux/macOS
            hosts_path = Path("/etc/hosts")
            if os.uname().sysname == "Darwin":  # macOS
                flush_cmd = ["dscacheutil", "-flushcache"]
            else:  # Linux
                flush_cmd = ["systemd-resolve", "--flush-caches"] if subprocess.run(["which", "systemd-resolve"], capture_output=True).returncode == 0 else None
            block_ip = "127.0.0.1"
            needs_elevation = True
        else:
            return {"ok": False, "error": "unsupported_os", "host": host, "base": base, "updated": False}
        
        if not hosts_path.exists():
            return {"ok": False, "error": "hosts_not_found", "host": host, "base": base, "updated": False}
        
        # Determine targets to block (base domain and full hostname)
        targets = {base, host}
        
        # Read existing hosts file
        try:
            with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except PermissionError:
            # Try with elevated permissions
            if os.name == "nt":
                try:
                    # Try to add entry using netsh (Windows)
                    for t in targets:
                        subprocess.run(["netsh", "interface", "ipv4", "add", "address", "Loopback", f"{block_ip}", f"255.255.255.255", f"store=persistent"], 
                                     capture_output=True, check=False)
                    # Add to hosts using runas or other method
                    return {"ok": False, "error": "permission_denied", "host": host, "base": base, "updated": False, "note": "Administrator privileges required"}
                except Exception:
                    return {"ok": False, "error": "permission_denied", "host": host, "base": base, "updated": False, "note": "Administrator privileges required"}
            else:
                return {"ok": False, "error": "permission_denied", "host": host, "base": base, "updated": False, "note": "sudo/root privileges required"}
        except Exception as e:
            return {"ok": False, "error": str(e), "host": host, "base": base, "updated": False}
        
        # Check existing entries
        existing = set()
        for ln in lines:
            s = ln.split("#", 1)[0].strip()
            if not s:
                continue
            parts = s.split()
            if len(parts) >= 2 and parts[0].strip() == block_ip:
                for t in targets:
                    if t in parts[1:]:
                        existing.add(t)
        
        to_add = [t for t in targets if t not in existing]
        if not to_add:
            return {"ok": True, "host": host, "base": base, "updated": False, "message": "Already blocked"}
        
        # Add blocking entries
        if force:
            try:
                # Try regular write first
                with open(hosts_path, "a", encoding="utf-8", errors="ignore") as f:
                    for t in to_add:
                        f.write(f"\n{block_ip} {t}  # Blocked by AI Shield\n")
            except PermissionError:
                # If permission denied, try alternative methods
                if os.name == "nt":
                    # Windows: Try using PowerShell with elevated privileges
                    try:
                        ps_script = f"""
                        $hosts = Get-Content '{hosts_path}' -Raw
                        $entries = @({', '.join([f"'{block_ip} {t}  # Blocked by AI Shield'" for t in to_add])})
                        $newEntries = $entries -join "`n"
                        if ($hosts -notmatch '{host}') {{
                            Add-Content -Path '{hosts_path}' -Value "`n$newEntries" -Force
                        }}
                        """
                        result = subprocess.run(["powershell", "-Command", ps_script], 
                                              capture_output=True, text=True, check=False)
                        if result.returncode != 0:
                            return {"ok": False, "error": "permission_denied", "host": host, "base": base, 
                                  "updated": False, "note": "Run as Administrator to block URLs"}
                    except Exception:
                        return {"ok": False, "error": "permission_denied", "host": host, "base": base, 
                              "updated": False, "note": "Administrator privileges required"}
                else:
                    # Linux/macOS: Need sudo
                    try:
                        entries = "\n".join([f"{block_ip} {t}  # Blocked by AI Shield" for t in to_add])
                        echo_cmd = f"echo -e '\n{entries}' | sudo tee -a {hosts_path} > /dev/null"
                        result = subprocess.run(echo_cmd, shell=True, capture_output=True, check=False)
                        if result.returncode != 0:
                            return {"ok": False, "error": "permission_denied", "host": host, "base": base, 
                                  "updated": False, "note": "sudo/root privileges required"}
                    except Exception:
                        return {"ok": False, "error": "permission_denied", "host": host, "base": base, 
                              "updated": False, "note": "sudo/root privileges required"}
            except Exception as e:
                return {"ok": False, "error": str(e), "host": host, "base": base, "updated": False}
        
        # Flush DNS cache
        try:
            if flush_cmd:
                subprocess.run(flush_cmd, capture_output=True, text=True, check=False)
        except Exception:
            pass
        
        return {"ok": True, "host": host, "base": base, "updated": True, "targets": list(to_add)}
    except Exception as e:
        return {"ok": False, "error": str(e), "host": None, "base": None, "updated": False}


def check_and_block_url(url: str, auto_block_threshold: float = 0.6, db=None) -> dict:
    """
    Check URL and automatically block if it exceeds risk threshold.
    Returns dict with url, score, category, blocked, and action fields.
    """
    # Import DB if not provided (avoid circular import)
    if db is None:
        from .store import DB
    else:
        DB = db
    
    # Check if WebShield protection is enabled
    protection = DB.state.get("protection", {})
    webshield_enabled = protection.get("webshield", True)
    
    # If WebShield is disabled, only return basic info without blocking
    if not webshield_enabled:
        scored = score_url(url)
        return {
            "url": url,
            "score": scored.get("score", 0.0),
            "category": scored.get("category", "benign"),
            "blocked": False,
            "action": "allowed",
            "os_blocked": False,
        }
    
    # Check if already blocked
    if DB.is_url_blocked(url):
        return {
            "url": url,
            "score": 1.0,
            "category": "blocked",
            "blocked": True,
            "action": "already_blocked",
            "os_blocked": True,
        }
    
    # Score the URL
    scored = score_url(url)
    score_val = scored.get("score", 0.0)
    category = scored.get("category", "benign")
    
    # Auto-block if score exceeds threshold
    should_block = score_val >= auto_block_threshold or category in {"phishing", "malware"}
    
    blocked = False
    os_blocked = False
    action = "allowed"
    
    if should_block:
        # Attempt OS-level blocking
        block_result = block_url(url, force=True)
        os_blocked = bool(block_result.get("updated", False)) or bool(block_result.get("ok", False))
        
        # Save to database
        host, base = _extract_host(url)
        if host and base:
            try:
                DB.add_blocked_url(url, base, score_val, category, os_blocked)
                blocked = True
                action = "auto_blocked" if os_blocked else "flagged"
            except Exception:
                pass
    
    return {
        "url": url,
        "score": score_val,
        "category": category,
        "blocked": blocked,
        "action": action,
        "os_blocked": os_blocked,
    }
