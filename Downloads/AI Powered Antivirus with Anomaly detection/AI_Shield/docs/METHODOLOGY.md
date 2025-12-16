# AI Shield - Project Methodology

## Real-Time Monitoring Framework

**File System Monitoring:** Implements dynamic file system event monitoring using the `watchdog` library (Python `watchdog.observers.Observer` and `watchdog.events.FileSystemEventHandler`) to track file creation, modification, and movement events in real-time. The system uses a delayed scan mechanism (default 1.0 second delay) to prevent duplicate scans of rapidly changing files, with configurable scan paths and exclusion patterns (node_modules, .git, __pycache__, venv, temp directories).

**Resource Tracking:** Implements system resource monitoring framework using `psutil` library for tracking CPU usage, memory consumption, disk I/O, and network bandwidth. Metrics are collected at 1-second intervals via WebSocket connections and broadcast to the frontend dashboard for real-time visualization. The system tracks network connections, process identification, and data transfer rates for anomaly detection.

**Continuous Background Scanning:** Performs continuous full-filesystem scans in addition to event-driven monitoring, with configurable threat report intervals (default: 1 minute, configurable via `BACKGROUND_SCAN_THREAT_REPORT_INTERVAL` environment variable). Scans files up to 100MB in size, maintains a cache of recently scanned files (last 3000 entries), and tracks scan progress with file count and session statistics.

## Anomaly Detection Algorithm

**Isolation Forest ML Model:** Uses scikit-learn's Isolation Forest algorithm (n_estimators=200, contamination=0.1) for statistical anomaly identification. The model extracts 11 features from files: logarithmic file size, entropy, non-ASCII ratio, printable character ratio, PE/ELF/PDF/ZIP magic byte detection, script type detection, image type detection, and suspicious string pattern hits.

**Anomaly Score Calculation:** Normalizes Isolation Forest output using logistic function `anomaly_score = 1.0 / (1.0 + exp(score_samples))` to convert decision function values to a 0-1 scale (higher = more anomalous). Applies type-aware damping: images receive 0.3x multiplier (unless suspicious content detected), PDFs receive 0.5x multiplier, executables receive 1.1x multiplier boost. Final risk score combines ML anomaly score with heuristic risk assessment using maximum value for safety.

**Feature Extraction:** Analyzes file headers (first 32 bytes) for magic byte detection, reads 256KB sample for content analysis, detects suspicious strings (Windows API calls, PowerShell obfuscation, command execution patterns, network activity indicators), and performs PE import/export analysis for packed executables. Risk scoring considers file extension mismatches, obfuscation indicators, and high-risk pattern combinations.

## Threat Detection Logic

**File Modification Rate Monitoring:** Tracks file modification events through watchdog's `on_modified()` handler with a 1-second scan delay to aggregate rapid changes. While explicit ransomware detection (10 modifications in 10 seconds) is not currently implemented, the system's continuous scanning and anomaly scoring effectively identifies suspicious file activity patterns that could indicate ransomware behavior.

**Risk Threshold Classification:** Classifies files as "malicious" if anomaly score > 0.7 or risk score > 0.8, "suspicious" if anomaly score > 0.5 or risk score > 0.6, and "benign" otherwise. Verdict determination considers multiple factors: ML anomaly score, heuristic risk indicators, suspicious string hits, file type mismatches, and PE/script characteristics.

**Cloud Intelligence Integration:** Enhances local detection with cloud-delivered threat intelligence via VirusTotal API (file hash reputation checks) and Hybrid Analysis API (sample submission and analysis). Automatic sample submission is enabled by default for detected threats, with configurable maximum file size limits and submission tracking to prevent duplicates.

## Behavioral Analysis Framework

**Sandbox Execution Simulation:** Performs context-aware behavioral analysis in an isolated sandbox environment (post-quarantine) using file type detection (executables, scripts, PDFs, images, text files). Simulates system calls (CreateFile, ReadFile, WriteFile, CreateProcess), registry modifications (HKCU\\Software), and network activity tracking. Generates verdicts (benign, suspicious, malicious) based on file type and detected behavior patterns.

**Post-Quarantine Analysis:** Reserves detailed TTP (Tactics, Techniques, and Procedures) observation for quarantined files in a secure, isolated environment. Quarantine algorithm moves files to `.quarantine` directory, renames files with timestamp and hash prefix, changes extension to `.quarantine`, and applies OS-level permission restrictions (Windows: icacls deny, Linux: chmod 0, chattr +i). Behavioral analysis is performed after quarantine to prevent execution while allowing safe inspection.

**System Call Analysis:** Tracks simulated system calls for executables and scripts: file operations (CreateFile, ReadFile, WriteFile), process creation (CreateProcess), registry access patterns, and network connection attempts. Analysis results include syscall list, registry modification attempts, network activity indicators, and a behavioral verdict score.

## Automated Response System

**Quarantine Algorithm:** Implements multi-step quarantine process: (1) Move file to `~/.quarantine` directory with obfuscated name format `YYYYMMDDTHHMMSS_{hash12}_{original_name}.quarantine`, (2) Compute SHA256 hash for integrity verification, (3) Lock file permissions using OS-level commands (Windows: `icacls /deny Everyone:(R,W)`, Linux: `chmod 0` + `chattr +i`), (4) Store metadata in SQLite database (original path, hash, size, timestamp, user, reason, state).

**File Deletion Service:** Implements multi-method deletion approach: (1) Primary: `send2trash` library for cross-platform safe deletion (Recycle Bin on Windows, Trash on Linux/macOS), (2) Fallback: Direct `os.remove()` with permission fixes, (3) Windows-specific: PowerShell `Remove-Item -Force`, batch script `del /f /q`, `takeown` + `icacls` for permission escalation, (4) Linux/macOS: `sudo rm -f` with chmod permission fixes. Includes admin privilege elevation requests (UAC on Windows, sudo on Linux/macOS) when required.

**Permission Restriction Levels:** Provides three levels of manual permission restriction: (1) Standard: Remove write permissions, (2) Moderate: Remove read and write permissions, (3) Strict: Remove all permissions (used for quarantined files). Applies restrictions using OS-native commands with admin elevation when necessary.

## Network Monitoring & Intrusion Detection

**Connection Tracking:** Monitors active network connections using system APIs, tracks process identification (PID, process name), remote IP addresses and ports, and data transfer rates (bytes per second). Updates are broadcast via WebSocket at configurable intervals (default: 15 seconds) to reduce system load.

**Snort IDS Integration:** Integrates with Snort Intrusion Detection System to read alert logs from common locations (`/var/log/snort/alert`, `C:\\Snort\\log\\alert.ids`). Parses Snort alert format (SID, message, source IP, destination IP, timestamp) and broadcasts alerts via WebSocket for real-time threat display. Supports manual IP blocking through system firewall rules.

**IP Blocking Mechanism:** Implements IP address blocking functionality with persistent storage in SQLite database. Blocks suspicious IPs identified through Snort alerts, manual user actions, or automated threat intelligence. Integration with system firewall (Windows Firewall, iptables on Linux) for enforcement.

## URL Filtering & Web Protection

**WebShield Risk Scoring:** Implements URL risk assessment algorithm that evaluates: domain reputation (TLD analysis, suspicious domain patterns), URL structure (path length, parameter count, encoding patterns), keyword detection (phishing terms, scam indicators, malware-related strings), and IP address resolution for reputation checks.

**Automatic Blocking:** Automatically blocks URLs with risk score > 0.5 (configurable threshold) and integrates with cloud threat intelligence (VirusTotal URL reputation API). Maintains blocked URL list in database with timestamp, category, and action taken. Supports OS-level URL blocking (hosts file modification) for persistent protection.

**Real-Time URL Analysis:** Performs on-demand URL scanning via `/api/scan/url` endpoint, checks against blocked URL database, queries cloud APIs for reputation, and generates risk score (0.0-1.0) with category classification (phishing, malware, scam, suspicious). Broadcasts WebShield alerts via WebSocket for immediate user notification.

## Threat Reporting & Logging

**Periodic Threat Aggregation:** Aggregates detected threats at configurable intervals (default: 1 minute) and reports via WebSocket `scan_event` messages. Tracks threats since last report, maintains recent threats list (last 30 threats, 7-day retention), and provides scan progress updates (files scanned, current path, session statistics).

**Comprehensive Audit Logging:** Maintains activity logs in SQLite database with severity levels (INFO, WARN, ERROR, CRITICAL), timestamps, and event descriptions. Logs include: threat detections, quarantine actions, deletion operations, network blocks, URL blocks, sandbox analysis results, and system configuration changes. Supports log export functionality for external analysis.

**Report Generation:** Generates comprehensive security reports including: system overview metrics, threat statistics, scan history, network activity summary, quarantined files list, and action history. Reports are downloadable in text format via `/api/logs/report-summary` endpoint for compliance and forensic analysis.

