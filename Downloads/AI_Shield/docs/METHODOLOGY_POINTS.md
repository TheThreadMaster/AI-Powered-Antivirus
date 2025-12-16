# AI Shield - Methodology (Bullet Points)

## Real-Time Monitoring Framework

- **File System Monitoring:** Implements dynamic file system event monitoring using `watchdog` library (`watchdog.observers.Observer` and `watchdog.events.FileSystemEventHandler`) to track file creation, modification, and movement events in real-time with a 1-second scan delay to prevent duplicate scans of rapidly changing files.

- **Resource Tracking:** Implements system resource monitoring framework using `psutil` library for tracking CPU usage, memory consumption, disk I/O, and network bandwidth at 1-second intervals via WebSocket connections, broadcasting metrics to the frontend dashboard for real-time visualization.

- **Continuous Background Scanning:** Performs continuous full-filesystem scans in addition to event-driven monitoring, with configurable threat report intervals (default: 1 minute via `BACKGROUND_SCAN_THREAT_REPORT_INTERVAL` environment variable), scanning files up to 100MB and maintaining a cache of recently scanned files (last 3000 entries).

## Anomaly Detection Algorithm

- **Isolation Forest ML Model:** Uses scikit-learn's Isolation Forest algorithm (n_estimators=200, contamination=0.1) for statistical anomaly identification, extracting 11 features: logarithmic file size, entropy, non-ASCII ratio, printable character ratio, PE/ELF/PDF/ZIP magic byte detection, script/image type detection, and suspicious string pattern hits.

- **Anomaly Score Calculation:** Normalizes Isolation Forest output using logistic function `anomaly_score = 1.0 / (1.0 + exp(score_samples))` to convert decision function values to a 0-1 scale (higher = more anomalous), applying type-aware damping: images receive 0.3x multiplier, PDFs receive 0.5x multiplier, executables receive 1.1x multiplier boost.

- **Feature Extraction:** Analyzes file headers (first 32 bytes) for magic byte detection, reads 256KB sample for content analysis, detects suspicious strings (Windows API calls, PowerShell obfuscation, command execution patterns), and performs PE import/export analysis for packed executables.

## Threat Detection Logic

- **File Modification Rate Monitoring:** Tracks file modification events through watchdog's `on_modified()` handler with 1-second scan delay to aggregate rapid changes, effectively identifying suspicious file activity patterns that could indicate ransomware behavior through continuous scanning and anomaly scoring.

- **Risk Threshold Classification:** Classifies files as "malicious" if anomaly score > 0.7 or risk score > 0.8, "suspicious" if anomaly score > 0.5 or risk score > 0.6, and "benign" otherwise, considering ML anomaly score, heuristic risk indicators, suspicious string hits, file type mismatches, and PE/script characteristics.

- **Cloud Intelligence Integration:** Enhances local detection with cloud-delivered threat intelligence via VirusTotal API (file hash reputation checks) and Hybrid Analysis API (sample submission and analysis), with automatic sample submission enabled by default for detected threats.

## Behavioral Analysis Framework

- **Sandbox Execution Simulation:** Performs context-aware behavioral analysis in an isolated sandbox environment (post-quarantine) using file type detection, simulating system calls (CreateFile, ReadFile, WriteFile, CreateProcess), registry modifications, and network activity tracking to generate verdicts (benign, suspicious, malicious).

- **Post-Quarantine Analysis:** Reserves detailed TTP (Tactics, Techniques, and Procedures) observation for quarantined files in a secure, isolated environment, performing behavioral analysis after quarantine to prevent execution while allowing safe inspection of system calls, registry access, and network activity.

- **System Call Analysis:** Tracks simulated system calls for executables and scripts including file operations, process creation, registry access patterns, and network connection attempts, generating analysis results with syscall list, registry modification attempts, network activity indicators, and behavioral verdict score.

## Automated Response System

- **Quarantine Algorithm:** Implements multi-step quarantine process: (1) Move file to `~/.quarantine` directory with obfuscated name `YYYYMMDDTHHMMSS_{hash12}_{original_name}.quarantine`, (2) Compute SHA256 hash, (3) Lock permissions using OS-level commands (Windows: `icacls /deny`, Linux: `chmod 0` + `chattr +i`), (4) Store metadata in SQLite database.

- **File Deletion Service:** Implements multi-method deletion approach: (1) Primary: `send2trash` for cross-platform safe deletion, (2) Fallback: Direct `os.remove()` with permission fixes, (3) Windows-specific: PowerShell `Remove-Item`, batch scripts, `takeown` + `icacls`, (4) Linux/macOS: `sudo rm -f` with chmod fixes, including admin privilege elevation when required.

- **Permission Restriction Levels:** Provides three levels of manual permission restriction: Standard (remove write), Moderate (remove read/write), Strict (remove all permissions), applying restrictions using OS-native commands with admin elevation when necessary.

## Network Monitoring & Intrusion Detection

- **Connection Tracking:** Monitors active network connections using system APIs, tracking process identification (PID, process name), remote IP addresses and ports, and data transfer rates, broadcasting updates via WebSocket at configurable intervals (default: 15 seconds).

- **Snort IDS Integration:** Integrates with Snort Intrusion Detection System to read alert logs from common locations, parsing Snort alert format (SID, message, source IP, destination IP, timestamp) and broadcasting alerts via WebSocket for real-time threat display with manual IP blocking support.

- **IP Blocking Mechanism:** Implements IP address blocking functionality with persistent storage in SQLite database, blocking suspicious IPs identified through Snort alerts, manual user actions, or automated threat intelligence, with integration to system firewall for enforcement.

## URL Filtering & Web Protection

- **WebShield Risk Scoring:** Implements URL risk assessment algorithm evaluating domain reputation (TLD analysis, suspicious patterns), URL structure (path length, parameter count, encoding), keyword detection (phishing terms, scam indicators), and IP address resolution for reputation checks.

- **Automatic Blocking:** Automatically blocks URLs with risk score > 0.5 (configurable threshold), integrating with cloud threat intelligence (VirusTotal URL reputation API), maintaining blocked URL list in database with timestamp, category, and action taken, supporting OS-level URL blocking (hosts file modification).

- **Real-Time URL Analysis:** Performs on-demand URL scanning, checks against blocked URL database, queries cloud APIs for reputation, generates risk score (0.0-1.0) with category classification (phishing, malware, scam, suspicious), and broadcasts WebShield alerts via WebSocket for immediate notification.

## Threat Reporting & Logging

- **Periodic Threat Aggregation:** Aggregates detected threats at configurable intervals (default: 1 minute), reporting via WebSocket `scan_event` messages, tracking threats since last report, maintaining recent threats list (last 30 threats, 7-day retention), and providing scan progress updates.

- **Comprehensive Audit Logging:** Maintains activity logs in SQLite database with severity levels (INFO, WARN, ERROR, CRITICAL), timestamps, and event descriptions, logging threat detections, quarantine actions, deletion operations, network blocks, URL blocks, sandbox analysis results, and system configuration changes.

- **Report Generation:** Generates comprehensive security reports including system overview metrics, threat statistics, scan history, network activity summary, quarantined files list, and action history, downloadable in text format via `/api/logs/report-summary` endpoint for compliance and forensic analysis.

