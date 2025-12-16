# AI-Powered Antivirus - Backend Documentation

## Overview

The AI-Powered Antivirus backend is built with **FastAPI** (Python) and provides a comprehensive REST API and WebSocket server for real-time threat detection, file analysis, network monitoring, and security management.

## Architecture

```
┌─────────────────────────────────────────┐
│         FastAPI Application              │
│  ┌──────────┐  ┌──────────┐            │
│  │ REST API │  │ WebSocket│            │
│  └──────────┘  └──────────┘            │
│  ┌──────────┐  ┌──────────┐            │
│  │ Routers  │  │ Services │            │
│  └──────────┘  └──────────┘            │
└─────────────────────────────────────────┘
            ↕
┌─────────────────────────────────────────┐
│         Security Services               │
│  • Anomaly Detection (ML)              │
│  • Cloud Protection                     │
│  • Sandbox Analysis                     │
│  • WebShield (URL Filtering)           │
│  • Snort IDS Integration                │
│  • Threat Actions (Quarantine/Delete)  │
│  • Background Scanner                   │
└─────────────────────────────────────────┘
            ↕
┌─────────────────────────────────────────┐
│         SQLite Database                 │
│  • Threats                              │
│  • Scan Jobs                            │
│  • Blocked URLs                         │
│  • Allowed Files                        │
└─────────────────────────────────────────┘
```

## Core Services

### 1. Anomaly Detection Service (`services/anomaly.py`)

**Purpose**: ML-based file anomaly detection using Isolation Forest algorithm.

**Workflow**:
1. Extract file features (entropy, file type, size, etc.)
2. Scale features using pre-trained scaler
3. Score file using Isolation Forest model
4. Return verdict: `benign`, `suspicious`, or `malicious`

**Key Functions**:
- `score_file(file_path: str) -> Dict`: Scores a file and returns anomaly score
- `_extract_features(data: bytes, file_path: str) -> List[float]`: Extracts ML features
- `_entropy(data: bytes) -> float`: Calculates file entropy

**Configuration**:
- Model file: `services/model.pkl`
- Scaler file: `services/scaler.pkl`
- Feature definitions: `services/feature_names.json`

### 2. Cloud Protection Service (`services/cloud_protection.py`)

**Purpose**: Cloud-delivered threat intelligence and automatic sample submission.

**Features**:
- File hash reputation checks (VirusTotal)
- URL reputation checks (VirusTotal)
- IP address reputation checks
- Automatic threat sample submission
- Caching for performance

**Workflow**:
1. Check file hash/URL/IP against cloud services
2. Cache results for 24 hours
3. Auto-submit samples if enabled
4. Return reputation score and verdict

**Key Functions**:
- `check_file_reputation(file_hash: str) -> Dict`: Check file hash
- `check_url_reputation(url: str) -> Dict`: Check URL reputation
- `check_ip_reputation(ip: str) -> Dict`: Check IP reputation
- `submit_threat_sample(file_path: str) -> Dict`: Submit file to cloud services

**Configuration**:
- `VIRUSTOTAL_API_KEY`: VirusTotal API key (required)
- `AUTO_SUBMIT_ENABLED`: Auto-submit samples (default: False)
- `AUTO_SUBMIT_MAX_SIZE`: Max file size for auto-submit (default: 10MB)

### 3. Sandbox Service (`services/sandbox.py`)

**Purpose**: Simulated file execution environment for behavior analysis.

**Workflow**:
1. Analyze file type and structure
2. Simulate execution behavior
3. Track system calls and operations
4. Generate verdict based on behavior

**Key Functions**:
- `analyze_file(file_path: str) -> Dict`: Analyze file in sandbox
- `_simulate_execution(data: bytes, file_type: str) -> List[str]`: Simulate execution

**Features**:
- PE (Windows executable) analysis
- ELF (Linux executable) analysis
- PDF analysis
- ZIP archive analysis
- System call tracking

### 4. WebShield Service (`services/webshield.py`)

**Purpose**: URL filtering and risk assessment.

**Workflow**:
1. Extract host and base URL from input
2. Score URL based on patterns and heuristics
3. Check against cloud reputation services
4. Auto-block if score exceeds threshold
5. Update OS hosts file if blocking enabled

**Key Functions**:
- `score_url(url: str) -> Dict`: Score URL risk
- `check_and_block_url(url: str, auto_block_threshold: float) -> Dict`: Check and block URL
- `block_url(url: str, force: bool) -> Dict`: Block URL in OS hosts file

**Scoring Factors**:
- Suspicious TLDs
- IP addresses in URL
- Suspicious keywords
- URL length and structure
- Cloud reputation

### 5. Background Scanner Service (`services/background.py`)

**Purpose**: Continuous file system monitoring and scanning.

**Features**:
- Real-time file system event monitoring (Watchdog)
- Continuous full directory scanning
- Periodic threat reporting
- Progress tracking via WebSocket
- Configurable scan intervals

**Workflow**:
1. Monitor file system events (create, modify, move)
2. Schedule delayed scans to avoid duplicates
3. Perform continuous full scans of monitored paths
4. Aggregate threats and report at intervals
5. Broadcast progress and threats via WebSocket

**Key Functions**:
- `start_monitoring(paths: List[str], scan_callback, threat_report_interval: float)`: Start monitoring
- `stop_monitoring()`: Stop monitoring
- `_scan_file(file_path: str) -> Dict`: Scan a single file
- `_report_threats()`: Aggregate and report threats

**Configuration**:
- `BACKGROUND_SCAN_THREAT_REPORT_INTERVAL`: Threat report interval in minutes (default: 1)
- `scan_delay`: Delay between file scans (default: 1.0 seconds)

**Python 3.13 Compatibility**:
- Handles `watchdog` library incompatibility gracefully
- Falls back to continuous scanning if real-time monitoring fails

### 6. Threat Actions Service (`services/threat_actions.py`)

**Purpose**: File quarantine and deletion operations.

#### Quarantine Workflow

1. **Primary Method** (quarantine_manager.py):
   - Move file to `~/.quarantine/` directory
   - Compute SHA256 hash
   - Obfuscate filename: `{timestamp}_{hash_prefix}_{original_name}.quarantine`
   - Lock file permissions (Windows: icacls, POSIX: chmod/chattr)
   - Store metadata in SQLite database (`~/.quarantine/quarantine.db`)
   - Update threat record in main database

2. **Fallback Method**:
   - Move file to `backend/quarantine/` directory
   - Generate obfuscated filename
   - Set restrictive permissions
   - Create metadata JSON file

**Key Functions**:
- `quarantine_file(threat: Threat) -> bool`: Quarantine a threat file
- `restore_quarantined_file(quarantined_filename: str) -> bool`: Restore quarantined file
- `list_quarantined_files() -> List[Dict]`: List all quarantined files
- `restrict_anomaly_file_permissions(file_path: str, level: str) -> Dict`: Restrict permissions without quarantining

**Permission Levels**:
- `standard`: Read-only, no execute
- `moderate`: Read-only with minimal restrictions
- `strict`: No permissions at all (maximum security)

#### Deletion Workflow

Uses `delete_anomalies_service.py` which:
1. Attempts Python deletion methods (send2trash, os.remove)
2. Falls back to Windows shell scripts (PowerShell, batch)
3. Requests admin elevation if needed
4. Moves to Recycle Bin on Windows (default)
5. Permanently deletes on Linux/macOS

**Key Functions**:
- `delete_file(threat: Threat, use_recycle_bin: bool) -> Optional[Threat]`: Delete threat file
- `_delete_to_recycle_bin(file_path: Path) -> bool`: Move to Recycle Bin (Windows)
- `_permanently_delete_file(file_path: Path) -> bool`: Permanently delete file

### 7. Deletion Service (`services/deletion/`)

**Purpose**: Enhanced file deletion with admin authorization and multiple methods.

**Scripts**:
- `delete_anomalies.py`: Main deletion script with admin elevation
- `delete_file.ps1`: PowerShell script for Windows
- `delete_file.bat`: Batch script for Windows
- `secure_delete_ps.ps1`: Secure deletion using sdelete.exe (Sysinternals)
- `delete_safe.py`: Safe deletion using send2trash

**Deletion Methods** (in order of preference):
1. Python direct methods (send2trash, os.remove)
2. Windows PowerShell script
3. Windows batch script
4. Python executor with admin elevation
5. OS-specific commands (takeown, icacls, sudo rm)

**Secure Deletion**:
- Uses `sdelete.exe` from Sysinternals Suite
- Overwrites files before deletion (configurable passes)
- Enabled via `secure_delete=True` parameter

**Key Functions** (via `delete_anomalies_service.py`):
- `delete_anomaly_files(threat_ids, file_paths, secure_delete=False) -> Dict`: Delete multiple files
- `delete_anomaly_file_simple(threat_id, file_path, secure_delete=False) -> Dict`: Delete single file

### 8. Quarantine Manager (`services/quarantine/quarantine_manager.py`)

**Purpose**: Comprehensive quarantine management with SQLite tracking.

**Features**:
- SQLite database for persistent tracking
- SHA256 hash computation
- Filename obfuscation
- Permission locking (OS-level)
- Metadata storage
- Restore and purge capabilities
- Action history tracking

**Database Schema**:
```sql
CREATE TABLE items (
    id INTEGER PRIMARY KEY,
    stored_name TEXT,
    original_path TEXT,
    sha256 TEXT,
    size INTEGER,
    user TEXT,
    timestamp TEXT,
    reason TEXT,
    state TEXT,
    threat_id INTEGER,
    metadata TEXT
)
```

**Key Functions**:
- `quarantine(path_str, reason, threat_id, metadata) -> Dict`: Quarantine a file
- `restore(stored_name, restore_path) -> bool`: Restore quarantined file
- `purge(stored_name, force) -> bool`: Permanently delete quarantined file
- `list_quarantined() -> List[Dict]`: List all quarantined items

## API Endpoints

### Threat Management

#### `POST /api/threats/bulk-action`
Bulk actions on threats (delete, quarantine, allow).

**Request**:
```json
{
  "ids": [1, 2, 3],
  "action": "delete" | "quarantine" | "allow"
}
```

**Response**:
```json
{
  "ok": true,
  "updated": 2,
  "deleted_ids": [1, 2],
  "status": "delete",
  "message": "Processed 3 threat(s): 2 updated, 2 deleted"
}
```

#### `GET /api/threats`
List threats with pagination.

**Query Parameters**:
- `limit`: Maximum number of threats (default: 50)
- `offset`: Pagination offset (default: 0)

#### `GET /api/threats/{tid}/analyze`
Comprehensive threat analysis.

**Response**:
```json
{
  "threat_id": 1,
  "severity": "high",
  "location": {...},
  "signature": {...},
  "behavior": {...}
}
```

### Threat Actions

#### `POST /api/threats/actions/quarantine`
Quarantine a threat file.

**Request**:
```json
{
  "threat_id": 1
}
```

#### `POST /api/threats/actions/restore`
Restore a quarantined file.

**Request**:
```json
{
  "quarantined_filename": "Qa3f2b1c_1704067200.quarantine",
  "restore_path": "C:/path/to/restore"
}
```

#### `POST /api/threats/actions/delete`
Delete a threat file.

**Request**:
```json
{
  "threat_id": 1,
  "use_recycle_bin": true
}
```

#### `POST /api/threats/actions/restrict-permissions`
Restrict permissions on a file without quarantining.

**Request**:
```json
{
  "file_path": "C:/path/to/file.exe",
  "level": "standard" | "moderate" | "strict"
}
```

#### `GET /api/threat-actions/quarantined`
List all quarantined files.

**Response**:
```json
[
  {
    "stored_name": "Qa3f2b1c_1704067200.quarantine",
    "original_path": "C:/path/to/file.exe",
    "quarantine_timestamp": "2024-01-01T12:00:00",
    "file_size": 1024,
    "actions": [...]
  }
]
```

### File Scanning

#### `POST /api/scan/file`
Upload and scan a file.

**Request**: Multipart form data with `file` field

**Response**:
```json
{
  "verdict": "suspicious",
  "risk": 0.75,
  "features": {...}
}
```

#### `POST /api/scan/url`
Scan a URL for threats.

**Request**:
```json
{
  "url": "https://example.com"
}
```

### Sandbox Analysis

#### `POST /api/sandbox/analyze`
Submit file for sandbox analysis.

**Request**: Multipart form data with `file` field

**Response**:
```json
{
  "job_id": "abc123",
  "status": "queued"
}
```

#### `GET /api/sandbox/jobs`
List sandbox analysis jobs (filtered to show only anomalies).

**Query Parameters**:
- `limit`: Maximum number of jobs (default: 50)

### Background Scanner

#### `POST /api/scanner/start`
Start background scanning.

**Request**:
```json
{
  "paths": ["C:/Users", "D:/Downloads"],
  "threat_report_interval": 1.0
}
```

#### `POST /api/scanner/stop`
Stop background scanning.

#### `GET /api/scanner/status`
Get scanner status and progress.

### Cloud Protection

#### `GET /api/cloud-protection/status`
Get cloud protection status.

#### `POST /api/cloud-protection/check-file`
Check file hash reputation.

**Request**:
```json
{
  "file_hash": "abc123..."
}
```

#### `POST /api/cloud-protection/check-url`
Check URL reputation.

**Request**:
```json
{
  "url": "https://example.com"
}
```

#### `POST /api/cloud-protection/submit-sample`
Submit file sample to cloud services.

**Request**: Multipart form data with `file` field

#### `POST /api/cloud-protection/auto-submit/enable`
Enable automatic sample submission.

#### `POST /api/cloud-protection/auto-submit/disable`
Disable automatic sample submission.

## WebSocket Events

### Connection
- **Endpoint**: `/ws`
- **Protocol**: JSON messages

### Event Types

#### `threat_detected`
New threat detected.

```json
{
  "type": "threat_detected",
  "id": 1,
  "filePath": "C:/path/to/file.exe",
  "severity": "high",
  "source": "ML Detection"
}
```

#### `threat_updated`
Threat status updated.

```json
{
  "type": "threat_updated",
  "id": 1,
  "action": "quarantined"
}
```

#### `threat_deleted`
Threat deleted.

```json
{
  "type": "threat_deleted",
  "id": 1,
  "method": "delete_anomalies_script"
}
```

#### `scan_progress`
Background scan progress update.

```json
{
  "type": "scan_progress",
  "current_path": "C:/Users/file.txt",
  "files_scanned": 100,
  "timestamp": "2024-01-01T12:00:00"
}
```

#### `threat_report`
Periodic threat report.

```json
{
  "type": "threat_report",
  "interval_minutes": 1,
  "threats_count": 5,
  "threats": [...],
  "timestamp": "2024-01-01T12:00:00"
}
```

#### `scan_status`
Scanner status update.

```json
{
  "type": "scan_status",
  "enabled": true,
  "paths": ["C:/Users"]
}
```

## Database Schema

### Threats Table
```sql
CREATE TABLE threat (
    id INTEGER PRIMARY KEY,
    filePath TEXT,
    severity TEXT,
    source TEXT,
    description TEXT,
    action TEXT,
    time DATETIME
)
```

### Scan Jobs Table
```sql
CREATE TABLE scanjob (
    id TEXT PRIMARY KEY,
    file_path TEXT,
    status TEXT,
    progress INTEGER,
    verdict TEXT,
    score REAL,
    error TEXT,
    created DATETIME
)
```

### Blocked URLs Table
```sql
CREATE TABLE blockedurl (
    id INTEGER PRIMARY KEY,
    url TEXT,
    score REAL,
    category TEXT,
    os_blocked BOOLEAN,
    created DATETIME
)
```

## Configuration

### Environment Variables

- `FRONTEND_ORIGIN`: Frontend URL for CORS (default: `http://localhost:3000`)
- `BACKGROUND_SCAN_THREAT_REPORT_INTERVAL`: Threat report interval in minutes (default: 1)
- `VIRUSTOTAL_API_KEY`: VirusTotal API key for cloud protection
- `AUTO_SUBMIT_ENABLED`: Enable automatic sample submission (default: False)
- `AUTO_SUBMIT_MAX_SIZE`: Max file size for auto-submit in bytes (default: 10485760)

### Auto-Quarantine

Enabled by default. Automatically quarantines threats detected by:
- ML anomaly detection
- Sandbox analysis
- Background scanner

## Recent Changes

### Enhanced Quarantine Algorithm
- Integrated `quarantine_manager.py` with SQLite tracking
- Filename obfuscation with timestamp and hash
- OS-level permission locking
- Action history tracking
- Restore and purge capabilities

### Enhanced Deletion Service
- Integrated `delete_anomalies.py` with admin authorization
- Windows shell scripts (PowerShell, batch) as primary methods
- Recycle Bin support (Windows)
- Secure deletion option (sdelete.exe)
- Multiple fallback methods

### Continuous Background Scanning
- Real-time file system monitoring (Watchdog)
- Continuous full directory scanning
- Periodic threat reporting (configurable interval)
- Progress tracking via WebSocket
- Python 3.13 compatibility handling

### Cloud-Delivered Protection
- VirusTotal integration for file/URL/IP reputation
- Automatic sample submission
- Caching for performance
- Configurable auto-submission

### Manual Permission Restriction
- Restrict file permissions without quarantining
- Three levels: standard, moderate, strict
- OS-level permission manipulation

## File Organization

```
backend/
├── app/
│   ├── main.py                 # FastAPI application
│   ├── store.py                # Database models and operations
│   ├── routers/                 # API route modules
│   │   ├── anomaly.py
│   │   ├── cloud_protection.py
│   │   ├── sandbox.py
│   │   ├── scanner.py
│   │   ├── snort.py
│   │   ├── threat_actions.py
│   │   └── webshield.py
│   └── services/                # Core service modules
│       ├── anomaly.py
│       ├── background.py
│       ├── cloud_protection.py
│       ├── delete_anomalies_service.py
│       ├── sandbox.py
│       ├── snort.py
│       ├── threat_actions.py
│       ├── webshield.py
│       ├── deletion/            # Deletion scripts
│       │   ├── delete_anomalies.py
│       │   ├── delete_file.ps1
│       │   ├── delete_file.bat
│       │   └── secure_delete_ps.ps1
│       └── quarantine/          # Quarantine scripts
│           ├── quarantine_manager.py
│           └── quarantine_algorithm.py
├── requirements.txt
└── run.py
```

## Troubleshooting

### Quarantine Not Working
- Check `~/.quarantine/` directory permissions
- Verify SQLite database is writable
- Check admin privileges for permission locking
- Review backend logs for errors

### Deletion Not Working
- Check file permissions
- Verify admin privileges if needed
- Check `delete_log.txt` for errors
- Ensure shell scripts are executable

### Background Scanner Not Working
- Check Python version (3.13 has watchdog issues)
- Verify monitored paths exist
- Check WebSocket connection
- Review scanner status endpoint

### Cloud Protection Not Working
- Verify VirusTotal API key is set
- Check internet connectivity
- Review API rate limits
- Check cache directory permissions


