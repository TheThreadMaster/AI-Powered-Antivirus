# AI-Powered Antivirus - Frontend Documentation

## Overview

The AI-Powered Antivirus frontend is built with **Next.js 16** (React 19) and TypeScript, providing a modern, responsive dashboard for real-time threat monitoring and security management.

## Architecture

```
┌─────────────────────────────────────────┐
│         Next.js 16 Application         │
│  ┌──────────┐  ┌──────────┐           │
│  │   UI     │  │  Store   │           │
│  │ (React)  │  │(Zustand) │           │
│  └──────────┘  └──────────┘           │
│  ┌──────────┐  ┌──────────┐           │
│  │   SWR    │  │    WS    │           │
│  │ (Fetch)  │  │ (Client) │           │
│  └──────────┘  └──────────┘           │
└─────────────────────────────────────────┘
            ↕ HTTP/WebSocket
┌─────────────────────────────────────────┐
│         Backend API                     │
│  • REST Endpoints                       │
│  • WebSocket Server                     │
└─────────────────────────────────────────┘
```

## Technology Stack

- **Framework**: Next.js 16 (App Router)
- **Language**: TypeScript
- **UI Library**: React 19
- **State Management**: Zustand
- **Data Fetching**: SWR (stale-while-revalidate)
- **Styling**: Tailwind CSS
- **Components**: shadcn/ui
- **WebSocket**: Custom WebSocket client
- **Icons**: Lucide React

## Core Features

### 1. Overview Dashboard (`features/overview/OverviewCards.tsx`)

**Purpose**: High-level security metrics and status.

**Components**:
- Threat Level Gauge
- Active Threats Count
- Files Scanned Counter
- Network Alerts Count
- Protection Status (Scan, WebShield, Snort)

**Data Source**: `/api/overview` endpoint

**Updates**: Real-time via WebSocket

### 2. Threat Feed (`features/threats/ThreatFeed.tsx`)

**Purpose**: Real-time display of detected threats.

**Features**:
- Real-time threat updates (5-second refresh)
- Threat severity indicators
- Individual threat actions (Delete, Quarantine, Restrict Permissions, Analyze)
- Bulk actions (Delete, Quarantine)
- Threat analysis dialog
- Confidence scores

**Actions**:
- **Delete**: Calls `/api/threats/bulk-action` with `action: "delete"`
- **Quarantine**: Calls `/api/threats/bulk-action` with `action: "quarantine"`
- **Restrict Permissions**: Calls `/api/threats/actions/restrict-permissions`
- **Analyze**: Calls `/api/threats/{id}/analyze`

**Data Source**: `/api/threats?limit=50` (SWR with 5s refresh)

### 3. Threat Management Center (`features/management/ThreatManagementCenter.tsx`)

**Purpose**: Comprehensive threat management interface.

**Features**:
- Table view of all threats
- Row selection for bulk operations
- Threat details dialog
- Bulk actions (Delete, Quarantine, Restrict Permissions)
- Threat filtering and sorting
- Threat history

**Actions**:
- Bulk delete/quarantine via `/api/threats/bulk-action`
- Individual threat management
- Permission restriction with level selection

### 4. Manual Scanner (`features/scanner/ManualScanner.tsx`)

**Purpose**: Manual file upload and scanning.

**Features**:
- File upload (drag & drop or file picker)
- Directory selection (File System Access API)
- Scan history with persistent storage
- Threat detection and display
- Delete and quarantine buttons for detected threats
- Scan progress indication

**Workflow**:
1. User selects file or directory
2. Files uploaded to `/api/scan/file`
3. Scan results displayed
4. Threats can be deleted or quarantined
5. History stored in browser localStorage

**Actions**:
- **Delete Threat**: Calls `/api/threats/bulk-action` with `action: "delete"`
- **Quarantine Threat**: Calls `/api/threats/bulk-action` with `action: "quarantine"`

### 5. Background Scanner Panel (`features/scanner/BackgroundScannerPanel.tsx`)

**Purpose**: Background scanning configuration and monitoring.

**Features**:
- Start/stop background scanning
- Add/remove monitored paths
- Configure threat report interval (default: 1 minute)
- Real-time scan progress display
- Progress animation
- Next report countdown timer
- Files scanned counter

**Configuration**:
- **Threat Report Interval**: Configurable in minutes (1-1440)
- **Monitored Paths**: Add/remove directories
- **Auto-Quarantine**: Toggle automatic quarantine

**Data Source**: 
- `/api/scanner/status` (SWR with 3s refresh)
- WebSocket events: `scan_progress`, `threat_report`, `scan_status`

### 6. Sandbox Panel (`features/sandbox/SandboxPanel.tsx`)

**Purpose**: Sandbox analysis results and quarantined files management.

**Features**:
- Sandbox analysis job list (filtered to show only anomalies)
- Job status and progress
- Verdict and score display
- System calls visualization
- **Quarantine Section**:
  - List of all quarantined files
  - Original path and quarantine timestamp
  - File size and metadata
  - Action history
  - Restore button

**Data Sources**:
- `/api/sandbox/jobs` (SWR with 3s refresh) - Shows only anomalies
- `/api/threat-actions/quarantined` (SWR with 3s refresh) - Quarantined files

**Actions**:
- **Restore**: Calls `/api/threat-actions/restore`

**Filtering**:
- Only displays jobs with:
  - Suspicious or malicious verdicts
  - Score > 0.5
  - Active status (running/pending/queued)

### 7. Network Panel (`features/network/NetworkPanel.tsx`)

**Purpose**: Network connection monitoring.

**Features**:
- Active network connections list
- Process name, PID, remote address
- Data transfer rates
- Connection filtering

**Data Source**: `/api/network/connections` (SWR with 15s refresh)

**Updates**: Real-time via WebSocket `connection_update` events

### 8. WebShield Panel (`features/webshield/WebShieldPanel.tsx`)

**Purpose**: URL filtering and blocking management.

**Features**:
- Blocked URLs list
- URL risk scoring
- Manual URL blocking
- WebShield toggle (enable/disable)
- Auto-block threshold configuration

**Actions**:
- **Block URL**: Calls `/api/network/webshield/block`
- **Toggle WebShield**: Calls `/api/network/webshield/toggle`
- **Unblock URL**: Calls `/api/webshield/blocked/{id}` (DELETE)

**Data Source**: `/api/network/webshield/blocked` (SWR)

### 9. Cloud Protection Panel (`features/cloud/CloudProtectionPanel.tsx`)

**Purpose**: Cloud-delivered protection management.

**Features**:
- Cloud protection status
- Statistics (files checked, URLs checked, IPs checked)
- Cache management
- Auto-submit samples toggle
- Submission statistics

**Actions**:
- **Toggle Cloud Protection**: Calls `/api/cloud-protection/toggle`
- **Clear Cache**: Calls `/api/cloud-protection/clear-cache`
- **Enable Auto-Submit**: Calls `/api/cloud-protection/auto-submit/enable`
- **Disable Auto-Submit**: Calls `/api/cloud-protection/auto-submit/disable`

**Data Source**: `/api/cloud-protection/status` (SWR)

### 10. Activity Audit Logs (`features/logs/ActivityAuditLogs.tsx`)

**Purpose**: System activity and audit trail.

**Features**:
- Log level filtering (info, warning, error)
- Timestamp display
- Log message display
- Auto-scroll to latest

**Data Source**: Zustand store (`logs` array)

**Updates**: Real-time via WebSocket and store updates

### 11. System Charts (`features/resources/SystemCharts.tsx`)

**Purpose**: System resource monitoring.

**Features**:
- CPU usage chart
- Memory usage chart
- Disk usage chart
- Network traffic chart
- 24-hour historical data

**Data Source**: `/api/metrics` (SWR with 2s refresh)

**Updates**: Real-time via WebSocket `metrics` events

### 12. Settings Panel (`features/settings/SettingsPanel.tsx`)

**Purpose**: Application settings and configuration.

**Features**:
- Theme toggle (light/dark)
- Protection toggles
- Scanner configuration
- General settings

## State Management (Zustand)

### Store Structure (`store/app-store.ts`)

```typescript
interface AppState {
  wsStatus: "connecting" | "open" | "closed" | "error"
  overview: {
    threatLevel: number
    threatIndex: number
    activeThreats: number
    filesScanned: number
    networkAlerts: number
    protection: {
      scan: boolean
      webshield: boolean
      snort: boolean
    }
  }
  threats: ThreatItem[]
  metrics: SystemMetricsPoint[]
  blockedUrls: string[]
  connections: ConnectionItem[]
  snortAlerts: SnortAlert[]
  webshieldAlerts: WebShieldAlert[]
  scanStatus?: ScanStatus
  scanProgress?: ScanProgress
  threatReports: ThreatReport[]
  sandboxJobs: SandboxJob[]
  logs: LogItem[]
  selectedFile: File | null
  actions: {
    quarantine: (ids: number[]) => void
    delete: (ids: number[]) => void
    allow: (ids: number[]) => void
  }
}
```

### Actions

- `quarantine(ids)`: Mark threats as quarantined in store
- `delete(ids)`: Remove threats from store
- `allow(ids)`: Mark threats as allowed in store

## WebSocket Integration

### Connection (`lib/ws.ts`)

**Hook**: `useRealtime()`

**Features**:
- Automatic reconnection
- Event type handling
- Store updates
- Connection status tracking

### Event Handlers

- `threat_detected`: Add to threats array
- `threat_updated`: Update threat in array
- `threat_deleted`: Remove from threats array
- `scan_progress`: Update scan progress
- `threat_report`: Add to threat reports
- `scan_status`: Update scan status
- `metrics`: Update metrics array
- `connection_update`: Update connections array
- `snort_alert`: Add to snort alerts
- `webshield_alert`: Add to webshield alerts

## API Integration

### API Client (`lib/api.ts`)

**Base URL**: `http://localhost:8000`

**Methods**:
- `get(url, config)`: GET request
- `post(url, data, config)`: POST request
- `delete(url, config)`: DELETE request

**Features**:
- Automatic error handling
- Toast notifications for errors
- Request/response interceptors

### SWR Configuration

**Default Settings**:
- `refreshInterval`: Varies by component (3s-15s)
- `revalidateOnFocus`: true (most components)
- `revalidateOnReconnect`: true
- `dedupingInterval`: 1s-5s

## Component Structure

```
frontend/src/
├── app/
│   ├── layout.tsx              # Root layout
│   ├── page.tsx               # Main dashboard page
│   └── globals.css            # Global styles
├── components/
│   ├── ui/                    # shadcn/ui components
│   │   ├── button.tsx
│   │   ├── card.tsx
│   │   ├── dialog.tsx
│   │   ├── table.tsx
│   │   └── ...
│   ├── RealtimeStatus.tsx     # WebSocket status indicator
│   └── theme-toggle.tsx       # Theme switcher
├── features/
│   ├── cloud/
│   │   └── CloudProtectionPanel.tsx
│   ├── gauge/
│   │   └── ThreatGauge.tsx
│   ├── logs/
│   │   └── ActivityAuditLogs.tsx
│   ├── management/
│   │   └── ThreatManagementCenter.tsx
│   ├── network/
│   │   └── NetworkPanel.tsx
│   ├── overview/
│   │   └── OverviewCards.tsx
│   ├── resources/
│   │   └── SystemCharts.tsx
│   ├── sandbox/
│   │   └── SandboxPanel.tsx
│   ├── scanner/
│   │   ├── BackgroundScannerPanel.tsx
│   │   └── ManualScanner.tsx
│   ├── settings/
│   │   └── SettingsPanel.tsx
│   ├── threats/
│   │   ├── ThreatAnalysisDialog.tsx
│   │   └── ThreatFeed.tsx
│   └── webshield/
│       └── WebShieldPanel.tsx
├── lib/
│   ├── api.ts                 # API client
│   ├── utils.ts              # Utility functions
│   └── ws.ts                 # WebSocket client
└── store/
    └── app-store.ts          # Zustand store
```

## UI/UX Features

### Design System
- **Theme**: Dark/light mode support
- **Style**: Glassmorphism with backdrop blur
- **Colors**: Custom color palette with dark/light variants
- **Typography**: Inter font family
- **Icons**: Lucide React icon library

### Responsive Design
- Mobile-first approach
- Breakpoints: sm, md, lg, xl
- Adaptive layouts for different screen sizes

### Animations
- Smooth transitions
- Loading spinners
- Progress indicators
- Hover effects

## Recent Changes

### Quarantine Integration
- Added quarantine section to Sandbox Panel
- Real-time quarantine list updates (3s refresh)
- Restore functionality
- Action history display

### Delete Integration
- All delete buttons use `/api/threats/bulk-action`
- Enhanced error handling
- Success/failure notifications
- File existence verification

### Manual Scanner Enhancements
- Added quarantine button
- Persistent scan history
- Improved error messages
- File deletion verification

### Background Scanner UI
- Progress animation
- Next report countdown
- Files scanned counter
- Configurable threat report interval

### Sandbox Filtering
- Only displays anomaly-related jobs
- Filters by verdict, score, and status
- Clear indication of anomaly focus

### Network Panel Optimization
- Reduced refresh interval (15s instead of 5s)
- Better performance with fewer updates

## API Endpoints Used

### Threat Management
- `GET /api/threats?limit=50` - List threats
- `POST /api/threats/bulk-action` - Bulk actions
- `GET /api/threats/{id}/analyze` - Threat analysis
- `POST /api/threats/actions/restrict-permissions` - Restrict permissions

### Scanning
- `POST /api/scan/file` - Upload and scan file
- `POST /api/scanner/start` - Start background scanner
- `POST /api/scanner/stop` - Stop background scanner
- `GET /api/scanner/status` - Scanner status

### Sandbox
- `GET /api/sandbox/jobs` - List sandbox jobs
- `GET /api/threat-actions/quarantined` - List quarantined files
- `POST /api/threat-actions/restore` - Restore quarantined file

### Network
- `GET /api/network/connections` - Network connections
- `GET /api/network/webshield/blocked` - Blocked URLs
- `POST /api/network/webshield/block` - Block URL
- `POST /api/network/webshield/toggle` - Toggle WebShield

### Cloud Protection
- `GET /api/cloud-protection/status` - Cloud protection status
- `POST /api/cloud-protection/auto-submit/enable` - Enable auto-submit
- `POST /api/cloud-protection/auto-submit/disable` - Disable auto-submit
- `POST /api/cloud-protection/clear-cache` - Clear cache

### System
- `GET /api/overview` - Overview metrics
- `GET /api/metrics` - System metrics

## Troubleshooting

### WebSocket Not Connecting
- Check backend is running on port 8000
- Verify CORS settings
- Check browser console for errors
- Verify WebSocket URL in `lib/ws.ts`

### Data Not Updating
- Check SWR refresh intervals
- Verify API endpoints are correct
- Check browser network tab
- Review Zustand store updates

### Quarantine List Not Showing
- Verify `/api/threat-actions/quarantined` endpoint
- Check SWR refresh interval (3s)
- Verify quarantine operations completed
- Check browser console for errors

### Delete Not Working
- Verify file paths are correct
- Check backend logs for errors
- Verify admin privileges if needed
- Check API response for error messages

### Background Scanner Not Showing Progress
- Verify WebSocket connection
- Check `/api/scanner/status` endpoint
- Verify scanner is running
- Check for WebSocket events in console


