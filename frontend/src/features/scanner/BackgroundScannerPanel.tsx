"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { api } from "@/lib/api"
import { useEffect, useState, useMemo, useRef } from "react"
import { useAppStore } from "@/store/app-store"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import useSWR from "swr"
import { fetcher } from "@/lib/api"
import { toast } from "sonner"
import InfoIcon from "@/components/InfoIcon"

type LiveScanStatus = {
  enabled: boolean
  paths: string[]
  recent_quarantine: string[]
  exclude_patterns?: string[]
  scan_delay?: number
  auto_quarantine?: boolean
  threat_report_interval?: number  // In minutes
  stats?: {
    files_scanned: number
    threats_found: number
    bytes_scanned: number
    uptime_seconds?: number
    scan_rate_per_second?: number
    last_scan_time?: number
  }
  recent_threats?: Array<{
    path: string
    verdict: string
    risk: number
    timestamp: string
    size: number
  }>
  scan_progress?: {
    is_scanning: boolean
    current_path?: string
    files_scanned_in_session: number
    session_start_time?: number
    threat_report_interval_minutes?: number
    next_report_in_seconds?: number
  }
}

export default function BackgroundScannerPanel() {
  const scanStatus = useAppStore((s) => s.scanStatus)
  const scanProgress = useAppStore((s) => s.scanProgress)
  const threatReports = useAppStore((s) => s.threatReports)
  const [status, setStatus] = useState<LiveScanStatus>({ enabled: true, paths: [], recent_quarantine: [], auto_quarantine: true, threat_report_interval: 1 })
  useEffect(() => {
    api.get("/api/scan/live/status")
      .then((res) => setStatus(res.data as LiveScanStatus))
      .catch(() => setStatus({ enabled: false, paths: [], recent_quarantine: [], auto_quarantine: false, threat_report_interval: 1 }))
  }, [])
  useSWR<LiveScanStatus>("/api/scan/live/status", fetcher, {
    refreshInterval: 5000, // Optimized for CPU
    onSuccess(data) {
      setStatus(data)
    },
  })
  const enabled = scanStatus?.enabled ?? status.enabled
  const paths = scanStatus?.paths ?? status.paths
  const setScanStatus = useAppStore((s) => s.actions.setScanStatus)
  
  // Show threat reports via toast when received (only show once per report)
  const lastReportTimestamp = useRef<string>("")
  useEffect(() => {
    if (threatReports.length > 0) {
      const latestReport = threatReports[0]
      if (latestReport.threats_count > 0 && latestReport.timestamp !== lastReportTimestamp.current) {
        lastReportTimestamp.current = latestReport.timestamp
        toast.warning(
          `Threat Report: ${latestReport.threats_count} threat(s) detected in the last ${latestReport.interval_minutes} minutes`,
          { duration: 10000 }
        )
      }
    }
  }, [threatReports])
  
  const toggle = async () => {
    const newEnabled = !enabled
    try {
      // Update protection state in store
      useAppStore.getState().actions.toggleProtection("scan", newEnabled)
      
      const res = await api.post("/api/scan/live/toggle", { enabled: newEnabled })
      const updatedStatus = res.data as LiveScanStatus
      setStatus(updatedStatus)
      setScanStatus({ enabled: updatedStatus.enabled, paths: updatedStatus.paths })
      
      // Also update via settings endpoint to keep protection state in sync
      await api.post("/api/settings/protection", { module: "scan", enabled: newEnabled })
      
      toast.success(`Background scanning ${newEnabled ? 'enabled' : 'disabled'}`)
    } catch (error: any) {
      // Revert on error
      useAppStore.getState().actions.toggleProtection("scan", enabled)
      console.error("Failed to toggle background scanning:", error)
      toast.error(error?.response?.data?.detail || "Failed to toggle background scanning")
    }
  }
  const addPath = async (path: string) => {
    const prev = status.paths
    setStatus((s) => ({ ...s, paths: [...s.paths, path] }))
    try {
      await api.post("/api/scan/live/add-path", { path })
    } catch {
      setStatus((s) => ({ ...s, paths: prev }))
    }
  }
  const removePath = async (path: string) => {
    const prev = status.paths
    setStatus((s) => ({ ...s, paths: s.paths.filter((p) => p !== path) }))
    try {
      await api.request({ url: "/api/scan/live/remove-path", method: "DELETE", data: { path } })
    } catch {
      setStatus((s) => ({ ...s, paths: prev }))
    }
  }
  return (
    <Card className="bg-card/40 backdrop-blur-md border-border/50 transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5">
      <CardHeader className="pb-3 space-y-0">
        <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent leading-snug break-words min-w-0 flex items-center gap-2">
          Live Background Scanner
          <InfoIcon description="Continuously monitors the file system in real-time, scanning files as they are created or modified. Uses machine learning anomaly detection to identify suspicious files without impacting system performance." />
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        {/* Status Toggle */}
        <div className="flex items-center justify-between rounded-md border border-border/30 bg-muted/20 p-3">
          <div>
            <span className="font-medium text-foreground">Background Scanning</span>
            <p className="text-xs text-muted-foreground mt-0.5">Real-time file system monitoring</p>
          </div>
          <Switch checked={enabled} onCheckedChange={toggle} />
        </div>

        {/* Statistics */}
        {status.stats && (
          <div className="grid grid-cols-2 gap-2 rounded-md border border-border/30 bg-muted/10 p-3">
            <div>
              <div className="text-xs text-muted-foreground">Files Scanned</div>
              <div className="text-lg font-semibold text-foreground">{status.stats.files_scanned.toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Threats Found</div>
              <div className="text-lg font-semibold text-red-500">{status.stats.threats_found}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Data Scanned</div>
              <div className="text-sm font-medium text-foreground">
                {(status.stats.bytes_scanned / (1024 * 1024)).toFixed(2)} MB
              </div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Scan Rate</div>
              <div className="text-sm font-medium text-foreground">
                {status.stats.scan_rate_per_second?.toFixed(1) ?? "0.0"} files/s
              </div>
            </div>
            {status.stats.uptime_seconds && (
              <div className="col-span-2">
                <div className="text-xs text-muted-foreground">Uptime</div>
                <div className="text-sm font-medium text-foreground">
                  {Math.floor(status.stats.uptime_seconds / 3600)}h {Math.floor((status.stats.uptime_seconds % 3600) / 60)}m
                </div>
              </div>
            )}
          </div>
        )}

        {/* Configuration */}
        <div className="space-y-2">
          <div className="text-xs font-medium text-foreground">Configuration</div>
          
          <div className="flex items-center justify-between rounded-md border border-border/30 bg-muted/20 p-2">
            <span className="text-xs">Auto-Quarantine Threats</span>
            <Switch
              checked={status.auto_quarantine ?? true}
              onCheckedChange={async (v) => {
                try {
                  const res = await api.post("/api/scan/live/config", { auto_quarantine: v })
                  const updatedStatus = res.data as LiveScanStatus
                  setStatus(updatedStatus)
                  toast.success(`Auto-quarantine ${v ? 'enabled' : 'disabled'}`)
                } catch (error: any) {
                  console.error("Failed to update auto-quarantine:", error)
                  toast.error(error?.response?.data?.detail || "Failed to update auto-quarantine setting")
                }
              }}
            />
          </div>

          <div className="rounded-md border border-border/30 bg-muted/20 p-2">
            <div className="text-xs mb-1">Scan Delay (seconds)</div>
            <Input
              type="number"
              min="0.1"
              max="10"
              step="0.1"
              value={status.scan_delay ?? 1.0}
              className="h-7 text-xs"
              onChange={(e) => {
                const val = parseFloat(e.target.value) || 1.0
                api.post("/api/scan/live/config", { scan_delay: val })
                  .then((res) => {
                    const updatedStatus = res.data as LiveScanStatus
                    setStatus(updatedStatus)
                  })
                  .catch((error: any) => {
                    console.error("Failed to update scan delay:", error)
                    toast.error(error?.response?.data?.detail || "Failed to update scan delay")
                  })
              }}
            />
          </div>

          <div className="rounded-md border border-border/30 bg-muted/20 p-2">
            <div className="text-xs mb-1">Threat Report Interval (minutes)</div>
            <Input
              type="number"
              min="1"
              max="1440"
              step="1"
              value={status.threat_report_interval ?? 1}
              className="h-7 text-xs"
              onChange={(e) => {
                const val = parseFloat(e.target.value) || 1
                api.post("/api/scan/live/config", { threat_report_interval: val })
                  .then((res) => {
                    const updatedStatus = res.data as LiveScanStatus
                    setStatus(updatedStatus)
                    toast.success(`Threat report interval set to ${val} minutes`)
                  })
                  .catch((error: any) => {
                    console.error("Failed to update threat report interval:", error)
                    toast.error(error?.response?.data?.detail || "Failed to update threat report interval")
                  })
              }}
            />
            <div className="text-xs text-muted-foreground mt-1">
              Threats will be reported every {status.threat_report_interval ?? 1} minutes
            </div>
          </div>
        </div>

        {/* Scan Progress Animation */}
        {(status.scan_progress?.is_scanning || scanProgress || enabled) && (
          <div className="space-y-2 rounded-md border border-border/30 bg-muted/10 p-3">
            <div className="flex items-center justify-between">
              <div className="text-xs font-medium text-foreground">Continuous Scanning</div>
              <div className="text-xs text-muted-foreground">
                {scanProgress?.files_scanned ?? status.scan_progress?.files_scanned_in_session ?? status.stats?.files_scanned ?? 0} files scanned
              </div>
            </div>
            <div className="relative">
              <Progress 
                value={100} 
                className="h-2"
              />
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="animate-pulse text-xs text-muted-foreground">Scanning...</div>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <div className="animate-spin rounded-full h-3 w-3 border-2 border-primary border-t-transparent"></div>
              <span className="truncate">
                {scanProgress?.current_path ? 
                  `Scanning: ${scanProgress.current_path.split(/[/\\]/).pop()}` : 
                  status.scan_progress?.current_path ? 
                    `Scanning: ${status.scan_progress.current_path.split(/[/\\]/).pop()}` :
                    "Monitoring file system..."}
              </span>
            </div>
            {status.scan_progress?.next_report_in_seconds !== undefined && status.scan_progress.next_report_in_seconds > 0 && (
              <div className="text-xs text-muted-foreground">
                Next threat report in: {Math.floor((status.scan_progress.next_report_in_seconds || 0) / 60)}m {Math.floor((status.scan_progress.next_report_in_seconds || 0) % 60)}s
              </div>
            )}
          </div>
        )}

        {/* Threat Reports */}
        {threatReports.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs font-medium text-foreground">Recent Threat Reports</div>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {threatReports.slice(0, 5).map((report, idx) => (
                <div key={idx} className="rounded-md border border-border/30 bg-muted/10 p-2">
                  <div className="flex items-center justify-between mb-1">
                    <div className="text-xs font-medium text-foreground">
                      {report.threats_count} threat(s) in {report.interval_minutes} min
                    </div>
                    <div className="text-xs text-muted-foreground">{report.timestamp}</div>
                  </div>
                  {report.threats.length > 0 && (
                    <div className="space-y-1 mt-2">
                      {report.threats.slice(0, 3).map((threat, tIdx) => (
                        <div key={tIdx} className="text-xs text-muted-foreground truncate">
                          <span className={`font-medium ${
                            threat.verdict === "malicious" ? "text-red-500" : 
                            threat.verdict === "suspicious" ? "text-orange-500" : 
                            "text-yellow-500"
                          }`}>
                            {threat.verdict}
                          </span>
                          {" "}
                          {threat.path.split(/[/\\]/).pop()}
                        </div>
                      ))}
                      {report.threats.length > 3 && (
                        <div className="text-xs text-muted-foreground">
                          +{report.threats.length - 3} more...
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Path Management */}
        <div className="space-y-2">
          <div className="text-xs font-medium text-foreground">Monitored Paths</div>
          <div className="flex items-center gap-2">
            <Input id="scan-path" placeholder="Enter path to monitor..." className="h-8 text-xs" />
            <Button 
              className="h-8 text-xs transition-all duration-200 hover:scale-105 active:scale-95" 
              onClick={() => {
                const el = document.getElementById("scan-path") as HTMLInputElement | null
                const p = el?.value || ""
                if (p) addPath(p)
                if (el) el.value = ""
              }}
            >
              Add
            </Button>
            {/* Directory Picker Button - Uses File System Access API for modern browsers */}
              <Button
                type="button"
                variant="outline"
                className="h-8 text-xs transition-all duration-200 hover:scale-105 active:scale-95 hover:border-primary/50"
                onClick={async () => {
                try {
                  // Try using the modern File System Access API (supported in Chrome, Edge, Opera)
                  if ('showDirectoryPicker' in window) {
                    const dirHandle = await (window as any).showDirectoryPicker({
                      mode: 'read',
                    })
                    if (dirHandle) {
                      // Get the directory path
                      // Note: The API doesn't directly expose the path, but we can try to get it
                      // For now, we'll use the directory name and ask user to confirm
                      const dirName = dirHandle.name
                      
                      // Try to construct a path (this is a workaround)
                      // We'll prompt the user or use the directory name
                      // Since we can't get absolute path directly, we'll show a message
                      const selectedPath = prompt(
                        `Selected directory: ${dirName}\n\nPlease enter the full path to this directory:`,
                        dirName
                      )
                      if (selectedPath && selectedPath.trim()) {
                        addPath(selectedPath.trim())
                      }
                    }
                  } else {
                    // Fallback: Use webkitdirectory for older browsers
                    const input = document.createElement('input')
                    input.type = 'file'
                    input.setAttribute('webkitdirectory', '')
                    input.setAttribute('directory', '')
                    input.style.display = 'none'
                    
                    input.onchange = (e) => {
                      const files = (e.target as HTMLInputElement).files
                      if (files && files.length > 0) {
                        const firstFile = files[0]
                        let dirPath = ''
                        
                        // Try to get path from file object (browser dependent)
                        const filePath = (firstFile as any).path || (input as any).value || ''
                        
                        if (filePath) {
                          // Extract directory path (remove filename)
                          dirPath = filePath.replace(/[/\\][^/\\]*$/, '')
                        } else if (firstFile.webkitRelativePath) {
                          // Fallback: Use relative path and prompt user
                          const parts = firstFile.webkitRelativePath.split('/')
                          if (parts.length > 1) {
                            const dirParts = parts.slice(0, -1)
                            const relativePath = dirParts.join('/')
                            dirPath = prompt(
                              `Selected directory: ${dirParts[dirParts.length - 1]}\n\nPlease enter the full path:`,
                              relativePath
                            ) || ''
                          }
                        }
                        
                        if (dirPath) {
                          addPath(dirPath.trim())
                        }
                      }
                      document.body.removeChild(input)
                    }
                    
                    document.body.appendChild(input)
                    input.click()
                  }
                } catch (error: any) {
                  // User cancelled or error occurred
                  if (error.name !== 'AbortError') {
                    console.error('Directory picker error:', error)
                    // Fallback to manual input
                    const manualPath = prompt('Please enter the full path to the directory:')
                    if (manualPath && manualPath.trim()) {
                      addPath(manualPath.trim())
                    }
                  }
                }
              }}
            >
              📁 Browse Folder
            </Button>
          </div>
          <div className="space-y-1 max-h-32 overflow-y-auto">
            {paths?.length ? paths.map((p, idx) => (
              <div 
                key={p} 
                className="flex items-center justify-between rounded-md border border-border/30 bg-muted/20 p-2 transition-all duration-300 animate-in fade-in slide-in-from-left-4 hover:bg-muted/30"
                style={{ animationDelay: `${idx * 50}ms` }}
              >
                <span className="text-xs truncate flex-1">{p}</span>
                <Button 
                  variant="secondary" 
                  size="sm" 
                  className="h-6 px-2 text-xs transition-all duration-200 hover:scale-105 active:scale-95" 
                  onClick={() => removePath(p)}
                >
                  Remove
                </Button>
              </div>
            )) : <span className="text-xs text-muted-foreground">No paths monitored</span>}
          </div>
        </div>

        {/* Recent Threats */}
        {status.recent_threats && status.recent_threats.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs font-medium text-foreground">Recent Threats ({status.recent_threats.length})</div>
            <div className="space-y-1 max-h-40 overflow-y-auto">
              {status.recent_threats.slice(0, 5).map((threat, idx) => (
                <div
                  key={idx}
                  className="rounded-md border border-red-500/30 bg-red-500/5 p-2 text-xs transition-all duration-300 animate-in fade-in slide-in-from-left-4"
                  style={{ animationDelay: `${idx * 50}ms` }}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-red-600 dark:text-red-400 capitalize">{threat.verdict}</span>
                    <span className="text-muted-foreground">{(threat.risk * 100).toFixed(0)}%</span>
                  </div>
                  <div className="truncate text-muted-foreground mt-0.5">{threat.path.split(/[/\\]/).pop() || threat.path}</div>
                  <div className="text-[10px] text-muted-foreground mt-0.5">{threat.timestamp}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Exclude Patterns */}
        {status.exclude_patterns && status.exclude_patterns.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs font-medium text-foreground">Excluded Patterns</div>
            <div className="flex flex-wrap gap-1">
              {status.exclude_patterns.slice(0, 6).map((pattern, idx) => (
                <span key={idx} className="text-[10px] px-1.5 py-0.5 rounded bg-muted/30 border border-border/30 text-muted-foreground">
                  {pattern}
                </span>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
