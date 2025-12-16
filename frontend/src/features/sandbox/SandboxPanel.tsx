"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import useSWR from "swr"
import { fetcher, api } from "@/lib/api"
import { useAppStore } from "@/store/app-store"
import { useEffect } from "react"
import { toast } from "sonner"
import { Shield, FileX, RotateCcw } from "lucide-react"
import InfoIcon from "@/components/InfoIcon"

type QuarantineAction = {
  action: string
  timestamp: string
  description?: string
  [key: string]: string | number | boolean | undefined
}

type QuarantinedFile = {
  quarantined_filename: string
  quarantined_path: string
  original_filename?: string
  original_path?: string
  quarantine_timestamp?: string
  threat_severity?: string
  file_size?: number
  permission_level?: string
  actions?: QuarantineAction[]
}

export default function SandboxPanel() {
  const jobs = useAppStore((s) => s.sandboxJobs)
  useSWR<{ job_id: string; target?: string; status: string; percent: number; verdict?: string; calls?: string[]; score?: number }[]>("/api/sandbox/jobs", fetcher, {
    refreshInterval: 5000, // Optimized for CPU
    onSuccess(data) {
      // Additional client-side filtering as backup (backend already filters, but this ensures consistency)
      const anomalyJobs = data.filter(job => {
        // Include if verdict is suspicious/malicious
        if (job.verdict && !job.verdict.toLowerCase().includes("benign")) {
          return true
        }
        // Include if score indicates anomaly (> 0.5)
        if (job.score !== undefined && job.score > 0.5) {
          return true
        }
        // Include if still running/pending
        if (job.status === "running" || job.status === "pending" || job.status === "queued") {
          return true
        }
        return false
      })
      useAppStore.setState({ sandboxJobs: anomalyJobs })
    },
  })

  const { data: quarantineData, mutate: mutateQuarantine } = useSWR<{ count: number; files: QuarantinedFile[] }>(
    "/api/threat-actions/quarantined",
    fetcher,
    { 
      refreshInterval: 3000, // Refresh every 3 seconds to catch new quarantined files
      revalidateOnFocus: true,
      revalidateOnReconnect: true,
      dedupingInterval: 1000 // Reduce deduplication interval for faster updates
    }
  )

  const quarantinedFiles = quarantineData?.files || []

  useEffect(() => {
    const t = setTimeout(async () => {
      if (jobs.length === 0) {
        try { await api.post("/api/sandbox/run", { target: "sample.exe" }) } catch {}
      }
    }, 500)
    return () => clearTimeout(t)
  }, [jobs.length])

  const handleRestore = async (filename: string) => {
    try {
      await api.post("/api/threat-actions/restore", { quarantined_filename: filename })
      toast.success("File restored successfully")
      // Force refresh of quarantine list
      mutateQuarantine()
      // Also refresh after a short delay to ensure backend has updated
      setTimeout(() => mutateQuarantine(), 1000)
    } catch (error) {
      const errorMessage = (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail || "Failed to restore file"
      toast.error(errorMessage)
    }
  }

  const formatFileSize = (bytes?: number) => {
    if (!bytes) return "—"
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  const formatTimestamp = (timestamp?: string) => {
    if (!timestamp) return "—"
    try {
      return new Date(timestamp).toLocaleString()
    } catch {
      return timestamp
    }
  }

  return (
    <div className="grid gap-4 md:grid-cols-2" aria-label="Sandbox">
      <Card aria-label="Jobs" className="bg-card/40 backdrop-blur-md border-border/50 transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5">
        <CardHeader>
          <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent flex items-center gap-2">
            Jobs
            <InfoIcon description="Behavioral analysis sandbox that executes files in an isolated environment to detect malicious activities. Analyzes system calls, registry modifications, and network behavior to identify threats." />
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-2 text-sm text-muted-foreground">Anomaly detection results from sandbox analysis. Only suspicious/malicious files are shown.</div>
          <div className="mb-3">
            <Button 
              className="h-8 transition-all duration-200 hover:scale-105 active:scale-95" 
              onClick={async () => { await api.post("/api/sandbox/run", { target: "sample.exe" }) }}
            >
              Run Sample
            </Button>
          </div>
          {jobs.length === 0 ? (
            <div className="text-sm text-muted-foreground">No anomalies detected. All analyzed files appear benign.</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Progress</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {jobs.slice(0, 10).map((j, idx) => (
                  <TableRow 
                    key={j.job_id}
                    className="transition-all duration-300 animate-in fade-in slide-in-from-left-4"
                    style={{ animationDelay: `${idx * 50}ms` }}
                  >
                    <TableCell className="truncate max-w-[140px]">{j.job_id}</TableCell>
                    <TableCell className="truncate max-w-[180px]">{j.target ?? "—"}</TableCell>
                    <TableCell className="capitalize">{j.status}</TableCell>
                    <TableCell className="tabular-nums">{j.percent}%</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card aria-label="Job Detail" className="bg-card/40 backdrop-blur-md border-border/50 transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5">
        <CardHeader>
          <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">Job Detail</CardTitle>
        </CardHeader>
        <CardContent className="text-sm space-y-2">
          <div className="text-muted-foreground">System calls, registry/file changes, network activity</div>
          <div>Verdict: {jobs[0]?.verdict ?? "—"}</div>
          {jobs[0]?.score !== undefined && <div>Score: {Math.round((jobs[0]?.score ?? 0) * 100) / 100}</div>}
          {jobs[0]?.calls && jobs[0]?.calls?.length ? (
            <div>
              <div className="text-muted-foreground">Calls:</div>
              <div className="text-xs">{jobs[0].calls.join(", ")}</div>
            </div>
          ) : (
            <div className="text-muted-foreground">No call trace yet.</div>
          )}
        </CardContent>
      </Card>

      <Card aria-label="Quarantine" className="bg-card/40 backdrop-blur-md border-border/50 transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5 md:col-span-2">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Quarantine
            </CardTitle>
            <Badge variant="secondary" className="text-xs">
              {quarantineData?.count || 0} file{quarantineData?.count !== 1 ? 's' : ''}
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="mb-3 text-sm text-muted-foreground">
            Files isolated using OS-level permission restrictions, obfuscated filenames, and extension manipulation.
          </div>
          {quarantinedFiles.length === 0 ? (
            <div className="text-sm text-muted-foreground text-center py-8">
              <FileX className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <div>No files in quarantine</div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Original Filename</TableHead>
                    <TableHead>Quarantined Name</TableHead>
                    <TableHead>Original Path</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>Quarantined</TableHead>
                    <TableHead>Recent Actions</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {quarantinedFiles.map((file, idx) => (
                    <TableRow 
                      key={file.quarantined_filename}
                      className="transition-all duration-300 animate-in fade-in slide-in-from-left-4"
                      style={{ animationDelay: `${idx * 50}ms` }}
                    >
                      <TableCell className="font-medium truncate max-w-[200px]" title={file.original_filename}>
                        {file.original_filename || "—"}
                      </TableCell>
                      <TableCell className="font-mono text-xs truncate max-w-[180px]" title={file.quarantined_filename}>
                        {file.quarantined_filename}
                      </TableCell>
                      <TableCell className="text-xs truncate max-w-[250px]" title={file.original_path}>
                        {file.original_path || "—"}
                      </TableCell>
                      <TableCell>
                        {file.threat_severity ? (
                          <Badge 
                            variant={
                              file.threat_severity === "high" || file.threat_severity === "critical" 
                                ? "destructive" 
                                : file.threat_severity === "medium" 
                                ? "default" 
                                : "secondary"
                            }
                            className="capitalize text-xs"
                          >
                            {file.threat_severity}
                          </Badge>
                        ) : (
                          "—"
                        )}
                      </TableCell>
                      <TableCell className="text-xs tabular-nums">
                        {formatFileSize(file.file_size)}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {formatTimestamp(file.quarantine_timestamp)}
                      </TableCell>
                      <TableCell className="text-xs">
                        {file.actions && file.actions.length > 0 ? (
                          <div className="space-y-1 max-w-[200px]">
                            {file.actions.slice(-3).reverse().map((action, idx) => (
                              <div key={idx} className="truncate" title={action.description || action.action}>
                                <Badge variant="outline" className="text-xs px-1.5 py-0.5">
                                  {action.action}
                                </Badge>
                                <span className="text-muted-foreground ml-1 text-[10px]">
                                  {new Date(action.timestamp).toLocaleTimeString()}
                                </span>
                              </div>
                            ))}
                            {file.actions.length > 3 && (
                              <div className="text-[10px] text-muted-foreground">
                                +{file.actions.length - 3} more
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 px-2"
                            onClick={() => handleRestore(file.quarantined_filename)}
                            title="Restore file"
                          >
                            <RotateCcw className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          {quarantinedFiles.length > 0 && (
            <div className="mt-4 p-3 rounded-md bg-muted/30 border border-border/30 text-xs space-y-1">
              <div className="font-medium text-foreground">Quarantine Protection Details:</div>
              <div className="text-muted-foreground space-y-0.5">
                <div>• Files are renamed with obfuscated names (Q[hash]_[timestamp].quarantine)</div>
                <div>• Original extensions are changed to .quarantine</div>
                <div>• OS-level permissions restrict execution and modification</div>
                <div>• Files are isolated in the quarantine directory</div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
