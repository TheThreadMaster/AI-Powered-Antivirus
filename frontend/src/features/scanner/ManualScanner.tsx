"use client"

import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { useState, useMemo, useEffect, useRef } from "react"
import { api, fetcher } from "@/lib/api"
import { useAppStore } from "@/store/app-store"
import useSWR from "swr"
import { toast } from "sonner"
import InfoIcon from "@/components/InfoIcon"

export default function ManualScanner() {
  type ScanResult = {
    ml: { path: string; risk: number; verdict: string }
    sandbox: { path: string; syscalls: string[]; registry: string[]; network: string[]; verdict: string }
    meta: { path: string; name: string; size: number; mime: string; structure: { is_dir: boolean; entries: string[] } }
    severity: "low" | "medium" | "high" | "critical"
  }
  type HistoryItem = { id: number; name: string; mime: string; size: number; severity: "low" | "medium" | "high" | "critical"; time: string; risk?: number; path?: string }
  const [progress, setProgress] = useState(0)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const { data: history, mutate } = useSWR<HistoryItem[]>("/api/scan/history", fetcher)
  const threats = useAppStore((s) => s.threats)
  const removeThreats = useAppStore((s) => s.actions.delete)
  const setSelectedFile = useAppStore((s) => s.actions.setSelectedFile)

  // Find threat IDs by filePath for the current scan result
  const resultThreatIds = useMemo(() => {
    if (!result?.meta?.path) return []
    return threats
      .filter((t) => t.filePath === result.meta.path)
      .map((t) => Number(t.id))
  }, [result, threats])

  // Find threat IDs by filePath for history items
  const getThreatIdsForPath = (filePath: string) => {
    return threats
      .filter((t) => t.filePath === filePath)
      .map((t) => Number(t.id))
  }

  const deleteThreatsForResult = async () => {
    if (resultThreatIds.length === 0) {
      toast.error("No associated threat found")
      return
    }
    try {
      const response = await api.post("/api/threats/bulk-action", { ids: resultThreatIds, action: "delete" })
      const result = response.data
      console.log("[Manual Scanner] Delete response:", result)
      const deletedIds = result.deleted_ids || resultThreatIds
      if (deletedIds.length > 0) {
        removeThreats(deletedIds.map((id: number) => String(id)))
        toast.success(`Threat permanently deleted (${deletedIds.length} item(s))`)
      } else {
        toast.error("No threats were deleted. Check console for details.")
      }
    } catch (e: any) {
      console.error("[Manual Scanner] Delete error:", e)
      const errorMsg = e?.response?.data?.detail || e?.message || "Failed to delete threat"
      toast.error(`Failed to delete threat: ${errorMsg}`)
    }
  }

  const deleteThreatsForHistoryItem = async (itemPath: string) => {
    const threatIds = getThreatIdsForPath(itemPath)
    if (threatIds.length === 0) {
      toast.error("No associated threat found")
      return
    }
    try {
      const response = await api.post("/api/threats/bulk-action", { ids: threatIds, action: "delete" })
      const result = response.data
      console.log("[Manual Scanner] Delete response:", result)
      const deletedIds = result.deleted_ids || threatIds
      if (deletedIds.length > 0) {
        removeThreats(deletedIds.map((id: number) => String(id)))
        toast.success(`Threat permanently deleted (${deletedIds.length} item(s))`)
      } else {
        toast.error("No threats were deleted. Check console for details.")
      }
    } catch (e: any) {
      console.error("[Manual Scanner] Delete error:", e)
      const errorMsg = e?.response?.data?.detail || e?.message || "Failed to delete threat"
      toast.error(`Failed to delete threat: ${errorMsg}`)
    }
  }

  const handleFile = (file: File) => {
    if (!file) return
    setSelectedFile(file)
    upload(file)
  }

  const [scanningJobId, setScanningJobId] = useState<string | null>(null)
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null)

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
      }
    }
  }, [])

  const upload = async (file: File) => {
    const fd = new FormData()
    fd.append("file", file)
    try {
      toast.info("Uploading file…")
      setProgress(10)
      const res = await api.post("/api/scan/file", fd, {
        // Let Axios set the correct multipart boundary automatically
        onUploadProgress: (pe) => {
          try {
            const pct = pe.total ? Math.round(((pe.loaded || 0) / pe.total) * 50) : 20
            setProgress(Math.max(10, Math.min(50, pct)))
          } catch {}
        },
      })
      
      // Check if we got a job_id (async scanning)
      if (res.data.job_id) {
        const jobId = res.data.job_id
        setScanningJobId(jobId)
        setProgress(50)
        toast.info("File uploaded. Scanning in progress…")
        
        // Clear any existing polling
        if (pollIntervalRef.current) {
          clearInterval(pollIntervalRef.current)
        }
        
        // Poll for scan status
        const pollInterval = setInterval(async () => {
          try {
            const statusRes = await api.get(`/api/scan/status/${jobId}`)
            const status = statusRes.data
            
            // Update progress
            if (status.progress) {
              setProgress(50 + Math.floor(status.progress * 0.5)) // 50-100 range
            }
            
            // Check if completed
            if (status.status === "completed" && status.result) {
              clearInterval(pollInterval)
              pollIntervalRef.current = null
              setResult(status.result)
              setScanningJobId(null)
              setProgress(100)
              mutate()
              toast.success("Scan completed")
            } else if (status.status === "failed") {
              clearInterval(pollInterval)
              pollIntervalRef.current = null
              setScanningJobId(null)
              setProgress(0)
              toast.error(status.error || "Scan failed")
            }
          } catch (e) {
            console.error("Failed to check scan status:", e)
          }
        }, 1000) // Poll every second
        pollIntervalRef.current = pollInterval
        
        // Cleanup interval after 5 minutes (timeout)
        setTimeout(() => {
          if (pollIntervalRef.current === pollInterval) {
            clearInterval(pollInterval)
            pollIntervalRef.current = null
          }
          if (scanningJobId === jobId) {
            setScanningJobId(null)
            toast.error("Scan timeout - check status manually")
          }
        }, 300000) // 5 minutes
      } else {
        // Fallback: synchronous response (backward compatibility)
        setResult(res.data)
        mutate()
        toast.success("Scan completed")
        setProgress(100)
      }
    } catch (e) {
      toast.error("Upload failed")
      setProgress(0)
      setScanningJobId(null)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          Manual File/Folder Scanner
          <InfoIcon description="On-demand scanning tool that allows you to manually scan specific files or folders. Provides detailed analysis including ML-based risk assessment, behavioral analysis, and metadata inspection." />
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div
          className={`rounded-lg border-2 border-dashed p-8 text-center transition-all cursor-pointer ${
            isDragging
              ? "border-primary bg-primary/5 scale-[1.02]"
              : "border-muted-foreground/25 hover:border-primary/50 hover:bg-muted/50"
          }`}
          onDragEnter={(e) => {
            e.preventDefault()
            e.stopPropagation()
            setIsDragging(true)
          }}
          onDragLeave={(e) => {
            e.preventDefault()
            e.stopPropagation()
            setIsDragging(false)
          }}
          onDragOver={(e) => {
            e.preventDefault()
            e.stopPropagation()
          }}
          onDrop={(e) => {
            e.preventDefault()
            e.stopPropagation()
            setIsDragging(false)
            const files = e.dataTransfer.files
            if (files && files.length > 0) {
              handleFile(files[0])
            }
          }}
        >
          <label htmlFor="file-upload" className="cursor-pointer">
            <div className="flex flex-col items-center gap-3">
              <div className={`rounded-full p-4 transition-colors ${isDragging ? "bg-primary/20" : "bg-primary/10"}`}>
                <svg className="size-8 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
              </div>
              <div>
                <div className="text-base font-medium">{isDragging ? "Drop file here" : "Choose a file to scan"}</div>
                <div className="text-sm text-muted-foreground mt-1">
                  {isDragging ? "Release to upload and scan" : "Click to browse or drag and drop a file"}
                </div>
                <div className="text-xs text-muted-foreground mt-2">
                  Supports: Images, PDFs, Documents, Archives, Executables, Scripts, and more
                </div>
              </div>
              <input
                id="file-upload"
                type="file"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0]
                  if (f) {
                    handleFile(f)
                  }
                }}
                accept="*/*"
              />
            </div>
          </label>
        </div>
        <div className="flex items-center justify-between">
          <div>ML + Snort + Sandbox Summary</div>
          {scanningJobId && (
            <div className="text-xs text-muted-foreground">
              Scanning… (Job: {scanningJobId.slice(-8)})
            </div>
          )}
        </div>
        <Progress value={progress} />
        {result && (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-sm font-medium">File Details</div>
                {resultThreatIds.length > 0 && (
                  <div className="flex gap-2">
                    <Button 
                      size="sm" 
                      className="h-7 transition-all duration-200 hover:scale-105 active:scale-95" 
                      onClick={async () => {
                        try {
                          await api.post("/api/threats/bulk-action", { ids: resultThreatIds, action: "quarantine" })
                          toast.success("Threat quarantined")
                        } catch (e) {
                          toast.error("Failed to quarantine threat")
                        }
                      }}
                    >
                      Quarantine
                    </Button>
                    <Button 
                      size="sm" 
                      variant="destructive" 
                      className="h-7 transition-all duration-200 hover:scale-105 active:scale-95" 
                      onClick={deleteThreatsForResult}
                    >
                      Delete Threat
                    </Button>
                  </div>
                )}
              </div>
              <div className="rounded border p-3">
                <div className="flex justify-between"><span>Path</span><span className="truncate max-w-[60%]">{result.meta?.path}</span></div>
                <div className="flex justify-between"><span>Name</span><span>{result.meta?.name}</span></div>
                <div className="flex justify-between"><span>Type</span><span>{result.meta?.mime}</span></div>
                <div className="flex justify-between"><span>Size</span><span>{(result.meta?.size ?? 0).toLocaleString()} bytes</span></div>
                <div className="flex justify-between"><span>Threat Level</span><span className="capitalize">{result.severity}</span></div>
                <div className="flex justify-between"><span>Verdict (ML)</span><span className="capitalize">{result.ml?.verdict}</span></div>
              </div>
              {result.meta?.structure?.entries?.length ? (
                <div className="space-y-2">
                  <div className="text-sm font-medium">Archive Contents</div>
                  <div className="rounded border p-3 max-h-40 overflow-auto text-xs">
                    {result.meta.structure.entries.slice(0, 50).map((e: string, i: number) => (
                      <div key={i}>{e}</div>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
            <div className="space-y-2">
              <div className="text-sm font-medium">Sandbox Analysis</div>
              <div className="rounded border p-3">
                <div className="flex justify-between"><span>Verdict</span><span>{result.sandbox?.verdict}</span></div>
                <div className="mt-2">
                  <div className="text-xs text-muted-foreground">Syscalls</div>
                  <div className="text-xs">{(result.sandbox?.syscalls || []).join(", ") || "—"}</div>
                </div>
                <div className="mt-2">
                  <div className="text-xs text-muted-foreground">Registry</div>
                  <div className="text-xs">{(result.sandbox?.registry || []).join(", ") || "—"}</div>
                </div>
                <div className="mt-2">
                  <div className="text-xs text-muted-foreground">Network</div>
                  <div className="text-xs">{(result.sandbox?.network || []).join(", ") || "—"}</div>
                </div>
              </div>
            </div>
          </div>
        )}
        <div className="space-y-2">
          <div className="text-sm font-medium">Scanned Files</div>
          <div className="rounded border p-3">
            {history?.length ? (
              <div className="space-y-2">
                {history.map((h) => {
                  const threatIds = h.path ? getThreatIdsForPath(h.path) : []
                  return (
                    <div key={h.id} className="flex items-center justify-between text-xs">
                      <div className="min-w-0 flex-1">
                        <div className="truncate">{h.name} <span className="text-muted-foreground">({h.mime})</span></div>
                        <div className="text-muted-foreground">{h.size?.toLocaleString()} bytes • <span className="capitalize">{h.severity}</span> • {h.time}</div>
                      </div>
                      <div className="flex gap-1">
                        {threatIds.length > 0 && (
                          <>
                            <Button 
                              size="sm" 
                              className="h-7 transition-all duration-200 hover:scale-105 active:scale-95" 
                              onClick={async () => {
                                try {
                                  await api.post("/api/threats/bulk-action", { ids: threatIds, action: "quarantine" })
                                  toast.success("Threat quarantined")
                                } catch (e) {
                                  toast.error("Failed to quarantine threat")
                                }
                              }}
                            >
                              Quarantine
                            </Button>
                            <Button 
                              size="sm" 
                              variant="destructive" 
                              className="h-7 transition-all duration-200 hover:scale-105 active:scale-95" 
                              onClick={() => h.path && deleteThreatsForHistoryItem(h.path)}
                            >
                              Delete Threat
                            </Button>
                          </>
                        )}
                        <Button 
                          size="sm" 
                          variant="secondary" 
                          className="h-7 transition-all duration-200 hover:scale-105 active:scale-95" 
                          onClick={async () => { await api.delete(`/api/scan/history/${h.id}`); mutate() }}
                        >
                          Delete History
                        </Button>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="text-muted-foreground text-xs">—</div>
            )}
          </div>
        </div>
      </CardContent>
      <CardFooter className="justify-end">
        <Button onClick={() => setProgress((p) => Math.min(100, p + 5))}>Simulate Progress</Button>
      </CardFooter>
    </Card>
  )
}
