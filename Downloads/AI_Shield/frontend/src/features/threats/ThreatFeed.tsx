"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { useAppStore } from "@/store/app-store"
import useSWR from "swr"
import { fetcher, api } from "@/lib/api"
import type { ThreatItem } from "@/store/app-store"
import { toast } from "sonner"
import { useState } from "react"
import { ThreatAnalysisDialog } from "./ThreatAnalysisDialog"
import type { ThreatAnalysis } from "./ThreatAnalysisDialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import InfoIcon from "@/components/InfoIcon"

function SevPill({ s }: { s: "low" | "medium" | "high" | "critical" }) {
  const color = { low: "#1FB6AB", medium: "#FF9F43", high: "#4F8DF7", critical: "#FF5C57" }[s]
  return (
    <span className="rounded-full px-2 py-0.5 text-xs font-medium" style={{ backgroundColor: `${color}22`, color }}>
      {s}
    </span>
  )
}

function confidenceFromSeverity(s: "low" | "medium" | "high" | "critical") {
  return { low: 30, medium: 60, high: 82, critical: 95 }[s]
}

export default function ThreatFeed() {
  const threats = useAppStore((s) => s.threats)
  const [analyzingThreatId, setAnalyzingThreatId] = useState<number | null>(null)
  const [analysis, setAnalysis] = useState<ThreatAnalysis | null>(null)
  const [analysisLoading, setAnalysisLoading] = useState(false)
  const [restrictDialogOpen, setRestrictDialogOpen] = useState<{ [key: string]: boolean }>({})
  useSWR<ThreatItem[]>("/api/threats?limit=50", fetcher, {
    refreshInterval: 5000, // 5 seconds refresh rate (reduced for better CPU usage)
    revalidateOnFocus: false,
    revalidateOnReconnect: true,
    onSuccess(data) {
      useAppStore.setState({ threats: data })
    },
  })
  const { quarantine, delete: del, allow } = useAppStore((s) => s.actions)
  const selected = threats.slice(0, 5).map((t) => t.id)

  const handleAnalyze = async (threatId: number) => {
    setAnalysisLoading(true)
    setAnalyzingThreatId(threatId)
    try {
      const { data } = await api.get(`/api/threats/${threatId}/analyze`)
      setAnalysis(data)
    } catch (error) {
      toast.error("Failed to analyze threat")
      setAnalyzingThreatId(null)
    } finally {
      setAnalysisLoading(false)
    }
  }

  const handleRestrictPermissions = async (filePath: string, level: string = "standard", threatId?: string) => {
    if (!filePath) {
      toast.error("No file path available for this threat")
      return
    }
    try {
      const { data } = await api.post("/api/threats/actions/restrict-permissions", {
        file_path: filePath,
        level: level
      })
      if (data.success) {
        toast.success(`Permissions restricted (${level} level)`)
        if (threatId) {
          setRestrictDialogOpen(prev => ({ ...prev, [threatId]: false }))
        }
      } else {
        toast.error(data.message || "Failed to restrict permissions")
      }
    } catch (error: any) {
      toast.error(error.response?.data?.detail || "Failed to restrict permissions")
    }
  }

  const bulk = async (action: "quarantine" | "delete" | "allow") => {
    if (selected.length === 0) return
    try {
      await api.post("/api/threats/bulk-action", { ids: selected.map((id) => Number(id)), action })
      if (action === "delete") del(selected)
      else if (action === "allow") allow(selected)
      else quarantine(selected)
      toast.success(`${action === "delete" ? "Deleted" : action === "allow" ? "Allowed" : "Quarantined"} ${selected.length} item(s)`) 
    } catch {}
  }
  return (
    <Card aria-label="Real-time threat feed" className="bg-card/40 backdrop-blur-md border-border/50 transition-all duration-300 hover:shadow-lg">
      <CardHeader>
        <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent flex items-center gap-2">
          Real-Time Threat Feed
          <InfoIcon description="Displays real-time threats detected by the system. Shows file anomalies, suspicious activities, and security events as they occur. You can quarantine, delete, or allow threats directly from this feed." />
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="mb-1 flex gap-2 flex-wrap">
          <Button 
            size="sm" 
            onClick={() => bulk("quarantine")}
            className="transition-all duration-200 hover:scale-105 active:scale-95"
          >
            Quarantine
          </Button>
          <Button 
            size="sm" 
            variant="destructive" 
            onClick={() => bulk("delete")}
            className="transition-all duration-200 hover:scale-105 active:scale-95"
          >
            Delete
          </Button>
          <Button 
            size="sm" 
            variant="secondary" 
            onClick={() => bulk("allow")}
            className="transition-all duration-200 hover:scale-105 active:scale-95"
          >
            Allow
          </Button>
        </div>
        <div className="space-y-2" role="list" aria-label="Threat events">
          {threats.slice(0, 10).map((t, idx) => {
            const bar = { low: 'var(--accent-teal)', medium: 'var(--accent-orange)', high: 'var(--accent-blue)', critical: 'var(--accent-red)' }[t.severity]
            const conf = confidenceFromSeverity(t.severity)
            return (
              <div 
                key={t.id} 
                role="listitem" 
                className="rounded-lg border border-border/50 p-3 transition-all duration-300 hover:bg-secondary/40 hover:shadow-md hover:-translate-x-1 animate-in fade-in slide-in-from-left-4" 
                style={{ 
                  boxShadow: `inset 3px 0 0 0 ${bar}`,
                  animationDelay: `${idx * 50}ms`
                }}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-3">
                    <span className="text-xs text-muted-foreground shrink-0">{new Date(t.time).toLocaleTimeString()}</span>
                    <div className="truncate text-sm">{t.description}</div>
                    {t.action && (
                      <span className="ml-2 rounded-full border px-2 py-0.5 text-[11px] capitalize" style={{ borderColor: 'var(--border)' }}>{t.action}</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">{t.source}</span>
                    <SevPill s={t.severity} />
                  </div>
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">ML confidence</span>
                  <div className="w-48">
                    <Progress value={conf} className="h-1.5" />
                  </div>
                  <span className="text-xs tabular-nums">{conf}%</span>
                  <div className="ml-auto flex gap-2 flex-wrap">
                    <Button
                      size="sm"
                      className="h-7 px-2 transition-all duration-200 hover:scale-105 active:scale-95"
                      onClick={async () => {
                        try {
                          await api.post("/api/threats/bulk-action", { ids: [Number(t.id)], action: "quarantine" })
                          quarantine([t.id])
                          toast.success("Quarantined")
                        } catch {}
                      }}
                    >
                      Quarantine
                    </Button>
                    {t.filePath && (
                      <Dialog open={restrictDialogOpen[t.id] || false} onOpenChange={(open) => {
                        setRestrictDialogOpen(prev => ({ ...prev, [t.id]: open }))
                      }}>
                        <DialogTrigger asChild>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 px-2 transition-all duration-200 hover:scale-105 active:scale-95"
                          >
                            Restrict Permissions
                          </Button>
                        </DialogTrigger>
                        <DialogContent>
                          <DialogHeader>
                            <DialogTitle>Restrict File Permissions</DialogTitle>
                            <DialogDescription>
                              Restrict permissions on this anomaly file without quarantining it. Choose the restriction level.
                            </DialogDescription>
                          </DialogHeader>
                          <div className="space-y-4 py-4">
                            <div className="space-y-2">
                              <label className="text-sm font-medium">File Path</label>
                              <p className="text-sm text-muted-foreground break-all">{t.filePath}</p>
                            </div>
                            <div className="space-y-2">
                              <label className="text-sm font-medium">Permission Level</label>
                              <Select defaultValue="standard" onValueChange={(level) => {
                                handleRestrictPermissions(t.filePath!, level, t.id)
                              }}>
                                <SelectTrigger>
                                  <SelectValue placeholder="Select level" />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="standard">Standard (Read-only, no execute)</SelectItem>
                                  <SelectItem value="moderate">Moderate (Read-only, minimal restrictions)</SelectItem>
                                  <SelectItem value="strict">Strict (Maximum restrictions)</SelectItem>
                                </SelectContent>
                              </Select>
                            </div>
                          </div>
                          <DialogFooter>
                            <Button variant="outline" onClick={() => {
                              setRestrictDialogOpen(prev => ({ ...prev, [t.id]: false }))
                            }}>
                              Cancel
                            </Button>
                          </DialogFooter>
                        </DialogContent>
                      </Dialog>
                    )}
                    <Button
                      size="sm"
                      variant="destructive"
                      className="h-7 px-2 transition-all duration-200 hover:scale-105 active:scale-95"
                      onClick={async () => {
                        try {
                          await api.post("/api/threats/bulk-action", { ids: [Number(t.id)], action: "delete" })
                          del([t.id])
                          toast.success("Deleted")
                        } catch {}
                      }}
                    >
                      Delete
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      className="h-7 px-2 transition-all duration-200 hover:scale-105 active:scale-95"
                      onClick={async () => {
                        try {
                          await api.post("/api/threats/bulk-action", { ids: [Number(t.id)], action: "allow" })
                          allow([t.id])
                          toast.success("Allowed")
                        } catch {}
                      }}
                    >
                      Allow
                    </Button>
                    <Button
                      size="sm"
                      className="h-7 px-2 transition-all duration-200 hover:scale-105 active:scale-95 hover:bg-primary/90"
                      onClick={() => handleAnalyze(Number(t.id))}
                    >
                      Analyze
                    </Button>
                  </div>
                </div>
              </div>
            )
          })}
          {threats.length === 0 && (
            <div className="rounded-lg border p-6 text-center text-sm text-muted-foreground">No threats yet. Monitoring…</div>
          )}
        </div>
      </CardContent>
      <ThreatAnalysisDialog
        open={analyzingThreatId !== null}
        onOpenChange={(open) => {
          if (!open) {
            setAnalyzingThreatId(null)
            setAnalysis(null)
          }
        }}
        analysis={analysis}
        loading={analysisLoading}
      />
    </Card>
  )
}
