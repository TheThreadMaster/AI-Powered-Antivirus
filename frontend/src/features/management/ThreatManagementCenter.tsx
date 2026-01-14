"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useAppStore } from "@/store/app-store"
import useSWR from "swr"
import { fetcher, api } from "@/lib/api"
import { useMemo, useState } from "react"
import { ThreatAnalysisDialog } from "@/features/threats/ThreatAnalysisDialog"
import { toast } from "sonner"
import type { ThreatAnalysis } from "@/features/threats/ThreatAnalysisDialog"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import InfoIcon from "@/components/InfoIcon"

export default function ThreatManagementCenter() {
  const threats = useAppStore((s) => s.threats)
  const [severity, setSeverity] = useState<string | undefined>(undefined)
  const [source, setSource] = useState<string | undefined>(undefined)
  const qs = useMemo(() => {
    const params = new URLSearchParams({ limit: "100" })
    if (severity) params.set("severity", severity)
    if (source) params.set("source", source)
    return `/api/threats?${params.toString()}`
  }, [severity, source])
  useSWR(qs, fetcher, {
    refreshInterval: 5000, // Optimized for CPU
    onSuccess(data) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      useAppStore.setState({ threats: data })
    },
  })
  const [selectedRows, setSelectedRows] = useState<number[]>([])
  const [analyzingThreatId, setAnalyzingThreatId] = useState<number | null>(null)
  const [analysis, setAnalysis] = useState<ThreatAnalysis | null>(null)
  const [analysisLoading, setAnalysisLoading] = useState(false)
  const [restrictDialogOpen, setRestrictDialogOpen] = useState<{ [key: string]: boolean }>({})
  const toggleSel = (id: number, on: boolean) => setSelectedRows((prev) => (on ? [...prev.filter((x) => x !== id), id] : prev.filter((x) => x !== id)))
  const removeThreats = useAppStore((s) => s.actions.delete)
  const handleAnalyze = async (threatId: number) => {
    setAnalysisLoading(true)
    setAnalyzingThreatId(threatId)
    try {
      const { data } = await api.get(`/api/threats/${threatId}/analyze`)
      setAnalysis(data)
    } catch {
      toast.error("Failed to analyze threat")
      setAnalyzingThreatId(null)
    } finally {
      setAnalysisLoading(false)
    }
  }
  const bulk = async (action: "quarantine" | "delete" | "allow") => {
    const response = await fetch("/api/threats/bulk-action", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ids: selectedRows, action }) })
    const result = await response.json()
    // Permanently remove deleted/quarantined threats from store
    if (action === "delete" || action === "quarantine") {
      const deletedIds = result.deleted_ids || selectedRows
      removeThreats(deletedIds.map((id: number) => String(id)))
    }
    setSelectedRows([])
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
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            Threat Management Center
            <InfoIcon description="Centralized threat management interface for viewing, filtering, and managing all detected threats. Provides bulk actions for quarantine, deletion, and permission restrictions with detailed threat analysis." />
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-3 flex flex-wrap items-center gap-2">
          <Select value={severity ?? "all"} onValueChange={(v) => setSeverity(v === "all" ? undefined : v)}>
            <SelectTrigger className="h-8 w-40"><SelectValue placeholder="Severity" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="low">Low</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
            </SelectContent>
          </Select>
          <Select value={source ?? "all"} onValueChange={(v) => setSource(v === "all" ? undefined : v)}>
            <SelectTrigger className="h-8 w-40"><SelectValue placeholder="Source" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="ML">ML</SelectItem>
              <SelectItem value="Snort">Snort</SelectItem>
              <SelectItem value="WebShield">WebShield</SelectItem>
              <SelectItem value="Sandbox">Sandbox</SelectItem>
            </SelectContent>
          </Select>
            <div className="ml-auto flex gap-2 flex-wrap">
              <Button 
                size="sm" 
                className="transition-all duration-200 hover:scale-105 active:scale-95 disabled:scale-100"
                onClick={() => bulk("quarantine")} 
                disabled={selectedRows.length === 0}
              >
                Quarantine
              </Button>
              {selectedRows.length > 0 && selectedRows.some(id => {
                const threat = threats.find(t => Number(t.id) === id)
                return threat?.filePath
              }) && (
                <Dialog open={restrictDialogOpen["bulk"] || false} onOpenChange={(open) => {
                  setRestrictDialogOpen(prev => ({ ...prev, "bulk": open }))
                }}>
                  <DialogTrigger asChild>
                    <Button 
                      size="sm" 
                      variant="outline"
                      className="transition-all duration-200 hover:scale-105 active:scale-95"
                    >
                      Restrict Permissions
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Restrict File Permissions</DialogTitle>
                      <DialogDescription>
                        Restrict permissions on selected anomaly files without quarantining them. Choose the restriction level.
                      </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-4">
                      <div className="space-y-2">
                        <label className="text-sm font-medium">Selected Threats</label>
                        <p className="text-sm text-muted-foreground">
                          {selectedRows.length} threat(s) with file paths will have permissions restricted.
                        </p>
                      </div>
                      <div className="space-y-2">
                        <label className="text-sm font-medium">Permission Level</label>
                        <Select defaultValue="standard" onValueChange={async (level) => {
                          const threatsWithPaths = selectedRows
                            .map(id => threats.find(t => Number(t.id) === id))
                            .filter(t => t?.filePath) as typeof threats
                          
                          for (const threat of threatsWithPaths) {
                            if (threat.filePath) {
                              await handleRestrictPermissions(threat.filePath, level)
                            }
                          }
                          setRestrictDialogOpen(prev => ({ ...prev, "bulk": false }))
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
                        setRestrictDialogOpen(prev => ({ ...prev, "bulk": false }))
                      }}>
                        Close
                      </Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              )}
              <Button 
                size="sm" 
                variant="destructive" 
                className="transition-all duration-200 hover:scale-105 active:scale-95 disabled:scale-100"
                onClick={() => bulk("delete")} 
                disabled={selectedRows.length === 0}
              >
                Delete
              </Button>
              <Button 
                size="sm" 
                variant="secondary" 
                className="transition-all duration-200 hover:scale-105 active:scale-95 disabled:scale-100"
                onClick={() => bulk("allow")} 
                disabled={selectedRows.length === 0}
              >
                Allow
              </Button>
            </div>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8">Sel</TableHead>
                <TableHead>Time</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Severity</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {threats.slice(0, 15).map((t) => (
              <TableRow key={`${String(t.id)}-${String(t.time)}`} onClick={() => toggleSel(Number(t.id), !selectedRows.includes(Number(t.id)))}>
                <TableCell>
                  <input
                    type="checkbox"
                    checked={selectedRows.includes(Number(t.id))}
                    onChange={(e) => toggleSel(Number(t.id), e.currentTarget.checked)}
                    aria-label={`Select threat ${t.id}`}
                  />
                </TableCell>
                <TableCell>{new Date(t.time).toLocaleString()}</TableCell>
                <TableCell>{t.source}</TableCell>
                <TableCell>{t.action ?? "—"}</TableCell>
                <TableCell className="capitalize">{t.severity}</TableCell>
              </TableRow>
              ))}
              {threats.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-sm text-muted-foreground">No items yet.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card aria-label="Threat detail">
        <CardHeader>
          <CardTitle className="text-base">Detail</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {selectedRows.length === 0 && (
            <div className="text-muted-foreground">Select a row to view details.</div>
          )}
          {selectedRows.length > 0 && (
            <div className="space-y-3">
              {selectedRows.map((id) => {
                const item = threats.find((x) => Number(x.id) === id)
                if (!item) return null
                return (
                  <div key={`detail-${id}-${item.time}`} className="rounded border p-3 space-y-2">
                    <div><span className="text-muted-foreground">Description:</span> {item.description}</div>
                    <div><span className="text-muted-foreground">Source:</span> {item.source}</div>
                    <div><span className="text-muted-foreground">Severity:</span> <span className="capitalize">{item.severity}</span></div>
                    <div><span className="text-muted-foreground">Time:</span> {new Date(item.time).toLocaleString()}</div>
                    <div><span className="text-muted-foreground">Action:</span> {item.action ?? "—"}</div>
                    <div className="pt-2 flex gap-2 flex-wrap">
                      <Button 
                        size="sm" 
                        className="transition-all duration-200 hover:scale-105 active:scale-95"
                        onClick={() => handleAnalyze(id)}
                      >
                        Analyze Threat
                      </Button>
                      {item.filePath && (
                        <Dialog open={restrictDialogOpen[String(id)] || false} onOpenChange={(open) => {
                          setRestrictDialogOpen(prev => ({ ...prev, [String(id)]: open }))
                        }}>
                          <DialogTrigger asChild>
                            <Button 
                              size="sm" 
                              variant="outline"
                              className="transition-all duration-200 hover:scale-105 active:scale-95"
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
                                <p className="text-sm text-muted-foreground break-all">{item.filePath}</p>
                              </div>
                              <div className="space-y-2">
                                <label className="text-sm font-medium">Permission Level</label>
                                <Select defaultValue="standard" onValueChange={(level) => {
                                  handleRestrictPermissions(item.filePath!, level, String(id))
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
                                setRestrictDialogOpen(prev => ({ ...prev, [String(id)]: false }))
                              }}>
                                Cancel
                              </Button>
                            </DialogFooter>
                          </DialogContent>
                        </Dialog>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>
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
    </div>
  )
}
