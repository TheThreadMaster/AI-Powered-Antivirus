"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { useAppStore } from "@/store/app-store"
import { useMemo, useState } from "react"
import useSWR from "swr"
import { fetcher, api } from "@/lib/api"
import { toast } from "sonner"
import InfoIcon from "@/components/InfoIcon"

export default function NetworkPanel() {
  const connections = useAppStore((s) => s.connections)
  type Connection = { pid: number; process: string; remote: string; bytes: number }
  type SnortAlert = { sid: number; msg: string; src: string; dst: string; time: string }
  const snortAlerts = useAppStore((s) => s.snortAlerts as SnortAlert[])
  const total = useMemo(() => connections.reduce((a, b) => a + b.bytes, 0) || 1, [connections])
  const [blockTarget, setBlockTarget] = useState<string | null>(null)
  useSWR<Connection[]>("/api/network/connections", fetcher, {
    refreshInterval: 15000, // 15 seconds refresh rate (slower update for network module)
    revalidateOnFocus: false,
    revalidateOnReconnect: true,
    onSuccess(data) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      useAppStore.setState({ connections: data })
    },
  })
  return (
    <div className="grid gap-4 md:grid-cols-3" aria-label="Network analysis">
      <Card aria-label="Connections" className="bg-card/40 backdrop-blur-md border-border/50 transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5">
        <CardHeader>
          <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent flex items-center gap-2">
            Connections
            <InfoIcon description="Monitors active network connections, showing process IDs, remote addresses, and data usage. Helps identify suspicious network activity and potential data exfiltration attempts." />
          </CardTitle>
        </CardHeader>
        <CardContent>
          {connections.length === 0 ? (
            <span className="text-sm text-muted-foreground">No active connections.</span>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>PID</TableHead>
                  <TableHead>Process</TableHead>
                  <TableHead>Remote</TableHead>
                  <TableHead>Usage</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {connections.slice(0, 8).map((c, idx) => (
                  <TableRow 
                    key={`${c.pid}-${c.remote}`}
                    className="transition-all duration-300 animate-in fade-in slide-in-from-left-4"
                    style={{ animationDelay: `${idx * 50}ms` }}
                  >
                    <TableCell>{c.pid}</TableCell>
                    <TableCell>{c.process}</TableCell>
                    <TableCell className="max-w-[220px] truncate">{c.remote}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-32 overflow-hidden rounded bg-secondary">
                          <div className="h-full bg-primary" style={{ width: `${(c.bytes / total) * 100}%` }} />
                        </div>
                        <span className="tabular-nums text-xs text-muted-foreground">{c.bytes} B/s</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <Dialog>
                        <DialogTrigger asChild>
                          <Button 
                            variant="destructive" 
                            size="sm" 
                            className="transition-all duration-200 hover:scale-105 active:scale-95"
                            onClick={() => setBlockTarget(c.remote)}
                          >
                            Block IP
                          </Button>
                        </DialogTrigger>
                        <DialogContent>
                          <DialogHeader>
                            <DialogTitle>Block {blockTarget}</DialogTitle>
                          </DialogHeader>
                          <DialogFooter>
                            <Button 
                              variant="secondary" 
                              className="transition-all duration-200 hover:scale-105 active:scale-95"
                              onClick={() => setBlockTarget(null)}
                            >
                              Cancel
                            </Button>
                            <Button
                              variant="destructive"
                              className="transition-all duration-200 hover:scale-105 active:scale-95"
                              onClick={async () => {
                                if (!blockTarget) return
                                const prev = connections
                                useAppStore.setState({ connections: prev.filter((p) => p.remote !== blockTarget) })
                                try {
                                  await api.post("/api/network/block", { remote: blockTarget })
                                  toast.success("Blocked IP")
                                } catch {
                                  useAppStore.setState({ connections: prev })
                                  toast.error("Block failed")
                                } finally {
                                  setBlockTarget(null)
                                }
                              }}
                            >
                              Confirm
                            </Button>
                          </DialogFooter>
                        </DialogContent>
                      </Dialog>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card aria-label="Top talkers" className="bg-card/40 backdrop-blur-md border-border/50 transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5">
        <CardHeader>
          <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">Top Talkers</CardTitle>
        </CardHeader>
        <CardContent className="text-sm">
          {connections.length === 0 ? (
            <div className="text-muted-foreground">No data</div>
          ) : (
            <div className="space-y-2">
              {connections
                .slice(0, 5)
                .sort((a, b) => b.bytes - a.bytes)
                .map((c, idx) => (
                  <div 
                    key={`${c.pid}-${c.remote}`} 
                    className="flex items-center gap-2 rounded-md border border-border/30 bg-muted/20 p-2 transition-all duration-300 animate-in fade-in slide-in-from-left-4 hover:bg-muted/30"
                    style={{ animationDelay: `${idx * 50}ms` }}
                  >
                    <span className="w-40 truncate">{c.process}</span>
                    <div className="h-1.5 w-40 overflow-hidden rounded bg-secondary">
                      <div className="h-full bg-blue-500" style={{ width: `${(c.bytes / total) * 100}%` }} />
                    </div>
                    <span className="tabular-nums w-16 text-right">{c.bytes}</span>
                  </div>
                ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card aria-label="Snort alerts" className="bg-card/40 backdrop-blur-md border-border/50 transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5">
        <CardHeader>
          <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent flex items-center gap-2">
            Snort IDS
            <InfoIcon description="Displays intrusion detection alerts from Snort IDS. Shows detected network attacks, suspicious patterns, and security rule violations in real-time." />
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex items-center justify-between rounded-md border border-border/30 bg-muted/20 p-2">
            <div>
              <span className="font-medium">Active Protection</span>
              <p className="text-xs text-muted-foreground mt-0.5">Monitors network traffic for threats</p>
            </div>
            <Switch
              checked={useAppStore((s) => s.overview.protection.snort)}
              onCheckedChange={async (v) => {
                const prev = useAppStore.getState().overview.protection.snort
                useAppStore.getState().actions.toggleProtection("snort", v)
                try {
                  await api.post("/api/settings/protection", { module: "snort", enabled: v })
                  toast.success(v ? "Snort IDS enabled - Network monitoring active" : "Snort IDS disabled")
                } catch {
                  useAppStore.getState().actions.toggleProtection("snort", prev)
                  toast.error("Failed to toggle Snort IDS")
                }
              }}
            />
          </div>
          {useAppStore((s) => s.overview.protection.snort) && (
            <div className="rounded-md bg-emerald-500/10 border border-emerald-500/20 p-2 text-xs">
              <span className="text-emerald-600 dark:text-emerald-400 font-medium">✓ Active:</span>
              <span className="text-muted-foreground ml-1">Monitoring network traffic for intrusion attempts</span>
            </div>
          )}
          <div className="space-y-2">
            {snortAlerts.length === 0 ? (
              <div className="text-muted-foreground">No alerts</div>
            ) : (
              snortAlerts.slice(0, 6).map((a, i) => (
                <div 
                  key={i} 
                  className="flex items-center justify-between gap-2 rounded-md border border-red-500/20 bg-red-500/5 p-2 transition-all duration-300 animate-in fade-in slide-in-from-left-4 hover:bg-red-500/10"
                  style={{ animationDelay: `${i * 50}ms` }}
                >
                  <span className="max-w-[220px] truncate">{a.msg}</span>
                  <span className="text-muted-foreground text-xs">{a.src} → {a.dst}</span>
                  <span className="text-xs">{a.time}</span>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
