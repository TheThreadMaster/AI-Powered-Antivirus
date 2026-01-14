"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useEffect, useState } from "react"
import { useAppStore } from "@/store/app-store"
import useSWR, { mutate } from "swr"
import { fetcher, api } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Switch } from "@/components/ui/switch"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts"
import { toast } from "sonner"
import InfoIcon from "@/components/InfoIcon"

export default function WebShieldPanel() {
  const [mounted, setMounted] = useState(false)
  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 0)
    return () => clearTimeout(t)
  }, [])
  type Alert = { url: string; score: number; category: string; action: string; timestamp: string; os_blocked?: boolean }
  type BlockedUrl = { id?: number; url: string; host: string; score: number; category: string; os_blocked: boolean; created: string }
  const alerts = useAppStore((s) => s.webshieldAlerts as Alert[])
  const protection = useAppStore((s) => s.overview.protection)
  const { data: blockedUrls, mutate: mutateBlocked } = useSWR<BlockedUrl[]>("/api/webshield/blocked", fetcher, {
    refreshInterval: 5000, // 5 seconds refresh rate (optimized for CPU)
    revalidateOnFocus: true,
    onSuccess(data) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      useAppStore.setState({ blockedUrls: data?.map(b => b.url) || [] })
    },
  })
  useSWR<Alert[]>("/api/network/webshield/alerts", fetcher, {
    onSuccess(data) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      useAppStore.setState({ webshieldAlerts: data })
    },
  })
  const data = [
    { name: "Phishing", value: alerts.filter((a) => a.category === "phishing").length, color: "var(--accent-red)" },
    { name: "Malware", value: alerts.filter((a) => a.category === "malware").length, color: "var(--accent-blue)" },
    { name: "Scam", value: alerts.filter((a) => a.category === "scam").length, color: "var(--accent-orange)" },
  ]
  const total = data.reduce((a, b) => a + b.value, 0) || 1
  return (
    <div className="grid gap-4 md:grid-cols-2" aria-label="AI WebShield">
      <Card aria-label="Recent URLs">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            Recent URLs
            <InfoIcon description="Monitors and analyzes web URLs in real-time, detecting phishing attempts, malware distribution sites, and scam websites. Automatically blocks malicious URLs to protect your system." />
          </CardTitle>
        </CardHeader>
        <CardContent>
          {alerts.length === 0 ? (
            <div className="text-sm text-muted-foreground">No alerts</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>URL</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>OS Block</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {alerts.slice(0, 8).map((a, i) => (
                  <TableRow key={i}>
                    <TableCell className="max-w-[320px] truncate">{a.url}</TableCell>
                    <TableCell>{Math.round(a.score * 100)}%</TableCell>
                    <TableCell>{a.category}</TableCell>
                    <TableCell>
                      <Badge className="bg-red-500 text-white">{a.action}</Badge>
                    </TableCell>
                    <TableCell>{a.os_blocked ? "yes" : "no"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card aria-label="Shield">
        <CardHeader>
          <CardTitle className="text-base">Shield</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-medium">Active Protection</span>
                <p className="text-xs text-muted-foreground mt-0.5">Automatically blocks risky URLs</p>
              </div>
              <Switch
                checked={protection.webshield}
                onCheckedChange={async (v) => {
                  const prev = protection.webshield
                  useAppStore.getState().actions.toggleProtection("webshield", v)
                  try {
                    // Update both endpoints to keep state in sync
                    await Promise.all([
                      api.post("/api/network/webshield/toggle", { enabled: v }),
                      api.post("/api/settings/protection", { module: "webshield", enabled: v })
                    ])
                    toast.success(v ? "WebShield enabled - URLs will be actively blocked" : "WebShield disabled")
                  } catch {
                    useAppStore.getState().actions.toggleProtection("webshield", prev)
                    toast.error("Failed to toggle WebShield")
                  }
                }}
              />
            </div>
            {protection.webshield && (
              <div className="rounded-md bg-emerald-500/10 border border-emerald-500/20 p-2 text-xs">
                <span className="text-emerald-600 dark:text-emerald-400 font-medium">✓ Active:</span>
                <span className="text-muted-foreground ml-1">Risky URLs are automatically detected and blocked at OS level</span>
              </div>
            )}
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Input placeholder="Enter URL to block permanently (e.g., http://example.com)" className="h-9" id="block-url" />
              <Button
                className="h-9 transition-all duration-200 hover:scale-105 active:scale-95"
                variant="destructive"
                onClick={async () => {
                const el = document.getElementById("block-url") as HTMLInputElement | null
                const url = el?.value || ""
                if (!url) return
                try {
                  const { data } = await api.post("/api/network/webshield/block", { url })
                  if (data && data.ok) {
                    mutateBlocked()
                    mutate("/api/network/webshield/alerts")
                    const message = data.os_block ? 
                      "URL permanently blocked at OS level" : 
                      (data.message || "URL added to blocked list")
                    toast.success(message)
                  } else {
                    toast.error(data?.message || "Failed to block URL")
                  }
                  if (el) el.value = ""
                } catch (err) {
                  console.error("[WebShield] block failed", err)
                  mutateBlocked()
                  mutate("/api/network/webshield/alerts")
                  const errMessage = (err as any)?.response?.data?.message || 
                                    (err instanceof Error ? err.message : "Failed to block URL. May require admin privileges.")
                  toast.error(errMessage)
                }
              }}
            >
              Block Permanently
            </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              This will permanently block the URL at the OS level (modifies hosts file). Requires administrator privileges.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card aria-label="Blocked URLs History" className="md:col-span-2">
        <CardHeader>
          <CardTitle className="text-base">Blocked URLs History</CardTitle>
        </CardHeader>
        <CardContent>
          {blockedUrls && blockedUrls.length > 0 ? (
            <div className="max-h-64 overflow-y-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>URL</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>OS Blocked</TableHead>
                    <TableHead>Blocked Date</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {blockedUrls.slice(0, 20).map((b) => (
                    <TableRow key={b.id || b.url}>
                      <TableCell className="max-w-[200px] truncate">{b.url}</TableCell>
                      <TableCell className="max-w-[150px] truncate">{b.host}</TableCell>
                      <TableCell>{Math.round(b.score * 100)}%</TableCell>
                      <TableCell>
                        <Badge variant={b.category === "phishing" ? "destructive" : "secondary"}>{b.category}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={b.os_blocked ? "bg-green-500 text-white" : "bg-yellow-500 text-white"}>
                          {b.os_blocked ? "Yes" : "No"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">{new Date(b.created).toLocaleDateString()}</TableCell>
                      <TableCell>
                        {b.id && (
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 text-xs transition-all duration-200 hover:scale-105 active:scale-95"
                            onClick={async () => {
                              try {
                                await api.delete(`/api/webshield/blocked/${b.id}`)
                                mutateBlocked()
                                toast.success("URL unblocked")
                              } catch (e) {
                                toast.error("Failed to unblock URL")
                              }
                            }}
                          >
                            Unblock
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="text-sm text-muted-foreground text-center py-4">No blocked URLs yet</div>
          )}
        </CardContent>
      </Card>

      <Card aria-label="Risk breakdown" className="overflow-hidden md:col-span-2">
        <CardHeader>
          <CardTitle className="text-base">Risk Breakdown</CardTitle>
        </CardHeader>
        <CardContent className="h-72 min-w-0 overflow-hidden">
          <div className="flex flex-row items-center gap-6 justify-start w-full h-full">
            {mounted ? (
              <div className="w-[260px] h-[260px] flex-shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Tooltip contentStyle={{ background: "var(--card)", border: "1px solid var(--border)" }} />
                    <Pie data={data} innerRadius={60} outerRadius={90} paddingAngle={3} dataKey="value" strokeWidth={2}>
                      {data.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color as string} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="w-[260px] h-[260px] flex-shrink-0" />
            )}
            <div className="space-y-2 text-sm">
              {data.map((d) => (
                <div key={d.name} className="flex items-center gap-2">
                  <span className="size-2 rounded-full" style={{ backgroundColor: d.color }} />
                  <span className="w-24">{d.name}</span>
                  <span className="tabular-nums">{d.value}</span>
                  <span className="text-muted-foreground">({((d.value / total) * 100).toFixed(0)}%)</span>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
