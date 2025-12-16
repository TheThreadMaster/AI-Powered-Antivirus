"use client"

import { create } from "zustand"

export type ThreatSource = "ML" | "Snort" | "WebShield" | "Sandbox"

export interface ThreatItem {
  id: string
  time: string
  severity: "low" | "medium" | "high" | "critical"
  description: string
  source: ThreatSource
  action?: "quarantined" | "deleted" | "allowed" | "analyzed" | null
  filePath?: string
  url?: string
  deep_analysis?: { calls?: string[]; score?: number; verdict?: string }
}

export interface SystemMetricsPoint {
  t: number
  cpu: number
  mem: number
  disk: number
  netUp: number
  netDown: number
}

// WebSocket event typing
export interface WSMetricEvent { type: "metric"; data: SystemMetricsPoint }
export interface WSThreatEvent { type: "threat"; data: ThreatItem }
export interface WSThreatLevelEvent { type: "threatLevel"; data: number }
export interface WSConnectionUpdateEvent { type: "connection_update"; pid: number; process: string; remote: string; bytes_sec: number; timestamp?: string }

type AppState = {
  wsStatus: "connecting" | "open" | "closed" | "error"
  lastMetricAt: number | null
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
  overviewDerived?: {
    activeAlerts: number
    activeAlertsPct: number
    totalAlerts: number
    totalAlertsPct: number
    netDownPct: number
    netUpPct: number
    maxActive24h: number
    maxTotal24h: number
    lastUpdated: { active: number | null; total: number | null; net: number | null; health: number | null }
  }
  threats: ThreatItem[]
  metrics: SystemMetricsPoint[]
  blockedUrls: string[]
  connections: { pid: number; process: string; remote: string; bytes: number }[]
  snortAlerts: { sid: number; msg: string; src: string; dst: string; time: string }[]
  webshieldAlerts: { url: string; score: number; category: string; action: string; timestamp: string }[]
  scanStatus?: { enabled: boolean; paths: string[] }
  scanProgress?: { current_path?: string; files_scanned: number; timestamp?: string }
  threatReports: Array<{ interval_minutes: number; threats_count: number; threats: Array<{ path: string; verdict: string; risk: number; timestamp: string }>; timestamp: string }>
  sandboxJobs: { job_id: string; target?: string; status: string; percent: number; verdict?: string; calls?: string[]; score?: number }[]
  logs: { level: string; msg: string; time: string }[]
  selectedFile: File | null
  actions: {
    quarantine(ids: string[]): void
    delete(ids: string[]): void
    allow(ids: string[]): void
    toggleProtection(key: keyof AppState["overview"]["protection"], value: boolean): void
    setThreatLevel(level: number): void
    pushMetric(point: SystemMetricsPoint): void
    addThreat(t: ThreatItem): void
    upsertThreat(t: ThreatItem): void
    recomputeOverviewDerived(): void
    setWSStatus(status: AppState["wsStatus"]): void
    upsertConnection(u: { pid: number; process: string; remote: string; bytes_sec: number }): void
    addSnortAlert(a: { sid: number; msg: string; src: string; dst: string; time: string }): void
    addWebShieldAlert(a: { url: string; score: number; category: string; action: string; timestamp: string }): void
    setScanStatus(s: { enabled: boolean; paths: string[] }): void
    setScanProgress(p: { current_path?: string; files_scanned: number; timestamp?: string }): void
    addThreatReport(r: { interval_minutes: number; threats_count: number; threats: Array<{ path: string; verdict: string; risk: number; timestamp: string }>; timestamp: string }): void
    upsertSandboxProgress(j: { job_id: string; percent: number }): void
    setSandboxResult(j: { job_id: string; verdict: string; calls?: string[]; score?: number }): void
    pushLog(l: { level: string; msg: string; time: string }): void
    setSelectedFile(file: File | null): void
  }
}

export const useAppStore = create<AppState>((set, get) => ({
  wsStatus: "closed",
  lastMetricAt: null,
  overview: {
    threatLevel: 15,
    threatIndex: 42,
    activeThreats: 0,
    filesScanned: 0,
    networkAlerts: 0,
    protection: { scan: true, webshield: true, snort: true },
  },
  overviewDerived: {
    activeAlerts: 0,
    activeAlertsPct: 0,
    totalAlerts: 0,
    totalAlertsPct: 0,
    netDownPct: 0,
    netUpPct: 0,
    maxActive24h: 0,
    maxTotal24h: 0,
    lastUpdated: { active: null, total: null, net: null, health: null },
  },
  threats: [],
  metrics: [],
  blockedUrls: [],
  connections: [],
  snortAlerts: [],
  webshieldAlerts: [],
  scanStatus: undefined,
  scanProgress: undefined,
  threatReports: [],
  sandboxJobs: [],
  logs: [],
  selectedFile: null,
  actions: {
    quarantine: (ids) => {
      set(({ threats }) => ({
        threats: threats.map((t) => (ids.includes(t.id) ? { ...t, action: "quarantined" } : t)),
      }))
    },
    delete: (ids) => {
      set(({ threats }) => ({ threats: threats.filter((t) => !ids.includes(t.id)) }))
    },
    allow: (ids) => {
      set(({ threats }) => ({
        threats: threats.map((t) => (ids.includes(t.id) ? { ...t, action: "allowed" } : t)),
      }))
    },
    toggleProtection: (key, value) => {
      set(({ overview }) => ({ overview: { ...overview, protection: { ...overview.protection, [key]: value } } }))
    },
    setThreatLevel: (level) => {
      set(({ overview, overviewDerived }) => {
        const base =
          overviewDerived ?? {
            activeAlerts: 0,
            activeAlertsPct: 0,
            totalAlerts: 0,
            totalAlertsPct: 0,
            netDownPct: 0,
            netUpPct: 0,
            maxActive24h: 0,
            maxTotal24h: 0,
            lastUpdated: { active: null, total: null, net: null, health: null },
          }
        return {
          overview: { ...overview, threatLevel: level },
          overviewDerived: { ...base, lastUpdated: { ...base.lastUpdated, health: Date.now() } },
        }
      })
      get().actions.recomputeOverviewDerived()
    },
    pushMetric: (point) => {
      set(({ metrics }) => {
        const now = Date.now()
        // Keep only last 10 minutes of data (reduced from 15 for better memory performance)
        const cutoff = now - (10 * 60 * 1000)
        const filtered = metrics.filter(m => m.t >= cutoff)
        // Limit to max 30 points (reduced from 60 for better memory/CPU performance)
        const limited = filtered.slice(-30)
        return { metrics: [...limited, point].slice(-30), lastMetricAt: point.t }
      })
      get().actions.recomputeOverviewDerived()
    },
    addThreat: (t) => {
      set(({ threats }) => {
        const now = Date.now()
        const cutoff = now - (7 * 24 * 60 * 60 * 1000) // Keep only last 7 days
        const filtered = threats.filter(th => {
          try {
            return new Date(th.time).getTime() >= cutoff
          } catch {
            return false
          }
        })
        return { threats: [t, ...filtered].slice(0, 200) } // Keep max 200 threats (reduced from 500 for memory)
      })
      get().actions.recomputeOverviewDerived()
    },
    upsertThreat: (t) => {
      set(({ threats }) => {
        const now = Date.now()
        const cutoff = now - (7 * 24 * 60 * 60 * 1000) // Keep only last 7 days
        let filtered = threats.filter(th => {
          try {
            return new Date(th.time).getTime() >= cutoff
          } catch {
            return false
          }
        })
        const idx = filtered.findIndex((x) => x.id === t.id)
        if (idx >= 0) filtered[idx] = { ...filtered[idx], ...t }
        else filtered = [t, ...filtered].slice(0, 500)
        return { threats: filtered }
      })
      get().actions.recomputeOverviewDerived()
    },
    recomputeOverviewDerived: () => {
      const { threats, metrics, overview } = get()
      const now = Date.now()
      const cutoff = now - 24 * 60 * 60 * 1000
      // Clean up old threats during recompute
      const recentThreats = threats.filter((t) => {
        try {
          return new Date(t.time).getTime() >= cutoff
        } catch {
          return false
        }
      })
      
      // Auto-cleanup old threats if store has too many (cleanup separately)
      if (threats.length > recentThreats.length + 50) {
        const cleanupCutoff = now - (7 * 24 * 60 * 60 * 1000) // Keep last 7 days
        const cleaned = threats.filter((t) => {
          try {
            return new Date(t.time).getTime() >= cleanupCutoff
          } catch {
            return false
          }
        })
        if (cleaned.length < threats.length) {
          set({ threats: cleaned.slice(0, 500) })
        }
      }
      const activeAlerts = recentThreats.filter((t) => t.action !== "allowed").length
      const totalAlerts = recentThreats.length
      const prevMaxActive = get().overviewDerived?.maxActive24h || 0
      const prevMaxTotal = get().overviewDerived?.maxTotal24h || 0
      const activeMax24h = Math.max(prevMaxActive, activeAlerts)
      const totalMax24h = Math.max(prevMaxTotal, totalAlerts)
      const activeAlertsPct = activeMax24h > 0 ? Math.min(100, Math.round((activeAlerts / activeMax24h) * 100)) : 0
      const totalAlertsPct = totalMax24h > 0 ? Math.min(100, Math.round((totalAlerts / totalMax24h) * 100)) : 0

      // Network usage: normalize against 24h max, use latest metric for percentages
      const recentMetrics = metrics.filter((m) => m.t >= cutoff)
      const maxUp = recentMetrics.reduce((mx, m) => Math.max(mx, m.netUp), 0) || 1
      const maxDown = recentMetrics.reduce((mx, m) => Math.max(mx, m.netDown), 0) || 1
      const last = recentMetrics[recentMetrics.length - 1]
      const netUpPct = Math.min(100, Math.round(((last?.netUp || 0) / maxUp) * 100))
      const netDownPct = Math.min(100, Math.round(((last?.netDown || 0) / maxDown) * 100))

      // Last updated timestamps: use newest threat time and latest metric timestamp
      const newestThreatTs = recentThreats.length
        ? recentThreats.reduce((mx, t) => Math.max(mx, new Date(t.time).getTime()), 0)
        : null

      set(({ overviewDerived }) => ({
        overviewDerived: {
          activeAlerts,
          activeAlertsPct,
          totalAlerts,
          totalAlertsPct,
          netDownPct,
          netUpPct,
          maxActive24h: activeMax24h,
          maxTotal24h: totalMax24h,
          lastUpdated: {
            active: newestThreatTs ?? overviewDerived?.lastUpdated?.active ?? null,
            total: newestThreatTs ?? overviewDerived?.lastUpdated?.total ?? null,
            net: last ? last.t : overviewDerived?.lastUpdated?.net ?? null,
            health: overviewDerived?.lastUpdated?.health ?? null,
          },
        },
        overview: { ...overview, activeThreats: activeAlerts, networkAlerts: overview.networkAlerts },
      }))
    },
      setWSStatus: (status) => set(() => ({ wsStatus: status })),
    upsertConnection: (u) =>
      set(({ connections }) => {
        // Cleanup old connections periodically (keep max 50, remove oldest)
        const connectionsList = [...connections]
        const idx = connectionsList.findIndex((c) => c.pid === u.pid && c.remote === u.remote)
        const next = { pid: u.pid, process: u.process, remote: u.remote, bytes: u.bytes_sec }
        if (idx >= 0) connectionsList[idx] = next
        else connectionsList.unshift(next)
        // Keep only most recent 50 connections
        return { connections: connectionsList.slice(0, 50) }
      }),
    addSnortAlert: (a) => set(({ snortAlerts }) => {
      const now = Date.now()
      const cutoff = now - (24 * 60 * 60 * 1000) // Keep only last 24 hours
      const filtered = snortAlerts.filter(alert => {
        try {
          return new Date(alert.time).getTime() >= cutoff
        } catch {
          return false
        }
      })
      return { snortAlerts: [a, ...filtered].slice(0, 100) } // Keep max 100 alerts
    }),
      addWebShieldAlert: (a) =>
        set(({ webshieldAlerts, blockedUrls }) => {
          const now = Date.now()
          const cutoff = now - (7 * 24 * 60 * 60 * 1000) // Keep only last 7 days
          const filteredAlerts = webshieldAlerts.filter(alert => {
            try {
              return new Date(alert.timestamp).getTime() >= cutoff
            } catch {
              return false
            }
          })
          // Keep unique blocked URLs, max 100
          const newBlockedUrls = a.action === "blocked" 
            ? Array.from(new Set([a.url, ...blockedUrls])).slice(0, 100)
            : blockedUrls
          return {
            webshieldAlerts: [a, ...filteredAlerts].slice(0, 100),
            blockedUrls: newBlockedUrls,
          }
        }),
    setScanStatus: (s) => set(() => ({ scanStatus: s })),
    setScanProgress: (p) => set(() => ({ scanProgress: p })),
    addThreatReport: (r) => set(({ threatReports }) => {
      // Keep only last 10 threat reports
      return { threatReports: [r, ...threatReports].slice(0, 10) }
    }),
    upsertSandboxProgress: (j) =>
      set(({ sandboxJobs }) => {
        // Keep only active jobs and recently completed ones (last 50)
        const activeJobs = sandboxJobs.filter(job => job.status === "running" || job.status === "pending")
        const completedJobs = sandboxJobs.filter(job => job.status === "done" || job.status === "failed").slice(0, 40)
        const allJobs = [...activeJobs, ...completedJobs]
        const idx = allJobs.findIndex((x) => x.job_id === j.job_id)
        if (idx >= 0) allJobs[idx] = { ...allJobs[idx], percent: j.percent, status: "running" }
        else allJobs.unshift({ job_id: j.job_id, status: "running", percent: j.percent })
        return { sandboxJobs: allJobs.slice(0, 50) }
      }),
    setSandboxResult: (j) =>
      set(({ sandboxJobs }) => {
        const idx = sandboxJobs.findIndex((x) => x.job_id === j.job_id)
        if (idx >= 0) sandboxJobs[idx] = { ...sandboxJobs[idx], verdict: j.verdict, calls: j.calls, score: j.score, status: "done", percent: 100 }
        return { sandboxJobs }
      }),
    pushLog: (l) => set(({ logs }) => {
      const now = Date.now()
      const cutoff = now - (24 * 60 * 60 * 1000) // Keep only last 24 hours
      const filtered = logs.filter(log => {
        try {
          return new Date(log.time).getTime() >= cutoff
        } catch {
          return false
        }
      })
      return { logs: [{ level: l.level, msg: l.msg, time: l.time }, ...filtered].slice(0, 200) } // Keep max 200 logs
    }),
    setSelectedFile: (file) => set(() => ({ selectedFile: file })),
  },
}))
