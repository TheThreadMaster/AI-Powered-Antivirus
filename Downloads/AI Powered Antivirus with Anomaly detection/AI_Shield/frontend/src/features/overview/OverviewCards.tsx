"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppStore } from "@/store/app-store"
import { Activity, AlertTriangle, Cpu, Wifi } from "lucide-react"

function StatBadge({ value, label, color }: { value: number; label: string; color: string }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span
        className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium"
        style={{ backgroundColor: `${color}22`, color, border: `1px solid ${color}55` }}
        aria-label={`${label} ${value}%`}
      >
        {value.toFixed(0)}%
      </span>
      <span className="text-muted-foreground">{label}</span>
    </div>
  )
}

export default function OverviewCards() {
  const overview = useAppStore((s) => s.overview)
  const derived = useAppStore((s) => s.overviewDerived)
  const systemHealth = Math.max(0, 100 - (overview.threatLevel || 0))
  const lastUpdated = derived?.lastUpdated || { active: null, total: null, net: null, health: null }
  const fmt = (ms: number | null) => (ms ? new Date(ms).toLocaleTimeString() : "—")

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Card className="group relative overflow-hidden transition-all duration-300 hover:-translate-y-1 hover:shadow-xl hover:shadow-red-500/10 border-red-500/20" aria-label="Active Alerts">
        <span className="absolute left-0 top-0 h-full w-1.5 bg-gradient-to-b from-red-500 to-red-600 group-hover:from-red-400 group-hover:to-red-500 transition-colors" />
        <div className="absolute inset-0 pointer-events-none opacity-5 group-hover:opacity-10 transition-opacity" style={{ background: 'radial-gradient(120px 80px at 20% -20%, var(--accent-red), transparent 70%)' }} />
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm font-semibold">
            <AlertTriangle className="size-4" color="var(--accent-red)" /> Active Alerts
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-4xl font-bold tracking-tight bg-gradient-to-br from-foreground to-foreground/80 bg-clip-text text-transparent group-hover:from-red-600 group-hover:to-red-500 transition-all duration-300">
            {derived?.activeAlerts ?? 0}
          </div>
          <div className="mt-2 flex items-center justify-between">
            <StatBadge value={derived?.activeAlertsPct ?? 0} label="24h normalized" color="var(--accent-red)" />
            <span className="text-[11px] text-muted-foreground">Last Updated: {fmt(lastUpdated.active)}</span>
          </div>
        </CardContent>
      </Card>

      <Card className="group relative overflow-hidden transition-all duration-300 hover:-translate-y-1 hover:shadow-xl hover:shadow-orange-500/10 border-orange-500/20" aria-label="Total Alerts">
        <span className="absolute left-0 top-0 h-full w-1.5 bg-gradient-to-b from-orange-500 to-orange-600 group-hover:from-orange-400 group-hover:to-orange-500 transition-colors" />
        <div className="absolute inset-0 pointer-events-none opacity-5 group-hover:opacity-10 transition-opacity" style={{ background: 'radial-gradient(120px 80px at 20% -20%, var(--accent-orange), transparent 70%)' }} />
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm font-semibold">
            <Activity className="size-4" color="var(--accent-orange)" /> Total Alerts
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-4xl font-bold tracking-tight bg-gradient-to-br from-foreground to-foreground/80 bg-clip-text text-transparent group-hover:from-orange-600 group-hover:to-orange-500 transition-all duration-300">
            {derived?.totalAlerts ?? 0}
          </div>
          <div className="mt-2 flex items-center justify-between">
            <StatBadge value={derived?.totalAlertsPct ?? 0} label="24h normalized" color="var(--accent-orange)" />
            <span className="text-[11px] text-muted-foreground">Last Updated: {fmt(lastUpdated.total)}</span>
          </div>
        </CardContent>
      </Card>

      <Card className="group relative overflow-hidden transition-all duration-300 hover:-translate-y-1 hover:shadow-xl hover:shadow-teal-500/10 border-teal-500/20" aria-label="System Health">
        <span className="absolute left-0 top-0 h-full w-1.5 bg-gradient-to-b from-teal-500 to-teal-600 group-hover:from-teal-400 group-hover:to-teal-500 transition-colors" />
        <div className="absolute inset-0 pointer-events-none opacity-5 group-hover:opacity-10 transition-opacity" style={{ background: 'radial-gradient(120px 80px at 20% -20%, var(--accent-teal), transparent 70%)' }} />
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm font-semibold">
            <Cpu className="size-4" color="var(--accent-teal)" /> System Health
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-4xl font-bold tracking-tight bg-gradient-to-br from-foreground to-foreground/80 bg-clip-text text-transparent group-hover:from-teal-600 group-hover:to-teal-500 transition-all duration-300">
            {systemHealth.toFixed(0)}%
          </div>
          <div className="mt-2 flex items-center justify-between">
            <StatBadge value={systemHealth} label="Overall" color="var(--accent-teal)" />
            <span className="text-[11px] text-muted-foreground">Last Updated: {fmt(lastUpdated.health)}</span>
          </div>
        </CardContent>
      </Card>

      <Card className="group relative overflow-hidden transition-all duration-300 hover:-translate-y-1 hover:shadow-xl hover:shadow-blue-500/10 border-blue-500/20" aria-label="Network Usage">
        <span className="absolute left-0 top-0 h-full w-1.5 bg-gradient-to-b from-blue-500 to-blue-600 group-hover:from-blue-400 group-hover:to-blue-500 transition-colors" />
        <div className="absolute inset-0 pointer-events-none opacity-5 group-hover:opacity-10 transition-opacity" style={{ background: 'radial-gradient(120px 80px at 20% -20%, var(--accent-blue), transparent 70%)' }} />
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm font-semibold">
            <Wifi className="size-4" color="var(--accent-blue)" /> Network Usage
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-4xl font-bold tracking-tight bg-gradient-to-br from-foreground to-foreground/80 bg-clip-text text-transparent group-hover:from-blue-600 group-hover:to-blue-500 transition-all duration-300">
            {(derived?.netDownPct ?? 0).toFixed(0)}%
          </div>
          <div className="mt-2 flex items-center justify-between">
            <StatBadge value={derived?.netDownPct ?? 0} label="Downlink" color="var(--accent-blue)" />
            <span className="text-[11px] text-muted-foreground">Last Updated: {fmt(lastUpdated.net)}</span>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
