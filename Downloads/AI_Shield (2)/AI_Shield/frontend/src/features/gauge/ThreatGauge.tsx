"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppStore } from "@/store/app-store"
import { PolarAngleAxis, RadialBar, RadialBarChart } from "recharts"
import { useState, useEffect, useMemo } from "react"
import { Badge } from "@/components/ui/badge"

function GaugeNeedle({ cx, cy, angle, length }: { cx: number; cy: number; angle: number; length: number }) {
  const rad = (Math.PI / 180) * angle
  const x = cx + length * Math.cos(rad)
  const y = cy + length * Math.sin(rad)
  return (
    <g>
      <line x1={cx} y1={cy} x2={x} y2={y} stroke="#e2e8f0" strokeWidth={3} strokeLinecap="round" />
      <circle cx={cx} cy={cy} r={4} fill="#e2e8f0" />
    </g>
  )
}

export default function ThreatGauge() {
  const level = useAppStore((s) => s.overview.threatLevel)
  const risk = Math.max(0, Math.min(1, level / 100))
  const data = [{ name: "risk", value: risk * 100 }]
  const threats = useAppStore((s) => s.threats)
  const derived = useAppStore((s) => s.overviewDerived)
  const lastUpdated = derived?.lastUpdated?.health || null
  
  // Store threat history - keep more items
  const [threatHistory, setThreatHistory] = useState<typeof threats>([])

  // Update history when new threats arrive
  useEffect(() => {
    if (threats.length > 0) {
      setThreatHistory((prev) => {
        const now = Date.now()
        const cutoff = now - (24 * 60 * 60 * 1000) // Keep only last 24 hours
        // Filter out old threats first
        const recentPrev = prev.filter(t => {
          try {
            return new Date(t.time).getTime() >= cutoff
          } catch {
            return false
          }
        })
        const newThreats = threats.filter((t) => !recentPrev.find((p) => p.id === t.id))
        if (newThreats.length > 0) {
          const combined = [...newThreats, ...recentPrev].slice(0, 20) // Keep last 20 threats
          return combined
        }
        return recentPrev.slice(0, 20)
      })
    }
  }, [threats])

  const sev = risk < 0.3 ? "Low" : risk < 0.6 ? "Medium" : risk < 0.8 ? "High" : "Critical"
  const color = risk < 0.3 ? "#22c55e" : risk < 0.6 ? "#eab308" : risk < 0.8 ? "#f59e0b" : "#ef4444"
  
  const severityColors = {
    low: "#1FB6AB",
    medium: "#FF9F43",
    high: "#4F8DF7",
    critical: "#FF5C57",
  }

  return (
    <Card aria-label="Threat Index gauge" className="transition-all duration-300 hover:-translate-y-1 hover:shadow-xl bg-card/40 backdrop-blur-md border-border/50 h-full flex flex-col">
      <CardHeader className="pb-2">
        <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">Threat Index</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 flex-1 min-h-0">
        <div className="flex flex-col items-center gap-3">
          <div className="mx-auto h-40 w-40">
            <RadialBarChart width={160} height={160} innerRadius={56} outerRadius={68} data={data} startAngle={225} endAngle={-45}>
              <PolarAngleAxis type="number" domain={[0, 100]} dataKey="value" tick={false} />
              {/* Severity zones: Low(0-30), Medium(30-60), High(60-80), Critical(80-100) */}
              <RadialBar dataKey={() => 30} cornerRadius={10} fill="#22c55e22" background={false} />
              <RadialBar dataKey={() => 30} cornerRadius={10} fill="#eab30822" background={false} />
              <RadialBar dataKey={() => 20} cornerRadius={10} fill="#f59e0b22" background={false} />
              <RadialBar dataKey={() => 20} cornerRadius={10} fill="#ef444422" background={false} />
              {/* Actual value track */}
              <RadialBar dataKey="value" cornerRadius={10} fill={color} background={{ fill: "#2a2f35" }} isAnimationActive />
              {/* Custom needle */}
              <GaugeNeedle cx={80} cy={80} angle={225 - risk * 270} length={48} />
            </RadialBarChart>
          </div>
          <div className="text-center w-full">
            <div className="text-3xl font-bold tabular-nums bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">{level.toFixed(0)}</div>
            <div className="mt-1 text-sm font-medium" style={{ color }}>Severity: {sev}</div>
            <div className="mt-1.5 text-[11px] text-muted-foreground">Updated: {lastUpdated ? new Date(lastUpdated).toLocaleTimeString() : "—"}</div>
          </div>
        </div>
        
        {/* Threat History - Compact version */}
        {threatHistory.length > 0 && (
          <div className="flex-1 min-h-0 flex flex-col space-y-1.5 border-t border-border/30 pt-2">
            <div className="flex items-center justify-between">
              <div className="text-xs font-semibold text-foreground">History</div>
              <div className="text-[10px] text-muted-foreground">{threatHistory.length}</div>
            </div>
            <div className="flex-1 overflow-y-auto space-y-1 pr-1 scrollbar-thin">
              {threatHistory.slice(0, 12).map((t, idx) => {
                const barColor = severityColors[t.severity]
                return (
                  <div
                    key={t.id}
                    className="rounded-md border border-border/50 bg-muted/20 p-1.5 backdrop-blur-sm transition-all duration-300 hover:bg-muted/30 hover:border-border/70 animate-in fade-in slide-in-from-right-4"
                    style={{
                      animationDelay: `${idx * 50}ms`,
                      boxShadow: `inset 2px 0 0 0 ${barColor}`,
                    }}
                  >
                    <div className="flex items-start justify-between gap-1.5">
                      <div className="flex-1 min-w-0">
                        <div className="truncate text-[11px] font-medium text-foreground">{t.description ?? "—"}</div>
                        <div className="mt-0.5 flex items-center gap-1.5 flex-wrap">
                          <span className="text-[9px] text-muted-foreground">{t.source}</span>
                          <Badge 
                            variant="outline" 
                            className="text-[9px] px-1 py-0 h-auto capitalize border-0"
                            style={{ 
                              backgroundColor: `${barColor}22`, 
                              color: barColor,
                              borderColor: `${barColor}44`
                            }}
                          >
                            {t.severity}
                          </Badge>
                        </div>
                      </div>
                      <span className="text-[9px] text-muted-foreground whitespace-nowrap shrink-0">
                        {new Date(t.time).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
