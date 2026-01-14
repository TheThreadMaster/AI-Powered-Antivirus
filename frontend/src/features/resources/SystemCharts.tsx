"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppStore } from "@/store/app-store"
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid, Legend, PieChart, Pie, Cell } from "recharts"
import type { SystemMetricsPoint, ThreatSource, ThreatItem } from "@/store/app-store"
import { useEffect, useState, useMemo, useRef } from "react"
import useSWR from "swr"
import { fetcher } from "@/lib/api"

function percentChange(series: number[]) {
  if (series.length < 2) return 0
  const prev = series[series.length - 2]
  const curr = series[series.length - 1]
  if (prev === 0) return curr > 0 ? 100 : 0
  return ((curr - prev) / prev) * 100
}

//
// ⭐ UPDATED Y-AXIS RULES ARE APPLIED HERE ONLY INSIDE AreaBox
//
function AreaBox({ title, dataKey, colorVar, domain, yLabel }: { 
  title: string; 
  dataKey: keyof SystemMetricsPoint; 
  colorVar: string; 
  domain?: [number, number] | [number, string]; 
  yLabel?: string 
}) {

  const [mounted, setMounted] = useState(false)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const previousDataHash = useRef<string>("")
  const refreshTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  
  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 0)
    return () => clearTimeout(t)
  }, [])

  const metrics = useAppStore((s) => s.metrics)
  const threatLevel = useAppStore((s) => s.overview.threatLevel)
  
  // Fixed time window: last 15 minutes (consistent across all graphs)
  const [currentTime, setCurrentTime] = useState(Date.now())
  
  useEffect(() => {
    // Update time window every 2 seconds for smooth traversal
    const interval = setInterval(() => {
      setCurrentTime(Date.now())
    }, 2000)
    return () => clearInterval(interval)
  }, [])
  
  const data = useMemo(() => {
    const now = currentTime
    const timeWindowMs = 10 * 60 * 1000 // 10 minutes (reduced for better performance)
    const windowStart = now - timeWindowMs
    
    // Filter to time window and limit points (reduced from 50 to 30)
    // Sort by timestamp to ensure proper traversal
    const recent = metrics
      .filter(m => m.t >= windowStart)
      .sort((a, b) => a.t - b.t)
      .slice(-30)
    
    return recent.map((m) => ({ x: m.t, ...m }))
  }, [metrics, currentTime])
  
  // Smooth refresh animation - debounce rapid updates
  useEffect(() => {
    if (!mounted || metrics.length === 0) return
    
    // Create a hash of the latest data points to detect meaningful changes (reduced from 5 to 3)
    const latestMetrics = metrics.slice(-3)
    const dataHash = JSON.stringify(latestMetrics.map(m => ({ t: m.t, [dataKey]: m[dataKey] })))
    
    if (dataHash !== previousDataHash.current && previousDataHash.current !== "") {
      // Clear existing timeout to debounce rapid updates
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current)
      }
      
      setIsRefreshing(true)
      refreshTimeoutRef.current = setTimeout(() => {
        setIsRefreshing(false)
        refreshTimeoutRef.current = null
      }, 200)
      
      previousDataHash.current = dataHash
    } else if (previousDataHash.current === "") {
      previousDataHash.current = dataHash
    }
    
    return () => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current)
        refreshTimeoutRef.current = null
      }
    }
  }, [metrics, dataKey, mounted])
  
  // Use dataMin/dataMax for X-axis to allow smooth traversal
  const timeDomain = useMemo(() => {
    if (data.length === 0) {
      const now = currentTime
      const windowStart = now - (10 * 60 * 1000)
      return [windowStart, now] as [number, number]
    }
    // Use the actual data range for smooth scrolling
    return ["dataMin", "dataMax"] as [string, string]
  }, [data.length, currentTime])
  
  const pc = percentChange(metrics.map((m) => m[dataKey] as number))
  const color = `var(${colorVar}, #4F8DF7)`

  const severity: "low" | "medium" | "high" =
    threatLevel >= 60 ? "high" : threatLevel >= 25 ? "medium" : "low"

  const cfg = {
    low: { top: 0.6, bottom: 0.2, stroke: 2.5 },
    medium: { top: 0.7, bottom: 0.25, stroke: 3 },
    high: { top: 0.85, bottom: 0.35, stroke: 3.5 },
  }[severity]

  //
  // ⭐ Select correct Y-axis config depending on chart
  //
  let yAxisProps: Record<string, unknown> = {}

  if (title === "CPU Usage" || title === "Memory Usage") {
    // FIXED 0–100 RANGE
    yAxisProps = {
      domain: [0, 100],
      tick: { fontSize: 10 },
      width: 28
    }
  }
  else {
    // DISK I/O + NETWORK BANDWIDTH = dynamic + spacing
    yAxisProps = {
      domain: [0, "dataMax + 50"],
      tick: { fontSize: 10 },
      tickMargin: 6,
      padding: { top: 10, bottom: 10 },
      width: 36,
      label: yLabel
        ? { value: yLabel, angle: -90, position: "insideLeft", style: { fontSize: 10 } }
        : undefined
    }
  }

  return (
    <Card aria-label={`${title} chart`} className="bg-card/60 backdrop-blur-md border-border/50 transition-all duration-500 ease-out hover:shadow-lg hover:-translate-y-0.5 relative z-10 group" style={{ 
      boxShadow: `0 0 15px ${color}40, 0 0 30px ${color}20, inset 0 0 15px ${color}10`,
      animation: 'card-glow 3s ease-in-out infinite',
      transition: 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)'
    }}>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center justify-between text-sm font-semibold">
          <span className="bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">{title}</span>
          <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
            pc >= 0 ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" : "bg-red-500/10 text-red-600 dark:text-red-400"
          }`}>
            {pc >= 0 ? "▲" : "▼"} {Math.abs(pc).toFixed(1)}%
          </span>
        </CardTitle>
      </CardHeader>

      <CardContent className="relative h-48 min-w-0 p-4">
        {!mounted && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center text-xs text-muted-foreground z-10">
            Loading…
          </div>
        )}

        <div 
          className="w-full h-full" 
          style={{ 
            visibility: mounted ? 'visible' : 'hidden',
            transition: 'opacity 0.4s cubic-bezier(0.4, 0, 0.2, 1), transform 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
            opacity: mounted ? (isRefreshing ? 0.7 : 1) : 0,
            transform: mounted ? (isRefreshing ? 'scale(0.98)' : 'scale(1)') : 'scale(0.95)',
            willChange: 'opacity, transform'
          }}
        >
            <ResponsiveContainer width="100%" height="100%" minWidth={0}>
            <AreaChart 
              key={`${dataKey}-chart`}
              data={data.length > 0 ? data : [{ x: Date.now(), [dataKey]: 0 }]} 
              margin={{ left: 8, right: 8, top: 8, bottom: 8 }}
            >
                
                <defs>
                  {/* Glow filter for the chart line */}
                  <filter id={`glow-${dataKey}`} x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                    <feMerge>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                  </filter>
                  
                  {/* Stronger glow filter */}
                  <filter id={`glow-strong-${dataKey}`} x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
                    <feMerge>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                  </filter>
                  
                  <linearGradient id={`grad-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={color} stopOpacity={cfg.top} />
                    <stop offset="95%" stopColor={color} stopOpacity={cfg.bottom} />
                  </linearGradient>
                  <linearGradient id={`shine-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={color} stopOpacity={0.15} />
                    <stop offset="50%" stopColor={color} stopOpacity={0} />
                  </linearGradient>
                  
                  {/* Glowing area gradient */}
                  <radialGradient id={`glow-grad-${dataKey}`} cx="50%" cy="0%">
                    <stop offset="0%" stopColor={color} stopOpacity="0.3" />
                    <stop offset="100%" stopColor={color} stopOpacity="0" />
                  </radialGradient>
                </defs>

                <CartesianGrid strokeDasharray="3 3" stroke="currentColor" opacity={0.25} />

                <XAxis
                  dataKey="x"
                  type="number"
                  domain={timeDomain}
                  tickFormatter={(v) => new Date(v as number).toLocaleTimeString()}
                  minTickGap={12}
                  stroke="currentColor"
                  strokeOpacity={0.6}
                  tick={{ fill: "currentColor", fontSize: 11, opacity: 0.7 }}
                />

                {/* ⭐ Correct Y-Axis inserted here */}
                <YAxis 
                  {...yAxisProps}
                  stroke="currentColor"
                  strokeOpacity={0.6}
                  tick={{ fill: "currentColor", fontSize: 11, opacity: 0.7 }}
                />

                <Tooltip contentStyle={{ background: "var(--card)", border: "1px solid var(--border)" }} />

                <Area 
                  type="monotone" 
                  dataKey={dataKey as string} 
                  stroke="none" 
                  fill={`url(#shine-${dataKey})`} 
                  isAnimationActive={mounted && data.length > 0}
                  animationDuration={1000}
                  animationEasing="ease-in-out"
                />
                
                {/* Glowing background layer */}
                <Area 
                  type="monotone" 
                  dataKey={dataKey as string} 
                  stroke="none" 
                  fill={`url(#glow-grad-${dataKey})`}
                  isAnimationActive={mounted && data.length > 0}
                  animationDuration={1000}
                  animationEasing="ease-in-out"
                  opacity={0.4}
                />
                
                {/* Main glowing chart line */}
                <Area 
                  type="monotone" 
                  dataKey={dataKey as string} 
                  stroke={color} 
                  fill={`url(#grad-${dataKey})`} 
                  strokeWidth={cfg.stroke} 
                  isAnimationActive={mounted && data.length > 0}
                  animationDuration={1000}
                  animationEasing="ease-in-out"
                  strokeOpacity={1}
                  fillOpacity={1}
                  filter={`url(#glow-${dataKey})`}
                  style={{
                    filter: `drop-shadow(0 0 6px ${color}) drop-shadow(0 0 12px ${color}80)`,
                    transition: 'filter 0.6s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.6s cubic-bezier(0.4, 0, 0.2, 1)',
                    opacity: isRefreshing ? 0.85 : 1
                  }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          {mounted && metrics.length === 0 && (
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center text-xs text-muted-foreground">
              Waiting for data…
          </div>
        )}
      </CardContent>
    </Card>
  )
}

//
// -------- Alert Breakdown (unchanged) --------
//
function AlertBreakdown() {
  const [mounted, setMounted] = useState(false)
  const [isRefreshing, setIsRefreshing] = useState(false)
  
  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 0)
    return () => clearTimeout(t)
  }, [])

  const threats = useAppStore((s) => s.threats)
  const counts = useMemo(() => {
    const c = { low: 0, medium: 0, high: 0, critical: 0 }
    threats.slice(0, 100).forEach((t) => c[t.severity]++)
    return c
  }, [threats])

  const data = useMemo(() => [
    { name: "Low", value: counts.low, color: "var(--accent-teal)", colorValue: "#1FB6AB", index: 0 },
    { name: "Medium", value: counts.medium, color: "var(--accent-orange)", colorValue: "#FF9F43", index: 1 },
    { name: "High", value: counts.high, color: "var(--accent-blue)", colorValue: "#4F8DF7", index: 2 },
    { name: "Critical", value: counts.critical, color: "var(--accent-red)", colorValue: "#FF5C57", index: 3 },
  ], [counts])
  
  const pieData = useMemo(() => data.filter(d => d.value > 0), [data])

  const total = useMemo(() => data.reduce((a, b) => a + b.value, 0), [data])
  const hasData = total > 0
  
  // Smooth refresh animation - debounce rapid updates
  const previousDataHash = useRef<string>("")
  const refreshTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  
  useEffect(() => {
    if (!mounted) return
    
    // Create a hash of data values to detect meaningful changes
    const dataHash = JSON.stringify(data.map(d => ({ name: d.name, value: d.value })))
    
    if (dataHash !== previousDataHash.current && previousDataHash.current !== "") {
      // Clear existing timeout to debounce rapid updates
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current)
      }
      
      setIsRefreshing(true)
      refreshTimeoutRef.current = setTimeout(() => {
        setIsRefreshing(false)
        refreshTimeoutRef.current = null
      }, 400)
      
      previousDataHash.current = dataHash
    } else if (previousDataHash.current === "") {
      previousDataHash.current = dataHash
    }
    
    return () => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current)
        refreshTimeoutRef.current = null
      }
    }
  }, [data, mounted])

  const primaryColor = data[0]?.colorValue || '#1FB6AB'

  return (
    <Card aria-label="Alert breakdown" className="bg-card/60 backdrop-blur-md border-border/50 transition-all duration-500 ease-out hover:shadow-lg hover:-translate-y-0.5 relative z-10 group" style={{ 
      boxShadow: `0 0 15px ${primaryColor}40, 0 0 30px ${primaryColor}20, inset 0 0 15px ${primaryColor}10`,
      animation: 'card-glow 3s ease-in-out infinite',
      transition: 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)'
    }}>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">Alert Breakdown</CardTitle>
      </CardHeader>

      <CardContent className="relative min-h-[280px] min-w-0 p-4">
        {!mounted && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center text-xs text-muted-foreground z-10">
            Loading…
          </div>
        )}
        <div className="flex h-full items-center justify-center gap-8 px-4">
          <div 
            className="flex-shrink-0 flex items-center justify-center" 
            style={{ 
              visibility: mounted ? 'visible' : 'hidden',
              transition: 'opacity 0.4s cubic-bezier(0.4, 0, 0.2, 1), transform 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
              opacity: mounted ? (isRefreshing ? 0.7 : 1) : 0,
              transform: mounted ? (isRefreshing ? 'scale(0.98)' : 'scale(1)') : 'scale(0.95)',
              willChange: 'opacity, transform',
              width: '360px',
              height: '240px',
              padding: '8px'
            }}
          >
            {hasData ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart 
                  key="alert-breakdown-pie"
                  margin={{ top: 10, right: 10, bottom: 10, left: 10 }}
                >
                  <defs>
                    {data.map((d, i) => {
                      const baseColor = d.colorValue || '#1FB6AB'
                      
                      return (
                        <g key={`pie-defs-${i}`}>
                          {/* Enhanced glow filter */}
                          <filter id={`glow-pie-${i}`} x="-100%" y="-100%" width="300%" height="300%">
                            <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
                            <feMerge>
                              <feMergeNode in="coloredBlur"/>
                              <feMergeNode in="SourceGraphic"/>
                            </feMerge>
                          </filter>
                          
                          {/* Radial gradient for depth and shine */}
                          <radialGradient id={`pie-gradient-${i}`} cx="30%" cy="30%">
                            <stop offset="0%" stopColor={baseColor} stopOpacity="1" />
                            <stop offset="50%" stopColor={baseColor} stopOpacity="0.95" />
                            <stop offset="100%" stopColor={baseColor} stopOpacity="0.8" />
                          </radialGradient>
                          
                          {/* Highlight gradient for shine effect */}
                          <linearGradient id={`pie-shine-${i}`} x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stopColor="rgba(255, 255, 255, 0.4)" stopOpacity="0.6" />
                            <stop offset="50%" stopColor="rgba(255, 255, 255, 0.1)" stopOpacity="0.2" />
                            <stop offset="100%" stopColor="rgba(255, 255, 255, 0)" stopOpacity="0" />
                          </linearGradient>
                        </g>
                      )
                    })}
                  </defs>
                  <Tooltip 
                    contentStyle={{ 
                      background: "var(--card)", 
                      border: "1px solid var(--border)",
                      borderRadius: "8px",
                      padding: "8px 12px",
                      boxShadow: "0 4px 12px rgba(0, 0, 0, 0.15)"
                    }}
                    formatter={(value: number, name: string) => {
                      const pct = total > 0 ? ((value / total) * 100).toFixed(1) : '0.0'
                      return [`${value} (${pct}%)`, name]
                    }}
                  />
                  <Pie 
                    data={pieData} 
                    cx="50%"
                    cy="50%"
                    innerRadius={50} 
                    outerRadius={90} 
                    paddingAngle={4} 
                    dataKey="value" 
                    isAnimationActive={mounted && hasData}
                    animationDuration={1200}
                    animationEasing="ease-out"
                    stroke="var(--card)"
                    strokeWidth={3}
                    startAngle={90}
                    endAngle={-270}
                  >
                    {pieData.map((d) => {
                      const baseColor = d.colorValue || '#1FB6AB'
                      const originalIndex = d.index
                      
                      return (
                        <Cell 
                          key={`cell-${originalIndex}`} 
                          fill={`url(#pie-gradient-${originalIndex})`}
                          filter={`url(#glow-pie-${originalIndex})`}
                          style={{
                            filter: `drop-shadow(0 0 8px ${baseColor}) drop-shadow(0 0 16px ${baseColor}80) drop-shadow(0 0 24px ${baseColor}40)`,
                            transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
                            opacity: isRefreshing ? 0.85 : 1,
                            cursor: 'pointer'
                          }}
                          onMouseEnter={(e) => {
                            if (e.target) {
                              (e.target as SVGElement).style.transform = 'scale(1.08)'
                              ;(e.target as SVGElement).style.filter = `drop-shadow(0 0 12px ${baseColor}) drop-shadow(0 0 24px ${baseColor}) drop-shadow(0 0 32px ${baseColor}60)`
                            }
                          }}
                          onMouseLeave={(e) => {
                            if (e.target) {
                              (e.target as SVGElement).style.transform = 'scale(1)'
                              ;(e.target as SVGElement).style.filter = `drop-shadow(0 0 8px ${baseColor}) drop-shadow(0 0 16px ${baseColor}80) drop-shadow(0 0 24px ${baseColor}40)`
                            }
                          }}
                        />
                      )
                    })}
                  </Pie>
                  {/* Center label showing total */}
                  <text 
                    x="50%" 
                    y="45%" 
                    textAnchor="middle" 
                    fill="currentColor" 
                    fontSize="20" 
                    fontWeight="bold"
                    className="fill-foreground"
                  >
                    {total}
                  </text>
                  <text 
                    x="50%" 
                    y="55%" 
                    textAnchor="middle" 
                    fill="currentColor" 
                    fontSize="12" 
                    className="fill-muted-foreground"
                  >
                    Total Alerts
                  </text>
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
                No alerts yet
              </div>
            )}
            </div>
          <div className="flex-1 grid grid-cols-2 gap-3 text-sm py-2 max-w-2xl">
            {data.map((d, i) => {
              const baseColor = d.colorValue || '#1FB6AB'
              const percentage = total > 0 ? ((d.value / total) * 100).toFixed(1) : '0.0'
              
              return (
                <div 
                  key={d.name} 
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-border/30 bg-muted/20 hover:bg-muted/40 transition-all duration-300 hover:scale-[1.02] hover:shadow-md group cursor-pointer"
                  style={{
                    borderLeftColor: baseColor,
                    borderLeftWidth: '4px'
                  }}
                >
                  <div 
                    className="size-4 rounded-full shrink-0 ring-2 ring-offset-2 ring-offset-background transition-all duration-300 group-hover:scale-125 group-hover:ring-4"
                    style={{ 
                      backgroundColor: baseColor,
                      ringColor: `${baseColor}40`,
                      boxShadow: `0 0 8px ${baseColor}40, inset 0 0 4px ${baseColor}20`
                    }} 
                  />
                  <span className="w-20 font-semibold text-foreground">{d.name}</span>
                  <div className="flex-1 flex items-center gap-2">
                    <div className="flex-1 h-2.5 bg-muted rounded-full overflow-hidden">
                      <div 
                        className="h-full rounded-full transition-all duration-700 ease-out"
                        style={{ 
                          width: `${percentage}%`,
                          backgroundColor: baseColor,
                          boxShadow: `0 0 8px ${baseColor}60`
                        }}
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-2 min-w-[85px] justify-end">
                    <span className="tabular-nums font-bold text-foreground">{d.value}</span>
                    <span className="text-muted-foreground text-xs font-medium min-w-[50px]">({percentage}%)</span>
                  </div>
              </div>
              )
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

//
// -------- Layout (same as your request) --------
//
export default function SystemCharts() {
  return (
    <div className="space-y-4">

      {/* ROW 1 */}
      <div className="grid gap-4 md:grid-cols-2">
        <AreaBox title="CPU Usage" dataKey="cpu" colorVar="--chart-1" />
        <AreaBox title="Memory Usage" dataKey="mem" colorVar="--chart-2" />
      </div>

      {/* ROW 2 */}
      <div className="grid gap-4 md:grid-cols-2">
        <AreaBox title="Disk I/O" dataKey="disk" colorVar="--chart-3" yLabel="Disk I/O (KB/s)" />
        <AreaBox title="Network Bandwidth" dataKey="netDown" colorVar="--chart-4" yLabel="Network (KB/s)" />
      </div>

      {/* ROW 3 */}
      <div className="grid gap-4">
        <AlertBreakdown />
      </div>
    </div>
  )
}
