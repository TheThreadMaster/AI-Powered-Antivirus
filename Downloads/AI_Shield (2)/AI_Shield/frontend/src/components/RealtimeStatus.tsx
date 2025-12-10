"use client"

import { useMemo } from "react"
import { useAppStore } from "@/store/app-store"

export default function RealtimeStatus() {
  const wsStatus = useAppStore((s) => s.wsStatus)
  const lastMetricAt = useAppStore((s) => s.lastMetricAt)

  const { color, label } = useMemo(() => {
    switch (wsStatus) {
      case "open":
        return { color: "bg-emerald-500", label: "Connected" }
      case "connecting":
        return { color: "bg-yellow-500", label: "Connecting…" }
      case "error":
        return { color: "bg-red-500", label: "Error" }
      default:
        return { color: "bg-red-500", label: "Disconnected" }
    }
  }, [wsStatus])

  const lastSeen = lastMetricAt ? new Date(lastMetricAt).toLocaleTimeString() : "—"

  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-border/50 bg-card/40 backdrop-blur-md px-4 py-3 text-sm shadow-lg transition-all duration-300 hover:shadow-xl hover:bg-card/50">
      <div className="flex items-center gap-2.5 justify-center">
        <div className="relative flex-shrink-0 w-4 h-4 flex items-center justify-center">
          <span className={`absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 h-3 w-3 rounded-full ${color} animate-pulse`} />
          <span className={`absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 h-3 w-3 rounded-full ${color} opacity-40 animate-ping`} />
        </div>
        <div className="flex items-center gap-2 flex-wrap justify-center">
          <span className="font-semibold text-foreground whitespace-nowrap leading-none">Live data:</span>
          <span className={`font-medium whitespace-nowrap leading-none ${
            wsStatus === "open" ? "text-emerald-600 dark:text-emerald-400" :
            wsStatus === "connecting" ? "text-yellow-600 dark:text-yellow-400" :
            "text-red-600 dark:text-red-400"
          }`}>{label}</span>
        </div>
      </div>
      <div className="flex items-center gap-2 text-muted-foreground justify-center">
        <span className="whitespace-nowrap">Last metric:</span>
        <span className="font-mono text-xs whitespace-nowrap">{lastSeen}</span>
      </div>
    </div>
  )
}

