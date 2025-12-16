"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { useAppStore } from "@/store/app-store"
import ThemeToggle from "@/components/theme-toggle"
import InfoIcon from "@/components/InfoIcon"
import { api } from "@/lib/api"
import { toast } from "sonner"

export default function SettingsPanel() {
  const protection = useAppStore((s) => s.overview.protection)
  const toggle = useAppStore((s) => s.actions.toggleProtection)

  const handleToggle = async (module: "scan" | "webshield" | "snort", value: boolean) => {
    const prev = protection[module]
    // Optimistically update UI
    toggle(module, value)
    
    try {
      // Call module-specific endpoints to ensure processes are stopped/started
      const promises: Promise<any>[] = [
        api.post("/api/settings/protection", { module, enabled: value })
      ]
      
      // For scan, also call the live scanner toggle to stop/start the process
      if (module === "scan") {
        promises.push(api.post("/api/scan/live/toggle", { enabled: value }))
      }
      // For webshield, also call the webshield toggle endpoint
      else if (module === "webshield") {
        promises.push(api.post("/api/network/webshield/toggle", { enabled: value }))
      }
      
      const results = await Promise.all(promises)
      const res = results[0]
      
      if (res.data.ok) {
        // Update protection state from response
        if (res.data.protection) {
          useAppStore.setState({
            overview: {
              ...useAppStore.getState().overview,
              protection: res.data.protection,
            },
          })
        }
        
        // Update scan status if it's the scan module
        if (module === "scan" && results[1]?.data) {
          useAppStore.getState().actions.setScanStatus({
            enabled: results[1].data.enabled,
            paths: results[1].data.paths || []
          })
        }
        
        toast.success(`${module === "scan" ? "Live Scan" : module === "webshield" ? "WebShield" : "Snort IDS"} ${value ? "enabled" : "disabled"}`)
      } else {
        throw new Error(res.data.error || "Failed to toggle protection")
      }
    } catch (error: any) {
      // Revert on error
      toggle(module, prev)
      toast.error(error?.response?.data?.error || error?.response?.data?.detail || `Failed to toggle ${module}`)
    }
  }

  return (
    <Card className="bg-card/40 backdrop-blur-md border-border/50 transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5">
      <CardHeader>
        <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent flex items-center gap-2">
          Settings
          <InfoIcon description="Configure security module settings including Live Scan, WebShield, and Snort IDS. Toggle protection features on or off and customize theme preferences." />
        </CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="flex items-center justify-between rounded-md border border-border/30 bg-muted/20 p-3 transition-all duration-300 hover:bg-muted/30">
          <span className="font-medium">Live Scan</span>
          <Switch id="scan" checked={protection.scan} onCheckedChange={(v) => handleToggle("scan", v)} />
        </div>
        <div className="flex items-center justify-between rounded-md border border-border/30 bg-muted/20 p-3 transition-all duration-300 hover:bg-muted/30">
          <span className="font-medium">WebShield</span>
          <Switch id="webshield" checked={protection.webshield} onCheckedChange={(v) => handleToggle("webshield", v)} />
        </div>
        <div className="flex items-center justify-between rounded-md border border-border/30 bg-muted/20 p-3 transition-all duration-300 hover:bg-muted/30">
          <span className="font-medium">Snort IDS</span>
          <Switch id="snort" checked={protection.snort} onCheckedChange={(v) => handleToggle("snort", v)} />
        </div>
        <div className="flex items-center justify-between rounded-md border border-border/30 bg-muted/20 p-3 transition-all duration-300 hover:bg-muted/30">
          <span className="font-medium">Theme</span>
          <ThemeToggle />
        </div>
      </CardContent>
    </Card>
  )
}