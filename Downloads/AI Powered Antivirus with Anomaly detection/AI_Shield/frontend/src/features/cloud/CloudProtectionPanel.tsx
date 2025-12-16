"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import useSWR from "swr"
import { fetcher, api } from "@/lib/api"
import { useState } from "react"
import { toast } from "sonner"
import InfoIcon from "@/components/InfoIcon"

type CloudProtectionStatus = {
  enabled: boolean
  auto_submit_enabled?: boolean
  stats: {
    file_checks: number
    url_checks: number
    ip_checks: number
    threats_detected: number
    api_errors: number
    samples_submitted?: number
    submissions_successful?: number
    submissions_failed?: number
  }
  cache_size: number
  submissions_tracked?: number
}

export default function CloudProtectionPanel() {
  const [enabled, setEnabled] = useState(true)
  const [autoSubmitEnabled, setAutoSubmitEnabled] = useState(true)
  const { data: status, mutate, error } = useSWR<CloudProtectionStatus>("/api/cloud-protection/status", fetcher, {
    refreshInterval: 5000,
    onSuccess(data) {
      if (data) {
        setEnabled(data.enabled ?? false)
        setAutoSubmitEnabled(data.auto_submit_enabled ?? false)
      }
    },
    onError(err) {
      console.error("Cloud protection status error:", err)
    },
  })

  const toggleCloudProtection = async (newEnabled: boolean) => {
    try {
      const endpoint = newEnabled ? "/api/cloud-protection/enable" : "/api/cloud-protection/disable"
      await api.post(endpoint)
      setEnabled(newEnabled)
      mutate()
      toast.success(newEnabled ? "Cloud protection enabled" : "Cloud protection disabled")
    } catch (error) {
      toast.error("Failed to toggle cloud protection")
    }
  }

  const toggleAutoSubmit = async (newEnabled: boolean) => {
    try {
      const endpoint = newEnabled ? "/api/cloud-protection/auto-submit/enable" : "/api/cloud-protection/auto-submit/disable"
      await api.post(endpoint)
      setAutoSubmitEnabled(newEnabled)
      mutate()
      toast.success(newEnabled ? "Automatic sample submission enabled" : "Automatic sample submission disabled")
    } catch (error) {
      toast.error("Failed to toggle auto-submit")
    }
  }

  const clearCache = async () => {
    try {
      await api.post("/api/cloud-protection/clear-cache")
      mutate()
      toast.success("Cache cleared")
    } catch (error) {
      toast.error("Failed to clear cache")
    }
  }

  const stats = status?.stats || {
    file_checks: 0,
    url_checks: 0,
    ip_checks: 0,
    threats_detected: 0,
    api_errors: 0,
  }

  if (error) {
    return (
      <Card className="bg-card/40 backdrop-blur-md border-border/50">
        <CardContent className="p-6">
          <div className="text-center text-muted-foreground">
            <p className="text-red-600 dark:text-red-400 mb-2">Error loading cloud protection status</p>
            <p className="text-sm">Please check your backend connection and try again.</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Card className="bg-card/40 backdrop-blur-md border-border/50 transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5">
        <CardHeader>
          <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent flex items-center gap-2">
            Cloud Delivered Protection
            <InfoIcon description="Enhances local threat detection with real-time cloud-based threat intelligence from services like VirusTotal and Hybrid Analysis. Provides file hash, URL, and IP reputation checks with automatic sample submission for detected threats." />
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between rounded-md border border-border/30 bg-muted/20 p-3 transition-all duration-300 hover:bg-muted/30">
              <div>
                <span className="font-medium">Cloud Protection</span>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Real-time threat intelligence from cloud services
                </p>
              </div>
              <Switch
                checked={enabled}
                onCheckedChange={toggleCloudProtection}
              />
            </div>
            {enabled && (
              <div className="rounded-md bg-blue-500/10 border border-blue-500/20 p-2 text-xs">
                <span className="text-blue-600 dark:text-blue-400 font-medium">✓ Active:</span>
                <span className="text-muted-foreground ml-1">
                  Files, URLs, and IPs are checked against cloud threat intelligence
                </span>
              </div>
            )}
            <div className="flex items-center justify-between rounded-md border border-border/30 bg-muted/20 p-3 transition-all duration-300 hover:bg-muted/30">
              <div>
                <span className="font-medium">Auto-Submit Samples</span>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Automatically submit detected threats to cloud platforms
                </p>
              </div>
              <Switch
                checked={autoSubmitEnabled}
                onCheckedChange={toggleAutoSubmit}
                disabled={!enabled}
              />
            </div>
            {autoSubmitEnabled && enabled && (
              <div className="rounded-md bg-green-500/10 border border-green-500/20 p-2 text-xs">
                <span className="text-green-600 dark:text-green-400 font-medium">✓ Active:</span>
                <span className="text-muted-foreground ml-1">
                  Threat samples are automatically submitted to VirusTotal and Hybrid Analysis
                </span>
              </div>
            )}
          </div>

          <div className="space-y-2">
            <div className="text-sm font-medium">Features</div>
            <div className="space-y-1 text-xs text-muted-foreground">
              <div>• File hash reputation checks</div>
              <div>• URL reputation analysis</div>
              <div>• IP address reputation</div>
              <div>• Cloud-based threat intelligence</div>
              <div>• Automatic cache for performance</div>
            </div>
          </div>

          <div className="pt-2">
            <Button
              size="sm"
              variant="outline"
              onClick={clearCache}
              className="w-full"
            >
              Clear Cache
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-card/40 backdrop-blur-md border-border/50 transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5">
        <CardHeader>
          <CardTitle className="text-base font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">
            Statistics
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-md border border-border/30 bg-muted/20 p-3">
              <div className="text-xs text-muted-foreground">File Checks</div>
              <div className="text-lg font-semibold">{stats.file_checks.toLocaleString()}</div>
            </div>
            <div className="rounded-md border border-border/30 bg-muted/20 p-3">
              <div className="text-xs text-muted-foreground">URL Checks</div>
              <div className="text-lg font-semibold">{stats.url_checks.toLocaleString()}</div>
            </div>
            <div className="rounded-md border border-border/30 bg-muted/20 p-3">
              <div className="text-xs text-muted-foreground">IP Checks</div>
              <div className="text-lg font-semibold">{stats.ip_checks.toLocaleString()}</div>
            </div>
            <div className="rounded-md border border-border/30 bg-muted/20 p-3">
              <div className="text-xs text-muted-foreground">Threats Detected</div>
              <div className="text-lg font-semibold text-red-600 dark:text-red-400">
                {stats.threats_detected.toLocaleString()}
              </div>
            </div>
            {stats.samples_submitted !== undefined && (
              <>
                <div className="rounded-md border border-border/30 bg-muted/20 p-3">
                  <div className="text-xs text-muted-foreground">Samples Submitted</div>
                  <div className="text-lg font-semibold text-blue-600 dark:text-blue-400">
                    {stats.samples_submitted.toLocaleString()}
                  </div>
                </div>
                <div className="rounded-md border border-border/30 bg-muted/20 p-3">
                  <div className="text-xs text-muted-foreground">Successful</div>
                  <div className="text-lg font-semibold text-green-600 dark:text-green-400">
                    {stats.submissions_successful?.toLocaleString() || 0}
                  </div>
                </div>
              </>
            )}
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Cache Size</span>
              <Badge variant="secondary">{status?.cache_size || 0} entries</Badge>
            </div>
            {status?.submissions_tracked !== undefined && status.submissions_tracked > 0 && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Submissions Tracked</span>
                <Badge variant="secondary">{status.submissions_tracked}</Badge>
              </div>
            )}
            {stats.api_errors > 0 && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">API Errors</span>
                <Badge variant="destructive">{stats.api_errors}</Badge>
              </div>
            )}
          </div>

          <div className="pt-2 text-xs text-muted-foreground space-y-1">
            <p>
              Cloud protection enhances local detection with real-time threat intelligence
              from cloud-based security services. Results are cached for optimal performance.
            </p>
            {autoSubmitEnabled && (
              <p className="text-green-600 dark:text-green-400">
                Automatic sample submission is active. Detected threats are automatically
                submitted to VirusTotal and Hybrid Analysis for analysis.
              </p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

