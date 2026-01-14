"use client"

import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"

export interface ThreatAnalysis {
  threat_id: number
  timestamp: string
  severity: string
  source: string
  description: string
  action: string | null
  location: {
    type: "file" | "url"
    path?: string
    filename?: string
    directory?: string
    exists?: boolean
    size?: number
    created?: number
    modified?: number
    url?: string
    domain?: string
    scheme?: string
  }
  signature: {
    file_type?: string
    extension?: string
    mime_type?: string
    sha256?: string
    entropy?: number
    header_magic?: string
    suspicious_strings_found?: string[]
    type?: string
    risk_score?: number
    category?: string
    risk_indicators?: Record<string, boolean>
  }
  behavior: {
    sandbox_verdict?: string
    sandbox_score?: number
    syscalls?: string[]
    system_interactions?: number
    ml_analysis?: {
      risk_score: number
      verdict: string
      anomaly_detected: boolean
    }
    sandbox_analysis?: {
      syscalls: string[]
      registry_access: string[]
      network_activity: string[]
      verdict: string
    }
  }
  risk_assessment: {
    overall_risk: number
    risk_level: string
    threat_category: string
    confidence: string
    recommendations: string[]
  }
}

interface ThreatAnalysisDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  analysis: ThreatAnalysis | null
  loading?: boolean
}

export function ThreatAnalysisDialog({ open, onOpenChange, analysis, loading }: ThreatAnalysisDialogProps) {
  if (loading) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Threat Analysis</DialogTitle>
            <DialogDescription>Analyzing threat details...</DialogDescription>
          </DialogHeader>
          <div className="flex items-center justify-center py-8">
            <div className="text-muted-foreground">Loading comprehensive analysis...</div>
          </div>
        </DialogContent>
      </Dialog>
    )
  }

  if (!analysis) {
    return null
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical": return "destructive"
      case "high": return "destructive"
      case "medium": return "default"
      case "low": return "secondary"
      default: return "secondary"
    }
  }

  const getRiskColor = (risk: number) => {
    if (risk >= 0.7) return "destructive"
    if (risk >= 0.4) return "default"
    return "secondary"
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            Comprehensive Threat Analysis
            <Badge variant={getSeverityColor(analysis.severity)} className="capitalize">
              {analysis.severity}
            </Badge>
          </DialogTitle>
          <DialogDescription>
            Threat ID: {analysis.threat_id} • Source: {analysis.source} • Detected: {new Date(analysis.timestamp).toLocaleString()}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Overview */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Overview</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div><span className="font-medium text-muted-foreground">Description:</span> {analysis.description}</div>
              {analysis.action && (
                <div><span className="font-medium text-muted-foreground">Current Action:</span> <Badge variant="outline" className="capitalize ml-2">{analysis.action}</Badge></div>
              )}
            </CardContent>
          </Card>

          {/* Location */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Location</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              {analysis.location.type === "file" ? (
                <>
                  <div><span className="font-medium text-muted-foreground">Type:</span> File</div>
                  <div><span className="font-medium text-muted-foreground">Path:</span> <code className="bg-muted px-1 rounded text-xs break-all">{analysis.location.path}</code></div>
                  {analysis.location.filename && (
                    <div><span className="font-medium text-muted-foreground">Filename:</span> {analysis.location.filename}</div>
                  )}
                  {analysis.location.directory && (
                    <div><span className="font-medium text-muted-foreground">Directory:</span> {analysis.location.directory}</div>
                  )}
                  {analysis.location.size !== undefined && (
                    <div><span className="font-medium text-muted-foreground">Size:</span> {(analysis.location.size / 1024).toFixed(2)} KB</div>
                  )}
                  <div><span className="font-medium text-muted-foreground">Exists:</span> {analysis.location.exists ? <Badge variant="outline" className="ml-2">Yes</Badge> : <Badge variant="destructive" className="ml-2">No</Badge>}</div>
                </>
              ) : (
                <>
                  <div><span className="font-medium text-muted-foreground">Type:</span> URL</div>
                  <div><span className="font-medium text-muted-foreground">URL:</span> <code className="bg-muted px-1 rounded text-xs break-all">{analysis.location.url}</code></div>
                  {analysis.location.domain && (
                    <div><span className="font-medium text-muted-foreground">Domain:</span> {analysis.location.domain}</div>
                  )}
                  {analysis.location.scheme && (
                    <div><span className="font-medium text-muted-foreground">Scheme:</span> {analysis.location.scheme}</div>
                  )}
                </>
              )}
            </CardContent>
          </Card>

          {/* Signature */}
          {Object.keys(analysis.signature).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Signature Analysis</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                {analysis.signature.file_type && (
                  <div><span className="font-medium text-muted-foreground">File Type:</span> {analysis.signature.file_type}</div>
                )}
                {analysis.signature.extension && (
                  <div><span className="font-medium text-muted-foreground">Extension:</span> {analysis.signature.extension}</div>
                )}
                {analysis.signature.mime_type && (
                  <div><span className="font-medium text-muted-foreground">MIME Type:</span> {analysis.signature.mime_type}</div>
                )}
                {analysis.signature.sha256 && (
                  <div>
                    <span className="font-medium text-muted-foreground">SHA256:</span>
                    <code className="bg-muted px-1 rounded text-xs break-all ml-2">{analysis.signature.sha256}</code>
                  </div>
                )}
                {analysis.signature.entropy !== undefined && (
                  <div>
                    <span className="font-medium text-muted-foreground">Entropy:</span> {analysis.signature.entropy}
                    {analysis.signature.entropy > 7.2 && (
                      <Badge variant="destructive" className="ml-2">High (Possible Packing/Obfuscation)</Badge>
                    )}
                  </div>
                )}
                {analysis.signature.header_magic && (
                  <div>
                    <span className="font-medium text-muted-foreground">Header Magic:</span>
                    <code className="bg-muted px-1 rounded text-xs ml-2">{analysis.signature.header_magic}</code>
                  </div>
                )}
                {analysis.signature.suspicious_strings_found && analysis.signature.suspicious_strings_found.length > 0 && (
                  <div>
                    <span className="font-medium text-muted-foreground">Suspicious Strings Found:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {analysis.signature.suspicious_strings_found.map((s, i) => (
                        <Badge key={i} variant="destructive" className="text-xs">{s}</Badge>
                      ))}
                    </div>
                  </div>
                )}
                {analysis.signature.category && (
                  <div><span className="font-medium text-muted-foreground">Category:</span> <Badge variant="outline" className="capitalize ml-2">{analysis.signature.category}</Badge></div>
                )}
                {analysis.signature.risk_score !== undefined && (
                  <div>
                    <span className="font-medium text-muted-foreground">Risk Score:</span> {analysis.signature.risk_score.toFixed(2)}
                    <Progress value={analysis.signature.risk_score * 100} className="mt-1" />
                  </div>
                )}
                {analysis.signature.risk_indicators && Object.keys(analysis.signature.risk_indicators).length > 0 && (
                  <div>
                    <span className="font-medium text-muted-foreground">Risk Indicators:</span>
                    <div className="mt-1 space-y-1">
                      {Object.entries(analysis.signature.risk_indicators).map(([key, value]) => (
                        value && (
                          <div key={key} className="flex items-center gap-2">
                            <Badge variant={value ? "destructive" : "secondary"} className="text-xs capitalize">
                              {key.replace(/_/g, " ")}
                            </Badge>
                          </div>
                        )
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Behavior */}
          {Object.keys(analysis.behavior).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Behavioral Analysis</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                {analysis.behavior.sandbox_verdict && (
                  <div>
                    <span className="font-medium text-muted-foreground">Sandbox Verdict:</span>
                    <Badge variant={analysis.behavior.sandbox_verdict === "malicious" ? "destructive" : "outline"} className="capitalize ml-2">
                      {analysis.behavior.sandbox_verdict}
                    </Badge>
                  </div>
                )}
                {analysis.behavior.sandbox_score !== undefined && (
                  <div>
                    <span className="font-medium text-muted-foreground">Sandbox Score:</span> {analysis.behavior.sandbox_score.toFixed(2)}
                  </div>
                )}
                {analysis.behavior.ml_analysis && (
                  <div className="space-y-2">
                    <div><span className="font-medium text-muted-foreground">ML Analysis:</span></div>
                    <div className="ml-4 space-y-1">
                      <div><span className="text-muted-foreground">Verdict:</span> <Badge variant="outline" className="capitalize ml-2">{analysis.behavior.ml_analysis.verdict}</Badge></div>
                      <div><span className="text-muted-foreground">Risk Score:</span> {analysis.behavior.ml_analysis.risk_score.toFixed(2)}</div>
                      <div><span className="text-muted-foreground">Anomaly Detected:</span> {analysis.behavior.ml_analysis.anomaly_detected ? <Badge variant="destructive" className="ml-2">Yes</Badge> : <Badge variant="secondary" className="ml-2">No</Badge>}</div>
                    </div>
                  </div>
                )}
                {analysis.behavior.sandbox_analysis && (
                  <div className="space-y-2">
                    <div><span className="font-medium text-muted-foreground">Sandbox Details:</span></div>
                    {analysis.behavior.sandbox_analysis.syscalls && analysis.behavior.sandbox_analysis.syscalls.length > 0 && (
                      <div className="ml-4">
                        <div className="text-muted-foreground mb-1">System Calls ({analysis.behavior.sandbox_analysis.syscalls.length}):</div>
                        <div className="flex flex-wrap gap-1">
                          {analysis.behavior.sandbox_analysis.syscalls.map((call, i) => (
                            <Badge key={i} variant="outline" className="text-xs">{call}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {analysis.behavior.sandbox_analysis.registry_access && analysis.behavior.sandbox_analysis.registry_access.length > 0 && (
                      <div className="ml-4">
                        <div className="text-muted-foreground mb-1">Registry Access ({analysis.behavior.sandbox_analysis.registry_access.length}):</div>
                        <div className="flex flex-wrap gap-1">
                          {analysis.behavior.sandbox_analysis.registry_access.map((reg, i) => (
                            <Badge key={i} variant="outline" className="text-xs">{reg}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {analysis.behavior.sandbox_analysis.network_activity && analysis.behavior.sandbox_analysis.network_activity.length > 0 && (
                      <div className="ml-4">
                        <div className="text-muted-foreground mb-1">Network Activity ({analysis.behavior.sandbox_analysis.network_activity.length}):</div>
                        <div className="flex flex-wrap gap-1">
                          {analysis.behavior.sandbox_analysis.network_activity.map((net, i) => (
                            <Badge key={i} variant="outline" className="text-xs">{net}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
                {analysis.behavior.syscalls && analysis.behavior.syscalls.length > 0 && (
                  <div>
                    <span className="font-medium text-muted-foreground">System Calls ({analysis.behavior.syscalls.length}):</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {analysis.behavior.syscalls.slice(0, 10).map((call, i) => (
                        <Badge key={i} variant="outline" className="text-xs">{call}</Badge>
                      ))}
                      {analysis.behavior.syscalls.length > 10 && (
                        <Badge variant="secondary" className="text-xs">+{analysis.behavior.syscalls.length - 10} more</Badge>
                      )}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Risk Assessment */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Risk Assessment</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-muted-foreground">Overall Risk:</span>
                  <Badge variant={getRiskColor(analysis.risk_assessment.overall_risk)} className="capitalize">
                    {analysis.risk_assessment.risk_level} ({(analysis.risk_assessment.overall_risk * 100).toFixed(0)}%)
                  </Badge>
                </div>
                <Progress value={analysis.risk_assessment.overall_risk * 100} className="h-2" />
              </div>
              <div><span className="font-medium text-muted-foreground">Threat Category:</span> {analysis.risk_assessment.threat_category}</div>
              <div>
                <span className="font-medium text-muted-foreground">Confidence:</span>
                <Badge variant={analysis.risk_assessment.confidence === "high" ? "destructive" : "outline"} className="capitalize ml-2">
                  {analysis.risk_assessment.confidence}
                </Badge>
              </div>
              {analysis.risk_assessment.recommendations && analysis.risk_assessment.recommendations.length > 0 && (
                <div>
                  <span className="font-medium text-muted-foreground">Recommendations:</span>
                  <ul className="list-disc list-inside mt-2 space-y-1 ml-2">
                    {analysis.risk_assessment.recommendations.map((rec, i) => (
                      <li key={i} className="text-muted-foreground">{rec}</li>
                    ))}
                  </ul>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </DialogContent>
    </Dialog>
  )
}

