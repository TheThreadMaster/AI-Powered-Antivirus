"use client"

import OverviewCards from "@/features/overview/OverviewCards"
import ThreatGauge from "@/features/gauge/ThreatGauge"
import SystemCharts from "@/features/resources/SystemCharts"
import ThreatFeed from "@/features/threats/ThreatFeed"
import NetworkPanel from "@/features/network/NetworkPanel"
import WebShieldPanel from "@/features/webshield/WebShieldPanel"
import SandboxPanel from "@/features/sandbox/SandboxPanel"
import BackgroundScannerPanel from "@/features/scanner/BackgroundScannerPanel"
import ManualScanner from "@/features/scanner/ManualScanner"
import ThreatManagementCenter from "@/features/management/ThreatManagementCenter"
import ActivityAuditLogs from "@/features/logs/ActivityAuditLogs"
import SettingsPanel from "@/features/settings/SettingsPanel"
import CloudProtectionPanel from "@/features/cloud/CloudProtectionPanel"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useRealtime } from "@/lib/ws"
import RealtimeStatus from "@/components/RealtimeStatus"
import { useEffect, useState } from "react"

type ParticleData = {
  size: number
  left: number
  top: number
  colorLight: string
  colorDark: string
  opacityLight: number
  opacityDark: number
  duration: number
  delay: number
  twinkleDelay: number
}

type SparkleData = {
  left: number
  top: number
  duration: number
  delay: number
  size: number
}

export default function Home() {
  useRealtime()
  const [particles, setParticles] = useState<ParticleData[]>([])
  const [sparkles, setSparkles] = useState<SparkleData[]>([])
  const [isMounted, setIsMounted] = useState(false)

  // Generate particles and sparkles client-side only to avoid hydration errors
  useEffect(() => {
    setIsMounted(true)
    
    const colorsLight = [
      '59, 130, 246',   // blue
      '147, 51, 234',   // purple
      '6, 182, 212',    // cyan
      '236, 72, 153',   // pink
      '99, 102, 241',   // indigo
      '16, 185, 129',   // emerald
    ]
    const colorsDark = [
      '96, 165, 250',   // blue-400
      '167, 139, 250',  // purple-400
      '34, 211, 238',   // cyan-400
      '244, 114, 182',  // pink-400
      '129, 140, 248',  // indigo-400
      '52, 211, 153',   // emerald-400
    ]

    // Generate particles - further reduced for better memory/CPU performance
    const generatedParticles: ParticleData[] = Array.from({ length: 8 }).map(() => {
      const colorIndex = Math.floor(Math.random() * colorsLight.length)
      return {
        size: Math.random() * 5 + 1.5,
        left: Math.random() * 100,
        top: Math.random() * 100,
        colorLight: colorsLight[colorIndex],
        colorDark: colorsDark[colorIndex],
        opacityLight: Math.random() * 0.5 + 0.15,
        opacityDark: Math.random() * 0.7 + 0.25,
        duration: Math.random() * 12 + 18,
        delay: Math.random() * 8,
        twinkleDelay: Math.random() * 3,
      }
    })
    setParticles(generatedParticles)

    // Generate sparkles - further reduced for better memory/CPU performance
    const generatedSparkles: SparkleData[] = Array.from({ length: 4 }).map(() => ({
      left: Math.random() * 100,
      top: Math.random() * 100,
      duration: Math.random() * 4 + 3,
      delay: Math.random() * 6,
      size: Math.random() * 3 + 1,
    }))
    setSparkles(generatedSparkles)
  }, [])

  // Request fullscreen on mount
  useEffect(() => {
    const requestFullscreen = async () => {
      try {
        const doc = document.documentElement as any
        
        // Try different fullscreen methods for browser compatibility
        if (doc.requestFullscreen) {
          await doc.requestFullscreen()
        } else if (doc.webkitRequestFullscreen) {
          // Safari
          await doc.webkitRequestFullscreen()
        } else if (doc.mozRequestFullScreen) {
          // Firefox
          await doc.mozRequestFullScreen()
        } else if (doc.msRequestFullscreen) {
          // IE/Edge
          await doc.msRequestFullscreen()
        }
      } catch (error) {
        // Fullscreen request failed (user denied or not supported)
        console.log("Fullscreen request failed:", error)
      }
    }

    // Small delay to ensure DOM is ready
    const timer = setTimeout(() => {
      requestFullscreen()
    }, 100)

    return () => clearTimeout(timer)
  }, [])
  return (
    <div className="relative min-h-screen overflow-hidden">
      {/* Enhanced Animated Background - Optimized for Performance */}
      <div className="fixed inset-0 -z-20 overflow-hidden pointer-events-none will-change-transform" style={{ contain: 'layout style paint' }}>
        {/* Base Gradient Mesh - Enhanced */}
        <div className="absolute inset-0 opacity-30 dark:opacity-40 bg-mesh-gradient will-change-auto" />
        
        {/* Animated Gradient Overlay - Reduced layers for performance */}
        <div className="absolute inset-0 opacity-40 dark:opacity-50 bg-gradient-shift will-change-auto" />
        
        {/* Primary Grid Layer - Main */}
        <div className="absolute inset-0 opacity-40 dark:opacity-30 grid-enhanced will-change-transform" />
        
        {/* Floating Orbs - Reduced count and optimized for performance */}
        <div className="absolute top-1/4 left-1/4 w-[550px] h-[550px] bg-blue-500/15 dark:bg-blue-400/25 rounded-full blur-3xl orb-blue will-change-transform" />
        <div className="absolute bottom-1/4 right-1/4 w-[650px] h-[650px] bg-purple-500/15 dark:bg-purple-400/25 rounded-full blur-3xl orb-purple will-change-transform" />
        <div className="absolute top-1/2 right-1/3 w-[450px] h-[450px] bg-cyan-500/12 dark:bg-cyan-400/22 rounded-full blur-3xl orb-cyan will-change-transform" />
        
        {/* Animated Particles/Dots - Optimized with GPU acceleration */}
        {isMounted && particles.map((p, i) => (
          <div
            key={i}
            className="absolute rounded-full particle-dot will-change-transform"
            style={{
              width: `${p.size}px`,
              height: `${p.size}px`,
              left: `${p.left}%`,
              top: `${p.top}%`,
              backgroundColor: `rgba(${p.colorLight}, ${p.opacityLight})`,
              boxShadow: `0 0 ${p.size * 2}px rgba(${p.colorLight}, ${p.opacityLight * 0.5})`,
              animation: `particle-float ${p.duration}s ease-in-out infinite, particle-twinkle ${p.duration * 0.7}s ease-in-out infinite`,
              animationDelay: `${p.delay}s, ${p.twinkleDelay}s`,
              transform: 'translateZ(0)', // Force GPU acceleration
              ['--particle-bg-light' as any]: `rgba(${p.colorLight}, ${p.opacityLight})`,
              ['--particle-shadow-light' as any]: `rgba(${p.colorLight}, ${p.opacityLight * 0.5})`,
              ['--particle-bg-dark' as any]: `rgba(${p.colorDark}, ${p.opacityDark})`,
              ['--particle-shadow-dark' as any]: `rgba(${p.colorDark}, ${p.opacityDark * 0.6})`,
            }}
          />
        ))}
        
        {/* Sparkle Effects - Optimized */}
        {isMounted && sparkles.map((s, i) => (
          <div
            key={`sparkle-${i}`}
            className="absolute rounded-full bg-white/70 dark:bg-white/90 will-change-transform"
            style={{
              width: `${s.size}px`,
              height: `${s.size}px`,
              left: `${s.left}%`,
              top: `${s.top}%`,
              boxShadow: '0 0 8px rgba(255, 255, 255, 0.5), 0 0 12px rgba(255, 255, 255, 0.3)',
              animation: `sparkle ${s.duration}s ease-in-out infinite`,
              animationDelay: `${s.delay}s`,
              transform: 'translateZ(0)', // Force GPU acceleration
            }}
          />
        ))}
      </div>
      
      <div className="relative space-y-6 p-4 md:p-6 lg:p-8 z-10">
        <div className="space-y-4">
          <div className="mb-2 text-center">
            <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">
              AI-Powered-Antivirus Dashboard
            </h1>
            <p className="text-sm text-muted-foreground mt-1">Real-time threat monitoring and protection</p>
          </div>
          <RealtimeStatus />
        </div>
        
        <div className="space-y-6">
          <OverviewCards />
          <div className="grid gap-6 lg:grid-cols-[1fr_1.5fr]">
            <ThreatGauge />
            <SystemCharts />
          </div>
        </div>
        
        <Tabs defaultValue="threats" className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">
              Security Modules
            </h2>
          </div>
          <TabsList className="flex w-full flex-wrap gap-2 bg-muted/30 backdrop-blur-md border border-border/50 p-1.5 rounded-xl shadow-xl transition-all duration-300 hover:shadow-2xl">
            <TabsTrigger value="threats">
              <span className="flex items-center gap-1.5">
                <span className="transition-transform duration-200 group-hover:rotate-12">🛡️</span>
                <span>Threat Feed</span>
              </span>
            </TabsTrigger>
            <TabsTrigger value="network">
              <span className="flex items-center gap-1.5">
                <span className="transition-transform duration-200 group-hover:rotate-12">🌐</span>
                <span>Network</span>
              </span>
            </TabsTrigger>
            <TabsTrigger value="webshield">
              <span className="flex items-center gap-1.5">
                <span className="transition-transform duration-200 group-hover:rotate-12">🔒</span>
                <span>WebShield</span>
              </span>
            </TabsTrigger>
            <TabsTrigger value="sandbox">
              <span className="flex items-center gap-1.5">
                <span className="transition-transform duration-200 group-hover:rotate-12">🧪</span>
                <span>Sandbox</span>
              </span>
            </TabsTrigger>
            <TabsTrigger value="bgscan">
              <span className="flex items-center gap-1.5">
                <span className="transition-transform duration-200 group-hover:rotate-12">🔍</span>
                <span>Background Scanner</span>
              </span>
            </TabsTrigger>
            <TabsTrigger value="manual">
              <span className="flex items-center gap-1.5">
                <span className="transition-transform duration-200 group-hover:rotate-12">📁</span>
                <span>Manual Scanner</span>
              </span>
            </TabsTrigger>
            <TabsTrigger value="manage">
              <span className="flex items-center gap-1.5">
                <span className="transition-transform duration-200 group-hover:rotate-12">⚙️</span>
                <span>Threat Center</span>
              </span>
            </TabsTrigger>
            <TabsTrigger value="logs">
              <span className="flex items-center gap-1.5">
                <span className="transition-transform duration-200 group-hover:rotate-12">📝</span>
                <span>Logs</span>
              </span>
            </TabsTrigger>
            <TabsTrigger value="cloud">
              <span className="flex items-center gap-1.5">
                <span className="transition-transform duration-200 group-hover:rotate-12">☁️</span>
                <span>Cloud Protection</span>
              </span>
            </TabsTrigger>
            <TabsTrigger value="settings">
              <span className="flex items-center gap-1.5">
                <span className="transition-transform duration-200 group-hover:rotate-12">⚙️</span>
                <span>Settings</span>
              </span>
            </TabsTrigger>
          </TabsList>
          <div className="relative min-h-[500px] w-full rounded-xl bg-card/30 backdrop-blur-md border border-border/50 shadow-xl p-4 transition-all duration-500 hover:shadow-2xl">
            <TabsContent value="threats" className="m-0 data-[state=inactive]:hidden"><ThreatFeed /></TabsContent>
            <TabsContent value="network" className="m-0 data-[state=inactive]:hidden"><NetworkPanel /></TabsContent>
            <TabsContent value="webshield" className="m-0 data-[state=inactive]:hidden"><WebShieldPanel /></TabsContent>
            <TabsContent value="sandbox" className="m-0 data-[state=inactive]:hidden"><SandboxPanel /></TabsContent>
            <TabsContent value="bgscan" className="m-0 data-[state=inactive]:hidden"><BackgroundScannerPanel /></TabsContent>
            <TabsContent value="manual" className="m-0 data-[state=inactive]:hidden"><ManualScanner /></TabsContent>
            <TabsContent value="manage" className="m-0 data-[state=inactive]:hidden"><ThreatManagementCenter /></TabsContent>
            <TabsContent value="logs" className="m-0 data-[state=inactive]:hidden"><ActivityAuditLogs /></TabsContent>
            <TabsContent value="cloud" className="m-0 data-[state=inactive]:hidden"><CloudProtectionPanel /></TabsContent>
            <TabsContent value="settings" className="m-0 data-[state=inactive]:hidden"><SettingsPanel /></TabsContent>
          </div>
        </Tabs>
      </div>
    </div>
  )
}
