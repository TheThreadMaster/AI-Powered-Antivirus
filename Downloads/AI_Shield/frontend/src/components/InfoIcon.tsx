"use client"

import { ReactNode } from "react"

interface InfoIconProps {
  description: string
  className?: string
}

export default function InfoIcon({ description, className = "" }: InfoIconProps) {
  return (
    <div className={`group relative inline-block ${className}`}>
      <span className="text-xs text-muted-foreground cursor-help select-none">ℹ️</span>
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-64 p-2 bg-popover border border-border rounded-md shadow-lg text-xs text-popover-foreground opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 pointer-events-none">
        {description}
      </div>
    </div>
  )
}

