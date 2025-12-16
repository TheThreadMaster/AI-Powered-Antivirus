"use client"

import * as React from "react"
import * as TabsPrimitive from "@radix-ui/react-tabs"

import { cn } from "@/lib/utils"

function Tabs({
  className,
  ...props
}: React.ComponentProps<typeof TabsPrimitive.Root>) {
  return (
    <TabsPrimitive.Root
      data-slot="tabs"
      className={cn("flex flex-col gap-2", className)}
      {...props}
    />
  )
}

function TabsList({
  className,
  ...props
}: React.ComponentProps<typeof TabsPrimitive.List>) {
  return (
    <TabsPrimitive.List
      data-slot="tabs-list"
      className={cn(
        "bg-muted/50 backdrop-blur-md text-muted-foreground inline-flex h-auto w-fit items-center justify-center rounded-lg p-1.5 border border-border/50 shadow-lg transition-all duration-300",
        className
      )}
      {...props}
    />
  )
}

function TabsTrigger({
  className,
  ...props
}: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      data-slot="tabs-trigger"
      className={cn(
        "data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-lg",
        "dark:data-[state=active]:bg-background dark:data-[state=active]:text-foreground",
        "focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:outline-ring",
        "text-muted-foreground dark:text-muted-foreground",
        "inline-flex h-9 flex-1 items-center justify-center gap-1.5 rounded-md",
        "border border-transparent px-3 py-2 text-sm font-medium whitespace-nowrap",
        "transition-all duration-300 ease-in-out relative overflow-hidden",
        "focus-visible:ring-[3px] focus-visible:outline-1",
        "disabled:pointer-events-none disabled:opacity-50",
        "hover:bg-muted/70 hover:text-foreground hover:scale-105 hover:-translate-y-0.5",
        "data-[state=active]:scale-[1.05] data-[state=active]:-translate-y-0.5",
        "data-[state=active]:border-primary/20 data-[state=active]:bg-gradient-to-br data-[state=active]:from-background data-[state=active]:to-background/95",
        "before:absolute before:inset-0 before:bg-gradient-to-r before:from-primary/0 before:via-primary/10 before:to-primary/0 before:opacity-0",
        "data-[state=active]:before:opacity-100 before:transition-opacity before:duration-300",
        "active:scale-[0.98]",
        "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4 [&_svg]:transition-transform [&_svg]:duration-200",
        "hover:[&_svg]:scale-110 data-[state=active]:[&_svg]:scale-110",
        className
      )}
      {...props}
    />
  )
}

function TabsContent({
  className,
  ...props
}: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return (
    <TabsPrimitive.Content
      data-slot="tabs-content"
      className={cn(
        "flex-1 outline-none",
        "transition-all duration-500 ease-out",
        "data-[state=active]:opacity-100 data-[state=active]:translate-x-0 data-[state=active]:translate-y-0 data-[state=active]:block data-[state=active]:animate-in data-[state=active]:fade-in data-[state=active]:slide-in-from-right-4 data-[state=active]:zoom-in-95",
        "data-[state=inactive]:opacity-0 data-[state=inactive]:translate-x-8 data-[state=inactive]:translate-y-2 data-[state=inactive]:hidden data-[state=inactive]:animate-out data-[state=inactive]:fade-out data-[state=inactive]:slide-out-to-left-4 data-[state=inactive]:zoom-out-95",
        className
      )}
      {...props}
    />
  )
}

export { Tabs, TabsList, TabsTrigger, TabsContent }
