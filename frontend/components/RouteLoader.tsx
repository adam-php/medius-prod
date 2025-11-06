"use client"

import { useEffect, useState } from "react"
import { usePathname } from "next/navigation"

export default function RouteLoader() {
  const pathname = usePathname()
  const [isNavigating, setIsNavigating] = useState(false)

  useEffect(() => {
    // When pathname changes, briefly show a top progress bar
    // to communicate navigation is in progress. The Suspense
    // boundary in layout will handle longer content loading.
    setIsNavigating(true)
    const t = setTimeout(() => setIsNavigating(false), 600)
    return () => clearTimeout(t)
  }, [pathname])

  return (
    <div
      aria-hidden
      className="fixed top-0 left-0 right-0 z-[60] pointer-events-none"
      style={{
        height: isNavigating ? "clamp(2px, 0.5vw, 4px)" : 0,
        transition: "height 180ms ease",
      }}
    >
      <div className="h-full w-full bg-gradient-to-r from-orange-400 via-orange-500 to-orange-600 animate-[progress_0.9s_ease_infinite] shadow-sm" />
      <style jsx>{`
        @keyframes progress {
          0% { transform: translateX(-60%); }
          50% { transform: translateX(-10%); }
          100% { transform: translateX(100%); }
        }
        div > div { transform: translateX(-100%); }
      `}</style>
    </div>
  )
}
