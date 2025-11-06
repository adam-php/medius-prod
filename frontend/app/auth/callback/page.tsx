"use client"

import { useEffect, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { supabase } from "@/lib/supabase"

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000"

export default function AuthCallbackPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [busy, setBusy] = useState(true)

  useEffect(() => {
    const run = async () => {
      // Wait for session
      let {
        data: { session },
      } = await supabase.auth.getSession()

      if (!session) {
        await new Promise((r) => setTimeout(r, 200))
        const res = await supabase.auth.getSession()
        session = res.data.session
      }

      if (!session) {
        router.replace("/auth")
        return
      }

      // Handle referral code if present
      try {
        const codeFromUrl = searchParams.get("ref")?.trim() || ""
        const codeFromStorage = typeof window !== "undefined" ? localStorage.getItem("medius_ref_code") || "" : ""
        const code = (codeFromUrl || codeFromStorage).trim()

        if (code) {
          await fetch(`${API_URL}/api/referrals/claim`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${session.access_token}`,
              "ngrok-skip-browser-warning": "1",
            },
            body: JSON.stringify({ code }),
          })
        }
      } catch (e) {
        console.warn("Referral claim failed:", e)
      } finally {
        try {
          localStorage.removeItem("medius_ref_code")
        } catch {}
      }

      router.replace("/dashboard")
    }

    run()
      .catch(() => {
        router.replace("/auth")
      })
      .finally(() => setBusy(false))
  }, [router, searchParams])

  return (
    <div className="flex min-h-screen items-center justify-center bg-black text-white">
      <p className="text-sm text-white/60">{busy ? "Finishing sign-in..." : ""}</p>
    </div>
  )
}
