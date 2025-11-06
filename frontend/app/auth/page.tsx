"use client"

import type React from "react"

import { useEffect, useMemo, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import Image from "next/image"
import { supabase } from "@/lib/supabase"

export default function AuthPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000"

  const [isLogin, setIsLogin] = useState(true)
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  const callbackUrl = useMemo(() => `${window.location.origin}/auth/callback`, [])

  // Persist referral code on landing so it survives redirects
  useEffect(() => {
    const codeFromUrl = searchParams.get("ref")?.trim()
    if (codeFromUrl) {
      try {
        localStorage.setItem("medius_ref_code", codeFromUrl)
      } catch {}
    }
  }, [searchParams])

  // If already authenticated, route to appropriate destination
  useEffect(() => {
    const run = async () => {
      const { data } = await supabase.auth.getSession()
      const session = data.session
      if (!session) return

      try {
        const codeFromUrl = searchParams.get("ref")?.trim() || ""
        const codeFromStorage = typeof window !== "undefined" ? localStorage.getItem("medius_ref_code") || "" : ""
        const code = (codeFromUrl || codeFromStorage || "").trim()
        if (code) {
          await fetch(`${API_URL}/api/referrals/claim`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${session.access_token}`,
              "ngrok-skip-browser-warning": "1",
            },
            body: JSON.stringify({ code }),
          }).catch(() => {})
        }
      } finally {
        try {
          if (typeof window !== "undefined") localStorage.removeItem("medius_ref_code")
        } catch {}
        router.replace("/dashboard")
      }
    }
    run()
  }, [router, searchParams, API_URL])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setMessage(null)
    setLoading(true)
    try {
      if (isLogin) {
        // Sign in with password
        const { error: signInErr } = await supabase.auth.signInWithPassword({ email, password })
        if (signInErr) throw signInErr

        // Claim referral if needed
        try {
          const {
            data: { session },
          } = await supabase.auth.getSession()
          const codeFromUrl = searchParams.get("ref")?.trim() || ""
          const codeFromStorage = typeof window !== "undefined" ? localStorage.getItem("medius_ref_code") || "" : ""
          const code = (codeFromUrl || codeFromStorage || "").trim()
          if (session && code) {
            await fetch(`${API_URL}/api/referrals/claim`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${session.access_token}`,
                "ngrok-skip-browser-warning": "1",
              },
              body: JSON.stringify({ code }),
            }).catch(() => {})
          }
        } finally {
          try {
            if (typeof window !== "undefined") localStorage.removeItem("medius_ref_code")
          } catch {}
          router.replace("/dashboard")
        }
      } else {
        // Sign up
        const { error: signUpErr } = await supabase.auth.signUp({
          email,
          password,
          options: { emailRedirectTo: callbackUrl },
        })
        if (signUpErr) throw signUpErr
        setMessage("Check your email to confirm your account.")
      }
    } catch (err: any) {
      setError(err?.message ?? "Something went wrong")
    } finally {
      setLoading(false)
    }
  }

  const handleOAuth = async (provider: "google" | "discord") => {
    setError(null)
    setLoading(true)
    try {
      const codeFromUrl = searchParams.get("ref")?.trim()
      if (codeFromUrl) {
        try {
          localStorage.setItem("medius_ref_code", codeFromUrl)
        } catch {}
      }
    } catch {}

    const { error } = await supabase.auth.signInWithOAuth({
      provider,
      options: { redirectTo: callbackUrl },
    })
    if (error) {
      setError(error.message)
      setLoading(false)
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-black text-white">
      <div className="absolute inset-0 opacity-40">
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[800px] h-[600px] rounded-full blur-3xl bg-orange-500/10" />
      </div>

      <div className="relative z-10 w-full max-w-md">
        <div className="rounded-xl border border-white/10 bg-black/80 backdrop-blur-sm p-8 shadow-lg transition-all duration-500 ease-out animate-in fade-in slide-in-from-bottom-4">
          <div className="mb-8">
            <div
              className="mx-auto mb-6 flex h-10 w-10 items-center justify-center opacity-0 animate-in fade-in slide-in-from-top-2 delay-100"
              style={{ animationFillMode: "forwards" }}
            >
              <Image
                src="/images/image.png"
                alt="Logo"
                width={40}
                height={40}
                className="h-10 w-10 object-contain"
                priority
              />
            </div>

            <div className="flex gap-1 rounded-lg bg-white/5 p-1 mb-8">
              <button
                onClick={() => setIsLogin(true)}
                className={`flex-1 py-2 px-3 rounded-md text-sm font-medium transition-colors duration-300 ${
                  isLogin ? "bg-white/10 text-white" : "text-white/60 hover:text-white"
                }`}
              >
                Sign In
              </button>
              <button
                onClick={() => setIsLogin(false)}
                className={`flex-1 py-2 px-3 rounded-md text-sm font-medium transition-colors duration-300 ${
                  !isLogin ? "bg-white/10 text-white" : "text-white/60 hover:text-white"
                }`}
              >
                Sign Up
              </button>
            </div>

            <h1
              className="text-center text-2xl font-semibold opacity-0 animate-in fade-in slide-in-from-top-4 delay-150"
              style={{ animationFillMode: "forwards" }}
            >
              {isLogin ? "Welcome back" : "Create an account"}
            </h1>
          </div>

          <form
            onSubmit={handleSubmit}
            className="space-y-4 opacity-0 animate-in fade-in slide-in-from-bottom-2 delay-200"
            style={{ animationFillMode: "forwards" }}
          >
            <div>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="h-12 w-full rounded-lg border border-white/10 bg-white/5 px-4 text-base text-white placeholder:text-white/40 focus:outline-none focus:ring-2 focus:ring-orange-500/50 focus:border-transparent transition-all duration-300"
                placeholder="Email"
              />
            </div>
            <div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="h-12 w-full rounded-lg border border-white/10 bg-white/5 px-4 text-base text-white placeholder:text-white/40 focus:outline-none focus:ring-2 focus:ring-orange-500/50 focus:border-transparent transition-all duration-300"
                placeholder="Password"
              />
            </div>
            {error && <p className="text-sm text-red-400/90 animate-in fade-in duration-300">{error}</p>}
            {message && <p className="text-sm text-emerald-400/90 animate-in fade-in duration-300">{message}</p>}
            <button
              type="submit"
              disabled={loading}
              className="mt-6 h-12 w-full rounded-lg bg-orange-500 text-base font-semibold text-white hover:bg-orange-600 disabled:opacity-50 transition-all duration-300 hover:shadow-lg hover:shadow-orange-500/20"
            >
              {loading ? "Loading..." : isLogin ? "Sign In" : "Sign Up"}
            </button>
          </form>

          <div
            className="mt-6 flex items-center gap-3 opacity-0 animate-in fade-in delay-300"
            style={{ animationFillMode: "forwards" }}
          >
            <div className="h-px flex-1 bg-white/10" />
            <span className="text-xs tracking-widest text-white/40">OR CONTINUE WITH</span>
            <div className="h-px flex-1 bg-white/10" />
          </div>

          <div
            className="mt-4 grid grid-cols-2 gap-3 opacity-0 animate-in fade-in delay-300"
            style={{ animationFillMode: "forwards" }}
          >
            <button
              onClick={() => handleOAuth("discord")}
              disabled={loading}
              className="h-11 rounded-lg bg-[#5865F2] hover:bg-[#5865F2]/90 text-white font-medium transition-all duration-300 hover:shadow-lg hover:shadow-[#5865F2]/20 disabled:opacity-50 flex items-center justify-center gap-2"
            >
              <svg className="h-5 w-5" viewBox="0 0 245 240" fill="currentColor">
                <path d="M104.4 104.9c-5.7 0-10.2 5-10.2 11.1s4.6 11.1 10.2 11.1c5.7 0 10.2-5 10.2-11.1s-4.5-11.1-10.2-11.1z" />
                <path d="M189.5 20h-134A35.6 35.6 0 0020 55.6v128.7A35.6 35.6 0 0055.6 220h115.4l-5.4-18.7 13.1 12.1 12.4 11.4 22.4 20v-44.7l-.1-1.1V55.6A35.6 35.6 0 00189.5 20z" />
              </svg>
              <span className="text-sm">Discord</span>
            </button>

            <button
              onClick={() => handleOAuth("google")}
              disabled={loading}
              className="h-11 rounded-lg border border-white/10 bg-white/5 hover:bg-white/10 text-white font-medium transition-all duration-300 hover:shadow-lg hover:shadow-white/10 disabled:opacity-50 flex items-center justify-center gap-2"
            >
              <svg className="h-5 w-5" viewBox="0 0 48 48">
                <path
                  fill="#FFC107"
                  d="M43.6 20.5H42V20H24v8h11.3C33.4 32.4 29 36 24 36c-6.6 0-12-5.4-12-12S17.4 12 24 12c3.1 0 6 1.2 8.2 3.2l5.7-5.7C34.1 6 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.1-.1-2.1-.4-3.1z"
                />
                <path
                  fill="#FF3D00"
                  d="M6.3 14.7l6.6 4.8C14.2 16 18.7 12 24 12c3.1 0 6 1.2 8.2 3.2l5.7-5.7C34.1 6 29.3 4 24 4 16.1 4 9.2 8.5 6.3 14.7z"
                />
                <path
                  fill="#4CAF50"
                  d="M24 44c5 0 9.7-1.9 13.2-5l-6.1-5c-2 1.4-4.6 2.2-7.1 2.2-5 0-9.3-3.6-10.7-8.4l-6.6 5.1C9.3 39.6 16.1 44 24 44z"
                />
                <path
                  fill="#1976D2"
                  d="M43.6 20.5H42V20H24v8h11.3c-1 3.1-3.4 5.6-6.3 6.9l.1.1 6.1 5C38 37.7 40 32.1 40 26c0-1.1-.1-2.1-.4-3.1z"
                />
              </svg>
              <span className="text-sm">Google</span>
            </button>
          </div>

          <p
            className="mt-8 text-center text-xs text-white/40 opacity-0 animate-in fade-in delay-400"
            style={{ animationFillMode: "forwards" }}
          >
            By continuing, you agree to our{" "}
            <span className="text-white/60 hover:text-white/80 cursor-pointer transition-colors">Terms</span> &{" "}
            <span className="text-white/60 hover:text-white/80 cursor-pointer transition-colors">Privacy</span>
          </p>
        </div>
      </div>
    </div>
  )
}
