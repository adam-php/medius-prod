"use client"

import { useEffect, useMemo, useState } from "react"
import Link from "next/link"
import Image from "next/image"
import { useRouter } from "next/navigation"
import { AnimatePresence, motion } from "framer-motion"
import {
  LayoutDashboard,
  PlusCircle,
  UserIcon,
  Gift,
  Menu,
  X,
  MessageCircle,
  ExternalLink,
  ClipboardList,
  RefreshCcw,
  CheckCircle,
  ShoppingBag,
  ArrowLeftRight,
} from "lucide-react"
import { ArrowDownIcon, ArrowUpIcon, Share2Icon, UsersIcon, Search } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

import { supabase, isSupabaseConfigured } from "@/lib/supabase"
import type { Escrow } from "@/lib/types"
import { AddNewEscrowButton } from "@/components/add-new-escrow-button"

function VolumeDisplay({
  totalVolume,
  activePercentage,
  completedPercentage,
}: {
  totalVolume: number
  activePercentage: number
  completedPercentage: number
}) {
  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-gray-400 text-lg font-medium mb-2">Your Volume</h3>
        <div className="text-4xl font-bold text-white mb-4">
          ${totalVolume.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
        </div>
      </div>

      {/* Progress Bar */}
      <div className="space-y-3">
        <div className="w-full bg-white/10 rounded-full h-3 overflow-hidden">
          <div className="flex h-full">
            <div className="bg-orange-400 h-full rounded-l-full" style={{ width: `${activePercentage}%` }} />
            <div className="bg-green-400 h-full rounded-r-full" style={{ width: `${completedPercentage}%` }} />
          </div>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-orange-400 rounded-full" />
            <span className="text-white font-semibold">{Math.round(activePercentage)}%</span>
            <span className="text-gray-400">Active</span>
          </div>
          <div className="text-gray-400">|</div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-green-400 rounded-full" />
            <span className="text-white font-semibold">{Math.round(completedPercentage)}%</span>
            <span className="text-gray-400">Completed</span>
          </div>
        </div>
      </div>
    </div>
  )
}

function DealsBreakdownBar({
  completed,
  active,
  disputed = 0,
  total,
  height = 12,
}: {
  completed: number
  active: number
  disputed?: number
  total: number
  height?: number
}) {
  const segments = [
    { key: "active", label: "Active", count: active, color: "#fb923c" },
    ...(disputed > 0 ? [{ key: "disputed", label: "Disputed", count: disputed, color: "#f87171" }] : []),
    { key: "completed", label: "Completed", count: completed, color: "#34d399" },
  ]

  if (disputed > 0) {
    segments.push({ key: "disputed", label: "Disputed", count: disputed, color: "#f87171" })
  }

  const sum = segments.reduce((acc, s) => acc + s.count, 0)
  const base = total || sum

  return (
    <div className="min-w-[220px]">
      {/* Bar */}
      <div
        className="w-full bg-white/10 rounded-full overflow-hidden"
        style={{ height }}
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={base}
        aria-valuenow={sum}
      >
        <div className="flex h-full">
          {segments.map((s, i) => {
            const pct = base ? Math.max(0, Math.min(100, (s.count / base) * 100)) : 0
            return (
              <motion.div
                key={s.key}
                initial={{ width: 0 }}
                animate={{ width: `${pct}%` }}
                transition={{ duration: 0.8, delay: i * 0.08, ease: [0.22, 1, 0.36, 1] }}
                style={{ background: s.color }}
                className={[
                  "h-full",
                  i === 0 ? "rounded-l-full" : "",
                  i === segments.length - 1 ? "rounded-r-full" : "",
                ].join(" ")}
                aria-label={`${s.label}: ${Math.round(pct)}%`}
                title={`${s.label}: ${Math.round(pct)}% (${s.count})`}
              />
            )
          })}
        </div>
      </div>

      {/* Legend */}
      <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3">
        {segments.map((s) => {
          const pct = base ? Math.round((s.count / base) * 100) : 0
          return (
            <div key={s.key} className="flex items-center gap-2">
              <span className="inline-block w-3 h-3 rounded-full shrink-0" style={{ background: s.color }} />
              <span className="text-white font-semibold">{pct}%</span>
              <span className="text-gray-400">{s.label}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function DealsDonut({
  active,
  completed,
  size = 88,
  stroke = 10,
}: {
  active: number
  completed: number
  size?: number
  stroke?: number
}) {
  const total = active + completed
  const cx = size / 2
  const cy = size / 2
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r

  const completedLen = total ? (completed / total) * c : 0
  const activeLen = total ? (active / total) * c : 0

  const colors = {
    completed: "#34d399",
    active: "#fb923c",
    track: "rgba(255,255,255,0.12)",
  }

  const percent = total ? Math.round((completed / total) * 100) : 0

  return (
    <div className="flex items-center gap-3 sm:gap-4">
      <svg width={size} height={size} className="shrink-0">
        <g transform={`rotate(-90 ${cx} ${cy})`}>
          {/* Track */}
          <circle cx={cx} cy={cy} r={r} fill="none" stroke={colors.track} strokeWidth={stroke} />
          {/* Completed segment */}
          {completed > 0 && (
            <circle
              cx={cx}
              cy={cy}
              r={r}
              fill="none"
              stroke={colors.completed}
              strokeWidth={stroke}
              strokeLinecap="butt"
              strokeDasharray={`${completedLen} ${c - completedLen}`}
              className="transition-[stroke-dasharray] duration-700 ease-out"
            />
          )}
          {/* Active segment */}
          {active > 0 && (
            <circle
              cx={cx}
              cy={cy}
              r={r}
              fill="none"
              stroke={colors.active}
              strokeWidth={stroke}
              strokeLinecap="butt"
              strokeDasharray={`${activeLen} ${c - activeLen}`}
              strokeDashoffset={-completedLen}
              className="transition-[stroke-dasharray] duration-700 ease-out"
            />
          )}
        </g>
        {/* Center label */}
        <text
          x={cx}
          y={cy}
          textAnchor="middle"
          dominantBaseline="central"
          style={{ fill: "white", fontSize: 14, fontWeight: 700 }}
        >
          {percent}%
        </text>
      </svg>

      {/* Legend */}
      <div className="flex flex-col text-xs">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: colors.active }} />
          <span className="text-gray-300">Active</span>
          <span className="ml-2 text-white font-medium">{active}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: colors.completed }} />
          <span className="text-gray-300">Completed</span>
          <span className="ml-2 text-white font-medium">{completed}</span>
        </div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [escrows, setEscrows] = useState<Escrow[]>([])
  const [loading, setLoading] = useState(true)
  const [user, setUser] = useState<any>(null)
  const [stats, setStats] = useState({ total: 0, completed: 0, pending: 0, totalValue: 0 })
  const [prices, setPrices] = useState<Record<string, number>>({})
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const router = useRouter()
  const [searchQuery, setSearchQuery] = useState("")

  useEffect(() => {
    const checkUser = async () => {
      if (!isSupabaseConfigured()) {
        console.warn("Supabase not configured, using demo data")
        setUser({ email: "demo@example.com", id: "demo-user" })
        setEscrows([])
        setLoading(false)
        return
      }

      const {
        data: { user },
      } = await supabase.auth.getUser()
      setUser(user)
      await fetchEscrows(user?.id ?? "demo-user")
      fetchPrices()
      const id = setInterval(fetchPrices, 60_000)
      return () => clearInterval(id)
    }
    checkUser()
  }, [router])

  const handleLogout = async () => {
    if (isSupabaseConfigured()) {
      await supabase.auth.signOut()
    }
    setMobileNavOpen(false)
    router.push("/")
  }

  const fetchPrices = async () => {
    try {
      const idMap: Record<string, string> = {
        BTC: "bitcoin",
        ETH: "ethereum",
        LTC: "litecoin",
        BCH: "bitcoin-cash",
        DOGE: "dogecoin",
        XRP: "ripple",
        ADA: "cardano",
        DOT: "polkadot",
        MATIC: "matic-network",
        SOL: "solana",
        AVAX: "avalanche-2",
        TRX: "tron",
        BNB: "binancecoin",
        ATOM: "cosmos",
        XLM: "stellar",
      }
      const ids = Object.values(idMap).join(",")
      const res = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd`)
      if (!res.ok) throw new Error("price fetch failed")
      const data = await res.json()
      const p: Record<string, number> = {}
      for (const [sym, id] of Object.entries(idMap)) {
        if (data[id]?.usd) p[sym] = data[id].usd
      }
      setPrices(p)
    } catch (e) {
      console.warn("Price fetch error, using cached values", e)
    }
  }

  const fetchEscrows = async (userId: string) => {
    try {
      if (!isSupabaseConfigured()) {
        setEscrows([])
        return
      }

      const { data, error } = await supabase
        .from("escrows")
        .select("*")
        .or(`buyer_id.eq.${userId},seller_id.eq.${userId}`)
        .order("created_at", { ascending: false })
      if (error) throw error
      setEscrows(data || [])
    } catch (error) {
      console.error("Error fetching escrows:", error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (escrows.length > 0) {
      const totalUsd = escrows
        .filter((e) => e.status === "completed")
        .reduce((sum, e) => {
          if (e.currency === "USD" || e.payment_method === "paypal") {
            return sum + Number(e.usd_amount ?? e.amount)
          }
          const live = prices[e.currency]
          if (live) return sum + Number(e.amount) * live
          return sum + Number(e.usd_amount ?? 0)
        }, 0)
      setStats({
        total: escrows.length,
        completed: escrows.filter((e) => e.status === "completed").length,
        pending: escrows.filter((e) => e.status === "pending" || e.status === "funded").length,
        totalValue: totalUsd,
      })
    } else {
      setStats({ total: 0, completed: 0, pending: 0, totalValue: 0 })
    }
  }, [escrows, prices])

  const getUserRole = (escrow: Escrow) => {
    if (!user) return "Unknown"
    if (escrow.buyer_id === user.id) return "Buyer"
    if (escrow.seller_id === user.id) return "Seller"
    return "Observer"
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "pending":
        return "bg-yellow-500/20 text-yellow-300 border-yellow-400/30"
      case "funded":
        return "bg-orange-500/20 text-orange-300 border-orange-400/30"
      case "confirmed":
        return "bg-orange-500/20 text-orange-300 border-orange-400/30"
      case "completed":
        return "bg-green-500/20 text-green-300 border-green-400/30"
      case "disputed":
        return "bg-red-500/20 text-red-300 border-red-400/30"
      case "cancelled":
        return "bg-gray-500/20 text-gray-300 border-gray-400/30"
      case "refunded":
        return "bg-orange-500/20 text-orange-300 border-orange-400/30"
      default:
        return "bg-gray-500/20 text-gray-300 border-gray-400/30"
    }
  }

  const escrowsStagger = useMemo(
    () => ({
      hidden: { opacity: 0, y: 8 },
      show: (i: number) => ({
        opacity: 1,
        y: 0,
        transition: { delay: 0.02 * i, duration: 0.22, ease: [0.22, 1, 0.36, 1] as const },
      }),
    }),
    [],
  )

  const filteredEscrows = useMemo(() => {
    const query = searchQuery.trim().toLowerCase()
    if (!query) return escrows
    return escrows.filter((e) => {
      const title = (e.title || "").toLowerCase()
      const id = (e.id || "").toLowerCase()
      const currency = (e.currency || "").toLowerCase()
      const status = (e.status || "").toLowerCase()
      return title.includes(query) || id.includes(query) || currency.includes(query) || status.includes(query)
    })
  }, [escrows, searchQuery])

  const activePercentage = stats.total > 0 ? (stats.pending / stats.total) * 100 : 0
  const completedPercentage = stats.total > 0 ? (stats.completed / stats.total) * 100 : 0

  if (loading) {
    return (
      <div className="min-h-screen bg-black relative overflow-hidden flex items-center justify-center">
        <div className="flex items-center space-x-3 text-white relative z-10">
          <div className="w-8 h-8 border-2 border-orange-500 border-t-transparent rounded-full animate-spin"></div>
          <span className="text-lg">Loading your escrows...</span>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-black relative overflow-hidden">
      {/* Desktop Sidebar */}
      <motion.aside
        initial={{ x: -10, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
        className="hidden lg:block fixed left-0 top-0 h-full w-64 backdrop-blur-xl bg-black/40 z-40"
      >
        <div className="p-6">
          <div className="flex items-center space-x-3 mb-8">
            <div className="w-10 h-10 bg-gradient-to-br from-orange-500 to-orange-600 rounded-xl flex items-center justify-center">
              <span className="text-white font-bold text-lg">E</span>
            </div>
            <div>
              <h1 className="text-white font-bold text-xl">Escrow</h1>
              <p className="text-gray-400 text-sm">Dashboard</p>
            </div>
          </div>
          <nav className="space-y-2">
            <Link
              href="/dashboard"
              className="flex items-center space-x-3 px-4 py-3 rounded-xl bg-orange-500/20 text-orange-300 border border-orange-400/30"
            >
              <LayoutDashboard className="h-5 w-5" />
              <span className="font-medium">Overview</span>
            </Link>

            <Link
              href="/marketplace"
              className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-400 hover:bg-white/5 hover:text-white transition-all duration-200"
            >
              <ShoppingBag className="h-5 w-5" />
              <span className="font-medium">Marketplace</span>
            </Link>

            <Link
              href="/exchange"
              className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-400 hover:bg-white/5 hover:text-white transition-all duration-200"
            >
              <ArrowLeftRight className="h-5 w-5" />
              <span className="font-medium">Exchange</span>
            </Link>

            <Link
              href="/marketplace/create"
              className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-400 hover:bg-white/5 hover:text-white transition-all duration-200"
            >
              <PlusCircle className="h-5 w-5" />
              <span className="font-medium">Create Listing</span>
            </Link>
            <Link
              href="/messages"
              className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-400 hover:bg-white/5 hover:text-white transition-all duration-200"
            >
              <MessageCircle className="h-5 w-5" />
              <span className="font-medium">Messages</span>
            </Link>
            <div className="my-2 h-px bg-white/10" role="separator" aria-hidden="true" />

            <Link
              href="/profile"
              className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-400 hover:bg-white/5 hover:text-white transition-all duration-200"
            >
              <UserIcon className="h-5 w-5" />
              <span className="font-medium">Profile</span>
            </Link>
            <Link
              href="/referrals"
              className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-400 hover:bg-white/5 hover:text-white transition-all duration-200"
            >
              <Gift className="h-5 w-5" />
              <span className="font-medium">Referrals</span>
            </Link>
          </nav>
        </div>
      </motion.aside>

      {/* Mobile Drawer */}
      <AnimatePresence>
        {mobileNavOpen && (
          <div className="lg:hidden fixed inset-0 z-50">
            <motion.div
              key="overlay"
              initial={{ opacity: 0, backdropFilter: "blur(0px)" as any }}
              animate={{ opacity: 1, backdropFilter: "blur(4px)" as any }}
              exit={{ opacity: 0, backdropFilter: "blur(0px)" as any }}
              transition={{ duration: 0.2 }}
              className="absolute inset-0 bg-black/60"
              onClick={() => setMobileNavOpen(false)}
              aria-hidden="true"
            />
            <motion.aside
              key="drawer"
              initial={{ x: -24, opacity: 0.6, scale: 0.98 }}
              animate={{ x: 0, opacity: 1, scale: 1 }}
              exit={{ x: -24, opacity: 0 }}
              transition={{ type: "spring", stiffness: 380, damping: 32 }}
              className="absolute left-0 top-0 h-full w-72 max-w-[85vw] bg-black/90 border-r border-white/10 p-6 shadow-2xl"
              role="dialog"
              aria-modal="true"
              aria-label="Mobile navigation"
            >
              <div className="flex items-center justify-between mb-8">
                <div className="flex items-center space-x-3">
                  <Image
                    src="/images/image.png"
                    alt="Medius Logo"
                    width={40}
                    height={40}
                    className="rounded-xl border border-orange-400/30"
                    priority
                  />
                  <div>
                    <h1 className="text-white font-bold text-xl">Medius</h1>
                    <p className="text-gray-400 text-sm">Dashboard</p>
                  </div>
                </div>
                <motion.button
                  whileTap={{ scale: 0.95 }}
                  whileHover={{ scale: 1.05 }}
                  className="text-gray-300 hover:text-white p-2 rounded-md hover:bg-white/5 transition-colors"
                  onClick={() => setMobileNavOpen(false)}
                  aria-label="Close menu"
                >
                  <X className="h-5 w-5" />
                </motion.button>
              </div>

              {/* Primary navigation */}
              <nav className="space-y-2">
                <motion.div initial={{ y: 6, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
                  <Link
                    href="/dashboard"
                    onClick={() => setMobileNavOpen(false)}
                    className="flex items-center space-x-3 px-4 py-3 rounded-xl bg-orange-500/20 text-orange-300 border border-orange-400/30"
                  >
                    <LayoutDashboard className="h-5 w-5" />
                    <span className="font-medium">Overview</span>
                  </Link>
                </motion.div>
                <motion.div initial={{ y: 6, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.03 }}>
                  <Link
                    href="/marketplace"
                    onClick={() => setMobileNavOpen(false)}
                    className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-300 hover:bg-white/5 hover:text-white transition-all duration-200"
                  >
                    <ShoppingBag className="h-5 w-5" />
                    <span className="font-medium">Marketplace</span>
                  </Link>
                </motion.div>
                <motion.div initial={{ y: 6, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.04 }}>
                  <Link
                    href="/exchange"
                    onClick={() => setMobileNavOpen(false)}
                    className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-300 hover:bg-white/5 hover:text-white transition-all duration-200"
                  >
                    <ArrowLeftRight className="h-5 w-5" />
                    <span className="font-medium">Exchange</span>
                  </Link>
                </motion.div>
                <motion.div initial={{ y: 6, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.05 }}>
                  <Link
                    href="/marketplace/create"
                    onClick={() => setMobileNavOpen(false)}
                    className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-300 hover:bg:white/5 hover:bg-white/5 hover:text-white transition-all duration-200"
                  >
                    <PlusCircle className="h-5 w-5" />
                    <span className="font-medium">Create Listing</span>
                  </Link>
                </motion.div>
                <motion.div initial={{ y: 6, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.07 }}>
                  <Link
                    href="/messages"
                    onClick={() => setMobileNavOpen(false)}
                    className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-300 hover:bg-white/5 hover:text-white transition-all duration-200"
                  >
                    <MessageCircle className="h-5 w-5" />
                    <span className="font-medium">Messages</span>
                  </Link>
                </motion.div>
                <div className="my-2 h-px bg-white/10" role="separator" aria-hidden="true" />
                <motion.div initial={{ y: 6, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.06 }}>
                  <Link
                    href="/profile"
                    onClick={() => setMobileNavOpen(false)}
                    className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-300 hover:bg-white/5 hover:text-white transition-all duration-200"
                  >
                    <UserIcon className="h-5 w-5" />
                    <span className="font-medium">Profile</span>
                  </Link>
                </motion.div>
                <motion.div initial={{ y: 6, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.09 }}>
                  <Link
                    href="/referrals"
                    onClick={() => setMobileNavOpen(false)}
                    className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-300 hover:bg-white/5 hover:text-white transition-all duration-200"
                  >
                    <Gift className="h-5 w-5" />
                    <span className="font-medium">Referrals</span>
                  </Link>
                </motion.div>
              </nav>

              {/* Former navbar items — mobile only */}
              <div className="mt-6 border-t border-white/10 pt-6 space-y-2">
                <motion.div initial={{ y: 6, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
                  <Link
                    href="https://discord.gg/8pzvCMVz"
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={() => setMobileNavOpen(false)}
                    className="flex items-center space-x-3 px-4 py-3 rounded-xl text-gray-300 hover:bg-white/5 hover:text-white transition-all duration-200"
                  >
                    <MessageCircle className="h-5 w-5" />
                    <span className="font-medium">Contact Us</span>
                    <ExternalLink className="ml-auto h-4 w-4 text-gray-400" />
                  </Link>
                </motion.div>

                {user ? (
                  <>
                    <div className="px-4 text-xs text-gray-400">
                      Signed in as <span className="text-gray-200">{user.email}</span>
                    </div>
                    <motion.button
                      initial={{ y: 6, opacity: 0 }}
                      animate={{ y: 0, opacity: 1 }}
                      onClick={handleLogout}
                      className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-white/10 hover:bg-white/15 border border-white/20 text-white font-medium transition-colors"
                    >
                      <span>Logout</span>
                    </motion.button>
                  </>
                ) : (
                  <motion.div initial={{ y: 6, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
                    <Link
                      href="/auth"
                      onClick={() => setMobileNavOpen(false)}
                      className="w-full inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-white/10 hover:bg-white/15 border border-white/20 text-white font-medium"
                    >
                      Login
                    </Link>
                  </motion.div>
                )}
              </div>
            </motion.aside>
          </div>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <div className="lg:ml-64 min-h-screen relative lg:pt-8">
        {/* Header */}
        <div className="backdrop-blur-xl bg-black/20 px-4 sm:px-6 md:px-8 py-2 relative z-10">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <motion.button
                whileTap={{ scale: 0.95 }}
                className="lg:hidden inline-flex items-center justify-center w-12 h-20 bg-black text-white rounded-xl border border-white/20"
                onClick={() => setMobileNavOpen(true)}
                aria-label="Open menu"
              >
                <Menu className="h-5 w-5" />
              </motion.button>
              <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }}>
                <h1 className="text-2xl sm:text-3xl font-bold text-white mb-1 sm:mb-2">
                  Dashboard<span className="text-orange-400">.</span>
                </h1>
                {user && <p className="text-gray-400 text-sm sm:text-base">Welcome back, {user.email}</p>}
              </motion.div>
            </div>
            <motion.div
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              className="flex items-center gap-3 w-full sm:w-auto sm:gap-4 sm:justify-end"
            >
              <AddNewEscrowButton className="hidden sm:inline-flex" />
            </motion.div>
          </div>

          <div className="px-0 pt-3 pb-[max(1rem,env(safe-area-inset-bottom))] relative z-10">
            <div className="mb-4 sm:mb-5">
              {/* KPI Tiles */}
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4 mb-6">
                <motion.div
                  initial={{ opacity: 0, y: 8, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  transition={{ duration: 0.22 }}
                  whileHover={{ scale: 1.01 }}
                >
                  <Card className="backdrop-blur-xl bg-black/30 border-white/10">
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                      <CardTitle className="text-sm font-medium text-gray-300">Total Volume</CardTitle>
                      <UsersIcon className="h-4 w-4 text-orange-400" />
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold text-white">
                        ${stats.totalValue.toLocaleString(undefined, { maximumFractionDigits: 2 })}
                      </div>
                      <p className="text-xs text-gray-400">
                        {stats.completed > 0 ? "+" : ""}
                        {((stats.completed / Math.max(stats.total, 1)) * 100).toFixed(1)}% completion rate
                        <ArrowUpIcon className="ml-1 h-4 w-4 text-green-500 inline" />
                      </p>
                    </CardContent>
                  </Card>
                </motion.div>

                <motion.div
                  initial={{ opacity: 0, y: 8, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  transition={{ delay: 0.1, duration: 0.22 }}
                  whileHover={{ scale: 1.01 }}
                >
                  <Card className="backdrop-blur-xl bg-black/30 border-white/10">
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                      <CardTitle className="text-sm font-medium text-gray-300">Active Deals</CardTitle>
                      <Share2Icon className="h-4 w-4 text-orange-400" />
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold text-white">{stats.pending}</div>
                      <p className="text-xs text-gray-400">
                        {stats.pending > stats.completed ? "+" : ""}
                        {stats.pending - stats.completed} from completed
                        {stats.pending > stats.completed ? (
                          <ArrowUpIcon className="ml-1 h-4 w-4 text-green-500 inline" />
                        ) : (
                          <ArrowDownIcon className="ml-1 h-4 w-4 text-red-500 inline" />
                        )}
                      </p>
                    </CardContent>
                  </Card>
                </motion.div>

                <motion.div
                  initial={{ opacity: 0, y: 8, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  transition={{ delay: 0.2, duration: 0.22 }}
                  whileHover={{ scale: 1.01 }}
                >
                  <Card className="backdrop-blur-xl bg-black/30 border-white/10">
                    <CardHeader>
                      <CardTitle className="text-white">Completed Deals</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold text-white">{stats.completed}</div>
                      <p className="text-xs text-gray-400">
                        {stats.completed} successful escrows
                        <CheckCircle className="ml-1 h-4 w-4 text-green-500 inline" />
                      </p>
                    </CardContent>
                  </Card>
                </motion.div>

                <motion.div
                  initial={{ opacity: 0, y: 8, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  transition={{ delay: 0.3, duration: 0.22 }}
                  whileHover={{ scale: 1.01 }}
                >
                  <Card className="backdrop-blur-xl bg-black/30 border-white/10">
                    <CardHeader>
                      <CardTitle className="text-white">Total Escrows</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold text-white">{stats.total}</div>
                      <p className="text-xs text-gray-400">
                        All-time escrow count
                        <RefreshCcw className="ml-1 h-4 w-4 text-orange-400 inline" />
                      </p>
                    </CardContent>
                  </Card>
                </motion.div>
              </div>
            </div>

            {/* Search Bar */}
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1, duration: 0.25 }}
              className="mb-4"
            >
              <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-white/10 border border-white/15 max-w-md">
                <Search className="h-4 w-4 text-gray-400" />
                <input
                  placeholder="Search escrows..."
                  className="bg-transparent focus:outline-none text-sm text-white placeholder:text-gray-400 w-full"
                  aria-label="Search escrows"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
            </motion.div>

            {/* Escrows */}
            {escrows.length === 0 || filteredEscrows.length === 0 ? (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="backdrop-blur-xl bg-black/30 border border-white/10 rounded-2xl p-8 sm:p-12 text-center relative"
              >
                <div className="w-14 h-14 sm:w-16 sm:h-16 bg-orange-500/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
                  <ClipboardList className="text-orange-400 h-8 w-8" />
                </div>
                <h3 className="text-lg sm:text-xl font-bold text-white mb-2">
                  {escrows.length === 0 ? "No Escrows Yet" : "No matching escrows"}
                </h3>
                <p className="text-gray-400 mb-6">
                  {escrows.length === 0
                    ? "You haven't created or participated in any escrow transactions yet."
                    : "Try a different search or clear the search field."}
                </p>
                {escrows.length === 0 ? (
                  <motion.div whileHover={{ scale: 1.03 }}>
                    <Link
                      href="/create-escrow"
                      className="inline-flex items-center justify-center space-x-2 w-full sm:w-auto px-5 sm:px-6 py-3 bg-[#FF7A00] hover:bg-[#FF7A00] text-white rounded-xl font-medium hover:scale-105 transition-transform duration-200"
                    >
                      <span>{"Create Your First Escrow"}</span>
                      <span>{"→"}</span>
                    </Link>
                  </motion.div>
                ) : searchQuery ? (
                  <motion.button
                    whileHover={{ scale: 1.03 }}
                    onClick={() => setSearchQuery("")}
                    className="inline-flex items-center justify-center px-5 py-3 bg-white/10 hover:bg-white/15 border border-white/20 text-white rounded-xl font-medium"
                  >
                    Clear search
                  </motion.button>
                ) : null}
              </motion.div>
            ) : (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="backdrop-blur-xl bg-black/30 border border-white/10 rounded-2xl overflow-hidden relative"
              >
                <div className="p-4 sm:p-6 border-b border-white/10 flex items-center justify-between">
                  <div>
                    <h2 className="text-lg sm:text-xl font-semibold text-white">{"Escrows"}</h2>
                    <p className="text-gray-400 text-xs sm:text-sm">{"Manage your transactions"}</p>
                  </div>
                  <Link
                    href="/create-escrow"
                    className="sm:hidden inline-flex items-center justify-center px-4 py-2 bg-[#FF7A00] hover:bg-[#FF7A00] text-white rounded-lg font-medium"
                  >
                    {"+ New"}
                  </Link>
                </div>

                {/* Desktop Table */}
                <div className="hidden md:grid px-6 py-4 border-b border-white/10 grid-cols-5 gap-4 text-sm text-gray-400">
                  <span>{"Title"}</span>
                  <span>{"Amount"}</span>
                  <span>{"Status"}</span>
                  <span>{"Role"}</span>
                  <span>{"Actions"}</span>
                </div>

                <div className="hidden md:block divide-y divide-white/10">
                  {filteredEscrows.map((escrow, i) => (
                    <motion.div
                      key={escrow.id}
                      initial="hidden"
                      animate="show"
                      variants={escrowsStagger}
                      custom={i}
                      className="px-6 py-4 hover:bg-white/5 transition-colors duration-200"
                    >
                      <div className="grid grid-cols-5 gap-4 items-center">
                        <div>
                          <div className="font-medium text-white">{escrow.title || `#${escrow.id.slice(0, 8)}`}</div>
                          <div className="text-sm text-gray-400">
                            {new Date(escrow.created_at).toLocaleDateString()}
                          </div>
                        </div>
                        <div>
                          <div className="text-white font-medium">
                            {escrow.amount} {escrow.currency}
                          </div>
                          <div className="text-sm text-gray-400">
                            {"$"}
                            {(() => {
                              const usd =
                                escrow.currency === "USD" || escrow.payment_method === "paypal"
                                  ? Number(escrow.usd_amount ?? escrow.amount)
                                  : prices[escrow.currency]
                                    ? Number(escrow.amount) * prices[escrow.currency]
                                    : Number(escrow.usd_amount ?? 0)
                              return usd.toLocaleString(undefined, { maximumFractionDigits: 2 })
                            })()} {"USD"}
                          </div>
                        </div>
                        <div>
                          <span
                            className={`px-3 py-1 rounded-full text-xs font-medium border ${getStatusColor(
                              escrow.status,
                            )}`}
                          >
                            {escrow.status.toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <span className="px-2 py-1 bg-orange-500/20 text-orange-300 rounded-lg text-xs font-medium">
                            {getUserRole(escrow)}
                          </span>
                        </div>
                        <div>
                          <Link
                            href={`/escrow/${escrow.id}`}
                            className="text-orange-400 hover:text-orange-300 font-medium transition-colors duration-200"
                          >
                            {"View Details →"}
                          </Link>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>

                {/* Mobile Cards */}
                <div className="md:hidden divide-y divide-white/10">
                  {filteredEscrows.map((escrow, i) => {
                    const usd =
                      escrow.currency === "USD" || escrow.payment_method === "paypal"
                        ? Number(escrow.usd_amount ?? escrow.amount)
                        : prices[escrow.currency]
                          ? Number(escrow.amount) * prices[escrow.currency]
                          : Number(escrow.usd_amount ?? 0)
                    return (
                      <motion.div
                        key={escrow.id}
                        initial="hidden"
                        animate="show"
                        variants={escrowsStagger}
                        custom={i}
                        className="p-4"
                      >
                        <div className="flex items-start justify-between">
                          <div>
                            <div className="font-medium text-white">{escrow.title || `#${escrow.id.slice(0, 8)}`}</div>
                            <div className="text-xs text-gray-400">
                              {new Date(escrow.created_at).toLocaleDateString()}
                            </div>
                          </div>
                          <span
                            className={`px-2 py-1 rounded-full text-2xs font-medium border ${getStatusColor(
                              escrow.status,
                            )}`}
                          >
                            {escrow.status.toUpperCase()}
                          </span>
                        </div>
                        <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
                          <div className="text-gray-400">{"Amount"}</div>
                          <div className="text-white text-right">
                            {escrow.amount} {escrow.currency}
                          </div>
                          <div className="text-gray-400">{"Approx USD"}</div>
                          <div className="text-white text-right">
                            {"$"}
                            {usd.toLocaleString(undefined, { maximumFractionDigits: 2 })}
                          </div>
                          <div className="text-gray-400">{"Role"}</div>
                          <div className="text-orange-300 text-right">{getUserRole(escrow)}</div>
                        </div>
                        <motion.div whileTap={{ scale: 0.98 }} className="mt-4">
                          <Link
                            href={`/escrow/${escrow.id}`}
                            className="inline-flex w-full items-center justify-center px-4 py-2 bg-white/10 hover:bg-white/15 border border-white/20 rounded-lg text-white text-sm font-medium"
                          >
                            {"View Details"}
                          </Link>
                        </motion.div>
                      </motion.div>
                    )
                  })}
                </div>
              </motion.div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}