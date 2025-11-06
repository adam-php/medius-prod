// frontend/app/exchange/history/page.tsx
"use client"

import { useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { supabase } from "@/lib/supabase"
import { authApiRequest, handleApiError } from "@/lib/api"
import { AlertCircle, ArrowRight, Clock, RefreshCw, Search } from "lucide-react"
import ScrollFadeIn from "@/components/ui/scroll-fade-in"
import GlitchText from "@/components/ui/glitch-text"

type ExchangeRow = {
  exchange_id: string
  status: string
  from_currency: string
  from_amount: number
  to_currency: string
  to_amount: number
  rate: number
  created_at: string
  completed_at?: string
}

type HistoryResponse = {
  exchanges: ExchangeRow[]
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
}

const STATUS_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: "pending", label: "Pending" },
  { value: "deposit_detected", label: "Deposit Detected" },
  { value: "confirming", label: "Confirming" },
  { value: "swapping", label: "Swapping" },
  { value: "sending_payout", label: "Sending Payout" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "refunded", label: "Refunded" },
  { value: "expired", label: "Expired" },
  { value: "rate_expired", label: "Rate Expired" }
]

export default function ExchangeHistoryPage() {
  const [items, setItems] = useState<ExchangeRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [page, setPage] = useState(1)
  const [limit] = useState(15)
  const [total, setTotal] = useState(0)
  const [pages, setPages] = useState(1)
  const [status, setStatus] = useState("")
  const [query, setQuery] = useState("")

  const apiBase = useMemo(() => process.env.NEXT_PUBLIC_API_URL!, [])

  useEffect(() => {
    fetchHistory(1)
  }, [status])

  const fetchHistory = async (p = page) => {
    setLoading(true)
    setError("")
    try {
      const { data: { session } } = await supabase.auth.getSession()
      if (!session) {
        window.location.href = "/auth/login?redirect=/exchange/history"
        return
      }
      const params = new URLSearchParams()
      params.set("page", String(p))
      params.set("limit", String(limit))
      if (status) params.set("status", status)

      const res = await authApiRequest(`${apiBase}/api/exchange/user/history?${params}`, session)
      await handleApiError(res)
      const data: HistoryResponse = await res.json()

      let list = data.exchanges || []

      // Client-side query filter by currency codes
      if (query.trim()) {
        const q = query.trim().toLowerCase()
        list = list.filter(
          r =>
            r.exchange_id.toLowerCase().includes(q) ||
            r.from_currency.toLowerCase().includes(q) ||
            r.to_currency.toLowerCase().includes(q)
        )
      }

      setItems(list)
      setPage(data.pagination.page)
      setTotal(data.pagination.total)
      setPages(data.pagination.pages)
    } catch (err: any) {
      setError(err.message || "Failed to load history")
    } finally {
      setLoading(false)
    }
  }

  const nextPage = () => {
    if (page < pages) fetchHistory(page + 1)
  }
  const prevPage = () => {
    if (page > 1) fetchHistory(page - 1)
  }

  return (
    <div className="min-h-screen bg-black text-white relative overflow-hidden">
      {/* Background glow */}
      <div
        className="absolute top-0 left-0 -z-10 rounded-2xl overflow-hidden pointer-events-none mix-blend-screen"
        style={{
          width: "min(50vw, 50vh)",
          height: "min(50vw, 50vh)",
          background:
            "radial-gradient(28% 28% at 18% 14%, rgba(255,180,110,0.78) 0%, rgba(255,180,110,0.00) 60%), " +
            "radial-gradient(70% 70% at 25% 20%, rgba(251,146,60,0.62) 0%, rgba(251,146,60,0.00) 62%), " +
            "linear-gradient(135deg, rgba(251,146,60,0.34) 0%, rgba(251,146,60,0.00) 70%)"
        }}
      />

      <div className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Header */}
        <ScrollFadeIn>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-6">
            <div>
              <h1 className="text-3xl font-bold">
                <GlitchText text="Exchange History" />
                <span className="text-orange-400">.</span>
              </h1>
              <p className="text-gray-400">Your past crypto exchanges</p>
            </div>
            <div className="flex gap-2">
              <Link
                href="/exchange"
                className="h-10 px-4 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 flex items-center justify-center text-sm"
              >
                New Exchange
              </Link>
            </div>
          </div>
        </ScrollFadeIn>

        {/* Filters */}
        <ScrollFadeIn delay={100}>
          <div className="rounded-2xl bg-[#12161C] border border-[#222831] p-4 mb-6">
            <div className="flex flex-col md:flex-row md:items-center gap-3">
              <div className="flex-1 flex items-center gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
                  <input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && fetchHistory(1)}
                    placeholder="Search by exchange ID or currency (e.g. BTC)"
                    className="w-full h-10 pl-10 pr-3 rounded-xl bg-black border border-white/10 text-white placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-orange-500"
                  />
                </div>
                <button
                  onClick={() => fetchHistory(1)}
                  className="h-10 px-3 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-sm"
                  title="Refresh"
                >
                  <RefreshCw className="h-4 w-4" />
                </button>
              </div>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="h-10 px-3 rounded-xl bg-black border border-white/10 text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
              >
                {STATUS_OPTIONS.map(opt => (
                  <option key={opt.value || "all"} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </ScrollFadeIn>

        {error && (
          <ScrollFadeIn delay={150}>
            <div className="mb-6 rounded-xl border border-red-400/30 bg-red-500/10 p-4 text-red-200 flex items-start gap-3">
              <AlertCircle className="h-5 w-5 flex-shrink-0 mt-0.5" />
              <div>{error}</div>
            </div>
          </ScrollFadeIn>
        )}

        {/* Table */}
        <ScrollFadeIn delay={200}>
          <div className="rounded-2xl bg-[#12161C] border border-[#222831] overflow-hidden">
            <div className="hidden md:grid grid-cols-12 gap-2 px-4 py-3 border-b border-white/10 text-xs text-gray-400">
              <div className="col-span-3">Exchange</div>
              <div className="col-span-2">You Sent</div>
              <div className="col-span-2">You Received</div>
              <div className="col-span-2">Rate</div>
              <div className="col-span-2">Created</div>
              <div className="col-span-1 text-right">Action</div>
            </div>

            {loading ? (
              <div className="p-6 text-center text-gray-400">Loading...</div>
            ) : items.length === 0 ? (
              <div className="p-6 text-center text-gray-400">No exchanges found.</div>
            ) : (
              <div className="divide-y divide-white/10">
                {items.map((row) => (
                  <div
                    key={row.exchange_id}
                    className="grid grid-cols-1 md:grid-cols-12 gap-2 px-4 py-4"
                  >
                    <div className="md:col-span-3">
                      <div className="text-sm font-medium text-white truncate">
                        {row.from_currency} → {row.to_currency}
                      </div>
                      <div className="text-xs text-gray-400">
                        <span
                          className={`inline-block px-2 py-0.5 rounded-md ${
                            row.status === "completed"
                              ? "bg-green-500/20 text-green-300"
                              : row.status === "failed" || row.status === "expired"
                              ? "bg-red-500/20 text-red-300"
                              : "bg-white/5 text-gray-300"
                          }`}
                        >
                          {row.status}
                        </span>
                      </div>
                    </div>

                    <div className="md:col-span-2 text-sm">
                      <div className="text-white">{row.from_amount.toFixed(8)}</div>
                      <div className="text-xs text-gray-400">{row.from_currency}</div>
                    </div>

                    <div className="md:col-span-2 text-sm">
                      <div className="text-white">{row.to_amount.toFixed(8)}</div>
                      <div className="text-xs text-gray-400">{row.to_currency}</div>
                    </div>

                    <div className="md:col-span-2 text-sm">
                      <div className="text-white">{row.rate.toFixed(8)}</div>
                      <div className="text-xs text-gray-400">
                        1 {row.from_currency} → {row.to_currency}
                      </div>
                    </div>

                    <div className="md:col-span-2 text-sm">
                      <div className="text-white">
                        {new Date(row.created_at).toLocaleString()}
                      </div>
                      {row.completed_at && (
                        <div className="text-xs text-gray-400">
                          <Clock className="inline h-3.5 w-3.5 mr-1" />
                          {new Date(row.completed_at).toLocaleString()}
                        </div>
                      )}
                    </div>

                    <div className="md:col-span-1 flex md:justify-end">
                      <Link
                        href={`/exchange/${row.exchange_id}`}
                        className="inline-flex items-center gap-1 h-9 px-3 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-sm"
                      >
                        View <ArrowRight className="h-4 w-4" />
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </ScrollFadeIn>

        {/* Pagination */}
        <ScrollFadeIn delay={240}>
          <div className="mt-6 flex items-center justify-between text-sm text-gray-400">
            <div>
              Page {page} of {pages} • {total} total
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={prevPage}
                disabled={page <= 1}
                className="h-9 px-3 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 disabled:opacity-50"
              >
                Prev
              </button>
              <button
                onClick={nextPage}
                disabled={page >= pages}
                className="h-9 px-3 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        </ScrollFadeIn>
      </div>
    </div>
  )
}