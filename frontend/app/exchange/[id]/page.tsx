// frontend/app/exchange/[id]/page.tsx
"use client"

import { useEffect, useMemo, useState } from "react"
import { useParams } from "next/navigation"
import Link from "next/link"
import { supabase } from "@/lib/supabase"
import { authApiRequest, handleApiError } from "@/lib/api"
import {
  AlertCircle,
  ArrowLeftRight,
  CheckCircle2,
  Clock,
  Copy,
  ExternalLink,
  Info,
  RefreshCw,
  XCircle,
} from "lucide-react"
import ScrollFadeIn from "@/components/ui/scroll-fade-in"
import GlitchText from "@/components/ui/glitch-text"
import { StatefulButton } from "@/components/ui/stateful-button"

interface ExchangeDetails {
  exchange_id: string
  status: string
  created_at: string
  updated_at: string
  completed_at?: string
  from: {
    currency: string
    amount: number
    amount_usd?: number
  }
  to: {
    currency: string
    amount: number
    amount_usd?: number
  }
  deposit: {
    address: string
    tag?: string
    tx_hash?: string
    confirmations: number
    detected_at?: string
    confirmed_at?: string
  }
  payout: {
    address: string
    tag?: string
    tx_hash?: string
    confirmations: number
    sent_at?: string
    confirmed_at?: string
  }
  fees: {
    platform_percent: number
    platform_amount: number
    platform_usd?: number
    network_amount: number
    network_usd?: number
  }
  rate: {
    value: number
    locked_at: string
    expires_at: string
    expires_in_seconds: number
    expired: boolean
  }
  ffio_order_id?: string
  error?: string
}

const STATUS_INFO: Record<
  string,
  { label: string; color: string; description: string; icon: any }
> = {
  pending: {
    label: "Waiting for Deposit",
    color: "text-yellow-400",
    description: "Send crypto to the deposit address below.",
    icon: Clock,
  },
  rate_expired: {
    label: "Rate Expired",
    color: "text-orange-400",
    description: "Rate lock expired. Please create a new exchange.",
    icon: AlertCircle,
  },
  deposit_detected: {
    label: "Deposit Detected",
    color: "text-blue-400",
    description: "We detected your deposit. Waiting for confirmations...",
    icon: RefreshCw,
  },
  confirming: {
    label: "Confirming",
    color: "text-blue-400",
    description: "Your deposit is being confirmed on the blockchain.",
    icon: RefreshCw,
  },
  swapping: {
    label: "Swapping",
    color: "text-purple-400",
    description: "Your exchange is being processed.",
    icon: ArrowLeftRight,
  },
  sending_payout: {
    label: "Sending Payout",
    color: "text-green-400",
    description: "Sending swapped crypto to your address.",
    icon: ArrowLeftRight,
  },
  completed: {
    label: "Completed",
    color: "text-green-400",
    description: "Exchange completed successfully!",
    icon: CheckCircle2,
  },
  failed: {
    label: "Failed",
    color: "text-red-400",
    description: "Exchange failed. You can request a refund below.",
    icon: XCircle,
  },
  refunded: {
    label: "Refunded",
    color: "text-gray-400",
    description: "Exchange was refunded to your address.",
    icon: RefreshCw,
  },
  expired: {
    label: "Expired",
    color: "text-gray-400",
    description: "Exchange expired without deposit.",
    icon: XCircle,
  },
}

const BLOCK_EXPLORERS: Record<string, string> = {
  BTC: "https://blockchair.com/bitcoin/transaction/",
  ETH: "https://etherscan.io/tx/",
  "USDT-ERC20": "https://etherscan.io/tx/",
  BNB: "https://bscscan.com/tx/",
  "USDT-BEP20": "https://bscscan.com/tx/",
  SOL: "https://solscan.io/tx/",
  "USDT-SOL": "https://solscan.io/tx/",
  TRX: "https://tronscan.org/#/transaction/",
  "USDT-TRON": "https://tronscan.org/#/transaction/",
  LTC: "https://blockchair.com/litecoin/transaction/",
  DOGE: "https://blockchair.com/dogecoin/transaction/",
  XRP: "https://xrpscan.com/tx/",
  MATIC: "https://polygonscan.com/tx/",
  AVAX: "https://snowtrace.io/tx/",
  ATOM: "https://www.mintscan.io/cosmos/txs/",
  XLM: "https://stellarchain.io/tx/",
}

export default function ExchangeDetailsPage() {
  const params = useParams()
  const exchangeId = params.id as string

  const [exchange, setExchange] = useState<ExchangeDetails | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [refreshing, setRefreshing] = useState(false)
  const [canceling, setCanceling] = useState(false)

  const [copied, setCopied] = useState<string | null>(null)
  const [refundAddress, setRefundAddress] = useState("")
  const [refundTag, setRefundTag] = useState("")

  const apiBase = useMemo(() => process.env.NEXT_PUBLIC_API_URL!, [])

  // Initial fetch
  useEffect(() => {
    fetchExchangeDetails()
  }, [exchangeId])

  // Auto-refresh active exchanges
  useEffect(() => {
    const interval = setInterval(() => {
      if (
        exchange &&
        !["completed", "failed", "refunded", "expired", "rate_expired"].includes(
          exchange.status
        )
      ) {
        fetchExchangeDetails(true)
      }
    }, 10000)
    return () => clearInterval(interval)
  }, [exchange])

  const fetchExchangeDetails = async (silent = false) => {
    if (!silent) setLoading(true)
    setError("")

    try {
      const {
        data: { session },
      } = await supabase.auth.getSession()
      if (!session) {
        window.location.href = "/auth/login?redirect=/exchange"
        return
      }

      const res = await authApiRequest(
        `${apiBase}/api/exchange/${exchangeId}`,
        session
      )
      await handleApiError(res)
      const data = (await res.json()) as ExchangeDetails
      setExchange(data)
    } catch (err: any) {
      setError(err.message || "Failed to load exchange details")
    } finally {
      setLoading(false)
    }
  }

  const refreshStatus = async () => {
    setRefreshing(true)
    setError("")
    try {
      const {
        data: { session },
      } = await supabase.auth.getSession()
      if (!session) return
      const res = await authApiRequest(
        `${apiBase}/api/exchange/${exchangeId}/refresh`,
        session,
        { method: "POST" }
      )
      await handleApiError(res)
      await fetchExchangeDetails(true)
    } catch (err: any) {
      setError(err.message || "Failed to refresh status")
    } finally {
      setRefreshing(false)
    }
  }

  const requestRefund = async () => {
    if (!refundAddress.trim()) {
      setError("Refund address is required.")
      return
    }
    setError("")
    setCanceling(true)
    try {
      const {
        data: { session },
      } = await supabase.auth.getSession()
      if (!session) return
      const res = await authApiRequest(
        `${apiBase}/api/exchange/${exchangeId}/cancel`,
        session,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            refund_address: refundAddress.trim(),
            refund_tag: refundTag.trim() || null,
          }),
        }
      )
      await handleApiError(res)
      await fetchExchangeDetails(true)
    } catch (err: any) {
      setError(err.message || "Failed to request refund")
    } finally {
      setCanceling(false)
    }
  }

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopied(label)
    setTimeout(() => setCopied(null), 2000)
  }

  const getBlockExplorerUrl = (currency: string, txHash: string): string => {
    const baseUrl = BLOCK_EXPLORERS[currency] || BLOCK_EXPLORERS["ETH"]
    return `${baseUrl}${txHash}`
  }

  const stepIndexFromStatus = (status: string) => {
    switch (status) {
      case "pending":
      case "rate_expired":
        return 0
      case "deposit_detected":
      case "confirming":
        return 1
      case "swapping":
        return 2
      case "sending_payout":
        return 3
      case "completed":
        return 4
      default:
        return 0
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <div className="text-center space-y-4">
          <div className="inline-block h-12 w-12 animate-spin rounded-full border-4 border-solid border-orange-500 border-r-transparent"></div>
          <p className="text-gray-400">Loading exchange...</p>
        </div>
      </div>
    )
  }

  if (error && !exchange) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <div className="text-center space-y-4">
          <AlertCircle className="h-16 w-16 text-red-400 mx-auto" />
          <h2 className="text-2xl font-bold">Error Loading Exchange</h2>
          <p className="text-gray-400">{error}</p>
          <Link
            href="/exchange"
            className="inline-block px-6 py-3 rounded-xl bg-orange-500 hover:bg-orange-600 text-white font-semibold"
          >
            Back to Exchange
          </Link>
        </div>
      </div>
    )
  }

  if (!exchange) return null

  const statusInfo = STATUS_INFO[exchange.status] || STATUS_INFO.pending
  const StatusIcon = statusInfo.icon
  const progressStep = stepIndexFromStatus(exchange.status)
  const steps = [
    "Waiting for Deposit",
    "Confirming",
    "Swapping",
    "Sending Payout",
    "Completed",
  ]

  return (
    <div className="min-h-screen bg-black text-white relative overflow-hidden">
      {/* Background gradient */}
      <div
        className="absolute top-0 left-0 -z-10 rounded-2xl overflow-hidden pointer-events-none mix-blend-screen"
        style={{
          width: "min(50vw, 50vh)",
          height: "min(50vw, 50vh)",
          background:
            "radial-gradient(28% 28% at 18% 14%, rgba(255,180,110,0.78) 0%, rgba(255,180,110,0.00) 60%), " +
            "radial-gradient(70% 70% at 25% 20%, rgba(251,146,60,0.62) 0%, rgba(251,146,60,0.00) 62%), " +
            "linear-gradient(135deg, rgba(251,146,60,0.34) 0%, rgba(251,146,60,0.00) 70%)",
        }}
      />

      <div className="container mx-auto px-4 py-8 max-w-4xl">
        {/* Header */}
        <ScrollFadeIn>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-8">
            <div>
              <h1 className="text-3xl font-bold">
                <GlitchText text="Exchange Details" />
                <span className="text-orange-400">.</span>
              </h1>
              <p className="text-gray-400">Track your crypto exchange</p>
            </div>
            <div className="flex gap-2">
              <button
                onClick={refreshStatus}
                disabled={refreshing}
                className="h-10 px-4 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 flex items-center justify-center gap-2 disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
                Refresh
              </button>
              <Link
                href="/exchange"
                className="h-10 px-4 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 flex items-center justify-center"
              >
                New Exchange
              </Link>
            </div>
          </div>
        </ScrollFadeIn>

        {error && (
          <ScrollFadeIn delay={100}>
            <div className="mb-6 rounded-xl border border-red-400/30 bg-red-500/10 p-4 text-red-200 flex items-start gap-3">
              <AlertCircle className="h-5 w-5 flex-shrink-0 mt-0.5" />
              <div>{error}</div>
            </div>
          </ScrollFadeIn>
        )}

        {/* Status Banner */}
        <ScrollFadeIn delay={150}>
          <div
            className={`rounded-2xl border p-6 mb-6 ${
              exchange.status === "completed"
                ? "bg-green-500/10 border-green-400/30"
                : exchange.status === "failed"
                ? "bg-red-500/10 border-red-400/30"
                : exchange.status === "refunded" || exchange.status === "expired"
                ? "bg-gray-500/10 border-gray-400/30"
                : "bg-blue-500/10 border-blue-400/30"
            }`}
          >
            <div className="flex items-start gap-4">
              <StatusIcon className={`h-8 w-8 flex-shrink-0 ${statusInfo.color}`} />
              <div className="flex-1">
                <h2 className={`text-2xl font-bold ${statusInfo.color}`}>
                  {statusInfo.label}
                </h2>
                <p className="text-gray-300 mt-1">{statusInfo.description}</p>
                {exchange.error && (
                  <p className="text-red-300 text-sm mt-2">
                    <AlertCircle className="inline h-4 w-4 mr-1" />
                    {exchange.error}
                  </p>
                )}
                {/* Rate lock info */}
                {exchange.rate && !["completed", "failed", "refunded"].includes(exchange.status) && (
                  <p className="text-xs text-gray-400 mt-2">
                    <Clock className="inline h-3.5 w-3.5 mr-1" />
                    Rate locked at {new Date(exchange.rate.locked_at).toLocaleString()} •
                    Expires {new Date(exchange.rate.expires_at).toLocaleTimeString()}
                  </p>
                )}
              </div>
            </div>
          </div>
        </ScrollFadeIn>

        {/* Progress Steps */}
        <ScrollFadeIn delay={200}>
          <div className="rounded-2xl bg-[#12161C] border border-[#222831] p-4 mb-6">
            <div className="flex items-center justify-between">
              {steps.map((label, idx) => (
                <div key={label} className="flex-1 flex flex-col items-center">
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold ${
                      idx <= progressStep ? "bg-orange-500 text-white" : "bg-white/5 text-gray-500"
                    }`}
                  >
                    {idx + 1}
                  </div>
                  <div className="text-[11px] text-gray-400 mt-2 text-center">{label}</div>
                  {idx < steps.length - 1 && (
                    <div
                      className={`h-1 w-full mt-2 ${
                        idx < progressStep ? "bg-orange-500/80" : "bg-white/5"
                      }`}
                    />
                  )}
                </div>
              ))}
            </div>
          </div>
        </ScrollFadeIn>

        {/* Exchange Summary */}
        <ScrollFadeIn delay={220}>
          <div className="rounded-2xl bg-[#12161C] border border-[#222831] p-6 mb-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* You Send */}
              <div>
                <h3 className="text-sm font-medium text-gray-300 mb-2">You Sent</h3>
                <div className="rounded-xl bg-black border border-white/10 p-4">
                  <div className="text-xl font-bold">
                    {exchange.from.amount.toFixed(8)}{" "}
                    <span className="text-orange-400">{exchange.from.currency}</span>
                  </div>
                  {exchange.from.amount_usd !== undefined && (
                    <div className="text-xs text-gray-500 mt-1">
                      ≈ ${Number(exchange.from.amount_usd).toFixed(2)} USD
                    </div>
                  )}
                  {/* Deposit address */}
                  <div className="mt-4 text-sm">
                    <div className="text-gray-400 mb-1">Deposit Address</div>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 truncate bg-white/5 px-2 py-1 rounded">
                        {exchange.deposit.address}
                      </code>
                      <button
                        onClick={() =>
                          copyToClipboard(exchange.deposit.address, "deposit_address")
                        }
                        className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10"
                        title="Copy address"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                      {exchange.deposit.tx_hash && (
                        <a
                          href={getBlockExplorerUrl(
                            exchange.from.currency,
                            exchange.deposit.tx_hash
                          )}
                          target="_blank"
                          className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10"
                          title="View on explorer"
                          rel="noreferrer"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      )}
                    </div>
                    {exchange.deposit.tag && (
                      <div className="mt-2">
                        <div className="text-gray-400 mb-1">Deposit Tag/Memo</div>
                        <div className="flex items-center gap-2">
                          <code className="flex-1 truncate bg-white/5 px-2 py-1 rounded">
                            {exchange.deposit.tag}
                          </code>
                          <button
                            onClick={() =>
                              copyToClipboard(exchange.deposit.tag!, "deposit_tag")
                            }
                            className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10"
                            title="Copy tag/memo"
                          >
                            <Copy className="h-4 w-4" />
                          </button>
                        </div>
                        <p className="text-xs text-yellow-500 mt-1">
                          <AlertCircle className="inline h-3.5 w-3.5 mr-1" />
                          Make sure to include the tag/memo, if required by your wallet.
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* You Receive */}
              <div>
                <h3 className="text-sm font-medium text-gray-300 mb-2">You Receive</h3>
                <div className="rounded-xl bg-black border border-white/10 p-4">
                  <div className="text-xl font-bold">
                    {exchange.to.amount.toFixed(8)}{" "}
                    <span className="text-green-400">{exchange.to.currency}</span>
                  </div>
                  {exchange.to.amount_usd !== undefined && (
                    <div className="text-xs text-gray-500 mt-1">
                      ≈ ${Number(exchange.to.amount_usd).toFixed(2)} USD
                    </div>
                  )}
                  <div className="mt-4 text-sm">
                    <div className="text-gray-400 mb-1">Destination Address</div>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 truncate bg-white/5 px-2 py-1 rounded">
                        {exchange.payout.address}
                      </code>
                      <button
                        onClick={() =>
                          copyToClipboard(exchange.payout.address, "destination_address")
                        }
                        className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10"
                        title="Copy address"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                      {exchange.payout.tx_hash && (
                        <a
                          href={getBlockExplorerUrl(
                            exchange.to.currency,
                            exchange.payout.tx_hash
                          )}
                          target="_blank"
                          className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10"
                          title="View on explorer"
                          rel="noreferrer"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      )}
                    </div>
                    {exchange.payout.tag && (
                      <p className="text-xs text-gray-500 mt-1">Tag/Memo: {exchange.payout.tag}</p>
                    )}
                  </div>

                  {/* Status notes */}
                  <div className="mt-4 text-xs text-gray-400 space-y-1">
                    {exchange.deposit.detected_at && (
                      <p>
                        Deposit detected: {new Date(exchange.deposit.detected_at).toLocaleString()}
                      </p>
                    )}
                    {exchange.deposit.confirmed_at && (
                      <p>
                        Deposit confirmed:{" "}
                        {new Date(exchange.deposit.confirmed_at).toLocaleString()}
                      </p>
                    )}
                    {exchange.payout.sent_at && (
                      <p>
                        Payout sent: {new Date(exchange.payout.sent_at).toLocaleString()}
                      </p>
                    )}
                    {exchange.completed_at && (
                      <p>Completed: {new Date(exchange.completed_at).toLocaleString()}</p>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </ScrollFadeIn>

        {/* Fees & Rate */}
        <ScrollFadeIn delay={240}>
          <div className="rounded-2xl bg-[#12161C] border border-[#222831] p-6 mb-6">
            <h3 className="text-lg font-bold mb-4">Fees & Rate</h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-sm">
              <div className="rounded-xl bg-black border border-white/10 p-4">
                <div className="text-gray-400">Exchange Rate</div>
                <div className="text-white font-mono mt-1">
                  1 {exchange.from.currency} = {exchange.rate.value.toFixed(8)}{" "}
                  {exchange.to.currency}
                </div>
                <div className="text-xs text-gray-500 mt-1">
                  Locked: {new Date(exchange.rate.locked_at).toLocaleTimeString()}
                </div>
              </div>
              <div className="rounded-xl bg-black border border-white/10 p-4">
                <div className="text-gray-400">Platform Fee</div>
                <div className="text-orange-400 font-semibold mt-1">
                  {exchange.fees.platform_percent}% (
                  {exchange.fees.platform_amount.toFixed(8)} {exchange.to.currency})
                </div>
                {exchange.fees.platform_usd !== undefined && (
                  <div className="text-xs text-gray-500">≈ ${exchange.fees.platform_usd}</div>
                )}
              </div>
              <div className="rounded-xl bg-black border border-white/10 p-4">
                <div className="text-gray-400">Network Fee (est.)</div>
                <div className="text-gray-200 mt-1">
                  {Number(exchange.fees.network_amount || 0).toFixed(8)} {exchange.to.currency}
                </div>
                {exchange.fees.network_usd !== undefined && (
                  <div className="text-xs text-gray-500">≈ ${exchange.fees.network_usd}</div>
                )}
              </div>
            </div>
          </div>
        </ScrollFadeIn>

        {/* Actions: Refund (when applicable) */}
        {["failed", "expired", "rate_expired", "pending", "deposit_detected"].includes(
          exchange.status
        ) && (
          <ScrollFadeIn delay={260}>
            <div className="rounded-2xl bg-[#12161C] border border-[#222831] p-6 mb-8">
              <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                <RefreshCw className="h-5 w-5 text-orange-400" />
                Request Refund
              </h3>
              <p className="text-sm text-gray-400 mb-3">
                If your exchange is stuck, expired, or failed, you can request a refund to your
                original currency. Enter a valid refund address for{" "}
                <span className="text-orange-400 font-semibold">{exchange.from.currency}</span>.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-gray-400">Refund Address</label>
                  <input
                    value={refundAddress}
                    onChange={(e) => setRefundAddress(e.target.value)}
                    placeholder={`Your ${exchange.from.currency} address`}
                    className="mt-1 w-full h-11 px-3 rounded-xl bg-black border border-white/10 text-white placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-orange-500"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400">Refund Tag / Memo (optional)</label>
                  <input
                    value={refundTag}
                    onChange={(e) => setRefundTag(e.target.value)}
                    placeholder="Enter tag/memo if required"
                    className="mt-1 w-full h-11 px-3 rounded-xl bg-black border border-white/10 text-white placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-orange-500"
                  />
                </div>
              </div>
              <div className="mt-4">
                <StatefulButton
                  onClick={requestRefund}
                  disabled={!refundAddress.trim()}
                  className="h-11 px-6 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-white font-semibold"
                  success={
                    <>
                      <CheckCircle2 className="h-5 w-5 mr-2" />
                      Refund Requested
                    </>
                  }
                >
                  {canceling ? "Requesting..." : "Request Refund"}
                </StatefulButton>
              </div>
              <p className="text-xs text-blue-300 mt-3">
                <Info className="inline h-3.5 w-3.5 mr-1" />
                Refunds are processed by the liquidity provider. It may take several confirmations.
              </p>
            </div>
          </ScrollFadeIn>
        )}

        {/* Help / Support */}
        <ScrollFadeIn delay={280}>
          <div className="rounded-2xl bg-[#12161C] border border-[#222831] p-6">
            <h3 className="text-lg font-bold mb-2">Need help?</h3>
            <p className="text-sm text-gray-400">
              If you need assistance with this exchange, please contact support with your exchange
              ID.
            </p>
            <div className="mt-3 text-sm">
              <div className="text-gray-400 mb-1">Exchange ID</div>
              <div className="flex items-center gap-2">
                <code className="flex-1 truncate bg-white/5 px-2 py-1 rounded">
                  {exchange.exchange_id}
                </code>
                <button
                  onClick={() => copyToClipboard(exchange.exchange_id, "exchange_id")}
                  className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 border border-white/10"
                  title="Copy exchange ID"
                >
                  <Copy className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>
        </ScrollFadeIn>
      </div>

      {/* Copied toast */}
      {copied && (
        <div className="fixed bottom-4 left-1/2 -translate-x-1/2 px-4 py-2 rounded-xl bg-white/10 backdrop-blur border border-white/20 text-white text-sm">
          Copied {copied.replace("_", " ")} to clipboard
        </div>
      )}
    </div>
  )
}