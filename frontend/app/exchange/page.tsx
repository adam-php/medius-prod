"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { supabase } from "@/lib/supabase"
import { authApiRequest, handleApiError } from "@/lib/api"
import { AlertCircle, ArrowLeftRight, Clock, History, Info, Repeat, TrendingDown, TrendingUp, Zap } from "lucide-react"
import ScrollFadeIn from "@/components/ui/scroll-fade-in"
import { CryptoSelector } from "@/components/crypto-selector"
import { cn } from "@/lib/utils"

interface CryptoPrice {
  usd: number
  change_24h: number
}

export default function ExchangePage() {
  const router = useRouter()
  const [error, setError] = useState<string | null>(null)
  const [fromCurrency, setFromCurrency] = useState("")
  const [toCurrency, setToCurrency] = useState("")
  const [usdAmount, setUsdAmount] = useState("")
  const [cryptoAmount, setCryptoAmount] = useState("")
  const [quote, setQuote] = useState<any>(null)
  const [quoteLoading, setQuoteLoading] = useState(false)
  const [quoteExpiry, setQuoteExpiry] = useState(0)
  const [showFeeBreakdown, setShowFeeBreakdown] = useState(false)
  const [destinationAddress, setDestinationAddress] = useState("")
  const [destinationTag, setDestinationTag] = useState("")
  const [needsTag, setNeedsTag] = useState(false)
  const [addressError, setAddressError] = useState("")
  const [isSwapping, setIsSwapping] = useState(false)
  const [cryptoPrices, setCryptoPrices] = useState<Record<string, CryptoPrice>>({})
  const [pricesLoading, setPricesLoading] = useState(true)
  const [isCreating, setIsCreating] = useState(false)

  const apiBase = process.env.NEXT_PUBLIC_API_URL!

  // Fetch prices
  const fetchCryptoPrices = async () => {
    try {
      setPricesLoading(true)
      const response = await fetch("/api/crypto/prices")
      const data = await response.json()

      if (data.success) {
        setCryptoPrices(data.prices)
      } else {
        setError("Failed to fetch cryptocurrency prices.")
      }
    } catch (err) {
      console.error("Error fetching prices:", err)
      setError("Unable to load cryptocurrency prices.")
    } finally {
      setPricesLoading(false)
    }
  }

  useEffect(() => {
    fetchCryptoPrices()
    const interval = setInterval(fetchCryptoPrices, 60000)
    return () => clearInterval(interval)
  }, [])

  const convertUsdToCrypto = (usd: string, currency: string): string => {
    if (!usd || !currency || !cryptoPrices[currency]) return "0"
    const usdValue = Number.parseFloat(usd)
    if (isNaN(usdValue)) return "0"
    return (usdValue / cryptoPrices[currency].usd).toFixed(8)
  }

  // Fetch quote
  useEffect(() => {
    if (!fromCurrency || !toCurrency || !usdAmount || Number.parseFloat(usdAmount) <= 0) {
      setQuote(null)
      setCryptoAmount("")
      return
    }

    if (!cryptoPrices[fromCurrency] || !cryptoPrices[toCurrency]) return

    const fetchQuote = async () => {
      setQuoteLoading(true)
      try {
        const cryptoAmountValue = convertUsdToCrypto(usdAmount, fromCurrency)
        setCryptoAmount(cryptoAmountValue)

        const {
          data: { session },
        } = await supabase.auth.getSession()
        if (!session) {
          window.location.href = "/auth?redirect=/exchange"
          return
        }

        const res = await authApiRequest(`${apiBase}/api/exchange/quote`, session, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            from_currency: fromCurrency,
            to_currency: toCurrency,
            amount: Number.parseFloat(cryptoAmountValue),
          }),
        })

        await handleApiError(res)
        const data = await res.json()

        setQuote({
          from_amount: data.from_amount,
          to_amount: data.to_amount,
          to_amount_after_fee: data.to_amount_after_fee || data.user_receives,
          rate: data.rate,
          platform_fee_percent: data.platform_fee_percent,
          platform_fee_amount: data.platform_fee_amount,
          network_fee_estimate: data.network_fee_estimate || 0,
          from_usd: Number.parseFloat(usdAmount),
          to_usd: (data.to_amount_after_fee || data.user_receives) * (cryptoPrices[toCurrency]?.usd || 0),
        })

        setQuoteExpiry(60)
      } catch (err: any) {
        console.error("Quote error:", err)
        setError(err.message || "Failed to fetch quote.")
      } finally {
        setQuoteLoading(false)
      }
    }

    fetchQuote()
  }, [fromCurrency, toCurrency, usdAmount, cryptoPrices])

  // Quote expiry
  useEffect(() => {
    if (quoteExpiry <= 0) return
    const timer = setInterval(() => {
      setQuoteExpiry((prev) => {
        if (prev <= 1) {
          clearInterval(timer)
          return 0
        }
        return prev - 1
      })
    }, 1000)
    return () => clearInterval(timer)
  }, [quoteExpiry])

  const swapCurrencies = () => {
    setIsSwapping(true)
    setTimeout(() => {
      const temp = fromCurrency
      setFromCurrency(toCurrency)
      setToCurrency(temp)
      setIsSwapping(false)
    }, 300)
  }

  const createExchange = async () => {
    if (!isFormValid) return

    setIsCreating(true)
    setError(null)

    try {
      const {
        data: { session },
      } = await supabase.auth.getSession()
      if (!session) {
        window.location.href = "/auth/login?redirect=/exchange"
        return
      }

      const payload: any = {
        from_currency: fromCurrency,
        to_currency: toCurrency,
        amount: Number.parseFloat(cryptoAmount),
        destination_address: destinationAddress.trim(),
      }

      if (needsTag && destinationTag.trim()) {
        payload.destination_tag = destinationTag.trim()
      }

      const res = await authApiRequest(`${apiBase}/api/exchange/create`, session, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })

      await handleApiError(res)
      const data = await res.json()

      router.push(`/exchange/${data.id}`)
    } catch (err: any) {
      console.error("Create exchange error:", err)
      setError(err.message || "Failed to create exchange.")
      setIsCreating(false)
    }
  }

  const validateAddress = (address: string) => {
    if (!address.trim()) {
      setAddressError("")
      return
    }
    if (address.length < 20) {
      setAddressError("Address appears to be too short")
    } else if (!/^[a-zA-Z0-9]+$/.test(address)) {
      setAddressError("Address contains invalid characters")
    } else {
      setAddressError("")
    }
  }

  useEffect(() => {
    const currenciesNeedingTags = ["XRP", "XLM", "EOS"]
    setNeedsTag(currenciesNeedingTags.includes(toCurrency))
  }, [toCurrency])

  const isFormValid =
    quote &&
    quoteExpiry > 0 &&
    destinationAddress.trim().length > 0 &&
    !addressError &&
    (!needsTag || destinationTag.trim().length > 0) &&
    !isCreating

  return (
    <div className="min-h-screen bg-black text-white">
      <div className="fixed inset-0 -z-10 overflow-hidden">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-slate-700/5 rounded-full blur-3xl animate-float" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-slate-600/5 rounded-full blur-3xl animate-float-delayed" />
      </div>

      <div className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Header */}
        <ScrollFadeIn>
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-4xl font-bold mb-2 text-white">Crypto Exchange</h1>
              <div className="flex items-center gap-2 text-sm">
                <Zap className="h-4 w-4 text-slate-400" />
                <span className="text-slate-400">
                  Instant swaps • {pricesLoading ? "Loading prices..." : "Live pricing"}
                </span>
              </div>
            </div>

            <Link
              href="/exchange/history"
              className="group relative overflow-hidden rounded-xl px-5 py-2.5 bg-white/5 border border-white/10 hover:border-slate-400/50 transition-all duration-300"
            >
              <div className="relative flex items-center gap-2">
                <History className="h-4 w-4" />
                <span className="font-medium">History</span>
              </div>
            </Link>
          </div>
        </ScrollFadeIn>

        {error && (
          <ScrollFadeIn delay={50}>
            <div className="mb-6 rounded-xl border border-red-500/30 bg-red-500/5 backdrop-blur-sm p-4 flex items-start gap-3">
              <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1 text-sm text-red-200">{error}</div>
              <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
                ✕
              </button>
            </div>
          </ScrollFadeIn>
        )}

        <div className="grid grid-cols-12 gap-6">
          {/* Main Panel */}
          <div className="col-span-12 lg:col-span-8">
            <ScrollFadeIn delay={100}>
              <div className="rounded-2xl bg-black backdrop-blur-xl border border-white/10 p-6 shadow-2xl">
                {/* You Send */}
                <div className="mb-6">
                  <label className="block text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <div className="w-1 h-4 bg-slate-400 rounded-full" />
                    You Send
                  </label>
                  <div className="grid grid-cols-12 gap-3">
                    <div className="col-span-7">
                      <CryptoSelector
                        value={fromCurrency}
                        onValueChange={setFromCurrency}
                        placeholder="Select currency"
                      />
                    </div>
                    <div className="col-span-5">
                      <div className="relative group">
                        <span className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none">
                          $
                        </span>
                        <input
                          type="number"
                          value={usdAmount}
                          onChange={(e) => setUsdAmount(e.target.value)}
                          placeholder="0.00"
                          disabled={pricesLoading || isCreating}
                          className="w-full h-12 pl-8 pr-4 rounded-xl bg-black/30 border border-white/10 text-white placeholder:text-slate-600 focus:border-slate-400/50 focus:ring-2 focus:ring-slate-400/20 transition-all disabled:opacity-50"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Crypto amount display */}
                  {cryptoAmount && fromCurrency && (
                    <div className="mt-3 px-4 py-2.5 rounded-lg bg-black/20 border border-white/5 animate-fade-in">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-400">Sending</span>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-white">{Number.parseFloat(cryptoAmount).toFixed(8)}</span>
                          <span className="text-slate-300 font-semibold">{fromCurrency}</span>
                        </div>
                      </div>
                      {cryptoPrices[fromCurrency] && (
                        <div className="flex items-center justify-between text-xs mt-1">
                          <span className="text-slate-500">${cryptoPrices[fromCurrency].usd.toLocaleString()}</span>
                          <div
                            className={cn(
                              "flex items-center gap-1",
                              cryptoPrices[fromCurrency].change_24h >= 0 ? "text-green-400" : "text-red-400",
                            )}
                          >
                            {cryptoPrices[fromCurrency].change_24h >= 0 ? (
                              <TrendingUp className="h-3 w-3" />
                            ) : (
                              <TrendingDown className="h-3 w-3" />
                            )}
                            {Math.abs(cryptoPrices[fromCurrency].change_24h).toFixed(2)}%
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Swap Button */}
                <div className="flex justify-center -my-2 relative z-10">
                  <button
                    onClick={swapCurrencies}
                    disabled={!fromCurrency || !toCurrency || pricesLoading || isCreating}
                    className={cn(
                      "relative w-12 h-12 rounded-full transition-all duration-300",
                      "bg-black hover:bg-slate-900",
                      "hover:scale-110 hover:shadow-lg hover:shadow-slate-500/30",
                      "active:scale-95",
                      "disabled:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50",
                      "border-2 border-black/50",
                    )}
                  >
                    <ArrowLeftRight
                      className={cn(
                        "h-5 w-5 text-white mx-auto transition-transform duration-500",
                        isSwapping && "rotate-180",
                      )}
                    />
                  </button>
                </div>

                {/* You Receive */}
                <div className="mt-6 mb-6">
                  <label className="block text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <div className="w-1 h-4 bg-green-500 rounded-full" />
                    You Receive
                  </label>
                  <div className="grid grid-cols-12 gap-3">
                    <div className="col-span-7">
                      <CryptoSelector value={toCurrency} onValueChange={setToCurrency} placeholder="Select currency" />
                    </div>
                    <div className="col-span-5">
                      <div className="h-12 px-4 rounded-xl bg-green-500/10 border border-green-500/20 flex items-center justify-end">
                        <span className="font-mono text-lg font-semibold text-white">
                          {quoteLoading ? (
                            <div className="h-4 w-4 animate-spin rounded-full border-2 border-green-500 border-r-transparent" />
                          ) : quote ? (
                            quote.to_amount_after_fee.toFixed(8)
                          ) : (
                            "0.00"
                          )}
                        </span>
                      </div>
                    </div>
                  </div>

                  {quote?.to_usd !== undefined && (
                    <div className="mt-3 px-4 py-2.5 rounded-lg bg-black/20 border border-white/5 animate-fade-in">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-400">You'll get</span>
                        <span className="text-green-400 font-semibold">≈ ${Number(quote.to_usd).toFixed(2)}</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Quote Card */}
                {quote && (
                  <div className="mb-6 rounded-xl bg-black border border-slate-500/20 p-4 animate-fade-in">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <Repeat className="h-4 w-4 text-slate-400" />
                        <span className="text-sm font-semibold">Rate</span>
                      </div>
                      {quoteExpiry > 0 && (
                        <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-black/30">
                          <Clock
                            className={cn(
                              "h-3.5 w-3.5",
                              quoteExpiry <= 10 ? "text-red-400 animate-pulse" : "text-slate-400",
                            )}
                          />
                          <span
                            className={cn(
                              "text-xs font-mono font-bold",
                              quoteExpiry <= 10 ? "text-red-400" : "text-white",
                            )}
                          >
                            {quoteExpiry}s
                          </span>
                        </div>
                      )}
                    </div>

                    <div className="text-lg font-bold mb-3">
                      1 {fromCurrency} = <span className="text-slate-300">{quote.rate.toFixed(8)}</span> {toCurrency}
                    </div>

                    <button
                      onClick={() => setShowFeeBreakdown(!showFeeBreakdown)}
                      className="w-full text-xs text-slate-400 hover:text-slate-300 flex items-center justify-between group transition-colors"
                    >
                      <span>Fee Breakdown</span>
                      <span
                        className={cn(
                          "transform transition-transform group-hover:translate-x-1",
                          showFeeBreakdown && "rotate-180",
                        )}
                      >
                        ▼
                      </span>
                    </button>

                    {showFeeBreakdown && (
                      <div className="mt-3 pt-3 border-t border-white/10 space-y-2 text-sm animate-fade-in">
                        <div className="flex justify-between text-slate-400">
                          <span>Before fees</span>
                          <span className="font-mono">
                            {quote.to_amount.toFixed(8)} {toCurrency}
                          </span>
                        </div>
                        <div className="flex justify-between text-slate-300">
                          <span>Platform fee ({quote.platform_fee_percent}%)</span>
                          <span className="font-mono">-{quote.platform_fee_amount.toFixed(8)}</span>
                        </div>
                        {quote.network_fee_estimate > 0 && (
                          <div className="flex justify-between text-slate-400">
                            <span>Network fee (est.)</span>
                            <span className="font-mono">~{quote.network_fee_estimate.toFixed(8)}</span>
                          </div>
                        )}
                        <div className="flex justify-between font-bold text-white pt-2 border-t border-white/10">
                          <span>You receive</span>
                          <span className="text-green-400 font-mono">{quote.to_amount_after_fee.toFixed(8)}</span>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Destination Address */}
                <div className="mb-6">
                  <label className="block text-sm font-semibold text-slate-300 mb-2">
                    Destination Address <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="text"
                    value={destinationAddress}
                    onChange={(e) => {
                      setDestinationAddress(e.target.value)
                      validateAddress(e.target.value)
                    }}
                    disabled={isCreating}
                    placeholder={toCurrency ? `Your ${toCurrency} address` : "Select currency first"}
                    className={cn(
                      "w-full h-12 px-4 rounded-xl bg-black/30 border text-white placeholder:text-slate-600 transition-all",
                      addressError
                        ? "border-red-500/50 focus:border-red-500 focus:ring-2 focus:ring-red-500/20"
                        : destinationAddress && !addressError
                          ? "border-green-500/50 focus:border-green-500 focus:ring-2 focus:ring-green-500/20"
                          : "border-white/10 focus:border-slate-400/50 focus:ring-2 focus:ring-slate-400/20",
                    )}
                  />
                  {addressError && (
                    <p className="mt-2 text-xs text-red-400 flex items-center gap-1.5">
                      <AlertCircle className="h-3 w-3" />
                      {addressError}
                    </p>
                  )}
                </div>

                {/* Destination Tag */}
                {needsTag && (
                  <div className="mb-6">
                    <label className="block text-sm font-semibold text-slate-300 mb-2">
                      Destination Tag/Memo <span className="text-slate-400">(Required)</span>
                    </label>
                    <input
                      type="text"
                      value={destinationTag}
                      onChange={(e) => setDestinationTag(e.target.value)}
                      disabled={isCreating}
                      placeholder="Enter tag/memo"
                      className="w-full h-12 px-4 rounded-xl bg-black/30 border border-white/10 text-white placeholder:text-slate-600 focus:border-slate-400/50 focus:ring-2 focus:ring-slate-400/20 transition-all"
                    />
                    <p className="mt-2 text-xs text-slate-400 flex items-center gap-1.5">
                      <AlertCircle className="h-3 w-3" />
                      {toCurrency} requires a tag. Verify this value!
                    </p>
                  </div>
                )}

                {/* Submit Button */}
                <button
                  onClick={createExchange}
                  disabled={!isFormValid}
                  className={cn(
                    "relative w-full h-14 rounded-xl font-bold text-lg overflow-hidden transition-all duration-300",
                    "flex items-center justify-center gap-2",
                    isFormValid
                      ? "bg-black hover:bg-slate-900 text-white shadow-lg shadow-slate-700/30 hover:shadow-slate-600/50 hover:scale-[1.02] active:scale-[0.98]"
                      : "bg-slate-800 text-slate-500 cursor-not-allowed",
                  )}
                >
                  <span className="relative">
                    {isCreating ? (
                      <>
                        <div className="inline-block h-5 w-5 animate-spin rounded-full border-2 border-white border-r-transparent mr-2" />
                        Creating...
                      </>
                    ) : !quote ? (
                      "Enter Amount"
                    ) : quoteExpiry <= 0 ? (
                      "Quote Expired"
                    ) : !destinationAddress.trim() ? (
                      "Enter Address"
                    ) : addressError ? (
                      "Fix Address"
                    ) : needsTag && !destinationTag.trim() ? (
                      "Enter Tag"
                    ) : (
                      "Create Exchange →"
                    )}
                  </span>
                </button>
              </div>
            </ScrollFadeIn>
          </div>

          {/* Sidebar */}
          <aside className="col-span-12 lg:col-span-4 space-y-6">
            <ScrollFadeIn delay={150}>
              <div className="rounded-2xl bg-black backdrop-blur-xl border border-white/10 p-6">
                <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                  <Info className="h-5 w-5 text-slate-400" />
                  How It Works
                </h3>
                <ol className="space-y-4">
                  {["Get instant quote", "Enter destination", "Send deposit", "Receive crypto"].map((step, i) => (
                    <li key={i} className="flex gap-3 group">
                      <span className="flex-shrink-0 w-7 h-7 rounded-full bg-black text-white flex items-center justify-center text-sm font-bold shadow-lg transition-all group-hover:bg-slate-900 group-hover:scale-110 border border-white/20">
                        {i + 1}
                      </span>
                      <span className="text-sm text-slate-300 group-hover:text-white transition-colors">{step}</span>
                    </li>
                  ))}
                </ol>
              </div>
            </ScrollFadeIn>

            <ScrollFadeIn delay={200}>
              <div className="rounded-2xl bg-black backdrop-blur-xl border border-white/10 p-6">
                <h3 className="text-lg font-bold mb-4">Summary</h3>
                {quote ? (
                  <div className="space-y-3 text-sm">
                    <div className="flex justify-between items-center p-3 rounded-lg bg-black/20 transition-all hover:bg-black/30">
                      <span className="text-slate-400">Rate</span>
                      <span className="font-mono text-white">{quote.rate.toFixed(8)}</span>
                    </div>
                    <div className="flex justify-between items-center p-3 rounded-lg bg-black/20 transition-all hover:bg-black/30">
                      <span className="text-slate-400">Fee</span>
                      <span className="text-slate-300 font-semibold">{quote.platform_fee_percent}%</span>
                    </div>
                    <div className="flex justify-between items-center p-3 rounded-lg bg-black/20 transition-all hover:bg-black/30">
                      <span className="text-slate-400">Time</span>
                      <span className="text-green-400 font-semibold">~5-15 min</span>
                    </div>
                    <div className="mt-4 pt-4 border-t border-white/10">
                      <div className="flex justify-between items-center mb-2">
                        <span className="text-white font-semibold">You send</span>
                        <span className="font-mono">
                          {quote.from_amount.toFixed(8)} {fromCurrency}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-green-400 font-semibold">You get</span>
                        <span className="font-mono text-green-400">
                          {quote.to_amount_after_fee.toFixed(8)} {toCurrency}
                        </span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <div className="w-16 h-16 mx-auto mb-3 rounded-full bg-slate-700/20 flex items-center justify-center">
                      <Zap className="h-8 w-8 text-slate-400" />
                    </div>
                    <p className="text-sm text-slate-500">Enter amount for details</p>
                  </div>
                )}
              </div>
            </ScrollFadeIn>
          </aside>
        </div>
      </div>
    </div>
  )
}
