"use client"

import type React from "react"
import { useEffect, useState, useRef, useMemo, useCallback } from "react"
import { supabase } from "@/lib/supabase"
import { useRouter, useSearchParams } from "next/navigation"
import type { Currency } from "@/lib/types"
import AnimatedBackButton from "@/components/animated-back-button"
import { ShoppingCart, Store } from "lucide-react"
import UsernamePicker from "@/components/UsernamePicker"

type FeeInfo = {
  payment_method: "crypto" | "paypal"
  currency: string
  usd_amount: number
  fee_percentage: number
  fee_rate: number
  fee_amount: number      // USD
  net_amount: number      // USD
  total_amount: number    // USD
  amount_crypto?: number
  fee_crypto?: number
  net_crypto?: number
}

export default function CreateEscrow() {
  const [user, setUser] = useState<any>(null)
  const [currentStep, setCurrentStep] = useState(1)
  const [role, setRole] = useState<"buyer" | "seller">("buyer")
  const [otherPartyUsername, setOtherPartyUsername] = useState("")
  const [escrowTitle, setEscrowTitle] = useState("")
  const [paymentMethod, setPaymentMethod] = useState<"crypto" | "paypal">("crypto")
  const [usdAmount, setUsdAmount] = useState("")
  const [currency, setCurrency] = useState("")
  const [currencies, setCurrencies] = useState<Currency[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [cryptoPrices, setCryptoPrices] = useState<{ [key: string]: number }>({})
  const [loadingPrices, setLoadingPrices] = useState(false)
  const [feeInfo, setFeeInfo] = useState<FeeInfo | null>(null)
  const [loadingFees, setLoadingFees] = useState(false)
  const [isDropdownOpen, setIsDropdownOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  // Animation states
  const [scrollY, setScrollY] = useState(0)
  const [visibleSections, setVisibleSections] = useState<Set<string>>(new Set())
  
  const [isGlitching, setIsGlitching] = useState(false)
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 })

  const router = useRouter()
  const searchParams = useSearchParams()
  const containerRef = useRef<HTMLDivElement>(null)
  const observerRef = useRef<IntersectionObserver | null>(null)

  // Price for the currently selected currency
  const selectedPrice = useMemo(() => cryptoPrices[currency], [cryptoPrices, currency])

  const minimumUsdAmounts = useMemo(() => ({
    BTC: 2,
    ETH: 3,
    LTC: 0.50,
    BCH: 0.50,
    DOGE: 1,
    XRP: 0.25,
    ADA: 0.50,
    DOT: 1,
    MATIC: 0.25,
    SOL: 1,
    AVAX: 0.50,
    TRX: 0.25,
    BNB: 0.50,
    ATOM: 0.50,
    XLM: 0.10,
    USD: 1,
    // USDT variants (minimum $1 each)
    'USDT-ERC20': 2,
    'USDT-BEP20': 2,
    'USDT-SOL': 2,
    'USDT-TRON': 2
  }), [])
  

  const getMinimumUsdAmount = () =>
    paymentMethod === "paypal"
      ? minimumUsdAmounts.USD
      : (minimumUsdAmounts[currency as keyof typeof minimumUsdAmounts] || 0.50)

  const getCryptoAmount = () => {
    if (paymentMethod === "paypal" || !usdAmount || !selectedPrice) return null
    const usdValue = Number.parseFloat(usdAmount)
    const cryptoPrice = selectedPrice
    if (!cryptoPrice || cryptoPrice <= 0) return null
    const cryptoAmount = usdValue / cryptoPrice

    // Debug logging to help identify conversion issues
    console.log(`Crypto conversion: $${usdValue} / $${cryptoPrice} = ${cryptoAmount} ${currency}`)

    return cryptoAmount.toFixed(8)
  }

  const validateUsername = (u: string) => {
    const trimmed = (u || "").trim()
    const isValid = /^[a-z0-9_-]{3,30}$/i.test(trimmed)
    console.log("Validating username:", trimmed, "Result:", isValid)
    return isValid
  }

  const validateTitle = (title: string) => {
    const trimmed = (title || "").trim()
    return trimmed.length >= 5 && trimmed.length <= 100
  }

  const validateAmount = () => {
    const numAmount = Number.parseFloat(usdAmount)
    const minAmount = getMinimumUsdAmount()
    if (!usdAmount || Number.isNaN(numAmount) || numAmount <= 0) return "Please enter an amount"
    if (numAmount < minAmount) {
      return paymentMethod === "paypal"
        ? `Minimum $${minAmount} USD for PayPal transactions (covers fees)`
        : `Minimum $${minAmount} USD to cover ${currency} network fees`
    }
    if (feeInfo && feeInfo.net_amount < 0.01) return "Amount too small - seller would receive less than $0.01"

    // Check USD amount meets minimum for the selected currency
    if (paymentMethod === "crypto" && usdAmount) {
      const usdValue = Number.parseFloat(usdAmount)
      const minUsdForCurrency = minimumUsdAmounts[currency as keyof typeof minimumUsdAmounts] || 0.50
      if (usdValue < minUsdForCurrency) {
        return `Minimum amount for ${currency} is $${minUsdForCurrency} USD. Please enter at least that amount.`
      }
    }

    return null
  }

  // Step validation functions
  const canProceedFromStep1 = () => {
    return role && validateUsername(otherPartyUsername.trim())
  }

  const canProceedFromStep2 = () => {
    return validateTitle(escrowTitle)
  }

  const canProceedFromStep3 = () => {
    return paymentMethod
  }

  const canSubmit = () => {
    return !validateAmount() && 
           usdAmount && 
           Number.parseFloat(usdAmount) > 0 &&
           (paymentMethod === "paypal" || selectedPrice)
  }

  // Navigation functions
  const nextStep = () => {
    if (currentStep === 1 && canProceedFromStep1()) {
      setCurrentStep(2)
      setError("")
    } else if (currentStep === 2 && canProceedFromStep2()) {
      setCurrentStep(3)
      setError("")
    } else if (currentStep === 3 && canProceedFromStep3()) {
      setCurrentStep(4)
      setError("")
    }
  }

  const prevStep = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1)
      setError("")
    }
  }

  const fetchCryptoPrices = async () => {
    setLoadingPrices(true)
    try {
      const cryptoIds: Record<string, string> = {
        BTC: "bitcoin", ETH: "ethereum", LTC: "litecoin", BCH: "bitcoin-cash", DOGE: "dogecoin",
        XRP: "ripple", ADA: "cardano", DOT: "polkadot", MATIC: "matic-network", SOL: "solana",
        AVAX: "avalanche-2", TRX: "tron", BNB: "binancecoin", ATOM: "cosmos", XLM: "stellar",
        // USDT mappings (all point to tether on coingecko)
        "USDT-ERC20": "tether",
        "USDT-BEP20": "tether",
        "USDT-SOL": "tether",
        "USDT-TRON": "tether"
      }

      const ids = Object.values(cryptoIds).join(",")
      const response = await fetch(
        `https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd`
      )
      if (!response.ok) throw new Error("Failed to fetch prices")
      const data = await response.json()
      const prices: { [key: string]: number } = {}
      Object.entries(cryptoIds).forEach(([code, id]) => {
        if (data[id]?.usd) prices[code] = data[id].usd
      })
      setCryptoPrices(prices)
    } catch (error) {
      console.error("Error fetching crypto prices:", error)
      // fallback prices
      setCryptoPrices({
        BTC: 45000, ETH: 2500, LTC: 70, BCH: 250, DOGE: 0.08, XRP: 0.6, ADA: 0.4, DOT: 4,
        MATIC: 0.4, SOL: 150, AVAX: 30, TRX: 0.1, BNB: 600, ATOM: 4, XLM: 0.1,
        "USDT-ERC20": 1,
        "USDT-BEP20": 1,
        "USDT-SOL": 1,
        "USDT-TRON": 1,
      })
    } finally {
      setLoadingPrices(false)
    }
  }

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsDropdownOpen(false)
      }
    }
    document.addEventListener("mousedown", handleClickOutside)
    return () => document.removeEventListener("mousedown", handleClickOutside)
  }, [])

  // Prefill from URL (e.g. ?to=username&role=buyer)
  useEffect(() => {
    const to = searchParams.get("to")
    const r = searchParams.get("role") as "buyer" | "seller" | null
    if (to) setOtherPartyUsername(to)
    if (r === "buyer" || r === "seller") setRole(r)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    const checkUser = async () => {
      const { data: { user } } = await supabase.auth.getUser()
      if (!user) {
        router.push("/auth")
        return
      }
      setUser(user)
    }

    const fetchCurrencies = async () => {
      try {
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/c-currencies`, {
          headers: { 'ngrok-skip-browser-warning': '1' },
        })
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`)
        const data = await response.json()
        if (!data || data.length === 0) throw new Error("No currencies returned from API")
        setCurrencies(data)
        if (data.length > 0) setCurrency(data[0].code)
      } catch (error) {
        console.error("Error ing currencies:", error)
        // fallback
        const fallback = [
          { code: "BTC", name: "Bitcoin" }, { code: "ETH", name: "Ethereum" }, { code: "LTC", name: "Litecoin" },
          { code: "BCH", name: "Bitcoin Cash" }, { code: "DOGE", name: "Dogecoin" }, { code: "XRP", name: "Ripple" },
          { code: "ADA", name: "Cardano" }, { code: "DOT", name: "Polkadot" }, { code: "MATIC", name: "Polygon" },
          { code: "SOL", name: "Solana" }, { code: "AVAX", name: "Avalanche" }, { code: "TRX", name: "Tron" },
          { code: "BNB", name: "Binance Coin" }, { code: "ATOM", name: "Cosmos" }, { code: "XLM", name: "Stellar" },
          // USDT fallback options
          { code: "USDT-ERC20", name: "USDT (ERC20)" },
          { code: "USDT-BEP20", name: "USDT (BEP20)" },
          { code: "USDT-SOL", name: "USDT (Solana)" },
          { code: "USDT-TRON", name: "USDT (TRC20)" }
        ]        
        setCurrencies(fallback)
        setCurrency("BTC")
      }
    }

    checkUser()
    fetchCurrencies()
    fetchCryptoPrices()
    // Removed automatic price updates to prevent annoying constant changes
    // const priceInterval = setInterval(fetchCryptoPrices, 30000)
    // return () => clearInterval(priceInterval)
  }, [router])

  // Debounced fee calculation
  useEffect(() => {
    const calc = async () => {
      const usd = Number.parseFloat(usdAmount)
      if (!usd || Number.isNaN(usd) || usd <= 0) {
        setFeeInfo(null)
        return
      }

      // Wait for a price before calculating crypto fees
      if (paymentMethod === "crypto" && !selectedPrice) {
        setFeeInfo(null)
        return
      }

      setLoadingFees(true)
      try {
        const cryptoAmount =
          paymentMethod === "paypal"
            ? undefined
            : usd / (selectedPrice as number)

        const body = {
          amount: paymentMethod === "paypal" ? usd : cryptoAmount,
          currency: paymentMethod === "paypal" ? "USD" : currency,
          payment_method: paymentMethod,
          usd_amount: usd,
        }
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/calculate-fee`, {
          method: "POST",
          headers: { "Content-Type": "application/json", 'ngrok-skip-browser-warning': '1' },
          body: JSON.stringify(body),
        })
        if (!response.ok) throw new Error("Fee calc failed")
        const fees: FeeInfo = await response.json()
        setFeeInfo(fees)
      } catch (e) {
        console.error("Error calculating fees:", e)
        setFeeInfo(null)
      } finally {
        setLoadingFees(false)
      }
    }
    const timeoutId = setTimeout(calc, 500)
    return () => clearTimeout(timeoutId)
  }, [usdAmount, paymentMethod, currency, selectedPrice])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")

    // Treat Enter as "Continue" for steps 1–3
    if (currentStep < 4) {
      // Optionally only advance if current step is valid
      if (
        (currentStep === 1 && canProceedFromStep1()) ||
        (currentStep === 2 && canProceedFromStep2()) ||
        (currentStep === 3 && canProceedFromStep3())
      ) {
        nextStep()
      }
      return
    }

    // Step 4: proceed with actual submit
    setLoading(true)

    // Trim the username before validation
    const trimmedUsername = otherPartyUsername.trim()

    // Validate username
    if (!validateUsername(trimmedUsername)) {
      setError("Please enter a valid username (3–30 chars: letters, numbers, _ or -)")
      setLoading(false)
      return
    }

    // Validate amount
    const amountError = validateAmount()
    if (amountError) {
      setError(amountError)
      setLoading(false)
      return
    }

    try {
      const { data: { session } } = await supabase.auth.getSession()
      if (!session?.access_token) throw new Error("Not authenticated")

      // Ensure counterparty exists
      const existsRes = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/users/${encodeURIComponent(trimmedUsername)}`,
        { headers: { 'ngrok-skip-browser-warning': '1' } }
      )
      if (!existsRes.ok) {
        setError("User not found. Please check the username.")
        setLoading(false)
        return
      }

      // Compute final amount + currency
      let finalAmount: number
      let finalCurrency: string
      if (paymentMethod === "paypal") {
        finalAmount = Number.parseFloat(usdAmount)
        finalCurrency = "USD"
      } else {
        const cryptoAmount = getCryptoAmount()
        if (!cryptoAmount) throw new Error("Unable to calculate crypto amount")
        finalAmount = Number.parseFloat(cryptoAmount)
        finalCurrency = currency
      }

      // normalize USD amount as a number and round to 2 decimals
      const usdAmountNum = Math.round((Number.parseFloat(usdAmount) || 0) * 100) / 100

      const payload: any = {
        initiator_role: role,
        counterparty_username: trimmedUsername,
        ...(role === "buyer" ? { seller_username: trimmedUsername } : {}),
        ...(role === "seller" ? { buyer_username: trimmedUsername } : {}),
        title: escrowTitle.trim(),
        // “amount” is the crypto amount for crypto payments, or USD amount for PayPal
        amount: finalAmount,
        currency: finalCurrency,
        payment_method: paymentMethod,
        // legacy field kept for backwards compatibility
        usd_amount: usdAmountNum,
        // NEW canonical USD field expected by analytics & queries
        amount_usd: usdAmountNum,
      }

      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/escrows`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session.access_token}`,
          'ngrok-skip-browser-warning': '1',
        },
        body: JSON.stringify(payload),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || `API Error: ${response.status} ${response.statusText}`)
      }

      const escrow = await response.json()
      router.push(`/escrow/${escrow.id}`)
    } catch (error: any) {
      setError(error.message || "Something went wrong")
    } finally {
      setLoading(false)
    }
  }

  const handleFormKeyDown = useCallback((e: React.KeyboardEvent<HTMLFormElement>) => {
    if ((e.key === "Enter" || e.key === "NumpadEnter") && !e.shiftKey) {
      const target = e.target as HTMLElement
      const tag = target.tagName.toLowerCase()
      const isTextarea = tag === "textarea"
      const isButton = tag === "button"
      const isLink = tag === "a"

      // Don’t advance if a dropdown/combobox is active (UsernamePicker or currency dropdown)
      const inOpenCurrencyDropdown = isDropdownOpen && !!dropdownRef.current?.contains(target)
      const comboboxOpen = !!target.closest('[role="listbox"],[aria-expanded="true"]')

      if (isTextarea || isButton || isLink || inOpenCurrencyDropdown || comboboxOpen) return

      if (currentStep < 4) {
        e.preventDefault()
        if (
          (currentStep === 1 && canProceedFromStep1()) ||
          (currentStep === 2 && canProceedFromStep2()) ||
          (currentStep === 3 && canProceedFromStep3())
        ) {
          nextStep()
        }
      }
    }
  }, [currentStep, isDropdownOpen, canProceedFromStep1, canProceedFromStep2, canProceedFromStep3, nextStep])

  const cryptoAmount = getCryptoAmount()

  // Animation functions
  const handleScroll = useCallback(() => {
    setScrollY(window.scrollY)
  }, [])

  const handleMouseMove = useCallback((e: MouseEvent) => {
    setMousePosition({ x: e.clientX, y: e.clientY })
  }, [])

  

  const triggerGlitch = useCallback(() => {
    if (!isGlitching) {
      setIsGlitching(true)
      setTimeout(() => setIsGlitching(false), 300)
    }
  }, [isGlitching])

  // Intersection Observer for scroll animations
  useEffect(() => {
    observerRef.current = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setVisibleSections(prev => new Set(prev).add(entry.target.id))
          }
        })
      },
      { threshold: 0.1 }
    )

    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect()
      }
    }
  }, [])

  // Scroll and mouse event listeners
  useEffect(() => {
    window.addEventListener('scroll', handleScroll, { passive: true })
    window.addEventListener('mousemove', handleMouseMove, { passive: true })

    return () => {
      window.removeEventListener('scroll', handleScroll)
      window.removeEventListener('mousemove', handleMouseMove)
    }
  }, [handleScroll, handleMouseMove])

  // Random glitch effect
  useEffect(() => {
    const glitchInterval = setInterval(() => {
      if (Math.random() < 0.1) { // 10% chance every 5 seconds
        triggerGlitch()
      }
    }, 5000)

    return () => clearInterval(glitchInterval)
  }, [triggerGlitch])

  // Observe elements for scroll animations
  useEffect(() => {
    const elements = document.querySelectorAll('[data-animate-on-scroll]')
    elements.forEach((el) => {
      if (observerRef.current) {
        observerRef.current.observe(el)
      }
    })

    return () => {
      elements.forEach((el) => {
        if (observerRef.current) {
          observerRef.current.unobserve(el)
        }
      })
    }
  }, [currentStep])

  return (
    <div
      ref={containerRef}
      className={`min-h-screen bg-black relative overflow-hidden text-white transition-all duration-300 ${
        isGlitching ? 'animate-pulse' : ''
      }`}
      style={{
        transform: `translateY(${scrollY * 0.1}px)`,
        filter: isGlitching ? 'contrast(1.2)' : 'none'
      }}
    >
      {/* Enhanced animated background with mouse interaction */}
      <div
        className="absolute inset-0 bg-gradient-to-br from-orange-500/8 via-black to-amber-500/8 transition-all duration-1000"
        style={{
          backgroundPosition: `${mousePosition.x * 0.01}px ${mousePosition.y * 0.01}px`
        }}
      ></div>

      {/* Animated floating orbs with enhanced effects */}
      <div
        className="absolute top-1/4 left-1/4 w-96 h-96 bg-orange-500/15 rounded-full blur-3xl motion-safe:animate-float-slow transition-all duration-500"
        style={{
          transform: `translate(${mousePosition.x * 0.02}px, ${mousePosition.y * 0.02}px)`,
        }}
      ></div>
      <div
        className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-amber-500/15 rounded-full blur-3xl motion-safe:animate-float-slow-reverse transition-all duration-500"
        style={{
          transform: `translate(${mousePosition.x * -0.02}px, ${mousePosition.y * -0.02}px)`,
        }}
      ></div>
      <div
        className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-64 h-64 rounded-full blur-2xl motion-safe:animate-float-gentle transition-all duration-700"
        style={{
          background: `radial-gradient(circle, rgba(249, 115, 22, ${0.08 + Math.sin(Date.now() * 0.001) * 0.02}) 0%, transparent 70%)`,
          transform: `-translate-x-1/2 -translate-y-1/2 scale(${1 + Math.sin(Date.now() * 0.002) * 0.1})`,
        }}
      ></div>

      <div className="container mx-auto px-4 py-6 sm:py-8 pb-[max(2rem,env(safe-area-inset-bottom))] relative z-10">
        <div className="max-w-2xl mx-auto">
          <div className="mb-6 sm:mb-8 animate-slide-in-down">
            <div className="flex items-center space-x-3 mb-4">
              <AnimatedBackButton onClick={() => router.push("/dashboard")} text="Back to Dashboard" />
            </div>
            <h1 className="text-3xl sm:text-4xl font-bold text-white mb-2">
              Create New Escrow<span className="text-orange-400">.</span>
            </h1>
            <p className="text-gray-400">Set up a secure escrow transaction with our automatic middleman services</p>

            {/* Step Progress Indicator */}
            <div className="mt-6 mb-4">
              <div className="flex items-center justify-center space-x-2">
                {[1, 2, 3, 4].map((step, index) => (
                  <div key={step} className="flex items-center">
                    <button
                      type="button"
                      onClick={() => {
                        console.log(`Step ${step} clicked`)
                        // Only allow going to completed steps or the next valid step
                        if (step <= currentStep) {
                          setCurrentStep(step)
                          setError("") // Clear error when navigating to previous steps
                        } else if (step === currentStep + 1) {
                          // Check if current step is valid before advancing
                          if ((currentStep === 1 && canProceedFromStep1()) ||
                              (currentStep === 2 && canProceedFromStep2()) ||
                              (currentStep === 3 && canProceedFromStep3())) {
                            setCurrentStep(step)
                            setError("") // Clear error when advancing to next step
                          }
                        }
                        // Don't allow skipping ahead to incomplete steps
                      }}
                      className={`flex items-center space-x-1 transition-all duration-200 ${
                        currentStep >= step ? 'cursor-pointer text-orange-400' :
                        step === currentStep + 1 && (
                          (currentStep === 1 && canProceedFromStep1()) ||
                          (currentStep === 2 && canProceedFromStep2()) ||
                          (currentStep === 3 && canProceedFromStep3())
                        ) ? 'cursor-pointer text-gray-500 hover:text-gray-400' :
                        'cursor-not-allowed text-gray-600 opacity-50'
                      }`}
                    >
                      <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-semibold transition-all duration-200 ${
                        currentStep >= step ? 'bg-orange-500 text-white' : 'bg-gray-600 text-gray-400 hover:bg-gray-500'
                      }`}>
                        {step}
                      </div>
                      <span className="text-xs font-medium hidden sm:inline">
                        {step === 1 && "Role"}
                        {step === 2 && "Title"}
                        {step === 3 && "Method"}
                        {step === 4 && "Amount"}
                      </span>
                    </button>
                    {index < 3 && (
                      <div className={`w-4 h-0.5 mx-2 ${currentStep > step ? 'bg-orange-500' : 'bg-gray-600'}`}></div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {user && (
              <div className="flex items-center mt-3 animate-fade-in" style={{ animationDelay: "0.2s" }}>
                <div className="w-2 h-2 bg-green-500 rounded-full mr-2 motion-safe:animate-glow-gentle"></div>
                <span className="text-sm text-gray-400">Creating as {user.email}</span>
              </div>
            )}
          </div>

          <div
            id="main-form"
            data-animate-on-scroll
            className={`backdrop-blur-xl bg-white/5 border border-white/10 rounded-3xl p-4 sm:p-6 md:p-8 shadow-2xl shadow-orange-500/10 relative overflow-visible md:overflow-hidden transition-all duration-500 ease-out animate-fade-in-up ${
              visibleSections.has('main-form')
                ? 'opacity-100 translate-y-0 scale-100'
                : 'opacity-0 translate-y-8 scale-95'
            } hover:border-white/15 hover:bg-white/8`}
          >
            <div className="absolute inset-0 bg-gradient-to-br from-orange-500/5 to-amber-500/5 rounded-3xl"></div>
            <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-orange-400/50 to-transparent"></div>

            <form onSubmit={handleSubmit} onKeyDown={handleFormKeyDown} className="space-y-6 relative z-10">
              {/* Step 1: Role & Username */}
              {currentStep === 1 && (
                <div
                  id="step1"
                  data-animate-on-scroll
                  className={`space-y-6 transition-all duration-700 ${
                    visibleSections.has('step1')
                      ? 'opacity-100 translate-x-0'
                      : 'opacity-0 -translate-x-4'
                  }`}
                  style={{
                    animationDelay: visibleSections.has('step1') ? '0.2s' : '0s'
                  }}
                >
                  {/* Role selector */}
                  <div className="animate-slide-in-left" style={{ animationDelay: "0.08s" }}>
                    <label className="block text-sm font-medium text-gray-300 mb-3">
                      <span className="flex items-center space-x-2">
                        <span><ShoppingCart className="inline-block w-4 h-4 mr-1 text-orange-400" /></span>
                        <span>Your role</span>
                      </span>
                    </label>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 sm:gap-4">
                      <button
                        type="button"
                        onClick={() => {
                          console.log("Buyer button clicked")
                          setRole("buyer")
                          triggerGlitch()
                        }}
                        className={`p-4 sm:p-6 rounded-2xl border-2 transition-all duration-300 ease-out md:hover:scale-105 active:scale-[0.99] transform text-left cursor-pointer group relative overflow-hidden ${
                          role === "buyer"
                            ? "border-orange-500 bg-orange-500/10 text-orange-300 shadow-lg shadow-orange-500/20"
                            : "border-white/20 bg-white/5 text-gray-300 hover:border-white/30 hover:bg-white/10"
                        }`}
                        aria-pressed={role === "buyer"}
                      >
                        {/* Animated background gradient on hover */}
                        <div className="absolute inset-0 bg-gradient-to-r from-orange-500/0 via-orange-500/5 to-orange-500/0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                        <div className="flex items-start relative z-10">
                          <div className="mr-3 mt-1">
                            <ShoppingCart className="w-6 h-6 transition-transform duration-300" />
                          </div>
                          <div>
                            <div className="font-semibold text-base sm:text-lg mb-1">Buyer</div>
                            <div className="text-xs text-gray-400">I will send funds. The other person is the seller.</div>
                          </div>
                        </div>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          console.log("Seller button clicked")
                          setRole("seller")
                          triggerGlitch()
                        }}
                        className={`p-4 sm:p-6 rounded-2xl border-2 transition-all duration-300 ease-out md:hover:scale-105 active:scale-[0.99] transform text-left cursor-pointer group relative overflow-hidden ${
                          role === "seller"
                            ? "border-orange-500 bg-orange-500/10 text-orange-300 shadow-lg shadow-orange-500/20"
                            : "border-white/20 bg-white/5 text-gray-300 hover:border-white/30 hover:bg-white/10"
                        }`}
                        aria-pressed={role === "seller"}
                      >
                        {/* Animated background gradient on hover */}
                        <div className="absolute inset-0 bg-gradient-to-r from-amber-500/0 via-amber-500/5 to-amber-500/0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
                        <div className="flex items-start relative z-10">
                          <div className="mr-3 mt-1">
                            <Store className="w-6 h-6 transition-transform duration-300" />
                          </div>
                          <div>
                            <div className="font-semibold text-base sm:text-lg mb-1">Seller</div>
                            <div className="text-xs text-gray-400">I will receive funds. The other person is the buyer.</div>
                          </div>
                        </div>
                      </button>
                    </div>
                  </div>

                  {/* Other party username */}
                  <div className="animate-slide-in-left" style={{ animationDelay: "0.12s" }}>
                    <label className="block text-sm font-medium text-gray-300 mb-3">
                      <span className="flex items-center space-x-2">
                        <span>👤</span>
                        <span>{role === "buyer" ? "Seller username" : "Buyer username"}</span>
                      </span>
                    </label>
                    <UsernamePicker
                      value={otherPartyUsername}
                      onChange={(v: any) => {
                        console.log("UsernamePicker returned:", v, "Type:", typeof v)

                        // Handle different possible return types
                        let username = ""
                        if (typeof v === "string") {
                          username = v
                        } else if (v && typeof v === "object") {
                          // Try different possible property names
                          username = v.username || v.value || v.label || v.name || ""
                        }

                        console.log("Setting username to:", username)
                        setOtherPartyUsername(username)
                      }}
                    />
                    <p className="text-xs text-gray-500 mt-2">Search by username</p>
                    {otherPartyUsername && !validateUsername(otherPartyUsername.trim()) && (
                      <p className="text-xs text-red-400 mt-2">
                        Usernames must be 3–30 chars: letters, numbers, _ or -
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* Step 2: Title */}
              {currentStep === 2 && (
                <div className="space-y-6">
                  <div className="animate-slide-in-left" style={{ animationDelay: "0.08s" }}>
                    <label className="block text-sm font-medium text-gray-300 mb-3">
                      <span className="flex items-center space-x-2">
                        <span>📝</span>
                        <span>Escrow Title</span>
                      </span>
                    </label>
                    <input
                      type="text"
                      value={escrowTitle}
                      onChange={(e) => setEscrowTitle(e.target.value)}
                      className="w-full px-4 py-3 backdrop-blur-sm bg-white/10 border border-white/20 rounded-2xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-500/50 focus:border-orange-400/50 focus:bg-white/15 transition-all duration-300 ease-out hover:bg-white/12"
                      placeholder="e.g., Website development project, Digital art purchase..."
                      required
                      maxLength={100}
                    />
                    <div className="flex justify-between mt-2">
                      <p className="text-xs text-gray-500">Describe what this escrow is for (5-100 characters)</p>
                      <p className="text-xs text-gray-500">{escrowTitle.length}/100</p>
                    </div>
                    {escrowTitle && !validateTitle(escrowTitle) && (
                      <p className="text-xs text-red-400 mt-2">
                        Title must be 5–100 characters long
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* Step 3: Payment Method */}
              {currentStep === 3 && (
                <div className="space-y-6">
                  <div className="animate-slide-in-right" style={{ animationDelay: "0.08s" }}>
                    <label className="block text-sm font-medium text-gray-300 mb-4">
                      <span className="flex items-center space-x-2">
                        <span>💳</span>
                        <span>Payment Method</span>
                      </span>
                    </label>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 sm:gap-4">
                      {/* Crypto */}
                      <button
                        type="button"
                        onClick={() => {
                          console.log("Crypto payment method clicked")
                          setPaymentMethod("crypto")
                        }}
                        aria-pressed={paymentMethod === "crypto"}
                        className={`p-4 sm:p-6 rounded-2xl border-2 transition-all duration-300 ease-out md:hover:scale-105 active:scale-[0.99] transform cursor-pointer ${
                          paymentMethod === "crypto"
                            ? "border-orange-500 bg-orange-500/10 text-orange-300 shadow-lg shadow-orange-500/20"
                            : "border-white/20 bg-white/5 text-gray-300 hover:border-white/30 hover:bg-white/10"
                        }`}
                      >
                        <div className="text-center">
                          <div className="text-2xl sm:text-3xl mb-2 sm:mb-3">₿</div>
                          <div className="font-semibold text-base sm:text-lg">Cryptocurrency</div>
                          <div className="text-xs text-gray-400 mt-2">Bitcoin, Ethereum, Litecoin, and more</div>
                        </div>
                      </button>

                      {/* PayPal */}
                      <button
                        type="button"
                        onClick={() => {
                          console.log("PayPal payment method clicked")
                          setPaymentMethod("paypal")
                        }}
                        aria-pressed={paymentMethod === "paypal"}
                        className={`p-4 sm:p-6 rounded-2xl border-2 transition-all duration-300 ease-out md:hover:scale-105 active:scale-[0.99] transform cursor-pointer ${
                          paymentMethod === "paypal"
                            ? "border-orange-500 bg-orange-500/10 text-orange-300 shadow-lg shadow-orange-500/20"
                            : "border-white/20 bg-white/5 text-gray-300 hover:border-white/30 hover:bg-white/10"
                        }`}
                      >
                        <div className="text-center">
                          <div className="text-2xl sm:text-3xl mb-2 sm:mb-3">💳</div>
                          <div className="font-semibold text-base sm:text-lg">PayPal</div>
                          <div className="text-xs text-gray-400 mt-2">Traditional payment</div>
                        </div>
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* Step 4: Amount & Currency */}
              {currentStep === 4 && (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Amount */}
                    <div className="animate-slide-in-left" style={{ animationDelay: "0.08s" }}>
                      <label className="block text-sm font-medium text-gray-300 mb-3">
                        <span className="flex items-center space-x-2">
                          <span>💰</span>
                          <span>Amount (USD)</span>
                        </span>
                      </label>
                      <input
                        type="number"
                        step="any"
                        value={usdAmount}
                        onChange={(e) => {
                          console.log("Amount changed to:", e.target.value)
                          setUsdAmount(e.target.value)
                        }}
                        className="w-full px-4 py-3 backdrop-blur-sm bg-white/10 border border-white/20 rounded-2xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-500/50 focus:border-orange-400/50 focus:bg-white/15 transition-all duration-300 ease-out hover:bg-white/12"
                        placeholder="0.00"
                        required
                        inputMode="decimal"
                      />

                      <div className="mt-2 space-y-1">
                        <p className="text-xs text-gray-500">
                          Minimum: ${getMinimumUsdAmount()} USD (covers fees)
                        </p>
                        {paymentMethod === "crypto" && selectedPrice && (
                          <p className="text-xs text-gray-500">
                            Current price: ${selectedPrice.toLocaleString()} per {currency}
                          </p>
                        )}
                      </div>

                      {paymentMethod === "crypto" && getCryptoAmount() && (
                        <div className="mt-3 p-3 bg-orange-500/10 border border-orange-400/20 rounded-lg">
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-orange-300">You'll send:</span>
                            <div className="text-right">
                              <div className="text-orange-200 font-semibold">
                                {getCryptoAmount()} {currency}
                              </div>
                            </div>
                          </div>
                        </div>
                      )}

                      {usdAmount && validateAmount() && (
                        <div className="mt-2 p-2 bg-red-500/10 border border-red-400/30 rounded-lg">
                          <div className="flex items-center space-x-2">
                            <span className="text-red-400 text-sm">⚠️</span>
                            <span className="text-red-300 text-sm">{validateAmount()}</span>
                          </div>
                        </div>
                      )}

                      {paymentMethod === "crypto" && !selectedPrice && (
                        <div className="mt-2 flex items-center space-x-2 text-xs text-gray-400">
                          <div className="w-3 h-3 border border-orange-500 border-t-transparent rounded-full motion-safe:animate-spin"></div>
                          <span>Loading current prices...</span>
                        </div>
                      )}
                    </div>

                    {/* Currency */}
                    <div className="animate-slide-in-right" style={{ animationDelay: "0.12s" }}>
                      <label className="block text-sm font-medium text-gray-300 mb-3">
                        <span className="flex items-center space-x-2">
                          <span>🪙</span>
                          <span>Currency</span>
                        </span>
                      </label>
                      {paymentMethod === "paypal" ? (
                        <div className="w-full px-4 py-3 backdrop-blur-sm bg-white/10 border border-white/20 rounded-2xl text-white flex items-center font-medium">
                          USD
                        </div>
                      ) : (
                        <div ref={dropdownRef} className="relative">
                          <button
                            type="button"
                            onClick={() => {
                          console.log("Currency dropdown clicked")
                          setIsDropdownOpen(!isDropdownOpen)
                        }}
                            className="w-full px-4 py-3 backdrop-blur-sm bg-white/10 border border-white/20 rounded-2xl text-white focus:outline-none focus:ring-2 focus:ring-orange-500/50 focus:border-orange-400/50 focus:bg-white/15 transition-all duration-300 ease-out hover:bg-white/12 flex items-center justify-between"
                            aria-haspopup="listbox"
                            aria-expanded={isDropdownOpen}
                          >
                            <span>{currency ? `${currency} - ${currencies.find(c => c.code === currency)?.name || ""}` : "Select currency"}</span>
                            <svg className={`w-5 h-5 text-gray-400 transition-transform ${isDropdownOpen ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                            </svg>
                          </button>

                          {isDropdownOpen && (
                            <div className="absolute z-50 w-full mt-2 backdrop-blur-xl bg-gray-900/95 border border-white/20 rounded-2xl shadow-2xl max-h-60 overflow-y-auto">
                              {currencies.map((curr, index) => (
                                <button
                                  key={curr.code}
                                  type="button"
                                  onClick={() => {
                                    setCurrency(curr.code)
                                    setIsDropdownOpen(false)
                                  }}
                                  className={`w-full px-4 py-3 text-left hover:bg-white/10 transition-colors ${
                                    currency === curr.code ? "bg-orange-500/20 text-orange-300" : "text-white"
                                  } ${index === 0 ? "rounded-t-2xl" : ""} ${
                                    index === currencies.length - 1 ? "rounded-b-2xl" : ""
                                  }`}
                                  role="option"
                                  aria-selected={currency === curr.code}
                                >
                                  {curr.code} - {curr.name}
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>

                  {feeInfo && !loadingFees && (
                    <div className="mt-6 p-4 bg-gradient-to-r from-orange-500/10 to-amber-500/10 border border-orange-400/20 rounded-2xl backdrop-blur-sm">
                      <div className="flex items-center space-x-2 mb-3">
                        <span className="text-orange-400">💰</span>
                        <h4 className="text-orange-300 font-semibold text-sm">Fee Breakdown</h4>
                      </div>
                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-orange-300">Transaction Amount:</span>
                          <span className="text-orange-200 font-medium">${feeInfo.total_amount.toFixed(2)}</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-orange-300">
                            Platform Fee ({feeInfo.fee_percentage}%):
                          </span>
                          <span className="text-orange-200 font-medium">${feeInfo.fee_amount.toFixed(2)}</span>
                        </div>
                        <div className="border-t border-orange-400/20 pt-2 mt-2">
                          <div className="flex justify-between items-center">
                            <span className="text-sm text-orange-200 font-semibold">Seller Receives (USD):</span>
                            <span className="text-orange-100 font-bold text-lg">${feeInfo.net_amount.toFixed(2)}</span>
                          </div>
                        </div>
                        {paymentMethod === "crypto" && typeof feeInfo.net_crypto === "number" && (
                          <div className="text-xs text-orange-300/80 mt-1">
                            ≈ {feeInfo.net_crypto} {currency} after fees
                          </div>
                        )}
                        <div className="mt-3 p-2 bg-orange-500/10 rounded-lg">
                          <p className="text-xs text-orange-300/80">
                            {paymentMethod === "paypal"
                              ? "PayPal transactions: 2% platform fee"
                              : (feeInfo.usd_amount < 50
                                  ? "Crypto under $50: 2% platform fee"
                                  : "Crypto $50+: 1.5% platform fee")}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}

                  {loadingFees && usdAmount && (
                    <div className="mt-3 flex items-center space-x-2 text-xs text-orange-400">
                      <div className="w-3 h-3 border border-orange-500 border-t-transparent rounded-full motion-safe:animate-spin"></div>
                      <span>Calculating fees...</span>
                    </div>
                  )}
                </div>
              )}

              {error && (
                <div className="backdrop-blur-sm bg-red-500/10 border border-red-400/20 text-red-300 px-4 py-3 rounded-2xl text-sm animate-shake">
                  <div className="flex items-center space-x-2">
                    <span>⚠️</span>
                    <span>{error}</span>
                  </div>
                </div>
              )}

              {/* Navigation Buttons */}
              <div className="flex justify-between items-center pt-4">
                {currentStep > 1 && (
                  <button
                    type="button"
                    onClick={() => {
                      console.log("Previous step button clicked")
                      prevStep()
                    }}
                    className="px-6 py-3 bg-gray-600/80 hover:bg-gray-600 backdrop-blur-sm border border-gray-500/30 text-white font-semibold rounded-2xl transition-all duration-300 hover:shadow-lg hover:shadow-gray-500/20 md:hover:scale-[1.02] active:scale-[0.99] transform ease-out"
                  >
                    <div className="flex items-center space-x-2">
                      <span>←</span>
                      <span>Back</span>
                    </div>
                  </button>
                )}

                {currentStep < 4 ? (
                  <button
                    type="button"
                    onClick={() => {
                      console.log("Next step button clicked")
                      nextStep()
                    }}
                    disabled={
                      (currentStep === 1 && !canProceedFromStep1()) ||
                      (currentStep === 2 && !canProceedFromStep2()) ||
                      (currentStep === 3 && !canProceedFromStep3())
                    }
                    className={`px-6 py-3 bg-[#FF7A00] hover:bg-[#FF7A00] backdrop-blur-sm border border-orange-400/30 text-white font-semibold rounded-2xl transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-orange-500/20 hover:shadow-orange-500/30 md:hover:scale-[1.02] active:scale-[0.99] transform ease-out ${currentStep === 1 ? 'ml-auto' : ''}`}
                  >
                    <div className="flex items-center space-x-2">
                      <span>Continue</span>
                      <span>→</span>
                    </div>
                  </button>
                ) : (
                  <button
                    type="submit"
                    disabled={
                      loading ||
                      !canSubmit() ||
                      (paymentMethod === "crypto" && !selectedPrice)
                    }
                    className={`px-6 py-3 bg-[#FF7A00] hover:bg-[#FF7A00] backdrop-blur-sm border border-orange-400/30 text-white font-semibold rounded-2xl transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-orange-500/20 hover:shadow-orange-500/30 md:hover:scale-[1.02] active:scale-[0.99] transform ease-out group relative overflow-hidden ${
                      isGlitching ? 'animate-bounce' : ''
                    }`}
                  >
                    {/* Animated background effects removed for solid button */}
                    <div className="flex items-center space-x-2">
                      {loading ? (
                        <>
                          <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full motion-safe:animate-spin"></div>
                          <span>Creating...</span>
                        </>
                      ) : (
                        <>
                          <span>Create Escrow</span>
                          <span>↗</span>
                        </>
                      )}
                    </div>
                  </button>
                )}
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  )
}