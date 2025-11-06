"use client"

import { useEffect, useMemo, useState } from "react"
import { useParams, useRouter } from "next/navigation"
import Link from "next/link"
import { supabase } from "@/lib/supabase"
import { apiRequest, authApiRequest } from "@/lib/api"
import { CryptoSelectorCompact } from "@/components/crypto-selector"
import { ShieldCheck, Zap, MessageCircle, Star } from "lucide-react"
import { StatefulButton } from "@/components/ui/stateful-button"
import ScrollFadeIn from "@/components/ui/scroll-fade-in"
import { useToast } from "@/components/ui/use-toast"
import ViewTracker from "@/components/ViewTracker"

type Listing = {
  id: string
  seller_id: string
  title: string
  description?: string
  price_usd: number
  accept_all: boolean
  payment_methods: string[]
  status: string
  images?: string[]
  currencies?: string[]
  rating?: number
  seller_volume_usd?: number
}

export default function ListingDetailPage() {
  const params = useParams() as { id?: string }
  const router = useRouter()
  const { toast } = useToast()
  const id = params?.id as string
  const [listing, setListing] = useState<Listing | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedCurrency, setSelectedCurrency] = useState<string>("")
  const [selectedMethod, setSelectedMethod] = useState<'paypal' | 'crypto'>("paypal")
  const [activeImgIdx, setActiveImgIdx] = useState<number>(0)
  const [currentUserId, setCurrentUserId] = useState<string | null>(null)
  const apiBase = useMemo(() => process.env.NEXT_PUBLIC_API_URL!, [])

  useEffect(() => {
    const init = async () => {
      try {
        if (!id) return
        console.log('Fetching listing from:', `${apiBase}/api/marketplace/${id}`)
        const res = await apiRequest(`${apiBase}/api/marketplace/${id}`)
        console.log('Response status:', res.status)
        if (!res.ok) {
          const j = await res.json().catch(() => ({}))
          console.log('Response error:', j)
          toast({
            title: "Error",
            description: j.error || 'Listing not found',
            variant: "destructive",
          })
          return
        }
        const data = await res.json()
        console.log('Response data:', data)
        setListing(data)
        setSelectedCurrency((data.currencies || ['BTC'])[0])
        const allowed: string[] = data.payment_methods || []
        setSelectedMethod(allowed.includes('paypal') ? 'paypal' : 'crypto')
        setActiveImgIdx(0)
      } catch (err) {
        console.error('Fetch error:', err)
        toast({
          title: "Network Error",
          description: "Failed to load listing. Please check your connection.",
          variant: "destructive",
        })
      } finally {
        setLoading(false)
      }
    }
    init()
  }, [id, apiBase])

  // Fetch current user ID
  useEffect(() => {
    const getCurrentUser = async () => {
      const { data: { session } } = await supabase.auth.getSession()
      if (session?.user?.id) {
        setCurrentUserId(session.user.id)
        console.log('Current user ID set:', session.user.id)
      } else {
        console.log('No user session found')
      }
    }
    getCurrentUser()
  }, [])

  const addToCart = async (method: 'crypto' | 'paypal') => {
    const { data: { session } } = await supabase.auth.getSession()
    if (!session) {
      toast({
        title: "Authentication Required",
        description: "Please log in to add items to your cart.",
        variant: "destructive",
      })
      throw new Error('Not logged in')
    }
    if (!listing) return
    const body: any = { listing_id: listing.id, payment_method: method, quantity: 1 }
    if (method === 'crypto') body.selected_currency = selectedCurrency || 'BTC'
    const res = await authApiRequest(`${apiBase}/api/cart`, session, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
    if (!res.ok) {
      const j = await res.json().catch(() => ({}))
      const msg = j.error || 'Failed to add to cart'
      toast({
        title: "Cart Error",
        description: msg,
        variant: "destructive",
      })
      throw new Error(msg)
    }
    toast({
      title: "Success",
      description: "Item added to cart successfully!",
    })
  }

  const startMessaging = async () => {
    const { data: { session } } = await supabase.auth.getSession()
    if (!session) {
      router.push('/auth')
      return
    }
    if (!listing) return
    const res = await authApiRequest(`${apiBase}/api/messages/start-from-listing`, session, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ listing_id: listing.id })
    })
    if (!res.ok) {
      const j = await res.json().catch(() => ({}))
      toast({
        title: "Message Error",
        description: j.error || 'Failed to start conversation',
        variant: "destructive",
      })
      return
    }
    const data = await res.json()
    const convId = data.conversation_id
    router.push(`/messages?c=${encodeURIComponent(convId)}`)
  }

  // Check if current user is the seller
  const isOwnListing = currentUserId && listing && currentUserId === listing.seller_id
  console.log('isOwnListing check:', { currentUserId, listingSellerId: listing?.seller_id, isOwnListing })

  if (loading) {
    return <div className="min-h-screen bg-black text-white flex items-center justify-center">Loading listing...</div>
  }

  if (!listing) {
    return <div className="min-h-screen bg-black text-white flex items-center justify-center">Listing not found</div>
  }

  return (
    <div className="min-h-screen bg-black text-white relative overflow-hidden">
      {/* View Tracking Component */}
      {id && <ViewTracker listingId={id} apiBase={apiBase} />}

      {/* Top-left glow (match dashboard) */}
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

      <div className="container mx-auto px-4 py-8 max-w-6xl">
        <div className="flex items-center gap-3 mb-6 text-sm text-gray-400">
          <Link href="/marketplace" className="hover:text-white">Marketplace</Link>
          <span>/</span>
          <span className="text-white truncate" title={listing.title}>{listing.title}</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-6">
          {/* Left gallery */}
          <div className="md:col-span-3">
            <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
              {listing.images && listing.images.length > 0 ? (
                // eslint-disable-next-line @next/next/no-img-element
                <img src={listing.images[activeImgIdx] || listing.images[0]} alt={listing.title} className="w-full h-[420px] object-cover" />
              ) : (
                <div className="w-full h-[420px] bg-gradient-to-br from-orange-500/10 to-black" />
              )}
              <div className="pointer-events-none -mt-16 h-16 w-full bg-gradient-to-t from-black/70 to-transparent" />
            </div>
            {(listing.images && listing.images.length > 1) && (
              <div className="mt-3 grid grid-cols-5 gap-2">
                {listing.images.slice(0,5).map((u, idx) => (
                  // eslint-disable-next-line @next/next/no-img-element
                  <img key={idx} src={u} alt="thumb" onClick={()=>setActiveImgIdx(idx)} className={`h-16 w-full object-cover rounded-lg border ${activeImgIdx===idx? 'border-white/40':'border-white/10'} cursor-pointer`} />
                ))}
              </div>
            )}
          </div>

          {/* Right sticky summary */}
          <div className="md:col-span-2 md:sticky md:top-20 space-y-4">
            <ScrollFadeIn>
              <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                <div className="text-xl font-semibold">{listing.title}</div>
                <div className="text-3xl font-bold text-[#EA580C] mt-2">${listing.price_usd.toFixed(2)}</div>
                <div className="flex items-center gap-3 text-sm text-gray-400 mt-2">
                  <span className="inline-flex items-center gap-1"><Star className="h-4 w-4 text-[#F59E0B]" />{listing.rating ?? 5}</span>
                  <span>•</span>
                  <span>${(listing.seller_volume_usd ?? 0).toLocaleString()}</span>
                </div>
              </div>
            </ScrollFadeIn>

            <ScrollFadeIn>
              <div className="rounded-2xl border border-white/10 bg-white/5 p-4 space-y-3">
                <div className="text-sm text-gray-300">Payment method</div>
                <div className="inline-flex rounded-lg border border-white/10 bg-black p-1">
                  <button onClick={()=>setSelectedMethod('paypal')} className={`px-3 py-1.5 text-sm rounded-md ${selectedMethod==='paypal' ? 'bg-white/10 text-white' : 'text-gray-300 hover:bg-white/5'}`}>PayPal</button>
                  <button onClick={()=>setSelectedMethod('crypto')} className={`px-3 py-1.5 text-sm rounded-md ${selectedMethod==='crypto' ? 'bg-white/10 text-white' : 'text-gray-300 hover:bg-white/5'}`}>Crypto</button>
                </div>
                {selectedMethod==='crypto' && (
                  <div className="space-y-2">
                    <div className="text-sm text-gray-300">Select currency</div>
                    <CryptoSelectorCompact value={selectedCurrency} onValueChange={setSelectedCurrency} />
                  </div>
                )}
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    {isOwnListing ? (
                      // Show disabled button for own listings
                      <button
                        disabled
                        className="flex-1 h-10 rounded-xl bg-gray-600 text-gray-400 font-semibold cursor-not-allowed"
                      >
                        Your Listing
                      </button>
                    ) : (
                      // Normal add to cart button for other listings
                      <StatefulButton
                        onClick={() => addToCart(selectedMethod)}
                        className="flex-1 h-10 rounded-xl bg-[#EA580C] text-white font-semibold hover:opacity-95 focus:outline-none focus:ring-2 focus:ring-[#93C5FD]"
                        success={
                          <>
                            <svg
                              className="h-4 w-4"
                              viewBox="0 0 24 24"
                              fill="none"
                              stroke="currentColor"
                              strokeWidth="3"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                            >
                              <path d="M20 6L9 17l-5-5" />
                            </svg>{" "}
                            Added
                          </>
                        }
                      >
                        Add to cart
                      </StatefulButton>
                    )}

                    <button
                      onClick={startMessaging}
                      className="h-10 w-10 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 flex items-center justify-center"
                      aria-label="Message seller"
                    >
                      <MessageCircle className="h-5 w-5" />
                    </button>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-xs text-gray-400 pt-1">
                  <span className="inline-flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5" />Buyer protection</span>
                </div>
              </div>
            </ScrollFadeIn>

            <ScrollFadeIn>
              <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                <div className="text-sm text-gray-300 mb-2">Description</div>
                <div className="text-sm text-gray-200 whitespace-pre-wrap">{listing.description || 'No description provided.'}</div>
              </div>
            </ScrollFadeIn>
          </div>
        </div>

        {/* Mobile bottom actions */}
      </div>
    </div>
  )
}


