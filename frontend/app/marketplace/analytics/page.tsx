"use client"

import { useState, useEffect, useMemo } from "react"
import ScrollFadeIn from "@/components/ui/scroll-fade-in"
import { authApiRequest } from "@/lib/api"
import { Eye, TrendingUp, ShoppingCart, Search, Package, Trash2, Pause, Play, AlertTriangle } from "lucide-react"
import AnimatedBackButton from "@/components/animated-back-button"
import type { SellerProduct, EscrowData, AnalyticsData } from "@/lib/fetch-seller-products"

type ViewMode = "list" | "analytics"

interface EnhancedProduct extends SellerProduct {
  viewsChange: number
  salesChange: number
}

// Helper to get session from Supabase that works with v1 and v2
async function getSessionFromSupabase(): Promise<any | null> {
  try {
    const { supabase } = await import("@/lib/supabase")
    // widen the type so TypeScript won't complain about missing members
    const auth = (supabase.auth as unknown) as Record<string, any>

    if (typeof auth.getSession === "function") {
      const res = await auth.getSession()
      return res?.data?.session ?? null
    }

    if (typeof auth.session === "function") {
      // legacy v1
      return auth.session()
    }

    return null
  } catch (e) {
    console.error("Failed to import supabase to get session:", e)
    return null
  }
}

export default function MyListingsPage() {
  const [viewMode, setViewMode] = useState<ViewMode>("list")
  const [selectedProductId, setSelectedProductId] = useState<string | null>(null)
  const [sellerProducts, setSellerProducts] = useState<EnhancedProduct[]>([])
  const [data, setData] = useState<AnalyticsData | null>(null)
  const [escrows, setEscrows] = useState<EscrowData[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [searchQuery, setSearchQuery] = useState("")
  const [statusFilter, setStatusFilter] = useState<string>("all")
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)

  const apiBase = useMemo(
    () => process.env.NEXT_PUBLIC_API_URL || (typeof window !== "undefined" ? window.location.origin : ""),
    [],
  )

  useEffect(() => {
    const fetchData = async () => {
      setError("")
      setLoading(true)
      try {
        const session = await getSessionFromSupabase()

        if (!session) {
          throw new Error("Not authenticated (no session). Please login.")
        }

        if (viewMode === "list") {
          const primaryUrl = `${apiBase}/api/marketplace/seller/products`
          const aliasUrls = [`${apiBase}/api/marketplace/seller/products/get`, `${apiBase}/api/y/products/get`]

          console.log("Fetching seller products from (primary):", primaryUrl)

          const res = await fetch(primaryUrl, {
            method: "GET",
            headers: {
              Authorization: `Bearer ${session.access_token || session.accessToken || session?.provider_token || ""}`,
              "Content-Type": "application/json",
              "ngrok-skip-browser-warning": "1",
            },
          })

          console.log("seller products response", res.status, res.statusText)
          const allow = res.headers.get("Allow") || res.headers.get("allow")
          const acah = res.headers.get("Access-Control-Allow-Headers")
          console.log("Allow header:", allow, "AC-Allow-Headers:", acah)

          let finalRes = res
          if (res.status === 405) {
            console.warn("Primary products endpoint returned 405 — attempting fallback aliases")
            for (const u of aliasUrls) {
              try {
                const r2 = await fetch(u, {
                  method: "GET",
                  headers: {
                    Authorization: `Bearer ${session.access_token || session.accessToken || session?.provider_token || ""}`,
                    "Content-Type": "application/json",
                    "ngrok-skip-browser-warning": "1",
                  },
                })
                console.log("Tried alias", u, "status:", r2.status)
                if (r2.ok) {
                  finalRes = r2
                  break
                }
                if (r2.status >= 200 && r2.status < 300) {
                  finalRes = r2
                  break
                }
              } catch (e) {
                console.warn("Alias fetch failed:", u, e)
              }
            }
          }

          if (!finalRes.ok) {
            if (finalRes.status === 401 || finalRes.status === 403) {
              throw new Error("Unauthorized. Token may be missing or invalid.")
            } else if (finalRes.status === 405) {
              let body = ""
              try {
                body = await finalRes.json()
              } catch {
                body = await finalRes.text().catch(() => "")
              }
              throw new Error(`Method Not Allowed (405). Server said: ${JSON.stringify(body)}`)
            } else {
              const text = await finalRes.text().catch(() => "")
              throw new Error(`Failed to fetch products: ${finalRes.status} ${text}`)
            }
          }

          const payload = await finalRes.json()
          const products: any[] = Array.isArray(payload) ? payload : payload?.products || []

          const enhancedProducts: EnhancedProduct[] = products.map((product: any) => ({
            id: product.id,
            title: product.title || product.name || "Untitled",
            description: product.description || "",
            status: product.status || "paused",
            totalViews: product.totalViews ?? product.total_views ?? product.views ?? 0,
            totalSales: product.totalSales ?? product.total_sales ?? product.sales ?? 0,
            conversionRate: product.conversionRate ?? product.conversion_rate ?? 0,
            analytics: {
              avg_sale_price: product.analytics?.avg_sale_price ?? product.avg_sale_price ?? 0,
            } as any,
            ...product,
            viewsChange: Math.floor(Math.random() * 50) - 25,
            salesChange: Math.floor(Math.random() * 40) - 20,
          }))

          setSellerProducts(enhancedProducts)
        } else if (selectedProductId) {
          const analyticsPrimary = `${apiBase}/api/marketplace/${selectedProductId}/analytics`
          const analyticsAliases = [
            `${apiBase}/api/y/products/get/${selectedProductId}/analytics`,
            `${apiBase}/api/marketplace/seller/products/get/${selectedProductId}/analytics`,
          ]

          const escrowsPrimary = `${apiBase}/api/marketplace/${selectedProductId}/escrows`
          const escrowsAliases = [`${apiBase}/api/marketplace/seller/products/get/${selectedProductId}/escrows`]

          async function fetchWithAliases(urlPrimary: string, aliases: string[]) {
            const headersBase: Record<string, string> = {
              Authorization: `Bearer ${session.access_token || session.accessToken || session?.provider_token || ""}`,
              "Content-Type": "application/json",
            }
            // inject ngrok header only for requests targeting the configured apiBase
            const needsNgrok = apiBase && urlPrimary.startsWith(apiBase)
            if (needsNgrok) {
              headersBase["ngrok-skip-browser-warning"] = "1"
            }

            const r = await fetch(urlPrimary, { method: "GET", headers: headersBase })
            if (r.status === 405) {
              for (const u of aliases) {
                try {
                  const aliasNeedsNgrok = apiBase && u.startsWith(apiBase)
                  const aliasHeaders = {
                    ...headersBase,
                    ...(aliasNeedsNgrok ? { "ngrok-skip-browser-warning": "1" } : {}),
                  }
                  const r2 = await fetch(u, { method: "GET", headers: aliasHeaders })
                  if (r2.ok) return r2
                } catch (e) {
                  console.warn("Alias fetch failed:", u, e)
                }
              }
            }
            return r
          }

          const analyticsRes = await fetchWithAliases(analyticsPrimary, analyticsAliases)
          const escrowsRes = await fetchWithAliases(escrowsPrimary, escrowsAliases)

          if (!analyticsRes.ok) throw new Error("Failed to fetch analytics")
          if (!escrowsRes.ok) throw new Error("Failed to fetch escrows")

          const analytics = await analyticsRes.json()
          const productEscrows = await escrowsRes.json()

          setData(analytics)
          setEscrows(Array.isArray(productEscrows) ? productEscrows : productEscrows?.escrows || [])
        }
      } catch (err: any) {
        console.error("Error fetching data:", err)
        setError(err?.message || "Failed to load data")
      } finally {
        setLoading(false)
      }
    }

    fetchData()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewMode, selectedProductId, apiBase])

  const filteredProducts = sellerProducts.filter((product) => {
    const matchesSearch = product.title.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesStatus = statusFilter === "all" || product.status === statusFilter
    // Only include products that are not marked as deleted, if such a status exists
    // If product.status cannot be "deleted", this will always be true, but we keep it for future-proofing
    const notDeleted = (product as any).status !== "deleted"
    return matchesSearch && matchesStatus && notDeleted
  })
  
  const handleStatusToggle = async (productId: string, currentStatus: string) => {
    try {
      const session = await getSessionFromSupabase()
      if (!session) throw new Error("Not authenticated")

      const endpoint = currentStatus === "active" ? "pause" : "resume"
      const response = await authApiRequest(
        `${apiBase}/api/marketplace/${productId}/${endpoint}`,
        session,
        {
          method: "POST",
          headers: { "ngrok-skip-browser-warning": "1" },
        },
      )

      if (!response.ok) throw new Error("Failed to update status")

      setSellerProducts((prev) =>
        prev.map((p) =>
          p.id === productId ? { ...p, status: currentStatus === "active" ? "paused" : ("active" as any) } : p,
        ),
      )
    } catch (error) {
      console.error("Error toggling status:", error)
      setError("Failed to update listing status")
    }
  }

  const handleDelete = async (productId: string) => {
    try {
      const session = await getSessionFromSupabase()
      if (!session) throw new Error("Not authenticated")

      const response = await authApiRequest(
        `${apiBase}/api/marketplace/${productId}`,
        session,
        { method: "DELETE", headers: { "ngrok-skip-browser-warning": "1" } },
      )

      if (!response.ok) throw new Error("Failed to delete listing")

      setSellerProducts((prev) => prev.filter((p) => p.id !== productId))
      setConfirmDelete(null)

      // If we're in analytics view and deleting the current product, go back to list
      if (viewMode === "analytics" && selectedProductId === productId) {
        setViewMode("list")
        setSelectedProductId(null)
        setData(null)
        setEscrows([])
      }
    } catch (error) {
      console.error("Error deleting product:", error)
      setError("Failed to delete listing")
    }
  }

  const handleStatusToggleInAnalytics = async (productId: string, currentStatus: string) => {
    try {
      const session = await getSessionFromSupabase()
      if (!session) throw new Error("Not authenticated")

      const endpoint = currentStatus === "active" ? "pause" : "resume"
      const response = await authApiRequest(
        `${apiBase}/api/marketplace/${productId}/${endpoint}`,
        session,
        {
          method: "POST",
          headers: { "ngrok-skip-browser-warning": "1" },
        },
      )

      if (!response.ok) throw new Error("Failed to update status")

      // Update the product status in both the main list and selected product
      setSellerProducts((prev) =>
        prev.map((p) =>
          p.id === productId ? { ...p, status: currentStatus === "active" ? "paused" : ("active" as any) } : p,
        ),
      )
    } catch (error) {
      console.error("Error toggling status:", error)
      setError("Failed to update listing status")
    }
  }

  const handleProductSelect = (productId: string) => {
    setSelectedProductId(productId)
    setViewMode("analytics")
    setLoading(true)
  }

  const handleBackToList = () => {
    setViewMode("list")
    setSelectedProductId(null)
    setData(null)
    setEscrows([])
    setLoading(true)
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0a0a0a] text-white flex flex-col items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500 mb-4"></div>
        <p className="text-gray-400">Loading...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen bg-[#0a0a0a] text-white flex flex-col items-center justify-center">
        <div className="max-w-md mx-auto text-center">
          <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Unable to Load Data</h2>
          <p className="text-gray-400 mb-6">{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition-colors"
          >
            Try Again
          </button>
        </div>
      </div>
    )
  }

  if (viewMode === "list") {
    return (
      <div className="min-h-screen bg-[#0a0a0a] text-white">
        <div className="container mx-auto px-4 py-4 sm:py-8 max-w-7xl">
          <div className="mb-6">
            <h1 className="text-3xl font-bold text-white mb-2">
              My Listings<span className="text-orange-500">.</span>
            </h1>
            <p className="text-gray-400">Manage your marketplace listings</p>
          </div>

          {error && (
            <div className="mb-6 rounded-xl border border-red-400/30 bg-red-500/10 p-4 text-red-200 text-sm">
              {error}
            </div>
          )}

          <div className="mb-6 flex flex-col sm:flex-row gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search listings..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full h-12 pl-10 pr-4 rounded-lg bg-[#1a1a1a] border border-[#333] text-white placeholder-gray-400 focus:border-orange-500 focus:outline-none"
              />
            </div>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-[#1a1a1a] border border-[#333] rounded-lg px-3 py-2 text-white focus:border-orange-500 focus:outline-none"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="paused">Paused</option>
              <option value="sold">Sold</option>
            </select>
          </div>

          <div className="mb-4">
            <h2 className="text-xl font-bold text-white mb-2">Your Listings</h2>
            <p className="text-gray-400">{filteredProducts.length} listings</p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            {filteredProducts.map((product, index) => (
              <ScrollFadeIn key={product.id} delay={index * 50}>
                <div className="rounded-lg bg-[#1a1a1a] border border-[#333] p-6 hover:border-orange-500/50 transition-all">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <Package className="h-5 w-5 text-orange-500" />
                      <div
                        className={`px-2 py-1 rounded-full text-xs font-bold ${
                          product.status === "active"
                            ? "bg-green-600 text-white"
                            : product.status === "paused"
                              ? "bg-yellow-600 text-white"
                              : "bg-gray-600 text-white"
                        }`}
                      >
                        {product.status.toUpperCase()}
                      </div>
                    </div>

                    <div className="flex gap-2">
                      <button
                        onClick={() => handleStatusToggle(product.id, product.status)}
                        className="p-2 text-gray-400 hover:text-white transition-colors hover:bg-[#333] rounded"
                        title={product.status === "active" ? "Pause" : "Activate"}
                      >
                        {product.status === "active" ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                      </button>
                      <button
                        onClick={() => setConfirmDelete(product.id)}
                        className="p-2 text-gray-400 hover:text-red-400 transition-colors hover:bg-[#333] rounded"
                        title="Delete"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>

                  <h3 className="text-lg font-semibold text-white mb-4 line-clamp-2">{product.title}</h3>

                  <div className="grid grid-cols-3 gap-4 mb-4">
                    <div>
                      <div className="text-2xl font-bold text-white">{product.totalViews.toLocaleString()}</div>
                      <div className="flex items-center gap-1 text-xs"></div>
                      <div className="text-xs text-gray-400">Views</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-white">{product.totalSales}</div>
                      <div className="flex items-center gap-1 text-xs"></div>
                      <div className="text-xs text-gray-400">Sales</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-white">{product.conversionRate}%</div>
                      <div className="text-xs text-gray-400">Conversion</div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <div></div>
                    <button
                      onClick={() => handleProductSelect(product.id)}
                      className="text-sm text-orange-500 hover:underline"
                    >
                      View Analytics →
                    </button>
                  </div>
                </div>
              </ScrollFadeIn>
            ))}
          </div>

          {filteredProducts.length === 0 && (
            <div className="text-center py-12">
              <Package className="h-12 w-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400">No listings found</p>
            </div>
          )}

          {confirmDelete && (
            <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
              <div className="bg-[#1a1a1a] border border-[#333] rounded-lg p-6 max-w-md mx-4">
                <div className="flex items-center gap-3 mb-4">
                  <AlertTriangle className="h-6 w-6 text-red-500" />
                  <h3 className="text-lg font-semibold text-white">Delete Listing</h3>
                </div>
                <p className="text-gray-400 mb-6">
                  Are you sure you want to delete this listing? This action cannot be undone.
                </p>
                <div className="flex gap-3">
                  <button
                    onClick={() => handleDelete(confirmDelete)}
                    className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
                  >
                    Delete
                  </button>
                  <button
                    onClick={() => setConfirmDelete(null)}
                    className="flex-1 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    )
  }

  if (!data) {
    return (
      <div className="min-h-screen bg-[#0a0a0a] text-white flex items-center justify-center">
        No analytics data available
      </div>
    )
  }

  const selectedProduct = sellerProducts.find((p) => p.id === selectedProductId)

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <div className="container mx-auto px-4 py-8 max-w-7xl">
        <div className="mb-6">
          <AnimatedBackButton onClick={handleBackToList} text="Back to Listings" className="mb-4" />
        </div>

        <div className="mb-8">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white mb-2">
                {selectedProduct?.title}
                <span className="text-orange-500">.</span>
              </h1>
              <p className="text-gray-400">Analytics & Insights</p>
            </div>

            <div className="flex items-center gap-3">
              <div
                className={`px-3 py-1 rounded-full text-xs font-bold ${
                  selectedProduct?.status === "active"
                    ? "bg-green-600 text-white"
                    : selectedProduct?.status === "paused"
                      ? "bg-yellow-600 text-white"
                      : "bg-gray-600 text-white"
                }`}
              >
                {selectedProduct?.status?.toUpperCase()}
              </div>

              <button
                onClick={() =>
                  selectedProduct && handleStatusToggleInAnalytics(selectedProduct.id, selectedProduct.status)
                }
                className="flex items-center gap-2 px-4 py-2 bg-orange-600/10 border border-orange-600/30 hover:bg-orange-600/20 text-orange-400 hover:text-orange-300 rounded-lg transition-all"
                title={selectedProduct?.status === "active" ? "Pause Listing" : "Activate Listing"}
              >
                {selectedProduct?.status === "active" ? (
                  <>
                    <Pause className="h-4 w-4" />
                    Pause
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" />
                    Activate
                  </>
                )}
              </button>

              <button
                onClick={() => selectedProduct && setConfirmDelete(selectedProduct.id)}
                className="flex items-center gap-2 px-4 py-2 bg-red-600/10 border border-red-600/30 hover:bg-red-600/20 text-red-400 hover:text-red-300 rounded-lg transition-all"
                title="Delete Listing"
              >
                <Trash2 className="h-4 w-4" />
                Delete
              </button>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <div className="rounded-lg bg-[#1a1a1a] border border-[#333] p-6">
            <div className="flex items-center gap-3 mb-4">
              <Eye className="h-5 w-5 text-orange-500" />
              <span className="text-gray-400 text-sm">Total Views</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">{data.overview.total_views.toLocaleString()}</div>
            <div className="text-sm text-green-400">+{data.overview.conversion_rate}% conversion</div>
          </div>

          <div className="rounded-lg bg-[#1a1a1a] border border-[#333] p-6">
            <div className="flex items-center gap-3 mb-4">
              <ShoppingCart className="h-5 w-5 text-orange-500" />
              <span className="text-gray-400 text-sm">Total Sales</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">{data.overview.total_sales}</div>
            <div className="text-sm text-green-400">${data.overview.avg_sale_price.toLocaleString()} avg</div>
          </div>

          <div className="rounded-lg bg-[#1a1a1a] border border-[#333] p-6">
            <div className="flex items-center gap-3 mb-4">
              <TrendingUp className="h-5 w-5 text-orange-500" />
              <span className="text-gray-400 text-sm">Unique Viewers</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">{data.overview.unique_viewers.toLocaleString()}</div>
            <div className="text-sm text-blue-400">
              {((data.overview.unique_viewers / data.overview.total_views) * 100).toFixed(1)}% of views
            </div>
          </div>

          <div className="rounded-lg bg-[#1a1a1a] border border-[#333] p-6">
            <div className="flex items-center gap-3 mb-4">
              <Package className="h-5 w-5 text-orange-500" />
              <span className="text-gray-400 text-sm">Active Escrows</span>
            </div>
            <div className="text-2xl font-bold text-white mb-1">
              {escrows.filter((e) => e.status === "pending").length}
            </div>
            <div className="text-sm text-purple-400">
              {escrows.filter((e) => e.status === "completed").length} completed
            </div>
          </div>
        </div>

        <div className="rounded-lg bg-[#1a1a1a] border border-[#333] p-6">
          <h3 className="text-lg font-semibold text-white mb-6">Recent Transactions</h3>
          <div className="space-y-4 max-h-80 overflow-y-auto">
            {escrows.slice(0, 10).map((escrow) => (
              <div
                key={escrow.id}
                className="flex items-center justify-between py-3 border-b border-[#333] last:border-b-0"
              >
                <div className="flex items-center gap-4">
                  <div className="text-white font-medium">{escrow.buyerEmail}</div>
                  <div className="text-sm text-gray-400">{new Date(escrow.createdAt).toLocaleDateString()}</div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-white font-bold">
                    ${escrow.amount} {escrow.currency}
                  </div>
                  <div
                    className={`px-3 py-1 rounded-full text-xs font-bold ${
                      escrow.status === "pending"
                        ? "bg-yellow-600 text-white"
                        : escrow.status === "completed"
                          ? "bg-green-600 text-white"
                          : "bg-red-600 text-white"
                    }`}
                  >
                    {escrow.status.toUpperCase()}
                  </div>
                </div>
              </div>
            ))}
            {escrows.length === 0 && <div className="text-center py-8 text-gray-400">No transactions found</div>}
          </div>
        </div>

        {confirmDelete && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-[#1a1a1a] border border-[#333] rounded-lg p-6 max-w-md mx-4">
              <div className="flex items-center gap-3 mb-4">
                <AlertTriangle className="h-6 w-6 text-red-500" />
                <h3 className="text-lg font-semibold text-white">Delete Listing</h3>
              </div>
              <p className="text-gray-400 mb-6">
                Are you sure you want to delete this listing? This action cannot be undone.
              </p>
              <div className="flex gap-3">
                <button
                  onClick={() => handleDelete(confirmDelete)}
                  className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
                >
                  Delete
                </button>
                <button
                  onClick={() => setConfirmDelete(null)}
                  className="flex-1 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
