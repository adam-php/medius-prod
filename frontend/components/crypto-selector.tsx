"use client"

import { useMemo, useState } from "react"
import { Check, ChevronDown, Search } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"

const ALL_CRYPTOS: { value: string; label: string; symbol: string }[] = [
  { value: "BTC", label: "Bitcoin", symbol: "BTC" },
  { value: "ETH", label: "Ethereum", symbol: "ETH" },
  { value: "LTC", label: "Litecoin", symbol: "LTC" },
  { value: "BCH", label: "Bitcoin Cash", symbol: "BCH" },
  { value: "DOGE", label: "Dogecoin", symbol: "DOGE" },
  { value: "XRP", label: "XRP", symbol: "XRP" },
  { value: "ADA", label: "Cardano", symbol: "ADA" },
  { value: "DOT", label: "Polkadot", symbol: "DOT" },
  { value: "MATIC", label: "Polygon", symbol: "MATIC" },
  { value: "SOL", label: "Solana", symbol: "SOL" },
  { value: "AVAX", label: "Avalanche", symbol: "AVAX" },
  { value: "TRX", label: "TRON", symbol: "TRX" },
  { value: "BNB", label: "BNB", symbol: "BNB" },
  { value: "ATOM", label: "Cosmos", symbol: "ATOM" },
  { value: "XLM", label: "Stellar", symbol: "XLM" },
  { value: "USDT-ERC20", label: "Tether (ERC20)", symbol: "USDT" },
  { value: "USDT-BEP20", label: "Tether (BEP20)", symbol: "USDT" },
  { value: "USDT-SOL", label: "Tether (Solana)", symbol: "USDT" },
  { value: "USDT-TRON", label: "Tether (TRC20)", symbol: "USDT" },
]

interface CryptoSelectorProps {
  value?: string
  onValueChange?: (value: string) => void
  placeholder?: string
  className?: string
}

export function CryptoSelector({
  value,
  onValueChange,
  placeholder = "Select cryptocurrency...",
  className,
}: CryptoSelectorProps) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return ALL_CRYPTOS
    return ALL_CRYPTOS.filter(
      (c) =>
        c.label.toLowerCase().includes(q) || c.symbol.toLowerCase().includes(q) || c.value.toLowerCase().includes(q),
    )
  }, [query])

  const selectedCrypto = ALL_CRYPTOS.find((crypto) => crypto.value === value)

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          aria-haspopup="listbox"
          aria-label="Select cryptocurrency"
          className={cn(
            "w-full justify-between h-12 px-4 text-sm rounded-xl bg-black border border-white/10 text-white transition-all duration-200 hover:bg-black hover:border-white/20 focus:ring-2 focus:ring-orange-500 focus:border-transparent",
            className,
          )}
        >
          {selectedCrypto ? (
            <div className="flex items-center gap-2 animate-in fade-in-0 slide-in-from-left-1 duration-200">
              <span className="font-semibold text-white">{selectedCrypto.label}</span>
              <span className="text-gray-400 text-xs">({selectedCrypto.symbol})</span>
            </div>
          ) : (
            <span className="text-gray-500">{placeholder}</span>
          )}
          <ChevronDown
            className={cn(
              "ml-2 h-4 w-4 shrink-0 text-gray-400 transition-all duration-300 ease-in-out",
              open && "rotate-180 text-orange-400",
            )}
          />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className="w-[var(--radix-popover-trigger-width)] p-0 bg-black border border-white/20 rounded-xl shadow-2xl shadow-black/50"
        align="start"
        sideOffset={4}
      >
        <div className="bg-black rounded-xl overflow-hidden">
          {/* Search Input */}
          <div className="flex items-center gap-2 p-3 border-b border-white/10 bg-black sticky top-0 z-10">
            <Search className="h-4 w-4 text-gray-400" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search cryptocurrency..."
              className="bg-transparent text-white placeholder:text-gray-500 flex-1 focus:outline-none text-sm"
              aria-label="Search cryptocurrencies"
            />
          </div>

          {/* Options List */}
          <div
            className="max-h-72 overflow-y-auto bg-black [&::-webkit-scrollbar]:w-2 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-white/20 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb:hover]:bg-white/30"
            role="listbox"
          >
            {filtered.length === 0 ? (
              <div className="px-4 py-8 text-gray-400 text-sm text-center">No cryptocurrency found.</div>
            ) : (
              filtered.map((crypto) => {
                const isSelected = value === crypto.value
                return (
                  <button
                    key={crypto.value}
                    onClick={() => {
                      onValueChange?.(crypto.value)
                      setOpen(false)
                      setQuery("")
                    }}
                    className={cn(
                      "w-full text-left px-4 py-3 text-sm transition-all duration-150 flex items-center gap-3 group",
                      isSelected
                        ? "bg-orange-500/10 text-white border-l-2 border-orange-500"
                        : "text-gray-300 hover:bg-white/5 hover:text-white border-l-2 border-transparent",
                    )}
                    role="option"
                    aria-selected={isSelected}
                  >
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                      <span className={cn("font-medium truncate", isSelected && "text-white")}>
                        {crypto.label}
                      </span>
                      <span className={cn("text-xs flex-shrink-0", isSelected ? "text-orange-300" : "text-gray-400")}>
                        ({crypto.symbol})
                      </span>
                    </div>
                    <Check
                      className={cn(
                        "ml-auto h-4 w-4 flex-shrink-0 transition-all duration-200",
                        isSelected ? "opacity-100 text-orange-400 scale-100" : "opacity-0 scale-75",
                      )}
                    />
                  </button>
                )
              })
            )}
          </div>
        </div>
      </PopoverContent>
    </Popover>
  )
}