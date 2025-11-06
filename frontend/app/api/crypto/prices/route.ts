import { NextResponse } from "next/server"

// Map our currency codes to CoinGecko IDs
const CURRENCY_ID_MAP: Record<string, string> = {
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
  "USDT-ERC20": "tether",
  "USDT-BEP20": "tether",
  "USDT-SOL": "tether",
  "USDT-TRON": "tether",
}

export async function GET() {
  try {
    // Get unique coin IDs (remove duplicates like USDT variants)
    const coinIds = [...new Set(Object.values(CURRENCY_ID_MAP))].join(",")

    // Fetch prices from CoinGecko API (free, no API key required)
    const response = await fetch(
      `https://api.coingecko.com/api/v3/simple/price?ids=${coinIds}&vs_currencies=usd&include_24hr_change=true`,
      {
        next: { revalidate: 60 }, // Cache for 60 seconds
      },
    )

    if (!response.ok) {
      throw new Error("Failed to fetch prices from CoinGecko")
    }

    const data = await response.json()

    // Map the response back to our currency codes
    const prices: Record<string, { usd: number; change_24h: number }> = {}

    Object.entries(CURRENCY_ID_MAP).forEach(([currencyCode, coinId]) => {
      if (data[coinId]) {
        prices[currencyCode] = {
          usd: data[coinId].usd,
          change_24h: data[coinId].usd_24h_change || 0,
        }
      }
    })

    return NextResponse.json({
      success: true,
      prices,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error("Error fetching crypto prices:", error)
    return NextResponse.json(
      {
        success: false,
        error: "Failed to fetch cryptocurrency prices",
      },
      { status: 500 },
    )
  }
}