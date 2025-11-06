"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { FaDiscord, FaTelegram, FaXTwitter } from "react-icons/fa6"

export default function Footer() {
  const pathname = usePathname()
  const isDashboard = pathname?.startsWith("/dashboard")

  return (
    <footer
      className={`mt-8 border-t border-white/10 bg-black md:bg-black/40 backdrop-blur-md md:backdrop-blur-md relative z-50 ${isDashboard ? "lg:ml-64" : ""}`}
    >
      <div
        className={`container mx-auto px-4 py-6 flex flex-col sm:flex-row items-center justify-between gap-4 ${isDashboard ? "lg:max-w-none lg:mx-0 lg:px-8" : ""}`}
      >
        <span className="text-xs sm:text-sm text-gray-400">© Medius 2025</span>
        <div className="flex items-center gap-4 text-gray-300">
          <Link
            href="https://discord.gg/"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Discord"
            className="hover:text-white transition-colors duration-200"
          >
            <FaDiscord className="w-5 h-5" />
          </Link>
          <Link
            href="https://t.me/"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Telegram"
            className="hover:text-white transition-colors duration-200"
          >
            <FaTelegram className="w-5 h-5" />
          </Link>
          <Link
            href="https://x.com/"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Twitter/X"
            className="hover:text-white transition-colors duration-200"
          >
            <FaXTwitter className="w-5 h-5" />
          </Link>
        </div>
      </div>
    </footer>
  )
}
