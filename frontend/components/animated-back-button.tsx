"use client"

import { useState } from "react"
import { ChevronLeft } from "lucide-react"

interface AnimatedBackButtonProps {
  onClick: () => void
  text?: string
  className?: string
}

export default function AnimatedBackButton({
  onClick,
  text = "Back to Dashboard",
  className = "",
}: AnimatedBackButtonProps) {
  const [isHovered, setIsHovered] = useState(false)

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={`group text-gray-400 hover:text-orange-400 transition-colors duration-300 flex items-center gap-2 mb-6 ${className}`}
    >
      <ChevronLeft
        className={`w-4 h-4 transition-transform duration-300 ease-out ${
          isHovered ? "transform -translate-x-1" : "transform translate-x-0"
        }`}
      />

      <span className="whitespace-nowrap">{text}</span>
    </button>
  )
}
