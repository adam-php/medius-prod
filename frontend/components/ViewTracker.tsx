"use client"

import { useEffect, useRef } from 'react'

interface ViewTrackerProps {
  listingId: string
  apiBase?: string
}

export default function ViewTracker({ listingId, apiBase }: ViewTrackerProps) {
  const hasTrackedRef = useRef(false)
  const apiUrl = apiBase || process.env.NEXT_PUBLIC_API_URL || ''

  useEffect(() => {
    // Only track once per component mount
    if (hasTrackedRef.current) return

    const trackView = async () => {
      try {
        // Get referrer from document
        const referrer = document.referrer

        // Generate session ID if not exists
        let sessionId = localStorage.getItem('analytics_session_id')
        if (!sessionId) {
          sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
          localStorage.setItem('analytics_session_id', sessionId)
        }

        const response = await fetch(`${apiUrl}/api/marketplace/${listingId}/track-view`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('supabase_token') || ''}`,
          },
          body: JSON.stringify({
            session_id: sessionId,
            referrer: referrer,
            event_type: 'view',
            event_data: {
              page: 'product_detail',
              user_agent: navigator.userAgent,
              timestamp: new Date().toISOString()
            }
          })
        })

        if (response.ok) {
          hasTrackedRef.current = true
          console.log(`✅ View tracked for listing ${listingId}`)
        } else {
          console.warn(`⚠️ Failed to track view: ${response.status}`)
        }
      } catch (error) {
        console.error('❌ Error tracking view:', error)
      }
    }

    // Small delay to ensure page has fully loaded
    const timer = setTimeout(trackView, 1000)

    return () => clearTimeout(timer)
  }, [listingId, apiUrl])

  // This component doesn't render anything
  return null
}
