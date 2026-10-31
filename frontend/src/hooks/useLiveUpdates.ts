import { useEffect, useRef, useState } from 'react'

export type ConnectionStatus = 'live' | 'polling' | 'offline'

interface LiveUpdatesOptions {
  onEvent?: (eventType: string, data: Record<string, unknown>) => void
  pollIntervalMs?: number
  enabled?: boolean
}

/**
 * useLiveUpdates hook:
 * Connects to SSE /api/stream with automatic fallback to polling.
 * Displays "live" when SSE is active, "polling" when falling back.
 */
export function useLiveUpdates({
  onEvent,
  pollIntervalMs = 5000,
  enabled = true,
}: LiveUpdatesOptions = {}) {
  const [status, setStatus] = useState<ConnectionStatus>('polling')
  const [lastTick, setLastTick] = useState<number>(Date.now())
  const eventSourceRef = useRef<EventSource | null>(null)
  const pollTimerRef = useRef<number | null>(null)

  useEffect(() => {
    if (!enabled) return

    let isMounted = true

    const startPolling = () => {
      if (pollTimerRef.current) return
      setStatus('polling')
      pollTimerRef.current = window.setInterval(() => {
        if (!isMounted) return
        setLastTick(Date.now())
        onEvent?.('poll', { timestamp: Date.now() })
      }, pollIntervalMs)
    }

    const stopPolling = () => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current)
        pollTimerRef.current = null
      }
    }

    try {
      const es = new EventSource('/api/stream')
      eventSourceRef.current = es

      es.onopen = () => {
        if (!isMounted) return
        setStatus('live')
        stopPolling()
      }

      es.onerror = () => {
        if (!isMounted) return
        setStatus('polling')
        es.close()
        startPolling()
      }

      const handleEvent = (event: MessageEvent) => {
        if (!isMounted) return
        try {
          const parsed = JSON.parse(event.data)
          setLastTick(Date.now())
          onEvent?.(event.type, parsed)
        } catch {
          // ignore heartbeat or parse errors
        }
      }

      es.addEventListener('incident_created', handleEvent)
      es.addEventListener('incident_updated', handleEvent)
      es.addEventListener('response_updated', handleEvent)
      es.addEventListener('audit_appended', handleEvent)
    } catch {
      startPolling()
    }

    return () => {
      isMounted = false
      if (eventSourceRef.current) {
        eventSourceRef.current.close()
      }
      stopPolling()
    }
  }, [enabled, pollIntervalMs, onEvent])

  return { status, lastTick }
}

