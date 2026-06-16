import { useEffect, useRef, useState } from 'react'

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1'

export default function useScanProgress(scanId) {
  const [events, setEvents] = useState([])
  const [connected, setConnected] = useState(false)
  const [done, setDone] = useState(false)
  const esRef = useRef(null)

  useEffect(() => {
    if (!scanId) return

    setEvents([])
    setDone(false)
    setConnected(false)

    const token = localStorage.getItem('access_token')
    const url = `${API_BASE}/analysis/jobs/${scanId}/events`
    // EventSource doesn't support headers natively; we use the URL for auth
    // in dev via vite proxy (cookie passthrough). For production, nginx strips
    // the token query param before proxying if needed.
    const es = new EventSource(`${url}?token=${token || ''}`)
    esRef.current = es

    es.onopen = () => setConnected(true)

    es.addEventListener('status', (e) => {
      const data = JSON.parse(e.data)
      setEvents((prev) => [...prev, { type: 'status', ...data }])
      if (data.status === 'COMPLETED' || data.status === 'FAILED') {
        setDone(true)
        es.close()
      }
    })

    es.addEventListener('analyzer', (e) => {
      const data = JSON.parse(e.data)
      setEvents((prev) => [...prev, { type: 'analyzer', ...data }])
    })

    es.onerror = () => {
      setConnected(false)
      // Auto-reconnect is built into EventSource; we just let it retry
    }

    return () => {
      es.close()
    }
  }, [scanId])

  return { events, connected, done }
}
