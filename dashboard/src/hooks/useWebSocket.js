/**
 * useWebSocket — connects to the WhoApp WS bridge and distributes
 * incoming messages by channel to registered handlers.
 */
import { useEffect, useRef, useState, useCallback } from 'react'

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8765'
const RECONNECT_DELAY = 3000

export function useWebSocket(onMessage) {
  const [status, setStatus] = useState(navigator.onLine ? 'disconnected' : 'offline')
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)
  const onMessageRef = useRef(onMessage)
  
  useEffect(() => {
    onMessageRef.current = onMessage
  }, [onMessage])

  const connect = useCallback(() => {
    if (!navigator.onLine) {
      setStatus('offline')
      return
    }
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    try {
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws

      ws.onopen = () => {
        setStatus('connected')
        clearTimeout(reconnectTimer.current)
      }

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          onMessageRef.current?.(msg)
        } catch (_) {}
      }

      ws.onclose = () => {
        if (navigator.onLine) {
          setStatus('disconnected')
          reconnectTimer.current = setTimeout(connect, RECONNECT_DELAY)
        } else {
          setStatus('offline')
        }
      }

      ws.onerror = () => {
        ws.close()
      }
    } catch (e) {
      if (navigator.onLine) {
        setStatus('disconnected')
        reconnectTimer.current = setTimeout(connect, RECONNECT_DELAY)
      } else {
        setStatus('offline')
      }
    }
  }, [])

  useEffect(() => {
    connect()

    const handleOnline = () => {
      setStatus('disconnected') // will attempt to connect
      connect()
    }

    const handleOffline = () => {
      setStatus('offline')
      clearTimeout(reconnectTimer.current)
      if (wsRef.current) {
        wsRef.current.close()
      }
    }

    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)

    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [connect])

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
    }
  }, [])

  return { status, send }
}
