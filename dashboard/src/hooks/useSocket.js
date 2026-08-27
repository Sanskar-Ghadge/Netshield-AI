/**
 * NetShield AI — Socket.io connection hook.
 *
 * Connects to the Node.js Socket.io server and exposes the socket instance
 * and connection status. Handles auto-reconnection natively via socket.io-client.
 *
 * Uses useState (not useRef) for the socket so that a re-render is triggered
 * immediately when the socket is created — before the `connect` event fires.
 * This ensures consumers (e.g. DashboardContext) can register their event
 * handlers before the server sends `initial:state`, preventing that event
 * from being silently dropped.
 *
 * @module hooks/useSocket
 */

import { useEffect, useState } from 'react'
import { io } from 'socket.io-client'
import { SOCKET_URL } from '../utils/constants.js'

/**
 * Establish a Socket.io connection to the Node.js backend.
 *
 * @returns {{ socket: import('socket.io-client').Socket | null, connected: boolean }}
 */
export function useSocket() {
  const [socket, setSocket] = useState(null)
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    const s = io(SOCKET_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 10000,
    })

    // Trigger a re-render immediately so consumers can register handlers
    // before the `connect` event fires and the server sends initial:state.
    setSocket(s)

    s.on('connect', () => setConnected(true))
    s.on('disconnect', () => setConnected(false))
    s.io.on('reconnect', () => setConnected(true))

    return () => {
      s.disconnect()
      setSocket(null)
      setConnected(false)
    }
  }, [])

  return { socket, connected }
}
