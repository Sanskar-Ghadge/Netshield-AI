/**
 * NetShield AI — Global dashboard state provider.
 *
 * Wraps the entire app in a React Context that holds all real-time state
 * and Socket.io event handlers. Components consume via `useDashboard()`.
 *
 * @module context/DashboardContext
 */

import { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react'
import { useSocket } from '../hooks/useSocket.js'
import { getStats, getStatus } from '../api/client.js'
import { STATS_REFRESH_INTERVAL } from '../utils/constants.js'

const DashboardContext = createContext(null)

/**
 * Hook to access the dashboard context.
 *
 * @returns {object} Dashboard state and actions.
 * @throws {Error} If used outside of DashboardProvider.
 */
export function useDashboard() {
  const ctx = useContext(DashboardContext)
  if (!ctx) throw new Error('useDashboard must be used within DashboardProvider')
  return ctx
}

/**
 * Provider component that manages all real-time dashboard state.
 *
 * @param {object} props
 * @param {import('react').ReactNode} props.children - Child components.
 * @returns {import('react').ReactElement}
 */
export function DashboardProvider({ children }) {
  const { socket, connected } = useSocket()

  // ── Status state ──────────────────────────────────────────
  const [threatLevel, setThreatLevel] = useState('SAFE')
  const [totalPackets, setTotalPackets] = useState(0)
  const [attackCount, setAttackCount] = useState(0)
  const [normalCount, setNormalCount] = useState(0)
  const [uptimeSeconds, setUptimeSeconds] = useState(0)
  const [captureActive, setCaptureActive] = useState(false)
  const [modelVersion, setModelVersion] = useState('')
  const [captureInterface, setCaptureInterface] = useState(null)

  // ── Stats state ───────────────────────────────────────────
  const [attackDistribution, setAttackDistribution] = useState([])
  const [topAttackers, setTopAttackers] = useState([])
  const [attackSummary, setAttackSummary] = useState([])

  // ── Recent data ───────────────────────────────────────────
  const [recentAttacks, setRecentAttacks] = useState([])
  const [lastAttack, setLastAttack] = useState(null)
  const [lastPacket, setLastPacket] = useState(null)

  // ── Packet buffer for feed ────────────────────────────────
  const packetBufferRef = useRef([])
  const [packets, setPackets] = useState([])
  const packetTimerRef = useRef(null)

  // ── Flush packet buffer to state at most 5x per second ────
  useEffect(() => {
    packetTimerRef.current = setInterval(() => {
      if (packetBufferRef.current.length > 0) {
        setPackets(prev => {
          const combined = [...packetBufferRef.current, ...prev]
          packetBufferRef.current = []
          return combined.slice(0, 50)
        })
      }
    }, 200)
    return () => clearInterval(packetTimerRef.current)
  }, [])

  // ── Socket event handlers ──────────────────────────────────
  useEffect(() => {
    if (!socket) return

    const onInitialState = (data) => {
      if (data.status) {
        setThreatLevel(data.status.threat_level || 'SAFE')
        setTotalPackets(data.status.total_packets || 0)
        setAttackCount(data.status.attack_count || 0)
        setNormalCount(data.status.normal_count || 0)
        setUptimeSeconds(data.status.uptime_seconds || 0)
        setCaptureActive(data.status.capture_active || false)
        setModelVersion(data.status.model_version || '')
        setCaptureInterface(data.status.capture_interface || null)
      }
      if (data.recentAttacks) {
        setRecentAttacks(data.recentAttacks)
      }
    }

    const onPacketData = (data) => {
      setTotalPackets(prev => prev + 1)
      if (data.is_attack) {
        setAttackCount(prev => prev + 1)
        setLastAttack(data)
      } else {
        setNormalCount(prev => prev + 1)
      }
      setLastPacket(data)
      packetBufferRef.current.push(data)
    }

    const onAttackAlert = (data) => {
      setLastAttack(data)
      setAttackCount(prev => prev + 1)
      setRecentAttacks(prev => [data, ...prev].slice(0, 100))
    }

    const onThreatUpdate = (data) => {
      if (data.threatLevel) setThreatLevel(data.threatLevel)
      if (data.total_packets !== undefined) setTotalPackets(data.total_packets)
      if (data.attack_count !== undefined) setAttackCount(data.attack_count)
    }

    socket.on('initial:state', onInitialState)
    socket.on('packet:data', onPacketData)
    socket.on('attack:alert', onAttackAlert)
    socket.on('threat:update', onThreatUpdate)

    return () => {
      socket.off('initial:state', onInitialState)
      socket.off('packet:data', onPacketData)
      socket.off('attack:alert', onAttackAlert)
      socket.off('threat:update', onThreatUpdate)
    }
  }, [socket])

  // ── Periodic stats + status refresh ───────────────────────
  const refreshStats = useCallback(async () => {
    try {
      const [stats, status] = await Promise.all([getStats(), getStatus()])
      setAttackDistribution(stats.attack_distribution || [])
      setTopAttackers(stats.top_attackers || [])
      setAttackSummary(stats.attack_summary || [])
      // Update status fields from REST as well (keeps uptime fresh even
      // when no Socket.io events are flowing)
      setThreatLevel(status.threat_level || 'SAFE')
      setTotalPackets(status.total_packets ?? 0)
      setAttackCount(status.attack_count ?? 0)
      setNormalCount(status.normal_count ?? 0)
      setUptimeSeconds(status.uptime_seconds ?? 0)
      setCaptureActive(status.capture_active ?? false)
      setModelVersion(status.model_version || '')
      setCaptureInterface(status.capture_interface || null)
    } catch {
      // Backend may be temporarily unavailable
    }
  }, [])

  useEffect(() => {
    refreshStats()
    const interval = setInterval(refreshStats, STATS_REFRESH_INTERVAL)
    return () => clearInterval(interval)
  }, [refreshStats])

  const value = {
    // Connection
    socketConnected: connected,

    // Status
    threatLevel,
    totalPackets,
    attackCount,
    normalCount,
    uptimeSeconds,
    captureActive,
    modelVersion,
    captureInterface,

    // Stats
    attackDistribution,
    topAttackers,
    attackSummary,

    // Recent data
    recentAttacks,
    lastAttack,
    lastPacket,
    packets,
    refreshStats,
  }

  return (
    <DashboardContext.Provider value={value}>
      {children}
    </DashboardContext.Provider>
  )
}
