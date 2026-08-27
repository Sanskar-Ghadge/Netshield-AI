/**
 * NetShield AI — Live traffic chart component.
 *
 * Recharts area chart showing packets per second, split into normal (cyan)
 * and attack (crimson) stacked areas. Rolling 60-second window.
 *
 * @module components/LiveTrafficChart
 */

import { useEffect, useRef, useState } from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { useDashboard } from '../context/DashboardContext.jsx'
import { MAX_CHART_POINTS } from '../utils/constants.js'

/**
 * Format a Unix timestamp (seconds) to HH:MM for the X axis.
 *
 * @param {number} ts - Unix epoch in seconds.
 * @returns {string} Formatted time string.
 */
function formatXAxis(ts) {
  const d = new Date(ts * 1000)
  return d.toLocaleTimeString('en-GB', {
    minute: '2-digit',
    second: '2-digit',
    timeZone: 'UTC',
  })
}

/**
 * Custom tooltip for the live traffic chart.
 * Defined at module level to avoid re-creation on every render.
 */
function TrafficTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null
  return (
    <div style={{
      background: 'rgba(17,24,39,0.95)',
      border: '1px solid var(--border-default)',
      borderRadius: '8px',
      padding: '8px 12px',
      fontSize: '0.8rem',
    }}>
      <div style={{ color: 'var(--text-secondary)', marginBottom: 4 }}>
        {formatXAxis(label)}
      </div>
      <div style={{ color: 'var(--accent-cyan)' }}>
        Normal: {payload[0]?.value || 0}
      </div>
      <div style={{ color: 'var(--accent-crimson)' }}>
        Attack: {payload[1]?.value || 0}
      </div>
    </div>
  )
}

export default function LiveTrafficChart() {
  const { lastPacket } = useDashboard()
  const [chartData, setChartData] = useState(() => {
    // Initialize with zeros
    const now = Math.floor(Date.now() / 1000)
    return Array.from({ length: MAX_CHART_POINTS }, (_, i) => ({
      time: now - (MAX_CHART_POINTS - 1 - i),
      normal: 0,
      attack: 0,
    }))
  })
  const bufferRef = useRef({ normal: 0, attack: 0 })

  // Accumulate incoming packets into the buffer
  useEffect(() => {
    if (!lastPacket) return
    if (lastPacket.is_attack) {
      bufferRef.current.attack += 1
    } else {
      bufferRef.current.normal += 1
    }
  }, [lastPacket])

  // Every second, push the buffered counts to the chart
  useEffect(() => {
    const id = setInterval(() => {
      const now = Math.floor(Date.now() / 1000)
      setChartData(prev => {
        const next = [...prev.slice(1), {
          time: now,
          normal: bufferRef.current.normal,
          attack: bufferRef.current.attack,
        }]
        bufferRef.current = { normal: 0, attack: 0 }
        return next
      })
    }, 1000)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="glass-card chart-card">
      <div className="chart-header">
        <span className="chart-title">Live Traffic</span>
        <span className="chart-subtitle text-muted">Packets per second (rolling 60s)</span>
      </div>
      <ResponsiveContainer width="100%" height={240}>
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="normalGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#00f0ff" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="attackGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis
            dataKey="time"
            tickFormatter={formatXAxis}
            stroke="#475569"
            fontSize={11}
            interval="preserveStartEnd"
            tickCount={6}
          />
          <YAxis stroke="#475569" fontSize={11} allowDecimals={false} />
          <Tooltip content={<TrafficTooltip />} />
          <Area
            type="monotone"
            dataKey="normal"
            stroke="#00f0ff"
            strokeWidth={1.5}
            fill="url(#normalGrad)"
            name="Normal"
          />
          <Area
            type="monotone"
            dataKey="attack"
            stroke="#ef4444"
            strokeWidth={1.5}
            fill="url(#attackGrad)"
            name="Attack"
          />
        </AreaChart>
      </ResponsiveContainer>

      <style>{`
        .chart-card {
          padding: 16px;
          display: flex;
          flex-direction: column;
        }
        .chart-header {
          display: flex;
          align-items: baseline;
          gap: 10px;
          margin-bottom: 8px;
        }
        .chart-title {
          font-size: 0.9rem;
          font-weight: 600;
          color: var(--text-primary);
        }
        .chart-subtitle {
          font-size: 0.75rem;
        }
      `}</style>
    </div>
  )
}
