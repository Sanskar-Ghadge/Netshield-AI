/**
 * NetShield AI — Live traffic telemetry chart.
 *
 * Recharts area chart showing packets per second, split into normal (cyan)
 * and attack (crimson) stacked areas over a rolling 60-second window.
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
import { Activity } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { MAX_CHART_POINTS } from '../utils/constants.js'

function formatXAxis(ts) {
  const d = new Date(ts * 1000)
  return d.toLocaleTimeString('en-GB', {
    minute: '2-digit',
    second: '2-digit',
    timeZone: 'UTC',
  })
}

function TrafficTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null
  return (
    <div className="chart-tooltip-glass">
      <div className="tooltip-time mono">
        {formatXAxis(label)}
      </div>
      <div className="tooltip-row text-cyan">
        <span className="tooltip-dot" style={{ background: 'var(--accent-cyan)' }} />
        Normal: <strong className="mono">{payload[0]?.value || 0}</strong> pkts/s
      </div>
      <div className="tooltip-row text-crimson">
        <span className="tooltip-dot" style={{ background: 'var(--accent-crimson)' }} />
        Attack: <strong className="mono">{payload[1]?.value || 0}</strong> pkts/s
      </div>
    </div>
  )
}

export default function LiveTrafficChart() {
  const { lastPacket } = useDashboard()
  const [chartData, setChartData] = useState(() => {
    const now = Math.floor(Date.now() / 1000)
    return Array.from({ length: MAX_CHART_POINTS }, (_, i) => ({
      time: now - (MAX_CHART_POINTS - 1 - i),
      normal: 0,
      attack: 0,
    }))
  })
  const bufferRef = useRef({ normal: 0, attack: 0 })

  useEffect(() => {
    if (!lastPacket) return
    if (lastPacket.is_attack) {
      bufferRef.current.attack += 1
    } else {
      bufferRef.current.normal += 1
    }
  }, [lastPacket])

  useEffect(() => {
    const id = setInterval(() => {
      const now = Math.floor(Date.now() / 1000)
      setChartData(prev => {
        const next = [
          ...prev.slice(1),
          {
            time: now,
            normal: bufferRef.current.normal,
            attack: bufferRef.current.attack,
          },
        ]
        bufferRef.current = { normal: 0, attack: 0 }
        return next
      })
    }, 1000)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="glass-card chart-card">
      <div className="chart-header">
        <div className="chart-title-wrap">
          <Activity size={18} className="text-cyan" />
          <span className="chart-title">Live Traffic Telemetry</span>
        </div>
        <span className="chart-subtitle text-muted">Packets per second (rolling 60s window)</span>
      </div>

      <ResponsiveContainer width="100%" height={245}>
        <AreaChart data={chartData} margin={{ top: 12, right: 12, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="normalGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.45} />
              <stop offset="95%" stopColor="#00f0ff" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="attackGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ff2a5f" stopOpacity={0.65} />
              <stop offset="95%" stopColor="#ff2a5f" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(56, 189, 248, 0.08)" />
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
            strokeWidth={2}
            fill="url(#normalGrad)"
            name="Normal"
          />
          <Area
            type="monotone"
            dataKey="attack"
            stroke="#ff2a5f"
            strokeWidth={2}
            fill="url(#attackGrad)"
            name="Attack"
          />
        </AreaChart>
      </ResponsiveContainer>

      <style>{`
        .chart-card {
          padding: 20px;
          display: flex;
          flex-direction: column;
        }
        .chart-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 12px;
        }
        .chart-title-wrap {
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .chart-title {
          font-family: var(--font-heading);
          font-size: 0.95rem;
          font-weight: 700;
          color: var(--text-primary);
        }
        .chart-subtitle {
          font-size: 0.75rem;
        }
        .chart-tooltip-glass {
          background: rgba(10, 16, 32, 0.92);
          backdrop-filter: blur(12px);
          border: 1px solid var(--border-hover);
          border-radius: var(--radius-sm);
          padding: 8px 12px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
          font-size: 0.78rem;
        }
        .tooltip-time {
          color: var(--text-secondary);
          margin-bottom: 4px;
          font-size: 0.72rem;
        }
        .tooltip-row {
          display: flex;
          align-items: center;
          gap: 6px;
          margin-top: 3px;
        }
        .tooltip-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
        }
      `}</style>
    </div>
  )
}
