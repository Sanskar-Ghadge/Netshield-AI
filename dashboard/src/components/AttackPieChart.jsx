/**
 * NetShield AI — Attack distribution pie chart component.
 *
 * Donut chart showing the percentage breakdown of detected attack types.
 *
 * @module components/AttackPieChart
 */

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { PieChart as PieIcon } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { ATTACK_COLORS, FALLBACK_COLOR } from '../utils/constants.js'

function PieTooltip({ active, payload, total }) {
  if (!active || !payload || !payload.length) return null
  const item = payload[0].payload
  const pct = total > 0 ? ((item.value / total) * 100).toFixed(1) : 0
  return (
    <div className="chart-tooltip-glass">
      <div style={{ color: item.color, fontWeight: 700, fontFamily: 'var(--font-heading)' }}>
        {item.name}
      </div>
      <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', marginTop: 2 }}>
        <strong className="mono" style={{ color: 'var(--text-primary)' }}>{item.value}</strong> attacks ({pct}%)
      </div>
    </div>
  )
}

export default function AttackPieChart() {
  const { attackDistribution } = useDashboard()

  const data = (attackDistribution || []).map(item => ({
    name: item.attack_type,
    value: item.count,
    color: ATTACK_COLORS[item.attack_type] || FALLBACK_COLOR,
  }))

  const total = data.reduce((sum, d) => sum + d.value, 0)

  const renderCenter = () => {
    if (total === 0) {
      return (
        <div className="pie-center">
          <span className="pie-center-value text-muted">0</span>
          <span className="pie-center-label text-faint">All Clear</span>
        </div>
      )
    }
    return (
      <div className="pie-center">
        <span className="pie-center-value" style={{ color: 'var(--accent-crimson)' }}>
          {total.toLocaleString('en-US')}
        </span>
        <span className="pie-center-label text-muted">Attacks</span>
      </div>
    )
  }

  return (
    <div className="glass-card pie-card">
      <div className="chart-header">
        <div className="chart-title-wrap">
          <PieIcon size={18} className="text-amber" />
          <span className="chart-title">Attack Distribution</span>
        </div>
        <span className="chart-subtitle text-muted">By category</span>
      </div>

      <div className="pie-wrap">
        <ResponsiveContainer width="100%" height={210}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={58}
              outerRadius={86}
              paddingAngle={3}
              isAnimationActive={true}
            >
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.color} stroke="#060913" strokeWidth={2} />
              ))}
            </Pie>
            <Tooltip content={<PieTooltip total={total} />} />
          </PieChart>
        </ResponsiveContainer>
        {renderCenter()}
      </div>

      {data.length > 0 && (
        <div className="pie-legend">
          {data.map((item, i) => (
            <div key={i} className="legend-item">
              <span className="legend-dot" style={{ background: item.color, boxShadow: `0 0 6px ${item.color}` }} />
              <span className="legend-label">{item.name}</span>
              <span className="legend-value mono">{item.value}</span>
            </div>
          ))}
        </div>
      )}

      <style>{`
        .pie-card {
          padding: 20px;
          display: flex;
          flex-direction: column;
          height: 425px;
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
        .pie-wrap {
          position: relative;
          display: flex;
          align-items: center;
          justify-content: center;
          margin-top: 6px;
        }
        .pie-center {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          text-align: center;
          pointer-events: none;
        }
        .pie-center-value {
          font-family: var(--font-heading);
          font-size: 1.6rem;
          font-weight: 800;
          display: block;
          line-height: 1;
        }
        .pie-center-label {
          font-size: 0.68rem;
          text-transform: uppercase;
          letter-spacing: 0.8px;
          margin-top: 2px;
        }
        .pie-legend {
          display: flex;
          flex-wrap: wrap;
          gap: 6px 14px;
          margin-top: auto;
          padding: 8px;
          background: rgba(15, 23, 42, 0.4);
          border-radius: var(--radius-sm);
          border: 1px solid rgba(255, 255, 255, 0.05);
        }
        .legend-item {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 0.74rem;
        }
        .legend-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          flex-shrink: 0;
        }
        .legend-label {
          color: var(--text-secondary);
        }
        .legend-value {
          color: var(--text-primary);
          font-weight: 600;
        }
      `}</style>
    </div>
  )
}
