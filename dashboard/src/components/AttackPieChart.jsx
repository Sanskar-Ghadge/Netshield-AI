/**
 * NetShield AI — Attack type pie chart component.
 *
 * Recharts donut chart showing the distribution of attack types.
 * Data is refreshed from the /api/stats endpoint every 30 seconds
 * (handled by DashboardContext).
 *
 * @module components/AttackPieChart
 */

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { useDashboard } from '../context/DashboardContext.jsx'
import { ATTACK_COLORS, FALLBACK_COLOR } from '../utils/constants.js'

/**
 * Custom tooltip for the pie chart.
 * Defined at module level to avoid re-creation on every render.
 *
 * @param {object} props - Tooltip props from recharts.
 * @param {number} props.total - Grand total for percentage calculation.
 */
function PieTooltip({ active, payload, total }) {
  if (!active || !payload || !payload.length) return null
  const item = payload[0].payload
  const pct = total > 0 ? ((item.value / total) * 100).toFixed(1) : 0
  return (
    <div style={{
      background: 'rgba(17,24,39,0.95)',
      border: '1px solid var(--border-default)',
      borderRadius: '8px',
      padding: '8px 12px',
      fontSize: '0.8rem',
    }}>
      <div style={{ color: item.color, fontWeight: 600 }}>{item.name}</div>
      <div style={{ color: 'var(--text-secondary)' }}>
        {item.value} attacks ({pct}%)
      </div>
    </div>
  )
}

export default function AttackPieChart() {
  const { attackDistribution, attackCount } = useDashboard()

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
          <span className="pie-center-value text-muted">No attacks</span>
          <span className="pie-center-label text-faint">All clear</span>
        </div>
      )
    }
    return (
      <div className="pie-center">
        <span className="pie-center-value" style={{ color: 'var(--accent-crimson)' }}>
          {total.toLocaleString('en-US')}
        </span>
        <span className="pie-center-label text-muted">Total attacks</span>
      </div>
    )
  }

  return (
    <div className="glass-card pie-card">
      <div className="chart-header">
        <span className="chart-title">Attack Distribution</span>
        <span className="chart-subtitle text-muted">By type</span>
      </div>
      <div className="pie-wrap">
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={90}
              paddingAngle={2}
              isAnimationActive={true}
            >
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.color} stroke="#0a0e1a" strokeWidth={1.5} />
              ))}
            </Pie>
            <Tooltip content={<PieTooltip total={total} />} />
          </PieChart>
        </ResponsiveContainer>
        {renderCenter()}
      </div>

      {/* Legend */}
      {data.length > 0 && (
        <div className="pie-legend">
          {data.map((item, i) => (
            <div key={i} className="legend-item">
              <span className="legend-dot" style={{ background: item.color }} />
              <span className="legend-label">{item.name}</span>
              <span className="legend-value mono">{item.value}</span>
            </div>
          ))}
        </div>
      )}

      <style>{`
        .pie-card {
          padding: 16px;
          display: flex;
          flex-direction: column;
        }
        .pie-wrap {
          position: relative;
          display: flex;
          align-items: center;
          justify-content: center;
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
          font-size: 1.4rem;
          font-weight: 700;
          display: block;
        }
        .pie-center-label {
          font-size: 0.7rem;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .pie-legend {
          display: flex;
          flex-wrap: wrap;
          gap: 6px 14px;
          margin-top: 8px;
          padding: 0 4px;
        }
        .legend-item {
          display: flex;
          align-items: center;
          gap: 5px;
          font-size: 0.75rem;
        }
        .legend-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          flex-shrink: 0;
        }
        .legend-label {
          color: var(--text-secondary);
        }
        .legend-value {
          color: var(--text-primary);
          font-weight: 500;
        }
      `}</style>
    </div>
  )
}
