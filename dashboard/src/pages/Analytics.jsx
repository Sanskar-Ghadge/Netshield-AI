/**
 * NetShield AI — Security Analytics Workspace Page.
 *
 * Dedicated analytics workspace featuring Attack Distribution, Top Attacker IPs,
 * and category breakdown metrics.
 *
 * @module pages/Analytics
 */

import AttackPieChart from '../components/AttackPieChart.jsx'
import AttackHistory from '../components/AttackHistory.jsx'
import { useDashboard } from '../context/DashboardContext.jsx'
import { ATTACK_COLORS, FALLBACK_COLOR } from '../utils/constants.js'

export default function Analytics() {
  const { attackDistribution, attackCount } = useDashboard()

  return (
    <div className="analytics-page flex-col gap-lg">
      <div className="dashboard-grid">
        <div className="grid-col-1">
          <AttackPieChart />
        </div>

        <div className="grid-col-span-2">
          <div className="glass-card analytics-summary-card">
            <div className="chart-header">
              <span className="chart-title">Attack Type Summary</span>
              <span className="chart-subtitle text-muted">Total events: {attackCount}</span>
            </div>

            <div className="type-breakdown-list">
              {(attackDistribution || []).length === 0 ? (
                <div className="text-muted text-center py-6">No attack distributions recorded yet.</div>
              ) : (
                attackDistribution.map((item, idx) => {
                  const color = ATTACK_COLORS[item.attack_type] || FALLBACK_COLOR
                  const pct = attackCount > 0 ? ((item.count / attackCount) * 100).toFixed(1) : 0
                  return (
                    <div key={idx} className="type-bar-row">
                      <div className="type-row-header">
                        <span className="type-name" style={{ color }}>{item.attack_type}</span>
                        <span className="type-count mono">{item.count} attacks ({pct}%)</span>
                      </div>
                      <div className="type-bar-bg">
                        <div
                          className="type-bar-fill"
                          style={{
                            width: `${pct}%`,
                            background: color,
                            boxShadow: `0 0 10px ${color}`,
                          }}
                        />
                      </div>
                    </div>
                  )
                })
              )}
            </div>
          </div>
        </div>
      </div>

      <AttackHistory showFilters />

      <style>{`
        .analytics-summary-card {
          padding: 20px;
          display: flex;
          flex-direction: column;
          height: 100%;
        }
        .type-breakdown-list {
          display: flex;
          flex-direction: column;
          gap: 14px;
          margin-top: 12px;
        }
        .type-bar-row {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }
        .type-row-header {
          display: flex;
          justify-content: space-between;
          font-size: 0.8rem;
          font-weight: 600;
        }
        .type-bar-bg {
          height: 8px;
          background: rgba(30, 41, 59, 0.6);
          border-radius: 4px;
          overflow: hidden;
        }
        .type-bar-fill {
          height: 100%;
          border-radius: 4px;
          transition: width 0.5s ease;
        }
      `}</style>
    </div>
  )
}
