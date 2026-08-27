/**
 * NetShield AI — Stats cards component.
 *
 * Four glassmorphic metric cards showing total packets, attacks detected,
 * threat level, and model accuracy. Values animate from old to new.
 *
 * @module components/StatsCards
 */

import { useEffect, useRef, useState } from 'react'
import { Activity, AlertTriangle, Shield, Cpu } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { THREAT_COLORS, MODEL_ACCURACY } from '../utils/constants.js'
import { formatNumber } from '../utils/format.js'

/**
 * Animate a number from its previous value to a new value over 500ms.
 *
 * @param {number} target - The new target value.
 * @returns {number} The current animated value.
 */
function useCountUp(target) {
  const [display, setDisplay] = useState(target)
  const prevRef = useRef(target)
  const rafRef = useRef(null)

  useEffect(() => {
    const start = prevRef.current
    const end = target
    if (start === end) return

    const duration = 500
    const startTime = performance.now()

    const tick = (now) => {
      const elapsed = now - startTime
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(start + (end - start) * eased))
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick)
      } else {
        prevRef.current = end
      }
    }

    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [target])

  return display
}

function StatCard({ icon, label, value, color, sublabel }) {
  return (
    <div className="glass-card stat-card">
      <div className="stat-card-top">
        <span className="stat-icon" style={{ color }}>{icon}</span>
        <span className="stat-label">{label}</span>
      </div>
      <div className="stat-value mono" style={{ color }}>{value}</div>
      {sublabel && <div className="stat-sublabel text-faint">{sublabel}</div>}
    </div>
  )
}

export default function StatsCards() {
  const { totalPackets, attackCount, threatLevel } = useDashboard()

  const animatedTotal = useCountUp(totalPackets)
  const animatedAttacks = useCountUp(attackCount)

  const threatColor = THREAT_COLORS[threatLevel] || THREAT_COLORS.SAFE

  return (
    <>
      <div className="stats-row">
        <StatCard
          icon={<Activity size={20} />}
          label="Total Packets"
          value={formatNumber(animatedTotal)}
          color="var(--accent-cyan)"
          sublabel="Analysed"
        />
        <StatCard
          icon={<AlertTriangle size={20} />}
          label="Attacks Detected"
          value={formatNumber(animatedAttacks)}
          color="var(--accent-crimson)"
          sublabel="Flagged as malicious"
        />
        <StatCard
          icon={<Shield size={20} />}
          label="Threat Level"
          value={threatLevel}
          color={threatColor}
          sublabel="Last 60 seconds"
        />
        <StatCard
          icon={<Cpu size={20} />}
          label="Model Accuracy"
          value={MODEL_ACCURACY}
          color="var(--accent-green)"
          sublabel="XGBoost v3"
        />
      </div>

      <style>{`
        .stats-row {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 16px;
          margin-bottom: 20px;
        }
        .stat-card {
          padding: 18px 20px;
          display: flex;
          flex-direction: column;
          gap: 8px;
          transition: border-color 0.3s;
        }
        .stat-card:hover {
          border-color: var(--border-glow);
        }
        .stat-card-top {
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .stat-icon {
          display: flex;
          align-items: center;
        }
        .stat-label {
          font-size: 0.75rem;
          font-weight: 500;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .stat-value {
          font-size: 1.8rem;
          font-weight: 600;
          line-height: 1.1;
        }
        .stat-sublabel {
          font-size: 0.7rem;
        }
        @media (max-width: 767px) {
          .stats-row {
            grid-template-columns: 1fr 1fr;
          }
          .stat-value {
            font-size: 1.4rem;
          }
        }
      `}</style>
    </>
  )
}
