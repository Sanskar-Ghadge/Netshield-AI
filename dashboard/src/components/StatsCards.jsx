/**
 * NetShield AI — Stats cards component.
 *
 * Four glassmorphic metric cards showing total packets, attacks detected,
 * threat level, and model accuracy with top light accents and glow effects.
 *
 * @module components/StatsCards
 */

import { useEffect, useRef, useState } from 'react'
import { Activity, AlertTriangle, ShieldCheck, Cpu } from 'lucide-react'
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

function StatCard({ icon, label, value, color, sublabel, accentGradient }) {
  return (
    <div className="glass-card stat-card">
      <div className="stat-accent-bar" style={{ background: accentGradient || color }} />
      <div className="stat-card-inner">
        <div className="stat-card-top">
          <div className="stat-icon-wrap" style={{ color, background: `${color}18`, borderColor: `${color}40` }}>
            {icon}
          </div>
          <span className="stat-label">{label}</span>
        </div>
        <div className="stat-value mono" style={{ color }}>{value}</div>
        {sublabel && <div className="stat-sublabel text-muted">{sublabel}</div>}
      </div>
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
          icon={<Activity size={22} />}
          label="Total Packets"
          value={formatNumber(animatedTotal)}
          color="var(--accent-cyan)"
          accentGradient="linear-gradient(90deg, #00f0ff, transparent)"
          sublabel="Real-time analysed"
        />
        <StatCard
          icon={<AlertTriangle size={22} />}
          label="Attacks Detected"
          value={formatNumber(animatedAttacks)}
          color="var(--accent-crimson)"
          accentGradient="linear-gradient(90deg, #ff2a5f, transparent)"
          sublabel="Flagged malicious"
        />
        <StatCard
          icon={<ShieldCheck size={22} />}
          label="Threat Level"
          value={threatLevel}
          color={threatColor}
          accentGradient={`linear-gradient(90deg, ${threatColor}, transparent)`}
          sublabel="Last 60 seconds status"
        />
        <StatCard
          icon={<Cpu size={22} />}
          label="Model Accuracy"
          value={MODEL_ACCURACY}
          color="var(--accent-green)"
          accentGradient="linear-gradient(90deg, #10b981, transparent)"
          sublabel="XGBoost v3 Engine"
        />
      </div>

      <style>{`
        .stats-row {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 20px;
          margin-bottom: 24px;
        }
        .stat-card {
          border-radius: var(--radius-md);
          display: flex;
          flex-direction: column;
          position: relative;
        }
        .stat-accent-bar {
          height: 3px;
          width: 100%;
          position: absolute;
          top: 0;
          left: 0;
        }
        .stat-card-inner {
          padding: 20px 22px;
          display: flex;
          flex-direction: column;
          gap: 10px;
        }
        .stat-card-top {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .stat-icon-wrap {
          display: flex;
          align-items: center;
          justify-content: center;
          width: 36px;
          height: 36px;
          border-radius: 10px;
          border: 1px solid;
          box-shadow: 0 0 12px rgba(0,0,0,0.2);
        }
        .stat-label {
          font-family: var(--font-heading);
          font-size: 0.8rem;
          font-weight: 700;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.8px;
        }
        .stat-value {
          font-family: var(--font-heading);
          font-size: 2rem;
          font-weight: 800;
          line-height: 1.1;
          letter-spacing: -0.02em;
        }
        .stat-sublabel {
          font-size: 0.73rem;
        }
        @media (max-width: 1024px) {
          .stats-row {
            grid-template-columns: repeat(2, 1fr);
          }
        }
        @media (max-width: 600px) {
          .stats-row {
            grid-template-columns: 1fr;
          }
          .stat-value {
            font-size: 1.6rem;
          }
        }
      `}</style>
    </>
  )
}
