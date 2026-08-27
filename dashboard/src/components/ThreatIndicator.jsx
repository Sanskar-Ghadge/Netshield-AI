/**
 * NetShield AI — Threat indicator component.
 *
 * Large circular indicator showing the current threat level with
 * colour-coded glow and pulse animation.
 *
 * @module components/ThreatIndicator
 */

import { Shield, ShieldAlert, ShieldX } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { THREAT_COLORS } from '../utils/constants.js'

export default function ThreatIndicator() {
  const { threatLevel, attackCount } = useDashboard()
  const color = THREAT_COLORS[threatLevel] || THREAT_COLORS.SAFE

  const Icon =
    threatLevel === 'SAFE' ? Shield :
    threatLevel === 'ELEVATED' ? ShieldAlert :
    ShieldX

  const description =
    threatLevel === 'SAFE' ? 'No attacks in last 60s' :
    threatLevel === 'ELEVATED' ? `${attackCount} attack(s) in last 60s` :
    `${attackCount}+ attacks in last 60s — CRITICAL`

  const pulseClass =
    threatLevel === 'CRITICAL' ? 'pulse-critical' :
    threatLevel === 'ELEVATED' ? 'pulse-elevated' :
    ''

  return (
    <div className="glass-card threat-card">
      <div className="threat-header">
        <span className="threat-title">Threat Level</span>
      </div>
      <div className={`threat-circle-wrap ${pulseClass}`}>
        <div className="threat-circle" style={{ borderColor: color, boxShadow: `0 0 40px ${color}40` }}>
          <Icon size={42} style={{ color }} />
        </div>
        <span className="threat-label" style={{ color }}>{threatLevel}</span>
        <span className="threat-desc text-muted">{description}</span>
      </div>

      <style>{`
        .threat-card {
          padding: 20px;
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 12px;
          height: 100%;
          min-height: 280px;
          justify-content: center;
        }
        .threat-header {
          width: 100%;
          text-align: center;
        }
        .threat-title {
          font-size: 0.8rem;
          font-weight: 600;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        .threat-circle-wrap {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 14px;
          padding: 10px 0;
        }
        .threat-circle {
          width: 110px;
          height: 110px;
          border-radius: 50%;
          border: 3px solid;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.3s;
        }
        .threat-label {
          font-size: 1.5rem;
          font-weight: 700;
          letter-spacing: 1px;
        }
        .threat-desc {
          font-size: 0.8rem;
          text-align: center;
          max-width: 200px;
        }
        .pulse-critical .threat-circle {
          animation: pulse-glow 1.5s infinite;
        }
        .pulse-elevated .threat-circle {
          animation: pulse-amber 2s infinite;
        }
      `}</style>
    </div>
  )
}
