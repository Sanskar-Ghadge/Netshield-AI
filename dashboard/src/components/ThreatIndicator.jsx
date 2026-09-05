/**
 * NetShield AI — Cyber Threat Radar component.
 *
 * Futuristic circular radar gauge displaying live system threat level,
 * status description, and real-time pulse glow.
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
    threatLevel === 'SAFE' ? 'Zero malicious flows detected in last 60s' :
    threatLevel === 'ELEVATED' ? `${attackCount} attack flow(s) flagged in last 60s` :
    `HIGH ALERT: ${attackCount}+ attacks in last 60s`

  const pulseClass =
    threatLevel === 'CRITICAL' ? 'pulse-critical-radar' :
    threatLevel === 'ELEVATED' ? 'pulse-amber-radar' :
    'pulse-safe-radar'

  return (
    <div className="glass-card threat-card">
      <div className="threat-header">
        <span className="threat-title">System Threat Status</span>
      </div>

      <div className={`threat-circle-wrap ${pulseClass}`}>
        <div className="radar-outer-ring" style={{ borderColor: `${color}30` }}>
          <div className="radar-inner-ring" style={{ borderColor: `${color}60` }} />
          <div
            className="threat-circle"
            style={{
              borderColor: color,
              background: `radial-gradient(circle, ${color}20 0%, transparent 75%)`,
              boxShadow: `0 0 35px ${color}50`,
            }}
          >
            <Icon size={46} style={{ color, filter: `drop-shadow(0 0 10px ${color})` }} />
          </div>
        </div>

        <span className="threat-label" style={{ color }}>{threatLevel}</span>
        <span className="threat-desc text-muted">{description}</span>
      </div>

      <style>{`
        .threat-card {
          padding: 22px;
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 12px;
          height: 100%;
          min-height: 310px;
          justify-content: center;
        }
        .threat-header {
          width: 100%;
          text-align: center;
        }
        .threat-title {
          font-family: var(--font-heading);
          font-size: 0.82rem;
          font-weight: 700;
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
        .radar-outer-ring {
          position: relative;
          width: 135px;
          height: 135px;
          border-radius: 50%;
          border: 1px dashed;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .radar-inner-ring {
          position: absolute;
          width: 115px;
          height: 115px;
          border-radius: 50%;
          border: 1px solid;
          opacity: 0.5;
        }
        .threat-circle {
          width: 95px;
          height: 95px;
          border-radius: 50%;
          border: 3px solid;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
          z-index: 2;
        }
        .threat-label {
          font-family: var(--font-heading);
          font-size: 1.6rem;
          font-weight: 800;
          letter-spacing: 1.5px;
          text-transform: uppercase;
        }
        .threat-desc {
          font-size: 0.8rem;
          text-align: center;
          max-width: 220px;
          line-height: 1.4;
        }
        .pulse-critical-radar .threat-circle {
          animation: pulse-glow 1.5s infinite;
        }
        .pulse-amber-radar .threat-circle {
          animation: pulse-amber 2s infinite;
        }
        .pulse-safe-radar .threat-circle {
          animation: pulse-safe 3s infinite;
        }
      `}</style>
    </div>
  )
}
