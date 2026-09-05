/**
 * NetShield AI — System info panel component.
 *
 * Shows capture interface, model version, uptime, and backend connection.
 *
 * @module components/SystemInfo
 */

import { Cpu, Wifi, Clock, ShieldCheck, Terminal } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'

export default function SystemInfo() {
  const {
    captureActive,
    captureInterface,
    modelVersion,
    uptimeSeconds,
    socketConnected,
  } = useDashboard()

  const uptimeStr = formatUptime(uptimeSeconds)

  return (
    <div className="glass-card system-info-card">
      <div className="chart-header">
        <div className="chart-title-wrap">
          <Terminal size={18} className="text-cyan" />
          <span className="chart-title">System Status & Environment</span>
        </div>
      </div>
      <div className="info-grid">
        <InfoRow
          icon={<Wifi size={15} />}
          label="Socket Connection"
          value={socketConnected ? 'LIVE SOCKET' : 'DISCONNECTED'}
          color={socketConnected ? 'var(--accent-green)' : 'var(--accent-crimson)'}
        />
        <InfoRow
          icon={<ShieldCheck size={15} />}
          label="Capture Interface"
          value={captureActive ? `ACTIVE (${captureInterface || 'Wi-Fi'})` : 'INACTIVE'}
          color={captureActive ? 'var(--accent-green)' : 'var(--text-tertiary)'}
        />
        <InfoRow
          icon={<Cpu size={15} />}
          label="ML Engine Model"
          value={modelVersion || 'xgboost_cicids2017_v3.pkl'}
          color="var(--accent-cyan)"
        />
        <InfoRow
          icon={<Clock size={15} />}
          label="Engine Uptime"
          value={uptimeStr}
        />
      </div>

      <style>{`
        .system-info-card {
          padding: 20px;
          display: flex;
          flex-direction: column;
          gap: 14px;
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
        .info-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 16px;
        }
        @media (max-width: 900px) {
          .info-grid {
            grid-template-columns: repeat(2, 1fr);
          }
        }
        @media (max-width: 500px) {
          .info-grid {
            grid-template-columns: 1fr;
          }
        }
      `}</style>
    </div>
  )
}

function InfoRow({ icon, label, value, color }) {
  return (
    <div className="info-item">
      <div className="info-top">
        <span className="info-icon" style={{ color: color || 'var(--accent-cyan)' }}>{icon}</span>
        <span className="info-label text-muted">{label}</span>
      </div>
      <span className="info-value mono" style={{ color: color || 'var(--text-primary)' }}>{value}</span>
      <style>{`
        .info-item {
          background: rgba(15, 23, 42, 0.4);
          border: 1px solid rgba(255, 255, 255, 0.06);
          border-radius: var(--radius-sm);
          padding: 10px 14px;
          display: flex;
          flex-direction: column;
          gap: 6px;
        }
        .info-top {
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .info-icon {
          display: flex;
          align-items: center;
        }
        .info-label {
          font-size: 0.72rem;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .info-value {
          font-size: 0.82rem;
          font-weight: 600;
        }
      `}</style>
    </div>
  )
}

function formatUptime(seconds) {
  if (!seconds || seconds <= 0) return '—'
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  if (h > 0) return `${h}h ${m}m ${s}s`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}
