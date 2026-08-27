/**
 * NetShield AI — System info panel component.
 *
 * Shows capture interface, model version, uptime, and backend connection
 * status in a compact info card. Data comes from the DashboardContext
 * which is populated by the `initial:state` Socket.io event and the
 * periodic `/api/status` REST refresh.
 *
 * @module components/SystemInfo
 */

import { Cpu, Wifi, Clock, Shield } from 'lucide-react'
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
        <span className="chart-title">System Info</span>
      </div>
      <div className="info-rows">
        <InfoRow
          icon={<Wifi size={14} />}
          label="Connection"
          value={socketConnected ? 'Live' : 'Disconnected'}
          color={socketConnected ? 'var(--accent-green)' : 'var(--accent-crimson)'}
        />
        <InfoRow
          icon={<Shield size={14} />}
          label="Capture"
          value={captureActive ? `Active on ${captureInterface || 'default'}` : 'Inactive'}
          color={captureActive ? 'var(--accent-green)' : 'var(--text-tertiary)'}
        />
        <InfoRow
          icon={<Cpu size={14} />}
          label="Model"
          value={modelVersion || 'Not loaded'}
        />
        <InfoRow
          icon={<Clock size={14} />}
          label="Uptime"
          value={uptimeStr}
        />
      </div>

      <style>{`
        .system-info-card {
          padding: 16px;
          display: flex;
          flex-direction: column;
          gap: 12px;
        }
        .info-rows {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }
        @media (max-width: 767px) {
          .info-rows {
            flex-direction: row;
            flex-wrap: wrap;
          }
        }
      `}</style>
    </div>
  )
}

/**
 * One row in the system info panel.
 *
 * @param {object} props
 * @param {import('react').ReactElement} props.icon - Icon element.
 * @param {string} props.label - Label text.
 * @param {string} props.value - Value text.
 * @param {string} [props.color] - Optional colour for the value.
 */
function InfoRow({ icon, label, value, color }) {
  return (
    <div className="info-row">
      <span className="info-icon" style={{ color: color || 'var(--text-secondary)' }}>{icon}</span>
      <span className="info-label text-muted">{label}</span>
      <span className="info-value mono" style={{ color: color || 'var(--text-primary)' }}>{value}</span>
      <style>{`
        .info-row {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 6px 0;
          border-bottom: 1px solid rgba(30,41,59,0.5);
        }
        .info-icon {
          display: flex;
          align-items: center;
        }
        .info-label {
          font-size: 0.75rem;
          flex: 1;
        }
        .info-value {
          font-size: 0.75rem;
          text-align: right;
        }
      `}</style>
    </div>
  )
}

/**
 * Format seconds into a human-readable uptime string.
 *
 * @param {number} seconds - Uptime in seconds.
 * @returns {string} e.g. "1h 23m 45s".
 */
function formatUptime(seconds) {
  if (!seconds || seconds <= 0) return '—'
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  if (h > 0) return `${h}h ${m}m ${s}s`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}
