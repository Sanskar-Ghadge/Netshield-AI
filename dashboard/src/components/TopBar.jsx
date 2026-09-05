/**
 * NetShield AI — Top Command Control Bar Component.
 *
 * Header control bar displaying current breadcrumb workspace title, live threat level,
 * session reset button, live UTC clock, and AI Assistant trigger.
 *
 * @module components/TopBar
 */

import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { RotateCcw, Bot, ShieldCheck, Search } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { THREAT_COLORS, THREAT_BG_COLORS } from '../utils/constants.js'

const BREADCRUMBS = {
  '/': { title: 'SOC Operations Dashboard', subtitle: 'Real-Time Network Intrusion Monitoring' },
  '/analytics': { title: 'Security Analytics & Forensics', subtitle: 'Attack Distribution, Trends & Top Attackers' },
  '/history': { title: 'Attack Log History', subtitle: 'Paginated Audit Trail of Detected Threats' },
  '/reports': { title: 'Executive Security Reports', subtitle: 'Export & PDF Security Summary Generator' },
  '/status': { title: 'System Environment & Status', subtitle: 'Live Packet Capture Engine & ML Model Details' },
}

export default function TopBar({ onOpenChat }) {
  const { threatLevel, resetData } = useDashboard()
  const location = useLocation()
  const [clock, setClock] = useState('')
  const [resetting, setResetting] = useState(false)

  const currentMeta = BREADCRUMBS[location.pathname] || {
    title: 'SOC Operations',
    subtitle: 'Security Workspace',
  }

  useEffect(() => {
    const update = () => {
      const d = new Date()
      setClock(
        d.toLocaleTimeString('en-GB', {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          timeZone: 'UTC',
        }) + ' UTC'
      )
    }
    update()
    const id = setInterval(update, 1000)
    return () => clearInterval(id)
  }, [])

  const handleReset = async () => {
    setResetting(true)
    await resetData()
    setResetting(false)
  }

  const threatColor = THREAT_COLORS[threatLevel] || THREAT_COLORS.SAFE
  const threatBg = THREAT_BG_COLORS[threatLevel] || THREAT_BG_COLORS.SAFE

  return (
    <header className="topbar">
      {/* Workspace Breadcrumb */}
      <div className="topbar-breadcrumb">
        <h1 className="breadcrumb-title">{currentMeta.title}</h1>
        <span className="breadcrumb-subtitle text-muted">{currentMeta.subtitle}</span>
      </div>

      {/* Control Actions */}
      <div className="topbar-actions">
        <button
          className="ai-trigger-btn"
          onClick={onOpenChat}
          title="Open Gemini AI Assistant (Ctrl+K)"
        >
          <Bot size={15} className="text-cyan" />
          <span>Ask Assistant</span>
        </button>

        <button
          className="reset-btn"
          onClick={handleReset}
          disabled={resetting}
          title="Reset packet counters and attack logs to 0"
        >
          <RotateCcw size={14} className={resetting ? 'spin' : ''} />
          {resetting ? 'Resetting…' : 'Reset Session'}
        </button>

        <div
          className="threat-badge"
          style={{ color: threatColor, background: threatBg, borderColor: threatColor }}
        >
          <span className="status-dot" style={{ background: threatColor }} />
          {threatLevel}
        </div>

        <span className="topbar-clock mono">{clock}</span>
      </div>

      <style>{`
        .topbar {
          height: var(--header-height);
          background: rgba(10, 16, 32, 0.7);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          border-bottom: 1px solid var(--border-default);
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 24px;
          position: sticky;
          top: 0;
          z-index: 100;
        }
        .topbar-breadcrumb {
          display: flex;
          flex-direction: column;
        }
        .breadcrumb-title {
          font-family: var(--font-heading);
          font-weight: 800;
          font-size: 1.15rem;
          color: var(--text-primary);
          line-height: 1.1;
        }
        .breadcrumb-subtitle {
          font-size: 0.72rem;
          margin-top: 2px;
        }
        .topbar-actions {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .ai-trigger-btn {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 6px 14px;
          border-radius: 10px;
          background: rgba(0, 240, 255, 0.1);
          border: 1px solid rgba(0, 240, 255, 0.25);
          color: var(--accent-cyan);
          font-size: 0.8rem;
          font-weight: 700;
          cursor: pointer;
          transition: all 0.25s;
        }
        .ai-trigger-btn:hover {
          background: rgba(0, 240, 255, 0.2);
          box-shadow: 0 0 15px rgba(0, 240, 255, 0.25);
        }
        .reset-btn {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 6px 14px;
          border-radius: 10px;
          background: rgba(30, 41, 59, 0.6);
          border: 1px solid rgba(255, 255, 255, 0.08);
          color: var(--text-secondary);
          font-size: 0.78rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.25s;
        }
        .reset-btn:hover {
          background: rgba(255, 42, 95, 0.15);
          color: #ff2a5f;
          border-color: rgba(255, 42, 95, 0.4);
        }
        .spin {
          animation: spin 1s linear infinite;
        }
        @keyframes spin {
          100% { transform: rotate(360deg); }
        }
        .threat-badge {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 5px 14px;
          border-radius: 10px;
          font-family: var(--font-heading);
          font-weight: 700;
          font-size: 0.8rem;
          border: 1px solid;
          text-transform: uppercase;
          letter-spacing: 0.8px;
        }
        .topbar-clock {
          font-size: 0.82rem;
          color: var(--text-secondary);
          background: rgba(15, 23, 42, 0.6);
          padding: 5px 12px;
          border-radius: 8px;
          border: 1px solid rgba(255, 255, 255, 0.05);
        }
        @media (max-width: 768px) {
          .breadcrumb-subtitle { display: none; }
          .breadcrumb-title { font-size: 1rem; }
          .topbar-clock { display: none; }
        }
      `}</style>
    </header>
  )
}
