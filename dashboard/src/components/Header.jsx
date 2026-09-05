/**
 * NetShield AI — Header component.
 *
 * Top navigation bar with logo, live UTC clock, and compact threat badge.
 *
 * @module components/Header
 */

import { useEffect, useState } from 'react'
import { NavLink } from 'react-router-dom'
import { Shield, Activity, FileText, Home, RotateCcw } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { THREAT_COLORS, THREAT_BG_COLORS } from '../utils/constants.js'

export default function Header() {
  const { threatLevel, socketConnected, resetData } = useDashboard()
  const [clock, setClock] = useState('')
  const [resetting, setResetting] = useState(false)

  useEffect(() => {
    const update = () => {
      const d = new Date()
      setClock(d.toLocaleTimeString('en-GB', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZone: 'UTC',
      }) + ' UTC')
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
    <header className="header">
      <div className="header-left">
        <Shield size={24} style={{ color: 'var(--accent-cyan)' }} />
        <span className="header-logo">NetShield AI</span>
        {socketConnected ? (
          <span className="header-status online">
            <span className="status-dot pulse-dot" />
            LIVE
          </span>
        ) : (
          <span className="header-status offline">
            <span className="status-dot" style={{ background: 'var(--accent-crimson)' }} />
            OFFLINE
          </span>
        )}
      </div>

      <nav className="header-nav">
        <NavLink to="/" end className="nav-link">
          <Home size={16} /> Dashboard
        </NavLink>
        <NavLink to="/history" className="nav-link">
          <Activity size={16} /> History
        </NavLink>
        <NavLink to="/reports" className="nav-link">
          <FileText size={16} /> Reports
        </NavLink>
      </nav>

      <div className="header-right">
        <button
          className="reset-btn"
          onClick={handleReset}
          disabled={resetting}
          title="Reset all packet counters and attack logs to 0"
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
        <span className="header-clock mono">{clock}</span>
      </div>

      <style>{`
        .header {
          height: var(--header-height);
          background: var(--bg-secondary);
          border-bottom: 1px solid var(--border-default);
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 20px;
          position: sticky;
          top: 0;
          z-index: 100;
          box-shadow: 0 2px 12px rgba(0,0,0,0.2);
        }
        .header-left {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .header-logo {
          font-weight: 700;
          font-size: 1.15rem;
          color: var(--accent-cyan);
          letter-spacing: 0.5px;
        }
        .header-status {
          display: flex;
          align-items: center;
          gap: 5px;
          font-size: 0.7rem;
          font-weight: 600;
          padding: 2px 8px;
          border-radius: 12px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .header-status.online {
          color: var(--accent-green);
          background: rgba(34,197,94,0.1);
        }
        .header-status.offline {
          color: var(--accent-crimson);
          background: rgba(239,68,68,0.1);
        }
        .status-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          display: inline-block;
        }
        .pulse-dot {
          background: var(--accent-green);
          animation: pulse-dot 2s infinite;
        }
        @keyframes pulse-dot {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
        .header-nav {
          display: flex;
          gap: 4px;
        }
        .nav-link {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 6px 14px;
          border-radius: 8px;
          color: var(--text-secondary);
          text-decoration: none;
          font-size: 0.85rem;
          font-weight: 500;
          transition: all 0.2s;
        }
        .nav-link:hover {
          background: var(--bg-hover);
          color: var(--text-primary);
        }
        .nav-link.active {
          background: rgba(0,240,255,0.1);
          color: var(--accent-cyan);
        }
        .header-right {
          display: flex;
          align-items: center;
          gap: 14px;
        }
        .reset-btn {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 5px 12px;
          border-radius: 8px;
          background: rgba(255,255,255,0.05);
          border: 1px solid var(--border-default);
          color: var(--text-secondary);
          font-size: 0.78rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s;
        }
        .reset-btn:hover {
          background: rgba(239,68,68,0.15);
          color: #ef4444;
          border-color: rgba(239,68,68,0.4);
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
          gap: 6px;
          padding: 4px 12px;
          border-radius: 12px;
          font-weight: 600;
          font-size: 0.8rem;
          border: 1px solid;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .header-clock {
          font-size: 0.85rem;
          color: var(--text-secondary);
        }
        @media (max-width: 768px) {
          .header-nav { display: none; }
          .header-logo { font-size: 1rem; }
          .header-clock { font-size: 0.75rem; }
        }
      `}</style>
    </header>
  )
}
