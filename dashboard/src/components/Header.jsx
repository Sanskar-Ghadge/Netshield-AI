/**
 * NetShield AI — CyberShield Header component.
 *
 * Top navigation bar with glowing logo, live status, UTC clock,
 * active threat badge, and navigation routes.
 *
 * @module components/Header
 */

import { useEffect, useState } from 'react'
import { NavLink } from 'react-router-dom'
import { Shield, Activity, FileText, LayoutDashboard, RotateCcw } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { THREAT_COLORS, THREAT_BG_COLORS } from '../utils/constants.js'

export default function Header() {
  const { threatLevel, socketConnected, resetData } = useDashboard()
  const [clock, setClock] = useState('')
  const [resetting, setResetting] = useState(false)

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
    <header className="header">
      <div className="header-left">
        <div className="logo-icon-wrap">
          <Shield size={26} className="logo-icon" />
        </div>
        <div className="logo-text-group">
          <span className="header-logo">NetShield<span className="logo-highlight">AI</span></span>
          <span className="header-version">v3.4 NIDS</span>
        </div>
        {socketConnected ? (
          <span className="header-status online">
            <span className="status-dot pulse-dot" />
            LIVE SOC
          </span>
        ) : (
          <span className="header-status offline">
            <span className="status-dot" style={{ background: 'var(--accent-crimson)' }} />
            DISCONNECTED
          </span>
        )}
      </div>

      <nav className="header-nav">
        <NavLink to="/" end className="nav-link">
          <LayoutDashboard size={15} /> Dashboard
        </NavLink>
        <NavLink to="/history" className="nav-link">
          <Activity size={15} /> Attack History
        </NavLink>
        <NavLink to="/reports" className="nav-link">
          <FileText size={15} /> Reports & Logs
        </NavLink>
      </nav>

      <div className="header-right">
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
        <span className="header-clock mono">{clock}</span>
      </div>

      <style>{`
        .header {
          height: var(--header-height);
          background: rgba(10, 15, 29, 0.85);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border-bottom: 1px solid var(--border-default);
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 24px;
          position: sticky;
          top: 0;
          z-index: 100;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        }
        .header-left {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .logo-icon-wrap {
          display: flex;
          align-items: center;
          justify-content: center;
          width: 38px;
          height: 38px;
          border-radius: 10px;
          background: rgba(0, 240, 255, 0.1);
          border: 1px solid rgba(0, 240, 255, 0.3);
          box-shadow: 0 0 15px rgba(0, 240, 255, 0.2);
        }
        .logo-icon {
          color: var(--accent-cyan);
          filter: drop-shadow(0 0 8px rgba(0, 240, 255, 0.6));
        }
        .logo-text-group {
          display: flex;
          flex-direction: column;
        }
        .header-logo {
          font-family: var(--font-heading);
          font-weight: 800;
          font-size: 1.25rem;
          color: var(--text-primary);
          letter-spacing: -0.01em;
          line-height: 1;
        }
        .logo-highlight {
          background: linear-gradient(135deg, #00f0ff, #38bdf8);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          margin-left: 2px;
        }
        .header-version {
          font-size: 0.65rem;
          font-family: var(--font-mono);
          color: var(--accent-cyan);
          letter-spacing: 0.5px;
          opacity: 0.8;
        }
        .header-status {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 0.68rem;
          font-weight: 700;
          padding: 3px 10px;
          border-radius: 20px;
          text-transform: uppercase;
          letter-spacing: 0.8px;
          border: 1px solid;
          margin-left: 6px;
        }
        .header-status.online {
          color: var(--accent-green);
          background: rgba(16, 185, 129, 0.12);
          border-color: rgba(16, 185, 129, 0.3);
        }
        .header-status.offline {
          color: var(--accent-crimson);
          background: rgba(255, 42, 95, 0.12);
          border-color: rgba(255, 42, 95, 0.3);
        }
        .status-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          display: inline-block;
        }
        .pulse-dot {
          background: var(--accent-green);
          box-shadow: 0 0 10px var(--accent-green);
          animation: pulse-dot-glow 2s infinite;
        }
        @keyframes pulse-dot-glow {
          0%, 100% { transform: scale(1); opacity: 1; }
          50% { transform: scale(1.4); opacity: 0.5; }
        }
        .header-nav {
          display: flex;
          align-items: center;
          gap: 6px;
          background: rgba(15, 23, 42, 0.6);
          padding: 4px;
          border-radius: 12px;
          border: 1px solid rgba(56, 189, 248, 0.1);
        }
        .nav-link {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 7px 16px;
          border-radius: 9px;
          color: var(--text-secondary);
          text-decoration: none;
          font-size: 0.83rem;
          font-weight: 600;
          transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .nav-link:hover {
          color: var(--text-primary);
          background: rgba(255, 255, 255, 0.05);
        }
        .nav-link.active {
          background: linear-gradient(135deg, rgba(0, 240, 255, 0.15), rgba(56, 189, 248, 0.08));
          color: var(--accent-cyan);
          border: 1px solid rgba(0, 240, 255, 0.3);
          box-shadow: 0 0 12px rgba(0, 240, 255, 0.15);
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
          padding: 6px 14px;
          border-radius: 10px;
          background: rgba(30, 41, 59, 0.6);
          border: 1px solid rgba(255, 255, 255, 0.1);
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
          box-shadow: 0 0 15px rgba(255, 42, 95, 0.2);
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
          box-shadow: 0 0 15px rgba(0, 0, 0, 0.2);
        }
        .header-clock {
          font-size: 0.82rem;
          color: var(--text-secondary);
          background: rgba(15, 23, 42, 0.6);
          padding: 5px 12px;
          border-radius: 8px;
          border: 1px solid rgba(255, 255, 255, 0.05);
        }
        @media (max-width: 900px) {
          .header-nav { display: none; }
          .header-logo { font-size: 1.1rem; }
          .header-clock { display: none; }
        }
      `}</style>
    </header>
  )
}
