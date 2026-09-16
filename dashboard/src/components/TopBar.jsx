/**
 * NetShield AI — Top Command Control Bar Component.
 *
 * Header control bar displaying current breadcrumb workspace title, live threat level,
 * session reset button, live UTC clock, and AI Assistant trigger.
 *
 * @module components/TopBar
 */

import { useEffect, useState, useRef } from 'react'
import { useLocation } from 'react-router-dom'
import { RotateCcw, Bot, ShieldCheck, User, LogIn, LogOut, Key, Check, Copy, ChevronDown } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { useAuth } from '../context/AuthContext.jsx'
import AuthModal from './AuthModal.jsx'
import { THREAT_COLORS, THREAT_BG_COLORS } from '../utils/constants.js'

const BREADCRUMBS = {
  '/': { title: 'SOC Operations Dashboard', subtitle: 'Real-Time Network Intrusion Monitoring' },
  '/devices': { title: 'Paired Laptop Devices', subtitle: 'Manage Connected Laptops & Agent Installer' },
  '/analytics': { title: 'Security Analytics & Forensics', subtitle: 'Attack Distribution, Trends & Top Attackers' },
  '/history': { title: 'Attack Log History', subtitle: 'Paginated Audit Trail of Detected Threats' },
  '/reports': { title: 'Executive Security Reports', subtitle: 'Export & PDF Security Summary Generator' },
  '/status': { title: 'System Environment & Status', subtitle: 'Live Packet Capture Engine & ML Model Details' },
}

export default function TopBar({ onOpenChat }) {
  const { threatLevel, resetData } = useDashboard()
  const { user, isAuthenticated, logout } = useAuth()
  const location = useLocation()

  const [clock, setClock] = useState('')
  const [resetting, setResetting] = useState(false)
  const [authModalOpen, setAuthModalOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [copiedKey, setCopiedKey] = useState(false)

  const menuRef = useRef(null)

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

  // Close user dropdown on outside click
  useEffect(() => {
    const handler = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setUserMenuOpen(false)
      }
    }
    window.addEventListener('mousedown', handler)
    return () => window.removeEventListener('mousedown', handler)
  }, [])

  const handleReset = async () => {
    setResetting(true)
    await resetData()
    setResetting(false)
  }

  const handleCopyKey = () => {
    if (user?.apiKey) {
      navigator.clipboard.writeText(user.apiKey)
      setCopiedKey(true)
      setTimeout(() => setCopiedKey(false), 2500)
    }
  }

  const threatColor = THREAT_COLORS[threatLevel] || THREAT_COLORS.SAFE
  const threatBg = THREAT_BG_COLORS[threatLevel] || THREAT_BG_COLORS.SAFE

  return (
    <>
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

          {/* User Auth Control */}
          {isAuthenticated ? (
            <div className="user-profile-menu-container" ref={menuRef}>
              <button
                className="user-profile-btn"
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                title="Account Settings & API Key"
              >
                <div className="user-avatar">
                  {user.username.charAt(0).toUpperCase()}
                </div>
                <span className="user-name">{user.username}</span>
                <ChevronDown size={14} className={`menu-arrow ${userMenuOpen ? 'open' : ''}`} />
              </button>

              {userMenuOpen && (
                <div className="user-dropdown-menu">
                  <div className="user-dropdown-header">
                    <div className="dropdown-user-name">{user.username}</div>
                    <div className="dropdown-user-email">{user.email}</div>
                  </div>

                  <div className="dropdown-section">
                    <div className="dropdown-label">
                      <Key size={12} />
                      <span>Agent API Key</span>
                    </div>
                    <div className="dropdown-api-key-row">
                      <code className="dropdown-key-code">
                        {user.apiKey ? `${user.apiKey.slice(0, 14)}…` : 'No Key'}
                      </code>
                      <button className="dropdown-copy-btn" onClick={handleCopyKey} title="Copy Full API Key">
                        {copiedKey ? <Check size={12} /> : <Copy size={12} />}
                        <span>{copiedKey ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>

                  <div className="dropdown-divider" />

                  <button className="dropdown-item logout-item" onClick={logout}>
                    <LogOut size={14} />
                    <span>Log Out</span>
                  </button>
                </div>
              )}
            </div>
          ) : (
            <button className="auth-trigger-btn" onClick={() => setAuthModalOpen(true)}>
              <LogIn size={15} />
              <span>Sign In / Register</span>
            </button>
          )}
        </div>

        <style>{`
          .topbar {
            height: var(--header-height);
            background: rgba(10, 16, 32, 0.85);
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

          /* Auth trigger button */
          .auth-trigger-btn {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 6px 14px;
            border-radius: 10px;
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(0, 153, 255, 0.15));
            border: 1px solid rgba(0, 240, 255, 0.4);
            color: #ffffff;
            font-size: 0.8rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.25s;
          }
          .auth-trigger-btn:hover {
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.35), rgba(0, 153, 255, 0.25));
            box-shadow: 0 0 15px rgba(0, 240, 255, 0.3);
          }

          /* User profile menu */
          .user-profile-menu-container {
            position: relative;
          }
          .user-profile-btn {
            display: flex;
            align-items: center;
            gap: 8px;
            background: #1e293b;
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-radius: 10px;
            padding: 4px 10px 4px 6px;
            color: #f8fafc;
            font-size: 0.82rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
          }
          .user-profile-btn:hover {
            border-color: var(--accent-cyan);
            background: #273549;
          }
          .user-avatar {
            width: 26px;
            height: 26px;
            border-radius: 50%;
            background: linear-gradient(135deg, #00f0ff, #0099ff);
            color: #060913;
            font-weight: 800;
            font-size: 0.78rem;
            display: flex;
            align-items: center;
            justify-content: center;
          }
          .menu-arrow {
            color: #94a3b8;
            transition: transform 0.2s;
          }
          .menu-arrow.open {
            transform: rotate(180deg);
          }

          .user-dropdown-menu {
            position: absolute;
            right: 0;
            top: calc(100% + 8px);
            width: 240px;
            background: #090e1a;
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.8), 0 0 20px rgba(0, 240, 255, 0.1);
            padding: 8px;
            z-index: 200;
            animation: auth-fade 0.2s ease-out;
          }
          .user-dropdown-header {
            padding: 8px 10px 10px 10px;
            border-bottom: 1px solid rgba(56, 189, 248, 0.15);
          }
          .dropdown-user-name {
            font-weight: 700;
            font-size: 0.9rem;
            color: #f8fafc;
          }
          .dropdown-user-email {
            font-size: 0.72rem;
            color: #94a3b8;
            word-break: break-all;
          }

          .dropdown-section {
            padding: 10px 8px 6px 8px;
          }
          .dropdown-label {
            display: flex;
            align-items: center;
            gap: 4px;
            font-size: 0.68rem;
            font-weight: 700;
            color: var(--accent-cyan);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
          }
          .dropdown-api-key-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #0f172a;
            border: 1px solid rgba(56, 189, 248, 0.2);
            border-radius: 8px;
            padding: 4px 8px;
          }
          .dropdown-key-code {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            color: #cbd5e1;
          }
          .dropdown-copy-btn {
            background: #1e293b;
            border: none;
            border-radius: 4px;
            padding: 2px 6px;
            color: var(--accent-cyan);
            font-size: 0.65rem;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 3px;
          }
          .dropdown-copy-btn:hover {
            background: #334155;
          }

          .dropdown-divider {
            height: 1px;
            background: rgba(56, 189, 248, 0.15);
            margin: 6px 0;
          }

          .dropdown-item {
            width: 100%;
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 10px;
            background: transparent;
            border: none;
            border-radius: 6px;
            font-size: 0.82rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
          }
          .logout-item {
            color: #ff6b8b;
          }
          .logout-item:hover {
            background: rgba(255, 42, 95, 0.15);
          }

          @media (max-width: 768px) {
            .breadcrumb-subtitle { display: none; }
            .breadcrumb-title { font-size: 1rem; }
            .topbar-clock { display: none; }
          }
        `}</style>
      </header>

      <AuthModal isOpen={authModalOpen} onClose={() => setAuthModalOpen(false)} />
    </>
  )
}
