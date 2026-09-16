/**
 * NetShield AI — Laptop Agent Control Center Component.
 *
 * Interactive card that displays live agent connection status, hostname, local IP,
 * and provides web-triggered START/STOP real-time packet protection controls.
 *
 * @module components/AgentStatusCard
 */

import { useState, useEffect } from 'react'
import { Shield, ShieldAlert, Play, Square, Laptop, Wifi, Terminal, Copy, Check, Info, AlertTriangle } from 'lucide-react'
import { useAuth } from '../context/AuthContext.jsx'
import { io } from 'socket.io-client'
import { SOCKET_URL } from '../utils/constants.js'

export default function AgentStatusCard() {
  const { user, isAuthenticated } = useAuth()
  const [agent, setAgent] = useState(null)
  const [socket, setSocket] = useState(null)
  const [copiedCmd, setCopiedCmd] = useState(false)
  const [actionLoading, setActionLoading] = useState(false)

  // Connect Socket.io for Agent Control Relay
  useEffect(() => {
    const s = io(SOCKET_URL, { transports: ['websocket', 'polling'] })
    setSocket(s)

    // Listen for agent status updates
    s.on('agent:status_changed', (data) => {
      if (user?.apiKey && data?.apiKey === user.apiKey) {
        setAgent(data.agent)
        setActionLoading(false)
      }
    })

    // Query status on mount if logged in
    if (user?.apiKey) {
      s.emit('dashboard:query_agent_status', { apiKey: user.apiKey })
    }

    return () => s.disconnect()
  }, [user?.apiKey])

  const handleToggleSniffing = () => {
    if (!socket || !user?.apiKey) return

    const newAction = agent?.status === 'SNIFFING' ? 'STOP_SNIFFING' : 'START_SNIFFING'
    setActionLoading(true)

    socket.emit('dashboard:agent_control', {
      apiKey: user.apiKey,
      action: newAction,
    })

    // Timeout safety for loading indicator
    setTimeout(() => setActionLoading(false), 4000)
  }

  const agentCommand = `py agent/agent.py --key ${user?.apiKey || 'YOUR_API_KEY'}`

  const handleCopyCmd = () => {
    navigator.clipboard.writeText(agentCommand)
    setCopiedCmd(true)
    setTimeout(() => setCopiedCmd(false), 2500)
  }

  if (!isAuthenticated) {
    return (
      <div className="agent-card-guest">
        <div className="guest-icon-box">
          <Shield size={24} className="text-cyan" />
        </div>
        <div className="guest-content">
          <h4>Connect Your Laptop Agent</h4>
          <p>Sign in or register an account to pair your laptop and control real-time network protection from the web.</p>
        </div>
        <style>{`
          .agent-card-guest {
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.8), rgba(9, 14, 26, 0.9));
            border: 1px dashed rgba(56, 189, 248, 0.25);
            border-radius: 16px;
            padding: 20px 24px;
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 24px;
          }
          .guest-icon-box {
            width: 46px;
            height: 46px;
            border-radius: 12px;
            background: rgba(0, 240, 255, 0.1);
            border: 1px solid rgba(0, 240, 255, 0.25);
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
          }
          .guest-content h4 {
            font-family: var(--font-heading);
            font-weight: 700;
            font-size: 1rem;
            color: #f8fafc;
            margin-bottom: 4px;
          }
          .guest-content p {
            font-size: 0.84rem;
            color: #94a3b8;
            line-height: 1.4;
          }
        `}</style>
      </div>
    )
  }

  const isOnline = agent && agent.status !== 'OFFLINE'
  const isSniffing = agent?.status === 'SNIFFING'

  return (
    <div className="agent-control-card">
      <div className="agent-card-main">
        {/* Header */}
        <div className="agent-header-row">
          <div className="agent-title">
            <Laptop size={20} className="text-cyan" />
            <h3>Laptop Protection Agent</h3>
          </div>

          <div className={`agent-status-pill ${isSniffing ? 'pill-sniffing' : isOnline ? 'pill-online' : 'pill-offline'}`}>
            <span className="status-ping-dot" />
            <span>{isSniffing ? 'SNIFFING ACTIVE' : isOnline ? 'ONLINE (STANDBY)' : 'AGENT OFFLINE'}</span>
          </div>
        </div>

        {/* Device Info & Control Action */}
        <div className="agent-body-grid">
          <div className="device-info-pane">
            {isOnline ? (
              <div className="device-specs">
                <div className="spec-item">
                  <span className="spec-label">Hostname:</span>
                  <span className="spec-value mono">{agent.hostname}</span>
                </div>
                <div className="spec-item">
                  <span className="spec-label">Local IP:</span>
                  <span className="spec-value mono">{agent.ip}</span>
                </div>
                <div className="spec-item">
                  <span className="spec-label">OS:</span>
                  <span className="spec-value">{agent.os || 'Windows'}</span>
                </div>
              </div>
            ) : (
              <div className="agent-offline-hint">
                <AlertTriangle size={16} className="text-warning" />
                <span>No active laptop agent detected for this account. Run the agent command below on your computer.</span>
              </div>
            )}
          </div>

          {/* Web Action Toggle Button */}
          <div className="agent-action-pane">
            <button
              className={`agent-toggle-btn ${isSniffing ? 'btn-stop' : 'btn-start'}`}
              onClick={handleToggleSniffing}
              disabled={!isOnline || actionLoading}
              title={!isOnline ? 'Start agent on your laptop first' : isSniffing ? 'Pause packet sniffing' : 'Start packet sniffing'}
            >
              {actionLoading ? (
                <span className="btn-spinner" />
              ) : isSniffing ? (
                <>
                  <Square size={16} />
                  <span>Stop Protection</span>
                </>
              ) : (
                <>
                  <Play size={16} />
                  <span>Start Real-Time Protection</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Command Setup Box */}
        <div className="agent-cmd-box">
          <div className="cmd-header">
            <Terminal size={13} />
            <span>Laptop Terminal Command</span>
          </div>
          <div className="cmd-code-row">
            <code className="cmd-code">{agentCommand}</code>
            <button className="cmd-copy-btn" onClick={handleCopyCmd} title="Copy Setup Command">
              {copiedCmd ? <Check size={13} /> : <Copy size={13} />}
              <span>{copiedCmd ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </div>
      </div>

      <style>{`
        .agent-control-card {
          background: #090e1a;
          border: 1px solid rgba(56, 189, 248, 0.25);
          border-radius: 16px;
          padding: 20px 24px;
          margin-bottom: 24px;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }
        .agent-header-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 16px;
        }
        .agent-title {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .agent-title h3 {
          font-family: var(--font-heading);
          font-weight: 700;
          font-size: 1.05rem;
          color: #f8fafc;
        }

        .agent-status-pill {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 5px 12px;
          border-radius: 20px;
          font-size: 0.72rem;
          font-weight: 700;
          letter-spacing: 0.5px;
        }
        .pill-sniffing {
          background: rgba(0, 240, 255, 0.15);
          border: 1px solid rgba(0, 240, 255, 0.4);
          color: var(--accent-cyan);
        }
        .pill-online {
          background: rgba(0, 255, 157, 0.15);
          border: 1px solid rgba(0, 255, 157, 0.4);
          color: #00ff9d;
        }
        .pill-offline {
          background: rgba(148, 163, 184, 0.15);
          border: 1px solid rgba(148, 163, 184, 0.3);
          color: #94a3b8;
        }
        .status-ping-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: currentColor;
        }

        .agent-body-grid {
          display: grid;
          grid-template-columns: 1fr auto;
          gap: 20px;
          align-items: center;
          background: #0f172a;
          border: 1px solid rgba(56, 189, 248, 0.15);
          border-radius: 12px;
          padding: 16px;
          margin-bottom: 16px;
        }

        .device-specs {
          display: flex;
          gap: 24px;
        }
        .spec-item {
          display: flex;
          flex-direction: column;
          gap: 2px;
        }
        .spec-label {
          font-size: 0.7rem;
          color: #64748b;
          text-transform: uppercase;
          font-weight: 600;
        }
        .spec-value {
          font-size: 0.88rem;
          font-weight: 600;
          color: #f8fafc;
        }

        .agent-offline-hint {
          display: flex;
          align-items: center;
          gap: 10px;
          font-size: 0.82rem;
          color: #cbd5e1;
        }

        .agent-toggle-btn {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 10px 20px;
          border-radius: 10px;
          font-weight: 700;
          font-size: 0.88rem;
          cursor: pointer;
          border: none;
          transition: all 0.25s;
          white-space: nowrap;
        }
        .btn-start {
          background: linear-gradient(135deg, #00f0ff, #0099ff);
          color: #060913;
          box-shadow: 0 4px 15px rgba(0, 240, 255, 0.3);
        }
        .btn-start:hover:not(:disabled) {
          transform: translateY(-1px);
          box-shadow: 0 6px 20px rgba(0, 240, 255, 0.4);
        }
        .btn-stop {
          background: rgba(255, 42, 95, 0.2);
          border: 1px solid rgba(255, 42, 95, 0.5);
          color: #ff6b8b;
        }
        .btn-stop:hover:not(:disabled) {
          background: rgba(255, 42, 95, 0.35);
        }
        .agent-toggle-btn:disabled {
          opacity: 0.4;
          cursor: not-allowed;
        }

        .btn-spinner {
          width: 16px;
          height: 16px;
          border: 2px solid rgba(6, 9, 19, 0.3);
          border-top-color: currentColor;
          border-radius: 50%;
          animation: spin 0.8s linear infinite;
        }

        .agent-cmd-box {
          background: #0b1120;
          border: 1px dashed rgba(56, 189, 248, 0.2);
          border-radius: 10px;
          padding: 10px 14px;
        }
        .cmd-header {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 0.7rem;
          font-weight: 700;
          color: var(--accent-cyan);
          text-transform: uppercase;
          margin-bottom: 6px;
        }
        .cmd-code-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }
        .cmd-code {
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.8rem;
          color: #cbd5e1;
          word-break: break-all;
        }
        .cmd-copy-btn {
          background: #1e293b;
          border: 1px solid rgba(56, 189, 248, 0.25);
          border-radius: 6px;
          padding: 4px 10px;
          color: #cbd5e1;
          font-size: 0.72rem;
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 4px;
          flex-shrink: 0;
          transition: all 0.2s;
        }
        .cmd-copy-btn:hover {
          background: #334155;
          color: var(--accent-cyan);
        }

        @media (max-width: 768px) {
          .agent-body-grid {
            grid-template-columns: 1fr;
          }
          .device-specs {
            flex-direction: column;
            gap: 8px;
          }
        }
      `}</style>
    </div>
  )
}
