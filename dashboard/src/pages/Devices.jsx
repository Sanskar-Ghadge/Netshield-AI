/**
 * NetShield AI — Connected Devices Workspace Page.
 *
 * Displays all paired laptop agents, system specs, online status,
 * 1-click installer download tools, and device revocation controls.
 *
 * @module pages/Devices
 */

import { useState, useEffect } from 'react'
import { Laptop, Cpu, Wifi, Shield, Terminal, Download, Copy, Check, Trash2, RefreshCw, AlertTriangle, Key } from 'lucide-react'
import { useAuth } from '../context/AuthContext.jsx'
import { fetchUserAgents, revokeUserAgent } from '../api/client.js'

export default function Devices() {
  const { user, isAuthenticated } = useAuth()
  const [devices, setDevices] = useState([])
  const [loading, setLoading] = useState(true)
  const [copiedCmd, setCopiedCmd] = useState(false)
  const [revokingId, setRevokingId] = useState(null)

  const loadDevices = async () => {
    if (!isAuthenticated) return
    setLoading(true)
    try {
      const data = await fetchUserAgents()
      setDevices(data.devices || [])
    } catch (err) {
      console.error('[Devices] Failed to fetch devices:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadDevices()
  }, [isAuthenticated])

  const handleRevoke = async (id) => {
    setRevokingId(id)
    try {
      await revokeUserAgent(id)
      await loadDevices()
    } catch (err) {
      console.error('[Devices] Failed to revoke agent:', err)
    } finally {
      setRevokingId(null)
    }
  }

  const agentCommand = `py agent/agent.py --key ${user?.apiKey || 'YOUR_API_KEY'}`

  const handleCopyCmd = () => {
    navigator.clipboard.writeText(agentCommand)
    setCopiedCmd(true)
    setTimeout(() => setCopiedCmd(false), 2500)
  }

  const handleDownloadBatch = () => {
    const scriptContent = `@echo off
title NetShield AI -- 1-Click Agent Setup
echo NetShield AI -- Setting up Laptop Agent...
py -m pip install "python-socketio[client]" websocket-client requests scapy python-dotenv
py agent.py --key ${user?.apiKey || ''}
pause`
    const blob = new Blob([scriptContent], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'install_netshield_agent.bat'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  if (!isAuthenticated) {
    return (
      <div className="devices-guest-card">
        <Shield size={36} className="text-cyan margin-bottom" />
        <h3>Sign In to Manage Your Laptop Devices</h3>
        <p>Log in or register an account to view paired laptops, copy agent keys, or download 1-click installers.</p>
        <style>{`
          .devices-guest-card {
            background: #090e1a;
            border: 1px dashed rgba(56, 189, 248, 0.3);
            border-radius: 16px;
            padding: 40px;
            text-align: center;
            max-width: 500px;
            margin: 40px auto;
          }
          .devices-guest-card h3 {
            font-family: var(--font-heading);
            color: #f8fafc;
            font-size: 1.2rem;
            margin-bottom: 8px;
          }
          .devices-guest-card p {
            color: #94a3b8;
            font-size: 0.88rem;
          }
        `}</style>
      </div>
    )
  }

  return (
    <div className="devices-page">
      {/* Overview Banner */}
      <div className="devices-banner">
        <div className="banner-info">
          <h2>Paired Laptop Devices & Agent Fleet</h2>
          <p>Manage all laptop computers authorized to capture network traffic and report threats to your SOC dashboard.</p>
        </div>
        <button className="refresh-btn" onClick={loadDevices} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span>Refresh Fleet</span>
        </button>
      </div>

      {/* Grid of Paired Devices */}
      <div className="devices-grid">
        {devices.map((device) => {
          const isSniffing = device.status === 'SNIFFING'
          const isOnline = device.status !== 'OFFLINE'

          return (
            <div key={device.id} className={`device-card ${isSniffing ? 'card-active-sniffing' : ''}`}>
              <div className="card-top-bar">
                <div className="device-icon-wrapper">
                  <Laptop size={22} className="text-cyan" />
                </div>
                <div className={`status-pill ${isSniffing ? 'pill-sniffing' : isOnline ? 'pill-online' : 'pill-offline'}`}>
                  <span className="dot" />
                  <span>{isSniffing ? 'SNIFFING ACTIVE' : isOnline ? 'ONLINE (STANDBY)' : 'OFFLINE'}</span>
                </div>
              </div>

              <div className="device-name">{device.hostname}</div>

              <div className="device-meta-list">
                <div className="meta-row">
                  <span className="meta-label">Local IP:</span>
                  <span className="meta-val mono">{device.ip}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">Operating System:</span>
                  <span className="meta-val">{device.os}</span>
                </div>
                <div className="meta-row">
                  <span className="meta-label">Last Handshake:</span>
                  <span className="meta-val text-faint">
                    {new Date(device.lastSeen).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </span>
                </div>
              </div>

              <div className="card-actions">
                <button
                  className="revoke-btn"
                  onClick={() => handleRevoke(device.id)}
                  disabled={revokingId === device.id}
                >
                  <Trash2 size={14} />
                  <span>{revokingId === device.id ? 'Disconnecting…' : 'Disconnect Device'}</span>
                </button>
              </div>
            </div>
          )
        })}
      </div>

      {/* Onboarding & Installer Section */}
      <div className="installer-section">
        <div className="installer-card">
          <div className="installer-header">
            <Download size={22} className="text-cyan" />
            <div>
              <h3>1-Click Windows Agent Installer</h3>
              <p>Download our automated setup script to pair a new laptop without manual configuration.</p>
            </div>
          </div>

          <div className="installer-actions">
            <button className="download-installer-btn" onClick={handleDownloadBatch}>
              <Download size={16} />
              <span>Download 1-Click Installer (.bat)</span>
            </button>
          </div>

          <div className="installer-manual">
            <div className="manual-header">
              <Terminal size={14} />
              <span>Manual PowerShell / Command Prompt Setup</span>
            </div>
            <div className="cmd-row">
              <code className="cmd-text">{agentCommand}</code>
              <button className="cmd-copy" onClick={handleCopyCmd}>
                {copiedCmd ? <Check size={14} /> : <Copy size={14} />}
                <span>{copiedCmd ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      <style>{`
        .devices-page {
          display: flex;
          flex-direction: column;
          gap: 24px;
        }
        .devices-banner {
          background: #090e1a;
          border: 1px solid rgba(56, 189, 248, 0.25);
          border-radius: 16px;
          padding: 24px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
        }
        .banner-info h2 {
          font-family: var(--font-heading);
          font-weight: 800;
          font-size: 1.25rem;
          color: #f8fafc;
          margin-bottom: 4px;
        }
        .banner-info p {
          color: #94a3b8;
          font-size: 0.85rem;
        }
        .refresh-btn {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 8px 16px;
          background: #1e293b;
          border: 1px solid rgba(56, 189, 248, 0.3);
          border-radius: 10px;
          color: #f8fafc;
          font-weight: 600;
          font-size: 0.82rem;
          cursor: pointer;
          transition: all 0.2s;
        }
        .refresh-btn:hover {
          border-color: var(--accent-cyan);
          background: #273549;
        }
        .spin {
          animation: spin 1s linear infinite;
        }

        .devices-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
          gap: 20px;
        }
        .device-card {
          background: #090e1a;
          border: 1px solid rgba(56, 189, 248, 0.2);
          border-radius: 16px;
          padding: 20px;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          transition: all 0.25s;
        }
        .card-active-sniffing {
          border-color: rgba(0, 240, 255, 0.5);
          box-shadow: 0 0 20px rgba(0, 240, 255, 0.15);
        }
        .card-top-bar {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 14px;
        }
        .device-icon-wrapper {
          width: 40px;
          height: 40px;
          border-radius: 10px;
          background: rgba(0, 240, 255, 0.1);
          border: 1px solid rgba(0, 240, 255, 0.25);
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .status-pill {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 4px 10px;
          border-radius: 14px;
          font-size: 0.7rem;
          font-weight: 700;
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
        .status-pill .dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: currentColor;
        }

        .device-name {
          font-family: var(--font-heading);
          font-weight: 700;
          font-size: 1.1rem;
          color: #f8fafc;
          margin-bottom: 16px;
        }

        .device-meta-list {
          display: flex;
          flex-direction: column;
          gap: 8px;
          background: #0f172a;
          border: 1px solid rgba(56, 189, 248, 0.15);
          border-radius: 10px;
          padding: 12px;
          margin-bottom: 18px;
        }
        .meta-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          font-size: 0.8rem;
        }
        .meta-label {
          color: #64748b;
          font-weight: 600;
        }
        .meta-val {
          color: #cbd5e1;
          font-weight: 600;
        }

        .card-actions {
          display: flex;
          justify-content: flex-end;
        }
        .revoke-btn {
          display: flex;
          align-items: center;
          gap: 6px;
          background: rgba(255, 42, 95, 0.15);
          border: 1px solid rgba(255, 42, 95, 0.3);
          border-radius: 8px;
          padding: 6px 12px;
          color: #ff6b8b;
          font-size: 0.78rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }
        .revoke-btn:hover:not(:disabled) {
          background: rgba(255, 42, 95, 0.3);
        }
        .revoke-btn:disabled {
          opacity: 0.4;
          cursor: not-allowed;
        }

        /* Installer Card */
        .installer-card {
          background: #090e1a;
          border: 1px solid rgba(56, 189, 248, 0.25);
          border-radius: 16px;
          padding: 24px;
          display: flex;
          flex-direction: column;
          gap: 18px;
        }
        .installer-header {
          display: flex;
          align-items: flex-start;
          gap: 14px;
        }
        .installer-header h3 {
          font-family: var(--font-heading);
          font-weight: 700;
          font-size: 1.05rem;
          color: #f8fafc;
          margin-bottom: 2px;
        }
        .installer-header p {
          color: #94a3b8;
          font-size: 0.84rem;
        }

        .download-installer-btn {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          background: linear-gradient(135deg, #00f0ff, #0099ff);
          color: #060913;
          border: none;
          border-radius: 10px;
          padding: 12px 20px;
          font-weight: 700;
          font-size: 0.88rem;
          cursor: pointer;
          box-shadow: 0 4px 15px rgba(0, 240, 255, 0.3);
          transition: all 0.2s;
        }
        .download-installer-btn:hover {
          transform: translateY(-1px);
          box-shadow: 0 6px 20px rgba(0, 240, 255, 0.4);
        }

        .installer-manual {
          background: #0f172a;
          border: 1px dashed rgba(56, 189, 248, 0.25);
          border-radius: 10px;
          padding: 12px 16px;
        }
        .manual-header {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 0.72rem;
          font-weight: 700;
          color: var(--accent-cyan);
          text-transform: uppercase;
          margin-bottom: 6px;
        }
        .cmd-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }
        .cmd-text {
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.8rem;
          color: #cbd5e1;
          word-break: break-all;
        }
        .cmd-copy {
          background: #1e293b;
          border: 1px solid rgba(56, 189, 248, 0.3);
          border-radius: 6px;
          padding: 4px 10px;
          color: #cbd5e1;
          font-size: 0.72rem;
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 4px;
          flex-shrink: 0;
        }
        .cmd-copy:hover {
          background: #334155;
          color: var(--accent-cyan);
        }

        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  )
}
