/**
 * NetShield AI — Authentication Modal Component.
 *
 * Tabbed Login and Registration modal dialog with high-contrast cyber theme,
 * error handling, password visibility toggle, and API key copy tool.
 *
 * @module components/AuthModal
 */

import { useState } from 'react'
import { X, Shield, Lock, Mail, User, Key, Eye, EyeOff, Check, AlertCircle, Copy, ArrowRight } from 'lucide-react'
import { useAuth } from '../context/AuthContext.jsx'

export default function AuthModal({ isOpen, onClose }) {
  const { login, register } = useAuth()
  const [tab, setTab] = useState('login') // 'login' | 'register'
  
  // Form fields
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  
  // UI States
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [registeredApiKey, setRegisteredApiKey] = useState(null)
  const [copiedKey, setCopiedKey] = useState(false)

  if (!isOpen) return null

  const handleReset = () => {
    setError('')
    setRegisteredApiKey(null)
    setLoading(false)
  }

  const switchTab = (newTab) => {
    setTab(newTab)
    handleReset()
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      if (tab === 'login') {
        await login(email || username, password)
        onClose()
      } else {
        const data = await register(username, email, password)
        setRegisteredApiKey(data.user.apiKey)
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Authentication failed.')
    } finally {
      setLoading(false)
    }
  }

  const handleCopyKey = () => {
    if (registeredApiKey) {
      navigator.clipboard.writeText(registeredApiKey)
      setCopiedKey(true)
      setTimeout(() => setCopiedKey(false), 2500)
    }
  }

  return (
    <div className="auth-modal-overlay" onClick={onClose}>
      <div className="auth-modal-card" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="auth-modal-header">
          <div className="auth-brand">
            <Shield size={22} className="auth-brand-icon" />
            <span>NetShield AI</span>
          </div>
          <button className="auth-close-btn" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>

        {/* Successful Registration Screen with API Key */}
        {registeredApiKey ? (
          <div className="auth-success-body">
            <div className="success-badge">
              <Check size={28} />
            </div>
            <h3>Account Created Successfully!</h3>
            <p className="success-desc">
              Your account has been created. Use your unique <strong>Agent API Key</strong> to connect your laptop's NetShield Agent to the SOC dashboard.
            </p>

            <div className="api-key-box">
              <div className="api-key-label">
                <Key size={14} />
                <span>Your Agent API Key</span>
              </div>
              <div className="api-key-value-row">
                <code className="api-key-code">{registeredApiKey}</code>
                <button className="api-key-copy-btn" onClick={handleCopyKey}>
                  {copiedKey ? <Check size={14} /> : <Copy size={14} />}
                  <span>{copiedKey ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>

            <button className="auth-primary-btn margin-top" onClick={onClose}>
              Go to Dashboard <ArrowRight size={16} />
            </button>
          </div>
        ) : (
          <>
            {/* Tabs */}
            <div className="auth-tabs">
              <button
                className={`auth-tab ${tab === 'login' ? 'auth-tab-active' : ''}`}
                onClick={() => switchTab('login')}
              >
                Sign In
              </button>
              <button
                className={`auth-tab ${tab === 'register' ? 'auth-tab-active' : ''}`}
                onClick={() => switchTab('register')}
              >
                Create Account
              </button>
            </div>

            {/* Error Banner */}
            {error && (
              <div className="auth-error-banner">
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} className="auth-form">
              {tab === 'register' && (
                <div className="form-group">
                  <label className="form-label">Username</label>
                  <div className="input-wrapper">
                    <User size={16} className="input-icon" />
                    <input
                      type="text"
                      className="auth-input"
                      placeholder="e.g. cyber_analyst"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      required
                    />
                  </div>
                </div>
              )}

              <div className="form-group">
                <label className="form-label">{tab === 'login' ? 'Email or Username' : 'Email Address'}</label>
                <div className="input-wrapper">
                  <Mail size={16} className="input-icon" />
                  <input
                    type={tab === 'register' ? 'email' : 'text'}
                    className="auth-input"
                    placeholder={tab === 'login' ? 'analyst@netshield.ai' : 'analyst@netshield.ai'}
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Password</label>
                <div className="input-wrapper">
                  <Lock size={16} className="input-icon" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    className="auth-input"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    className="toggle-pass-btn"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <button type="submit" className="auth-primary-btn" disabled={loading}>
                {loading ? (
                  <span className="auth-spinner" />
                ) : (
                  <>
                    <span>{tab === 'login' ? 'Sign In' : 'Create Account'}</span>
                    <ArrowRight size={16} />
                  </>
                )}
              </button>
            </form>
          </>
        )}
      </div>

      <style>{`
        .auth-modal-overlay {
          position: fixed;
          inset: 0;
          background: rgba(4, 6, 14, 0.75);
          backdrop-filter: blur(6px);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 500;
          padding: 20px;
          animation: auth-fade 0.25s ease-out;
        }

        .auth-modal-card {
          width: 100%;
          max-width: 440px;
          background: #090e1a;
          border: 1px solid rgba(56, 189, 248, 0.3);
          border-radius: 16px;
          box-shadow: 0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(0, 240, 255, 0.1);
          overflow: hidden;
        }

        .auth-modal-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 18px 24px;
          background: #0f172a;
          border-bottom: 1px solid rgba(56, 189, 248, 0.2);
        }

        .auth-brand {
          display: flex;
          align-items: center;
          gap: 10px;
          font-family: var(--font-heading);
          font-weight: 700;
          font-size: 1.1rem;
          color: #f8fafc;
        }
        .auth-brand-icon {
          color: var(--accent-cyan);
        }

        .auth-close-btn {
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid rgba(255, 255, 255, 0.1);
          color: #94a3b8;
          border-radius: 8px;
          padding: 6px;
          cursor: pointer;
          transition: all 0.2s;
          display: flex;
        }
        .auth-close-btn:hover {
          background: rgba(255, 42, 95, 0.2);
          color: #ff2a5f;
          border-color: rgba(255, 42, 95, 0.3);
        }

        .auth-tabs {
          display: flex;
          background: #0b1120;
          border-bottom: 1px solid rgba(56, 189, 248, 0.15);
        }
        .auth-tab {
          flex: 1;
          padding: 14px;
          background: transparent;
          border: none;
          border-bottom: 2px solid transparent;
          color: #94a3b8;
          font-weight: 600;
          font-size: 0.9rem;
          cursor: pointer;
          transition: all 0.2s;
        }
        .auth-tab-active {
          color: var(--accent-cyan);
          border-bottom-color: var(--accent-cyan);
          background: rgba(0, 240, 255, 0.04);
        }

        .auth-error-banner {
          margin: 16px 24px 0 24px;
          padding: 10px 14px;
          background: rgba(255, 42, 95, 0.15);
          border: 1px solid rgba(255, 42, 95, 0.4);
          border-radius: 8px;
          color: #ff6b8b;
          font-size: 0.82rem;
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .auth-form {
          padding: 24px;
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }
        .form-label {
          font-size: 0.78rem;
          font-weight: 600;
          color: #cbd5e1;
          letter-spacing: 0.3px;
        }

        .input-wrapper {
          position: relative;
          display: flex;
          align-items: center;
        }
        .input-icon {
          position: absolute;
          left: 12px;
          color: #64748b;
        }
        .auth-input {
          width: 100%;
          background: #1e293b;
          border: 1px solid rgba(56, 189, 248, 0.25);
          border-radius: 10px;
          padding: 10px 14px 10px 38px;
          color: #f8fafc;
          font-size: 0.88rem;
          outline: none;
          transition: border-color 0.2s, box-shadow 0.2s;
        }
        .auth-input:focus {
          border-color: var(--accent-cyan);
          box-shadow: 0 0 10px rgba(0, 240, 255, 0.2);
        }
        .toggle-pass-btn {
          position: absolute;
          right: 12px;
          background: none;
          border: none;
          color: #64748b;
          cursor: pointer;
          display: flex;
        }
        .toggle-pass-btn:hover {
          color: #cbd5e1;
        }

        .auth-primary-btn {
          margin-top: 8px;
          width: 100%;
          background: linear-gradient(135deg, #00f0ff, #0099ff);
          color: #060913;
          border: none;
          border-radius: 10px;
          padding: 12px;
          font-weight: 700;
          font-size: 0.92rem;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          box-shadow: 0 4px 15px rgba(0, 240, 255, 0.3);
          transition: all 0.2s;
        }
        .auth-primary-btn:hover:not(:disabled) {
          transform: translateY(-1px);
          box-shadow: 0 6px 20px rgba(0, 240, 255, 0.4);
        }
        .auth-primary-btn.margin-top {
          margin-top: 20px;
        }

        .auth-spinner {
          width: 18px;
          height: 18px;
          border: 2px solid rgba(6, 9, 19, 0.3);
          border-top-color: #060913;
          border-radius: 50%;
          animation: spin 0.8s linear infinite;
        }

        /* Success View */
        .auth-success-body {
          padding: 32px 24px;
          display: flex;
          flex-direction: column;
          align-items: center;
          text-align: center;
        }
        .success-badge {
          width: 56px;
          height: 56px;
          border-radius: 50%;
          background: rgba(0, 255, 157, 0.15);
          border: 1px solid rgba(0, 255, 157, 0.4);
          color: #00ff9d;
          display: flex;
          align-items: center;
          justify-content: center;
          margin-bottom: 16px;
        }
        .auth-success-body h3 {
          font-family: var(--font-heading);
          color: #f8fafc;
          font-size: 1.15rem;
          margin-bottom: 8px;
        }
        .success-desc {
          font-size: 0.84rem;
          color: #94a3b8;
          line-height: 1.5;
          margin-bottom: 20px;
        }
        .api-key-box {
          width: 100%;
          background: #0f172a;
          border: 1px dashed rgba(0, 240, 255, 0.4);
          border-radius: 12px;
          padding: 12px 14px;
          text-align: left;
        }
        .api-key-label {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 0.72rem;
          font-weight: 700;
          color: var(--accent-cyan);
          margin-bottom: 6px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .api-key-value-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
        }
        .api-key-code {
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.78rem;
          color: #f8fafc;
          word-break: break-all;
        }
        .api-key-copy-btn {
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
          transition: all 0.2s;
        }
        .api-key-copy-btn:hover {
          background: #334155;
          color: var(--accent-cyan);
        }

        @keyframes auth-fade {
          from { opacity: 0; transform: scale(0.96); }
          to { opacity: 1; transform: scale(1); }
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  )
}
