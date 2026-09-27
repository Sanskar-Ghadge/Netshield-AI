/**
 * NetShield AI — Project Home & Getting Started Landing Page.
 *
 * Standalone introductory page displaying project architecture, operational workflow,
 * and step-by-step instructions on running protection on any computer.
 * Features top-right Login and Register buttons with direct redirect to SOC Dashboard.
 *
 * @module pages/Home
 */

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield,
  ShieldCheck,
  Terminal,
  Download,
  Key,
  Play,
  Flame,
  FileText,
  Bot,
  Laptop,
  Activity,
  LogIn,
  LogOut,
  UserPlus,
  ArrowRight,
  Check,
  Copy,
  ExternalLink,
  Lock,
  Server,
  Zap,
  Eye,
  Sliders,
} from 'lucide-react'
import { useAuth } from '../context/AuthContext.jsx'
import { useDashboard } from '../context/DashboardContext.jsx'
import AuthModal from '../components/AuthModal.jsx'

export default function Home() {
  const navigate = useNavigate()
  const { user, isAuthenticated, logout } = useAuth()
  const { socketConnected } = useDashboard()

  const [authModalOpen, setAuthModalOpen] = useState(false)
  const [authTab, setAuthTab] = useState('login')
  const [copiedStep, setCopiedStep] = useState(null)

  const handleOpenAuth = (tab) => {
    setAuthTab(tab)
    setAuthModalOpen(true)
  }

  const handleAuthSuccess = () => {
    navigate('/dashboard')
  }

  const handleCopyCommand = (text, stepIndex) => {
    navigator.clipboard.writeText(text)
    setCopiedStep(stepIndex)
    setTimeout(() => setCopiedStep(null), 2000)
  }

  return (
    <div className="home-page-wrapper">
      {/* ── Top Navigation Bar ──────────────────────────────────── */}
      <header className="home-nav">
        <div className="home-nav-container">
          <div className="home-brand" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
            <div className="home-logo-glow">
              <Shield size={24} className="home-logo-icon" />
            </div>
            <div className="home-brand-text">
              <span className="brand-title">NetShield <span className="brand-highlight">AI</span></span>
              <span className="brand-tag">Autonomous Network Defense</span>
            </div>
          </div>

          <nav className="home-nav-links">
            <a href="#how-it-works" className="nav-anchor">How It Works</a>
            <a href="#setup-guide" className="nav-anchor">Setup & Run Guide</a>
            <a href="#features" className="nav-anchor">Platform Features</a>
          </nav>

          <div className="home-nav-auth">
            {isAuthenticated ? (
              <div className="logged-in-box">
                <div className="user-pill">
                  <div className="user-avatar-dot">{user?.username?.charAt(0).toUpperCase()}</div>
                  <span className="user-pill-name">{user?.username}</span>
                </div>
                <button className="open-dashboard-btn" onClick={() => navigate('/dashboard')}>
                  <span>Open SOC Dashboard</span>
                  <ArrowRight size={15} />
                </button>
                <button className="auth-btn-ghost" onClick={logout} title="Sign Out">
                  <LogOut size={14} />
                  <span>Sign Out</span>
                </button>
              </div>
            ) : (
              <div className="guest-auth-buttons">
                <button className="auth-btn-ghost" onClick={() => handleOpenAuth('login')}>
                  <LogIn size={15} />
                  <span>Sign In</span>
                </button>
                <button className="auth-btn-primary" onClick={() => handleOpenAuth('register')}>
                  <UserPlus size={15} />
                  <span>Register</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* ── Hero Presentation ────────────────────────────────────── */}
      <section className="home-hero">
        <div className="hero-glow-sphere cyan" />
        <div className="hero-glow-sphere purple" />

        <div className="hero-content">
          <div className="status-pill-badge">
            <span className={`status-pulse-dot ${socketConnected ? 'active' : ''}`} />
            <span>NetShield Central Security Engine Online</span>
          </div>

          <h1 className="hero-headline">
            Next-Generation Autonomous <br />
            <span className="gradient-text">Network Security & SOC Defense</span>
          </h1>

          <p className="hero-subtitle">
            Continuous real-time traffic monitoring, instant intrusion detection, and centralized fleet protection 
            for all your team's computers and connected laptops.
          </p>

          <div className="hero-actions">
            {isAuthenticated ? (
              <button className="hero-cta-primary" onClick={() => navigate('/dashboard')}>
                <span>Enter SOC Operations Dashboard</span>
                <ArrowRight size={18} />
              </button>
            ) : (
              <button className="hero-cta-primary" onClick={() => handleOpenAuth('register')}>
                <span>Get Started / Create Account</span>
                <ArrowRight size={18} />
              </button>
            )}

            <a href="#setup-guide" className="hero-cta-secondary">
              <Terminal size={17} />
              <span>View Setup Instructions</span>
            </a>
          </div>

          {/* Quick Metrics Banner */}
          <div className="hero-stats-row">
            <div className="hero-stat-card">
              <span className="stat-val text-cyan">&lt; 5ms</span>
              <span className="stat-lbl">Detection Latency</span>
            </div>
            <div className="hero-stat-divider" />
            <div className="hero-stat-card">
              <span className="stat-val text-green">1-Click</span>
              <span className="stat-lbl">Device Pairing</span>
            </div>
            <div className="hero-stat-divider" />
            <div className="hero-stat-card">
              <span className="stat-val text-purple">100% Local</span>
              <span className="stat-lbl">SQLite Storage</span>
            </div>
            <div className="hero-stat-divider" />
            <div className="hero-stat-card">
              <span className="stat-val text-yellow">24 / 7</span>
              <span className="stat-lbl">Real-Time Protection</span>
            </div>
          </div>
        </div>
      </section>

      {/* ── Section: How NetShield AI Runs & Operates ─────────────── */}
      <section id="how-it-works" className="home-section">
        <div className="section-header text-center">
          <div className="section-tag">System Architecture</div>
          <h2 className="section-title">How NetShield AI Operates</h2>
          <p className="section-desc">
            A seamless, two-tier architecture designed for modern personal and enterprise network security.
          </p>
        </div>

        <div className="architecture-grid">
          <div className="arch-card">
            <div className="arch-card-icon-wrap cyan">
              <Server size={28} />
            </div>
            <div className="arch-badge">Tier 1: Central Hub</div>
            <h3 className="arch-card-title">Central SOC Web Operations</h3>
            <p className="arch-card-text">
              Your web-based mission control room. Access live network packet feeds, view traffic speed charts, 
              inspect threat levels (Safe, Elevated, Critical), and remotely control protection across all your 
              connected devices from any browser.
            </p>
            <div className="arch-features-list">
              <div className="arch-feature-item"><Check size={14} className="text-cyan" /> Central Command Dashboard</div>
              <div className="arch-feature-item"><Check size={14} className="text-cyan" /> User & Fleet Management</div>
              <div className="arch-feature-item"><Check size={14} className="text-cyan" /> Direct PDF Incident Reports</div>
            </div>
          </div>

          <div className="arch-card highlight">
            <div className="arch-card-icon-wrap green">
              <Laptop size={28} />
            </div>
            <div className="arch-badge">Tier 2: Device Sensor</div>
            <h3 className="arch-card-title">Distributed Computer Agents</h3>
            <p className="arch-card-text">
              Lightweight background agents running on each laptop or workstation you wish to protect. 
              Quietly monitors incoming and outgoing network packets across Wi-Fi and Ethernet interfaces 
              and streams security telemetry to your dashboard.
            </p>
            <div className="arch-features-list">
              <div className="arch-feature-item"><Check size={14} className="text-green" /> 1-Click Windows Installer</div>
              <div className="arch-feature-item"><Check size={14} className="text-green" /> Secure API Key Pairing</div>
              <div className="arch-feature-item"><Check size={14} className="text-green" /> Standby & Active Sniffing Modes</div>
            </div>
          </div>

          <div className="arch-card">
            <div className="arch-card-icon-wrap crimson">
              <ShieldCheck size={28} />
            </div>
            <div className="arch-badge">Core Engine</div>
            <h3 className="arch-card-title">Autonomous Threat Defense</h3>
            <p className="arch-card-text">
              Evaluates packet flows instantaneously. Rapidly classifies malicious behaviors—such as DDoS SYN floods, 
              reconnaissance port scans, and unauthorized brute-force attempts—and instantly pushes high-priority 
              alerts directly to your screen.
            </p>
            <div className="arch-features-list">
              <div className="arch-feature-item"><Check size={14} className="text-crimson" /> Millisecond Threat Detection</div>
              <div className="arch-feature-item"><Check size={14} className="text-crimson" /> Instant Visual & Audio Alerts</div>
              <div className="arch-feature-item"><Check size={14} className="text-crimson" /> Automatic Session Isolation</div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Section: How to Run the Project (Step-by-Step) ─────────── */}
      <section id="setup-guide" className="home-section setup-section">
        <div className="section-header text-center">
          <div className="section-tag">Quick Start Guide</div>
          <h2 className="section-title">How to Run & Protect Your Computer</h2>
          <p className="section-desc">
            Follow these 4 simple steps to connect and start monitoring your computer in less than two minutes.
          </p>
        </div>

        <div className="steps-container">
          {/* Step 1 */}
          <div className="step-card">
            <div className="step-number-col">
              <div className="step-number">01</div>
              <div className="step-line" />
            </div>
            <div className="step-content">
              <div className="step-header">
                <Key size={20} className="text-cyan" />
                <h3 className="step-title">Create an Account & Obtain Your Agent API Key</h3>
              </div>
              <p className="step-text">
                Every user on NetShield receives a unique, cryptographically secure API Key (e.g. <code>ns_live_...</code>). 
                This key safely pairs your laptops and devices to your personal web dashboard.
              </p>
              <div className="step-action-box">
                {isAuthenticated ? (
                  <div className="user-connected-badge">
                    <Check size={16} className="text-green" />
                    <span>You are signed in as <strong>{user?.username}</strong>. Your API key is ready in your profile.</span>
                  </div>
                ) : (
                  <button className="step-btn-primary" onClick={() => handleOpenAuth('register')}>
                    <UserPlus size={15} />
                    <span>Register Account Now</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Step 2 */}
          <div className="step-card">
            <div className="step-number-col">
              <div className="step-number">02</div>
              <div className="step-line" />
            </div>
            <div className="step-content">
              <div className="step-header">
                <Terminal size={20} className="text-green" />
                <h3 className="step-title">Connect Your Computer via Agent</h3>
              </div>
              <p className="step-text">
                On the computer you want to protect, run the client agent command in terminal using your API key. 
                Alternatively, you can double-click <code>agent/install_agent.bat</code> for an automated 1-click installer.
              </p>

              <div className="terminal-code-block">
                <div className="terminal-header">
                  <div className="terminal-dots">
                    <span className="dot red" />
                    <span className="dot yellow" />
                    <span className="dot green" />
                  </div>
                  <span className="terminal-title">PowerShell / Command Prompt</span>
                  <button 
                    className="copy-code-btn" 
                    onClick={() => handleCopyCommand(
                      isAuthenticated && user?.apiKey 
                        ? `py agent/agent.py --key ${user.apiKey}`
                        : `py agent/agent.py --key ns_live_YOUR_API_KEY_HERE`,
                      2
                    )}
                  >
                    {copiedStep === 2 ? <Check size={14} className="text-green" /> : <Copy size={14} />}
                    <span>{copiedStep === 2 ? 'Copied!' : 'Copy'}</span>
                  </button>
                </div>
                <div className="terminal-body">
                  <code>
                    <span className="cmd-prompt">&gt; </span>
                    <span className="cmd-text">
                      {isAuthenticated && user?.apiKey 
                        ? `py agent/agent.py --key ${user.apiKey}`
                        : `py agent/agent.py --key ns_live_YOUR_API_KEY_HERE`}
                    </span>
                  </code>
                </div>
              </div>

              <p className="step-note text-muted">
                💡 <strong>Multi-Computer Fleet:</strong> You can run this command on as many laptops as you want. All of them will appear under your <strong>"My Devices"</strong> page!
              </p>
            </div>
          </div>

          {/* Step 3 */}
          <div className="step-card">
            <div className="step-number-col">
              <div className="step-number">03</div>
              <div className="step-line" />
            </div>
            <div className="step-content">
              <div className="step-header">
                <Play size={20} className="text-cyan" />
                <h3 className="step-title">Activate Real-Time Protection</h3>
              </div>
              <p className="step-text">
                By default, newly connected devices sit quietly in <strong>STANDBY mode</strong> consuming 0% CPU. 
                When you are ready to monitor live network traffic, open your SOC dashboard and click 
                <strong>"Start Real-Time Protection"</strong>.
              </p>
              <div className="step-callout">
                <div className="callout-pill green">Active Protection</div>
                <span>Inspects incoming & outgoing packet flows in real time, alerting you the instant malicious traffic is detected.</span>
              </div>
            </div>
          </div>

          {/* Step 4 */}
          <div className="step-card">
            <div className="step-number-col">
              <div className="step-number">04</div>
            </div>
            <div className="step-content">
              <div className="step-header">
                <Flame size={20} className="text-crimson" />
                <h3 className="step-title">Simulate Attacks & Verify Live Alerts</h3>
              </div>
              <p className="step-text">
                Test your protection in real time using the built-in attack simulation tool. Run any test attack below 
                in a separate terminal and watch the SOC dashboard immediately turn <strong>RED (CRITICAL ALERT)</strong>:
              </p>

              <div className="terminal-code-block">
                <div className="terminal-header">
                  <div className="terminal-dots">
                    <span className="dot red" />
                    <span className="dot yellow" />
                    <span className="dot green" />
                  </div>
                  <span className="terminal-title">Simulate a DDoS SYN Flood</span>
                  <button 
                    className="copy-code-btn" 
                    onClick={() => handleCopyCommand('py scripts\\simulate_attack.py --ddos', 4)}
                  >
                    {copiedStep === 4 ? <Check size={14} className="text-green" /> : <Copy size={14} />}
                    <span>{copiedStep === 4 ? 'Copied!' : 'Copy'}</span>
                  </button>
                </div>
                <div className="terminal-body">
                  <code>
                    <span className="cmd-prompt">&gt; </span>
                    <span className="cmd-text">py scripts\simulate_attack.py --ddos</span>
                  </code>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Section: Platform Features ───────────────────────────── */}
      <section id="features" className="home-section">
        <div className="section-header text-center">
          <div className="section-tag">Enterprise Capabilities</div>
          <h2 className="section-title">Built for Modern Cyber Defense</h2>
          <p className="section-desc">
            Everything you need to monitor, detect, and investigate network threats across your environment.
          </p>
        </div>

        <div className="features-grid">
          <div className="feature-card">
            <div className="feature-icon cyan"><Activity size={24} /></div>
            <h3 className="feature-title">Live Traffic Telemetry</h3>
            <p className="feature-desc">
              High-frequency packet speed graphs (PPS), protocol breakdowns, and continuous rolling window metrics.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon green"><Laptop size={24} /></div>
            <h3 className="feature-title">Multi-Device Fleet Guard</h3>
            <p className="feature-desc">
              Centralized visibility into all connected computers. Inspect hostnames, IP addresses, OS types, and revoke access anytime.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon crimson"><Flame size={24} /></div>
            <h3 className="feature-title">Instant Threat Alerts</h3>
            <p className="feature-desc">
              Visual threat status indicators (Safe / Elevated / Critical) with audio voice alerts and instant incident banners.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon purple"><FileText size={24} /></div>
            <h3 className="feature-title">In-Memory PDF Reports</h3>
            <p className="feature-desc">
              Generate executive security audits with 1-click. Downloads directly to your browser without cluttering disk space.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon yellow"><Bot size={24} /></div>
            <h3 className="feature-title">AI Security Assistant</h3>
            <p className="feature-desc">
              Interactive chatbot assistant to ask questions in plain English about current threats, network flows, and safety tips.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon cyan"><Sliders size={24} /></div>
            <h3 className="feature-title">Zero-Server SQLite Engine</h3>
            <p className="feature-desc">
              Lightweight local database storage with permanent user preservation across restarts and instant reset capabilities.
            </p>
          </div>
        </div>
      </section>

      {/* ── Bottom Call To Action ─────────────────────────────────── */}
      <section className="home-bottom-cta">
        <div className="bottom-cta-card">
          <Shield size={36} className="text-cyan mb-2" />
          <h2 className="bottom-cta-title">Ready to Secure Your Computers?</h2>
          <p className="bottom-cta-desc">
            Join your central SOC command and start monitoring your network traffic in real time.
          </p>
          <div className="bottom-cta-actions">
            {isAuthenticated ? (
              <button className="hero-cta-primary" onClick={() => navigate('/dashboard')}>
                <span>Enter SOC Operations Dashboard</span>
                <ArrowRight size={18} />
              </button>
            ) : (
              <button className="hero-cta-primary" onClick={() => handleOpenAuth('register')}>
                <span>Register & Open Dashboard</span>
                <ArrowRight size={18} />
              </button>
            )}
          </div>
        </div>
      </section>

      {/* ── Footer ───────────────────────────────────────────────── */}
      <footer className="home-footer">
        <div className="footer-container">
          <div className="footer-left">
            <span className="brand-title">NetShield <span className="brand-highlight">AI</span></span>
            <span className="footer-sub">Autonomous Network Defense & SOC Operations</span>
          </div>
          <div className="footer-right">
            <span className="footer-status-pill">
              <span className="status-dot green" /> Engine Online
            </span>
            <span className="footer-copy">© 2026 NetShield AI. All rights reserved.</span>
          </div>
        </div>
      </footer>

      {/* ── Authentication Modal ─────────────────────────────────── */}
      <AuthModal 
        isOpen={authModalOpen} 
        onClose={() => setAuthModalOpen(false)} 
        initialTab={authTab}
        onSuccess={handleAuthSuccess}
      />

      {/* ── Inline Scoped Styles ─────────────────────────────────── */}
      <style>{`
        .home-page-wrapper {
          min-height: 100vh;
          width: 100%;
          background: #070b14;
          color: #f1f5f9;
          font-family: var(--font-sans, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif);
          overflow-x: hidden;
          position: relative;
        }

        /* ── Navbar ────────────────────────────────────────────── */
        .home-nav {
          height: 72px;
          background: rgba(7, 11, 20, 0.85);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          border-bottom: 1px solid rgba(255, 255, 255, 0.08);
          position: sticky;
          top: 0;
          z-index: 100;
        }
        .home-nav-container {
          max-width: 1300px;
          height: 100%;
          margin: 0 auto;
          padding: 0 24px;
          display: flex;
          align-items: center;
          justify-content: space-between;
        }
        .home-brand {
          display: flex;
          align-items: center;
          gap: 12px;
          cursor: pointer;
        }
        .home-logo-glow {
          width: 40px;
          height: 40px;
          background: linear-gradient(135deg, rgba(0,240,255,0.2), rgba(16,185,129,0.1));
          border: 1px solid rgba(0, 240, 255, 0.4);
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: 0 0 15px rgba(0,240,255,0.25);
        }
        .home-logo-icon {
          color: #00f0ff;
        }
        .home-brand-text {
          display: flex;
          flex-direction: column;
        }
        .brand-title {
          font-size: 1.15rem;
          font-weight: 800;
          letter-spacing: -0.02em;
          color: #fff;
        }
        .brand-highlight {
          color: #00f0ff;
        }
        .brand-tag {
          font-size: 0.68rem;
          color: #94a3b8;
          text-transform: uppercase;
          letter-spacing: 0.06em;
        }
        .home-nav-links {
          display: flex;
          align-items: center;
          gap: 28px;
        }
        .nav-anchor {
          color: #cbd5e1;
          font-size: 0.88rem;
          font-weight: 500;
          text-decoration: none;
          transition: color 0.2s;
        }
        .nav-anchor:hover {
          color: #00f0ff;
        }
        .home-nav-auth {
          display: flex;
          align-items: center;
        }
        .guest-auth-buttons {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .auth-btn-ghost {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 8px 16px;
          background: rgba(255, 255, 255, 0.04);
          border: 1px solid rgba(255, 255, 255, 0.12);
          border-radius: 8px;
          color: #e2e8f0;
          font-size: 0.86rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }
        .auth-btn-ghost:hover {
          background: rgba(255, 255, 255, 0.08);
          border-color: rgba(255, 255, 255, 0.25);
        }
        .auth-btn-primary {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 8px 18px;
          background: linear-gradient(135deg, #00f0ff, #0099ff);
          border: none;
          border-radius: 8px;
          color: #070b14;
          font-size: 0.86rem;
          font-weight: 700;
          cursor: pointer;
          box-shadow: 0 0 16px rgba(0, 240, 255, 0.35);
          transition: all 0.2s;
        }
        .auth-btn-primary:hover {
          transform: translateY(-1px);
          box-shadow: 0 0 22px rgba(0, 240, 255, 0.5);
        }
        .logged-in-box {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .user-pill {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 4px 12px 4px 6px;
          background: rgba(15, 23, 42, 0.8);
          border: 1px solid rgba(0, 240, 255, 0.2);
          border-radius: 20px;
        }
        .user-avatar-dot {
          width: 26px;
          height: 26px;
          border-radius: 50%;
          background: linear-gradient(135deg, #00f0ff, #3b82f6);
          color: #070b14;
          font-weight: 800;
          font-size: 0.75rem;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .user-pill-name {
          font-size: 0.82rem;
          font-weight: 600;
          color: #e2e8f0;
        }
        .open-dashboard-btn {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 8px 16px;
          background: linear-gradient(135deg, #00f0ff, #00b4d8);
          border: none;
          border-radius: 8px;
          color: #070b14;
          font-size: 0.84rem;
          font-weight: 700;
          cursor: pointer;
          box-shadow: 0 0 16px rgba(0, 240, 255, 0.3);
          transition: all 0.2s;
        }
        .open-dashboard-btn:hover {
          box-shadow: 0 0 24px rgba(0, 240, 255, 0.5);
        }

        /* ── Hero ──────────────────────────────────────────────── */
        .home-hero {
          position: relative;
          padding: 80px 24px 60px;
          display: flex;
          justify-content: center;
          text-align: center;
          overflow: hidden;
        }
        .hero-glow-sphere {
          position: absolute;
          width: 600px;
          height: 600px;
          border-radius: 50%;
          filter: blur(120px);
          pointer-events: none;
          z-index: 0;
          opacity: 0.35;
        }
        .hero-glow-sphere.cyan {
          top: -150px;
          left: 15%;
          background: radial-gradient(circle, #00f0ff, transparent 70%);
        }
        .hero-glow-sphere.purple {
          top: -50px;
          right: 15%;
          background: radial-gradient(circle, #8b5cf6, transparent 70%);
        }
        .hero-content {
          position: relative;
          z-index: 1;
          max-width: 900px;
          display: flex;
          flex-direction: column;
          align-items: center;
        }
        .status-pill-badge {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 6px 16px;
          background: rgba(16, 185, 129, 0.1);
          border: 1px solid rgba(16, 185, 129, 0.3);
          border-radius: 20px;
          font-size: 0.78rem;
          font-weight: 600;
          color: #10b981;
          margin-bottom: 24px;
        }
        .status-pulse-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #10b981;
          box-shadow: 0 0 8px #10b981;
          animation: pulse-glow 2s infinite;
        }
        .hero-headline {
          font-size: 3.1rem;
          font-weight: 900;
          line-height: 1.15;
          letter-spacing: -0.03em;
          margin-bottom: 20px;
          color: #ffffff;
        }
        .gradient-text {
          background: linear-gradient(135deg, #00f0ff 0%, #3b82f6 50%, #a855f7 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }
        .hero-subtitle {
          font-size: 1.15rem;
          line-height: 1.6;
          color: #94a3b8;
          max-width: 720px;
          margin-bottom: 36px;
        }
        .hero-actions {
          display: flex;
          align-items: center;
          gap: 16px;
          margin-bottom: 50px;
        }
        .hero-cta-primary {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 14px 28px;
          background: linear-gradient(135deg, #00f0ff, #0099ff);
          border: none;
          border-radius: 10px;
          color: #070b14;
          font-size: 0.98rem;
          font-weight: 800;
          cursor: pointer;
          box-shadow: 0 0 24px rgba(0, 240, 255, 0.4);
          transition: all 0.25s ease;
        }
        .hero-cta-primary:hover {
          transform: translateY(-2px);
          box-shadow: 0 0 32px rgba(0, 240, 255, 0.6);
        }
        .hero-cta-secondary {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 14px 24px;
          background: rgba(255, 255, 255, 0.04);
          border: 1px solid rgba(255, 255, 255, 0.15);
          border-radius: 10px;
          color: #e2e8f0;
          font-size: 0.92rem;
          font-weight: 600;
          text-decoration: none;
          cursor: pointer;
          transition: all 0.2s;
        }
        .hero-cta-secondary:hover {
          background: rgba(255, 255, 255, 0.08);
          border-color: rgba(0, 240, 255, 0.4);
          color: #00f0ff;
        }
        .hero-stats-row {
          display: flex;
          align-items: center;
          background: rgba(15, 23, 42, 0.6);
          backdrop-filter: blur(12px);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 16px;
          padding: 16px 32px;
          box-shadow: 0 20px 40px rgba(0,0,0,0.4);
        }
        .hero-stat-card {
          display: flex;
          flex-direction: column;
          align-items: center;
          padding: 4px 20px;
        }
        .stat-val {
          font-size: 1.35rem;
          font-weight: 800;
          font-family: var(--font-mono, monospace);
        }
        .stat-lbl {
          font-size: 0.72rem;
          color: #94a3b8;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          margin-top: 2px;
        }
        .hero-stat-divider {
          width: 1px;
          height: 32px;
          background: rgba(255, 255, 255, 0.1);
        }

        /* ── Sections ──────────────────────────────────────────── */
        .home-section {
          max-width: 1200px;
          margin: 0 auto;
          padding: 80px 24px;
        }
        .section-header {
          margin-bottom: 50px;
        }
        .section-tag {
          font-size: 0.75rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.12em;
          color: #00f0ff;
          margin-bottom: 8px;
        }
        .section-title {
          font-size: 2.2rem;
          font-weight: 800;
          color: #ffffff;
          margin-bottom: 12px;
        }
        .section-desc {
          font-size: 0.98rem;
          color: #94a3b8;
          max-width: 600px;
          margin: 0 auto;
        }

        /* ── Architecture Grid ─────────────────────────────────── */
        .architecture-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 24px;
        }
        .arch-card {
          background: rgba(15, 23, 42, 0.5);
          backdrop-filter: blur(12px);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 16px;
          padding: 32px 24px;
          display: flex;
          flex-direction: column;
          position: relative;
          transition: all 0.3s ease;
        }
        .arch-card:hover {
          transform: translateY(-4px);
          border-color: rgba(0, 240, 255, 0.3);
          box-shadow: 0 12px 30px rgba(0,0,0,0.4);
        }
        .arch-card.highlight {
          border-color: rgba(16, 185, 129, 0.35);
          background: rgba(15, 23, 42, 0.7);
        }
        .arch-card-icon-wrap {
          width: 54px;
          height: 54px;
          border-radius: 14px;
          display: flex;
          align-items: center;
          justify-content: center;
          margin-bottom: 20px;
        }
        .arch-card-icon-wrap.cyan { background: rgba(0, 240, 255, 0.1); color: #00f0ff; }
        .arch-card-icon-wrap.green { background: rgba(16, 185, 129, 0.1); color: #10b981; }
        .arch-card-icon-wrap.crimson { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
        .arch-badge {
          font-size: 0.72rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.06em;
          color: #64748b;
          margin-bottom: 6px;
        }
        .arch-card-title {
          font-size: 1.2rem;
          font-weight: 700;
          color: #fff;
          margin-bottom: 12px;
        }
        .arch-card-text {
          font-size: 0.88rem;
          line-height: 1.6;
          color: #94a3b8;
          margin-bottom: 24px;
          flex: 1;
        }
        .arch-features-list {
          display: flex;
          flex-direction: column;
          gap: 8px;
          border-top: 1px solid rgba(255, 255, 255, 0.06);
          padding-top: 16px;
        }
        .arch-feature-item {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 0.82rem;
          color: #cbd5e1;
        }

        /* ── Steps Container ───────────────────────────────────── */
        .setup-section {
          background: linear-gradient(180deg, transparent, rgba(15, 23, 42, 0.4), transparent);
          border-radius: 24px;
        }
        .steps-container {
          display: flex;
          flex-direction: column;
          gap: 32px;
          max-width: 900px;
          margin: 0 auto;
        }
        .step-card {
          display: flex;
          gap: 24px;
        }
        .step-number-col {
          display: flex;
          flex-direction: column;
          align-items: center;
          width: 48px;
          flex-shrink: 0;
        }
        .step-number {
          width: 44px;
          height: 44px;
          border-radius: 12px;
          background: rgba(15, 23, 42, 0.8);
          border: 1px solid rgba(0, 240, 255, 0.3);
          color: #00f0ff;
          font-weight: 800;
          font-size: 1rem;
          font-family: var(--font-mono, monospace);
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: 0 0 12px rgba(0, 240, 255, 0.2);
        }
        .step-line {
          width: 2px;
          flex: 1;
          background: linear-gradient(180deg, rgba(0, 240, 255, 0.3), rgba(255, 255, 255, 0.05));
          margin: 8px 0;
        }
        .step-content {
          flex: 1;
          background: rgba(15, 23, 42, 0.6);
          backdrop-filter: blur(12px);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 16px;
          padding: 24px;
        }
        .step-header {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 10px;
        }
        .step-title {
          font-size: 1.15rem;
          font-weight: 700;
          color: #fff;
        }
        .step-text {
          font-size: 0.9rem;
          line-height: 1.6;
          color: #94a3b8;
          margin-bottom: 16px;
        }
        .step-text code {
          background: rgba(0, 240, 255, 0.1);
          color: #00f0ff;
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 0.84rem;
        }
        .step-action-box {
          margin-top: 14px;
        }
        .step-btn-primary {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 10px 20px;
          background: linear-gradient(135deg, #00f0ff, #0099ff);
          border: none;
          border-radius: 8px;
          color: #070b14;
          font-size: 0.88rem;
          font-weight: 700;
          cursor: pointer;
          transition: all 0.2s;
        }
        .step-btn-primary:hover {
          box-shadow: 0 0 16px rgba(0, 240, 255, 0.4);
        }
        .user-connected-badge {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 8px 16px;
          background: rgba(16, 185, 129, 0.1);
          border: 1px solid rgba(16, 185, 129, 0.3);
          border-radius: 8px;
          font-size: 0.85rem;
          color: #e2e8f0;
        }
        .step-callout {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          background: rgba(255, 255, 255, 0.03);
          border-left: 3px solid #10b981;
          border-radius: 0 8px 8px 0;
          font-size: 0.85rem;
          color: #cbd5e1;
        }
        .callout-pill.green {
          background: rgba(16, 185, 129, 0.2);
          color: #10b981;
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 0.72rem;
          font-weight: 700;
          text-transform: uppercase;
        }

        /* ── Terminal Code Block ────────────────────────────────── */
        .terminal-code-block {
          background: #040711;
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 10px;
          overflow: hidden;
          margin-bottom: 12px;
        }
        .terminal-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 8px 14px;
          background: rgba(255, 255, 255, 0.03);
          border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }
        .terminal-dots {
          display: flex;
          gap: 6px;
        }
        .terminal-dots .dot {
          width: 10px;
          height: 10px;
          border-radius: 50%;
        }
        .terminal-dots .dot.red { background: #ff5f56; }
        .terminal-dots .dot.yellow { background: #ffbd2e; }
        .terminal-dots .dot.green { background: #27c93f; }
        .terminal-title {
          font-size: 0.72rem;
          color: #64748b;
          font-family: var(--font-mono, monospace);
        }
        .copy-code-btn {
          display: flex;
          align-items: center;
          gap: 6px;
          background: rgba(255, 255, 255, 0.06);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 6px;
          color: #cbd5e1;
          font-size: 0.75rem;
          font-weight: 600;
          padding: 3px 10px;
          cursor: pointer;
          transition: all 0.2s;
        }
        .copy-code-btn:hover {
          background: rgba(0, 240, 255, 0.15);
          color: #00f0ff;
          border-color: rgba(0, 240, 255, 0.3);
        }
        .terminal-body {
          padding: 14px 16px;
          font-family: var(--font-mono, monospace);
          font-size: 0.88rem;
          word-break: break-all;
        }
        .cmd-prompt { color: #10b981; font-weight: 700; }
        .cmd-text { color: #f1f5f9; }

        /* ── Features Grid ─────────────────────────────────────── */
        .features-grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 20px;
        }
        .feature-card {
          background: rgba(15, 23, 42, 0.45);
          border: 1px solid rgba(255, 255, 255, 0.06);
          border-radius: 14px;
          padding: 24px;
          transition: all 0.25s ease;
        }
        .feature-card:hover {
          border-color: rgba(255, 255, 255, 0.15);
          background: rgba(15, 23, 42, 0.7);
          transform: translateY(-3px);
        }
        .feature-icon {
          width: 44px;
          height: 44px;
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          margin-bottom: 16px;
        }
        .feature-icon.cyan { background: rgba(0, 240, 255, 0.1); color: #00f0ff; }
        .feature-icon.green { background: rgba(16, 185, 129, 0.1); color: #10b981; }
        .feature-icon.crimson { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
        .feature-icon.purple { background: rgba(168, 85, 247, 0.1); color: #a855f7; }
        .feature-icon.yellow { background: rgba(234, 179, 8, 0.1); color: #eab308; }
        .feature-title {
          font-size: 1.05rem;
          font-weight: 700;
          color: #fff;
          margin-bottom: 8px;
        }
        .feature-desc {
          font-size: 0.84rem;
          line-height: 1.55;
          color: #94a3b8;
        }

        /* ── Bottom CTA ────────────────────────────────────────── */
        .home-bottom-cta {
          max-width: 900px;
          margin: 0 auto;
          padding: 40px 24px 80px;
        }
        .bottom-cta-card {
          background: linear-gradient(135deg, rgba(0, 240, 255, 0.08), rgba(139, 92, 246, 0.08));
          border: 1px solid rgba(0, 240, 255, 0.3);
          border-radius: 20px;
          padding: 48px 32px;
          text-align: center;
          display: flex;
          flex-direction: column;
          align-items: center;
          box-shadow: 0 20px 50px rgba(0,0,0,0.5);
        }
        .bottom-cta-title {
          font-size: 2rem;
          font-weight: 800;
          color: #fff;
          margin-bottom: 10px;
        }
        .bottom-cta-desc {
          font-size: 1rem;
          color: #94a3b8;
          max-width: 500px;
          margin-bottom: 28px;
        }

        /* ── Footer ────────────────────────────────────────────── */
        .home-footer {
          border-top: 1px solid rgba(255, 255, 255, 0.08);
          background: #040711;
          padding: 30px 24px;
        }
        .footer-container {
          max-width: 1200px;
          margin: 0 auto;
          display: flex;
          align-items: center;
          justify-content: space-between;
        }
        .footer-left {
          display: flex;
          flex-direction: column;
        }
        .footer-sub {
          font-size: 0.75rem;
          color: #64748b;
          margin-top: 2px;
        }
        .footer-right {
          display: flex;
          align-items: center;
          gap: 20px;
        }
        .footer-status-pill {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          font-size: 0.75rem;
          color: #10b981;
        }
        .status-dot.green {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: #10b981;
        }
        .footer-copy {
          font-size: 0.75rem;
          color: #64748b;
        }

        /* ── Responsive ────────────────────────────────────────── */
        @media (max-width: 992px) {
          .architecture-grid, .features-grid {
            grid-template-columns: 1fr;
          }
          .hero-headline {
            font-size: 2.3rem;
          }
          .hero-stats-row {
            flex-wrap: wrap;
            gap: 16px;
          }
          .hero-stat-divider { display: none; }
        }
        @media (max-width: 768px) {
          .home-nav-links { display: none; }
          .hero-actions {
            flex-direction: column;
            width: 100%;
          }
          .hero-cta-primary, .hero-cta-secondary {
            width: 100%;
            justify-content: center;
          }
          .step-card {
            flex-direction: column;
          }
          .step-line { display: none; }
          .footer-container {
            flex-direction: column;
            gap: 16px;
            text-align: center;
          }
        }
      `}</style>
    </div>
  )
}
