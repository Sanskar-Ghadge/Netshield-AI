/**
 * NetShield AI — Enterprise SOC Sidebar Navigation Component.
 *
 * Collapsible sidebar navigation for switching between enterprise workspaces:
 * Overview, Analytics, Attack Logs, Reports, and System Status.
 *
 * @module components/Sidebar
 */

import { useState } from 'react'
import { NavLink } from 'react-router-dom'
import {
  Shield,
  LayoutDashboard,
  PieChart,
  Activity,
  FileText,
  Terminal,
  Bot,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'

export default function Sidebar({ collapsed, onToggle }) {
  const { attackCount, socketConnected } = useDashboard()

  return (
    <aside className={`soc-sidebar ${collapsed ? 'collapsed' : ''}`}>
      {/* Sidebar Header / Logo */}
      <div className="sidebar-header">
        <div className="sidebar-logo-group">
          <div className="sidebar-logo-icon">
            <Shield size={24} className="logo-shield" />
          </div>
          {!collapsed && (
            <div className="logo-text">
              <span className="brand-name">NetShield <span className="brand-ai">AI</span></span>
              <span className="brand-subtitle">SOC Operations</span>
            </div>
          )}
        </div>
        <button className="sidebar-toggle" onClick={onToggle} title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}>
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>

      {/* Navigation Menu */}
      <nav className="sidebar-menu">
        <div className="menu-label">{!collapsed ? 'SOC Workspaces' : '•'}</div>

        <NavLink to="/" end className={({ isActive }) => `sidebar-item ${isActive ? 'active' : ''}`}>
          <LayoutDashboard size={18} className="item-icon" />
          {!collapsed && <span className="item-text">Overview</span>}
        </NavLink>

        <NavLink to="/analytics" className={({ isActive }) => `sidebar-item ${isActive ? 'active' : ''}`}>
          <PieChart size={18} className="item-icon" />
          {!collapsed && <span className="item-text">Analytics</span>}
        </NavLink>

        <NavLink to="/history" className={({ isActive }) => `sidebar-item ${isActive ? 'active' : ''}`}>
          <div className="icon-with-badge">
            <Activity size={18} className="item-icon" />
            {attackCount > 0 && <span className="nav-badge-dot" />}
          </div>
          {!collapsed && (
            <div className="item-text-row">
              <span className="item-text">Attack Logs</span>
              {attackCount > 0 && <span className="nav-count-badge mono">{attackCount}</span>}
            </div>
          )}
        </NavLink>

        <NavLink to="/reports" className={({ isActive }) => `sidebar-item ${isActive ? 'active' : ''}`}>
          <FileText size={18} className="item-icon" />
          {!collapsed && <span className="item-text">Reports</span>}
        </NavLink>

        <div className="menu-label" style={{ marginTop: '16px' }}>{!collapsed ? 'System' : '•'}</div>

        <NavLink to="/status" className={({ isActive }) => `sidebar-item ${isActive ? 'active' : ''}`}>
          <Terminal size={18} className="item-icon" />
          {!collapsed && <span className="item-text">System Status</span>}
        </NavLink>
      </nav>

      {/* Sidebar Footer / AI Prompt */}
      <div className="sidebar-footer">
        {!collapsed && (
          <div className="ai-banner">
            <div className="ai-banner-top">
              <Bot size={16} className="text-cyan" />
              <span className="ai-banner-title">AI Assistant</span>
            </div>
            <span className="ai-banner-desc text-muted">Press <kbd className="mono">Ctrl+K</kbd> to query threats</span>
          </div>
        )}
        <div className="system-live-indicator">
          <span className={`status-dot ${socketConnected ? 'pulse-dot' : 'offline-dot'}`} />
          {!collapsed && (
            <span className="status-label mono">
              {socketConnected ? 'SOC ENGINE ONLINE' : 'ENGINE OFFLINE'}
            </span>
          )}
        </div>
      </div>

      <style>{`
        .soc-sidebar {
          width: 240px;
          height: 100vh;
          background: rgba(8, 14, 28, 0.95);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border-right: 1px solid var(--border-default);
          display: flex;
          flex-direction: column;
          position: sticky;
          top: 0;
          z-index: 150;
          transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1);
          box-shadow: 4px 0 25px rgba(0, 0, 0, 0.3);
        }
        .soc-sidebar.collapsed {
          width: 72px;
        }

        /* ── Sidebar Header ── */
        .sidebar-header {
          height: var(--header-height);
          padding: 0 16px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 1px solid var(--border-default);
        }
        .sidebar-logo-group {
          display: flex;
          align-items: center;
          gap: 10px;
          overflow: hidden;
        }
        .sidebar-logo-icon {
          width: 36px;
          height: 36px;
          border-radius: 10px;
          background: rgba(0, 240, 255, 0.1);
          border: 1px solid rgba(0, 240, 255, 0.3);
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
        }
        .logo-shield {
          color: var(--accent-cyan);
          filter: drop-shadow(0 0 6px rgba(0, 240, 255, 0.6));
        }
        .logo-text {
          display: flex;
          flex-direction: column;
          white-space: nowrap;
        }
        .brand-name {
          font-family: var(--font-heading);
          font-weight: 800;
          font-size: 1.1rem;
          color: var(--text-primary);
          line-height: 1;
        }
        .brand-ai {
          background: linear-gradient(135deg, #00f0ff, #38bdf8);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }
        .brand-subtitle {
          font-size: 0.65rem;
          font-family: var(--font-mono);
          color: var(--accent-cyan);
          letter-spacing: 0.5px;
          opacity: 0.8;
          margin-top: 2px;
        }
        .sidebar-toggle {
          background: rgba(30, 41, 59, 0.6);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 6px;
          color: var(--text-secondary);
          width: 26px;
          height: 26px;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          transition: all 0.2s;
          flex-shrink: 0;
        }
        .sidebar-toggle:hover {
          background: rgba(0, 240, 255, 0.15);
          color: var(--accent-cyan);
          border-color: rgba(0, 240, 255, 0.3);
        }

        /* ── Menu Items ── */
        .sidebar-menu {
          flex: 1;
          padding: 16px 10px;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }
        .menu-label {
          font-size: 0.68rem;
          font-weight: 700;
          color: var(--text-tertiary);
          text-transform: uppercase;
          letter-spacing: 1px;
          padding: 0 10px 6px 10px;
          white-space: nowrap;
        }
        .sidebar-item {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 10px 12px;
          border-radius: 10px;
          color: var(--text-secondary);
          text-decoration: none;
          font-size: 0.86rem;
          font-weight: 600;
          transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
          white-space: nowrap;
          border: 1px solid transparent;
        }
        .sidebar-item:hover {
          color: var(--text-primary);
          background: rgba(255, 255, 255, 0.04);
        }
        .sidebar-item.active {
          background: linear-gradient(135deg, rgba(0, 240, 255, 0.14), rgba(56, 189, 248, 0.06));
          color: var(--accent-cyan);
          border-color: rgba(0, 240, 255, 0.3);
          box-shadow: 0 0 15px rgba(0, 240, 255, 0.12);
        }
        .item-icon {
          flex-shrink: 0;
        }
        .icon-with-badge {
          position: relative;
          display: flex;
          align-items: center;
        }
        .nav-badge-dot {
          position: absolute;
          top: -2px;
          right: -2px;
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: var(--accent-crimson);
          box-shadow: 0 0 8px var(--accent-crimson);
        }
        .item-text-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          width: 100%;
        }
        .nav-count-badge {
          font-size: 0.68rem;
          background: rgba(255, 42, 95, 0.2);
          color: var(--accent-crimson);
          border: 1px solid rgba(255, 42, 95, 0.4);
          padding: 1px 6px;
          border-radius: 10px;
        }

        /* ── Sidebar Footer ── */
        .sidebar-footer {
          padding: 14px;
          border-top: 1px solid var(--border-default);
          display: flex;
          flex-direction: column;
          gap: 12px;
        }
        .ai-banner {
          background: rgba(15, 23, 42, 0.6);
          border: 1px solid rgba(0, 240, 255, 0.15);
          border-radius: 10px;
          padding: 10px 12px;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }
        .ai-banner-top {
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .ai-banner-title {
          font-size: 0.78rem;
          font-weight: 700;
          color: var(--text-primary);
        }
        .ai-banner-desc {
          font-size: 0.68rem;
        }
        .ai-banner-desc kbd {
          background: rgba(0, 240, 255, 0.1);
          border: 1px solid rgba(0, 240, 255, 0.25);
          color: var(--accent-cyan);
          padding: 1px 4px;
          border-radius: 4px;
        }
        .system-live-indicator {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 0.68rem;
          color: var(--text-secondary);
        }
        .status-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          flex-shrink: 0;
        }
        .pulse-dot {
          background: var(--accent-green);
          box-shadow: 0 0 10px var(--accent-green);
        }
        .offline-dot {
          background: var(--accent-crimson);
        }
      `}</style>
    </aside>
  )
}
