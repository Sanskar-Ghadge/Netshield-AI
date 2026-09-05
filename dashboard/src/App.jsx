/**
 * NetShield AI — Enterprise SOC Layout App root component.
 *
 * Sets up the Enterprise SOC Operations Layout with a collapsible left sidebar,
 * top command control bar, multi-tab workspace router, and floating AI assistant.
 *
 * @module App
 */

import { useState } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { DashboardProvider, useDashboard } from './context/DashboardContext.jsx'
import Sidebar from './components/Sidebar.jsx'
import TopBar from './components/TopBar.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Analytics from './pages/Analytics.jsx'
import History from './pages/History.jsx'
import Reports from './pages/Reports.jsx'
import SystemStatus from './pages/SystemStatus.jsx'
import Chatbot from './components/Chatbot.jsx'
import { WifiOff } from 'lucide-react'

function DisconnectBanner() {
  const { socketConnected } = useDashboard()
  if (socketConnected) return null
  return (
    <div className="disconnect-banner">
      <WifiOff size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
      Disconnected from SOC Server — attempting automatic reconnect…
    </div>
  )
}

function MainLayout() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [chatOpen, setChatOpen] = useState(false)

  return (
    <div className="soc-layout">
      <DisconnectBanner />
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(prev => !prev)} />
      
      <div className="soc-main-shell">
        <TopBar onOpenChat={() => setChatOpen(true)} />
        <main className="soc-workspace">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/history" element={<History />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/status" element={<SystemStatus />} />
          </Routes>
        </main>
      </div>

      <Chatbot externalOpen={chatOpen} onExternalClose={() => setChatOpen(false)} />

      <style>{`
        .soc-layout {
          display: flex;
          min-height: 100vh;
          width: 100vw;
          overflow-x: hidden;
          background: var(--bg-dark);
        }
        .soc-main-shell {
          flex: 1;
          display: flex;
          flex-direction: column;
          min-width: 0;
        }
        .soc-workspace {
          flex: 1;
          padding: 24px;
          max-width: 1700px;
          width: 100%;
          margin: 0 auto;
        }
        @media (max-width: 768px) {
          .soc-workspace {
            padding: 14px;
          }
        }
      `}</style>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <DashboardProvider>
        <MainLayout />
      </DashboardProvider>
    </BrowserRouter>
  )
}
