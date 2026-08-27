/**
 * NetShield AI — App root component.
 *
 * Sets up the React Router with three routes (Dashboard, History, Reports),
 * wraps everything in the DashboardContext provider, and renders the Header
 * in a persistent layout shell. Also shows a disconnect banner when the
 * Socket.io connection drops.
 *
 * @module App
 */

import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { DashboardProvider, useDashboard } from './context/DashboardContext.jsx'
import Header from './components/Header.jsx'
import Dashboard from './pages/Dashboard.jsx'
import History from './pages/History.jsx'
import Reports from './pages/Reports.jsx'
import { WifiOff } from 'lucide-react'

function DisconnectBanner() {
  const { socketConnected } = useDashboard()
  if (socketConnected) return null
  return (
    <div className="disconnect-banner">
      <WifiOff size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
      Disconnected from server — attempting to reconnect…
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <DashboardProvider>
        <div className="app-layout">
          <DisconnectBanner />
          <Header />
          <main className="app-main">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/history" element={<History />} />
              <Route path="/reports" element={<Reports />} />
            </Routes>
          </main>
        </div>
      </DashboardProvider>
    </BrowserRouter>
  )
}
