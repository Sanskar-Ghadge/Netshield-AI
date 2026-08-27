/**
 * NetShield AI — Main dashboard page.
 *
 * Combines all components into a responsive grid layout.
 *
 * @module pages/Dashboard
 */

import StatsCards from '../components/StatsCards.jsx'
import ThreatIndicator from '../components/ThreatIndicator.jsx'
import LiveTrafficChart from '../components/LiveTrafficChart.jsx'
import AttackPieChart from '../components/AttackPieChart.jsx'
import PacketFeed from '../components/PacketFeed.jsx'
import AttackHistory from '../components/AttackHistory.jsx'
import AlertBanner from '../components/AlertBanner.jsx'
import Chatbot from '../components/Chatbot.jsx'
import SystemInfo from '../components/SystemInfo.jsx'

export default function Dashboard() {
  return (
    <>
      <AlertBanner />

      <StatsCards />

      <div className="dashboard-grid">
        <div className="grid-col-span-2">
          <LiveTrafficChart />
        </div>
        <div className="grid-col-1">
          <ThreatIndicator />
        </div>
      </div>

      <div className="dashboard-grid" style={{ marginTop: '20px' }}>
        <div className="grid-col-1">
          <AttackPieChart />
        </div>
        <div className="grid-col-1">
          <PacketFeed />
        </div>
        <div className="grid-col-1">
          <AttackHistory compact />
        </div>
      </div>

      <div className="dashboard-grid" style={{ marginTop: '20px' }}>
        <div className="grid-col-span-2">
          <SystemInfo />
        </div>
        <div className="grid-col-1" />
      </div>

      <Chatbot />

      <style>{`
        .dashboard-grid {
          display: grid;
          grid-template-columns: 1fr 1fr 1fr;
          gap: 20px;
        }
        .grid-col-span-2 {
          grid-column: span 2;
        }
        .grid-col-1 {
          grid-column: span 1;
        }
        @media (max-width: 1199px) {
          .dashboard-grid {
            grid-template-columns: 1fr 1fr;
          }
          .grid-col-span-2 {
            grid-column: span 2;
          }
        }
        @media (max-width: 767px) {
          .dashboard-grid {
            grid-template-columns: 1fr;
          }
          .grid-col-span-2, .grid-col-1 {
            grid-column: span 1;
          }
        }
      `}</style>
    </>
  )
}
