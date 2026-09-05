/**
 * NetShield AI — System Status Workspace Page.
 *
 * Full system health, machine learning model details, and network capture interface diagnostic.
 *
 * @module pages/SystemStatus
 */

import SystemInfo from '../components/SystemInfo.jsx'
import { Cpu, ShieldCheck, Terminal, HardDrive, Database, Server } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { MODEL_ACCURACY } from '../utils/constants.js'

export default function SystemStatus() {
  const { captureActive, captureInterface, modelVersion, socketConnected, totalPackets } = useDashboard()

  return (
    <div className="status-page flex-col gap-lg">
      <SystemInfo />

      <div className="dashboard-grid">
        <div className="glass-card status-detail-card">
          <div className="chart-header">
            <Cpu size={18} className="text-cyan" />
            <span className="chart-title">Machine Learning Model Metadata</span>
          </div>
          <div className="status-kv-list">
            <div className="kv-item">
              <span className="text-muted">Model Classifier</span>
              <span className="mono">XGBoost Multiclass v3</span>
            </div>
            <div className="kv-item">
              <span className="text-muted">Training Dataset</span>
              <span className="mono">CICIDS2017 Benchmark</span>
            </div>
            <div className="kv-item">
              <span className="text-muted">Test Accuracy Score</span>
              <span className="mono text-green">{MODEL_ACCURACY}</span>
            </div>
            <div className="kv-item">
              <span className="text-muted">Input Features</span>
              <span className="mono">40 Standardized Flow Metrics</span>
            </div>
            <div className="kv-item">
              <span className="text-muted">Model Binary File</span>
              <span className="mono text-faint">{modelVersion || 'xgboost_cicids2017_v3.pkl'}</span>
            </div>
          </div>
        </div>

        <div className="glass-card status-detail-card">
          <div className="chart-header">
            <ShieldCheck size={18} className="text-green" />
            <span className="chart-title">Live Sniffer & Traffic Filter</span>
          </div>
          <div className="status-kv-list">
            <div className="kv-item">
              <span className="text-muted">Capture Engine</span>
              <span className="mono">Scapy / Npcap Live Sniffer</span>
            </div>
            <div className="kv-item">
              <span className="text-muted">Selected Interface</span>
              <span className="mono text-cyan">{captureInterface || 'Wi-Fi'}</span>
            </div>
            <div className="kv-item">
              <span className="text-muted">Sniffer State</span>
              <span className="mono text-green">{captureActive ? 'RECORDING' : 'INACTIVE'}</span>
            </div>
            <div className="kv-item">
              <span className="text-muted">Noise Pre-Filter</span>
              <span className="mono text-green">ACTIVE (ICMP/DHCP Bypass)</span>
            </div>
            <div className="kv-item">
              <span className="text-muted">Total Analysed Packets</span>
              <span className="mono">{totalPackets.toLocaleString()}</span>
            </div>
          </div>
        </div>

        <div className="glass-card status-detail-card">
          <div className="chart-header">
            <Server size={18} className="text-amber" />
            <span className="chart-title">Backend REST & Socket Gateway</span>
          </div>
          <div className="status-kv-list">
            <div className="kv-item">
              <span className="text-muted">FastAPI Python Engine</span>
              <span className="mono text-green">Port 8000</span>
            </div>
            <div className="kv-item">
              <span className="text-muted">Node.js API Express</span>
              <span className="mono text-green">Port 3001</span>
            </div>
            <div className="kv-item">
              <span className="text-muted">Socket.io Connection</span>
              <span className="mono text-green">{socketConnected ? 'CONNECTED' : 'DISCONNECTED'}</span>
            </div>
            <div className="kv-item">
              <span className="text-muted">Database Storage</span>
              <span className="mono">SQLite (netshield.db)</span>
            </div>
          </div>
        </div>
      </div>

      <style>{`
        .status-detail-card {
          padding: 20px;
          display: flex;
          flex-direction: column;
          gap: 14px;
        }
        .status-kv-list {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }
        .kv-item {
          display: flex;
          justify-content: space-between;
          font-size: 0.8rem;
          padding: 6px 0;
          border-bottom: 1px solid rgba(30, 41, 59, 0.4);
        }
      `}</style>
    </div>
  )
}
