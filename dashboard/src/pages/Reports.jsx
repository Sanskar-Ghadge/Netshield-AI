/**
 * NetShield AI — PDF report generation page.
 *
 * Allows the user to trigger PDF report generation. Shows a summary
 * of what the report contains and the file path after generation.
 *
 * @module pages/Reports
 */

import { useState } from 'react'
import { FileText, Download, FileCheck, Loader2 } from 'lucide-react'
import { generateReport } from '../api/client.js'
import { useDashboard } from '../context/DashboardContext.jsx'

export default function Reports() {
  const { attackCount, totalPackets, threatLevel, attackSummary } = useDashboard()
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const handleGenerate = async () => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const data = await generateReport()
      setResult(data)
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Failed to generate report'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const handleRetry = () => {
    setError(null)
    handleGenerate()
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">Security Reports</h1>
        <p className="page-subtitle text-muted">
          Generate a comprehensive PDF security report
        </p>
      </div>

      <div className="reports-grid">
        {/* Summary card */}
        <div className="glass-card report-summary-card">
          <div className="report-card-header">
            <FileText size={20} style={{ color: 'var(--accent-cyan)' }} />
            <span className="report-card-title">Current System State</span>
          </div>
          <div className="report-stats">
            <div className="report-stat-row">
              <span className="text-muted">Total Packets Analysed</span>
              <span className="mono">{totalPackets.toLocaleString()}</span>
            </div>
            <div className="report-stat-row">
              <span className="text-muted">Attacks Detected</span>
              <span className="mono text-crimson">{attackCount.toLocaleString()}</span>
            </div>
            <div className="report-stat-row">
              <span className="text-muted">Threat Level</span>
              <span className="mono">{threatLevel}</span>
            </div>
            <div className="report-stat-row">
              <span className="text-muted">Attack Types</span>
              <span className="mono">{attackSummary.length}</span>
            </div>
          </div>
        </div>

        {/* Generate button card */}
        <div className="glass-card report-action-card">
          <div className="report-card-header">
            <FileCheck size={20} style={{ color: 'var(--accent-green)' }} />
            <span className="report-card-title">Generate PDF Report</span>
          </div>
          <p className="report-desc text-muted">
            The report includes: executive summary, attack breakdown table,
            top 10 attacker IPs, and security recommendations.
          </p>
          <button
            className="generate-btn"
            onClick={handleGenerate}
            disabled={loading}
          >
            {loading ? (
              <>
                <Loader2 size={18} className="spin" />
                Generating…
              </>
            ) : (
              <>
                <Download size={18} />
                Generate Report
              </>
            )}
          </button>

          {result && (
            <div className="report-result">
              <div className="report-result-icon">
                <FileCheck size={24} style={{ color: 'var(--accent-green)' }} />
              </div>
              <div className="report-result-info">
                <span className="report-result-title">Report Generated!</span>
                <span className="report-result-file mono text-muted">
                  {result.filename}
                </span>
                <span className="report-result-path mono text-faint">
                  {result.path}
                </span>
              </div>
            </div>
          )}

          {error && (
            <div className="report-error">
              <span>{error}</span>
              <button className="retry-btn" onClick={handleRetry}>Retry</button>
            </div>
          )}
        </div>
      </div>

      <style>{`
        .page-container {
          max-width: 1000px;
        }
        .page-header {
          margin-bottom: 24px;
        }
        .page-title {
          font-size: 1.5rem;
          font-weight: 700;
        }
        .page-subtitle {
          font-size: 0.85rem;
          margin-top: 4px;
        }
        .reports-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 20px;
        }
        @media (max-width: 767px) {
          .reports-grid {
            grid-template-columns: 1fr;
          }
        }
        .report-summary-card, .report-action-card {
          padding: 24px;
          display: flex;
          flex-direction: column;
          gap: 16px;
        }
        .report-card-header {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .report-card-title {
          font-size: 0.95rem;
          font-weight: 600;
        }
        .report-stats {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }
        .report-stat-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          font-size: 0.85rem;
          padding: 6px 0;
          border-bottom: 1px solid rgba(30,41,59,0.5);
        }
        .report-desc {
          font-size: 0.82rem;
          line-height: 1.5;
        }
        .generate-btn {
          display: flex;
          align-items: center;
          gap: 8px;
          justify-content: center;
          padding: 12px 24px;
          background: var(--accent-cyan);
          color: var(--bg-primary);
          border: none;
          border-radius: 10px;
          font-size: 0.9rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }
        .generate-btn:hover:not(:disabled) {
          box-shadow: 0 0 20px rgba(0,240,255,0.3);
        }
        .generate-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
        .report-result {
          display: flex;
          gap: 12px;
          padding: 14px;
          background: rgba(34,197,94,0.08);
          border: 1px solid rgba(34,197,94,0.2);
          border-radius: 8px;
          animation: fade-in 0.3s;
        }
        .report-result-info {
          display: flex;
          flex-direction: column;
          gap: 4px;
          word-break: break-all;
        }
        .report-result-title {
          font-weight: 600;
          color: var(--accent-green);
          font-size: 0.9rem;
        }
        .report-result-file {
          font-size: 0.85rem;
        }
        .report-result-path {
          font-size: 0.72rem;
        }
        .report-error {
          padding: 12px;
          background: rgba(239,68,68,0.08);
          border: 1px solid rgba(239,68,68,0.2);
          border-radius: 8px;
          color: var(--accent-crimson);
          font-size: 0.85rem;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }
        .retry-btn {
          background: rgba(0,240,255,0.1);
          border: 1px solid rgba(0,240,255,0.3);
          border-radius: 6px;
          padding: 4px 12px;
          color: var(--accent-cyan);
          font-size: 0.8rem;
          cursor: pointer;
          transition: all 0.2s;
          flex-shrink: 0;
        }
        .retry-btn:hover {
          background: rgba(0,240,255,0.2);
        }
        .spin {
          animation: spin 1s linear infinite;
        }
      `}</style>
    </div>
  )
}
