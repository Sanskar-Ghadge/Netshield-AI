/**
 * NetShield AI — Attack history table component.
 *
 * Sortable, filterable, paginated table of recent attacks. In compact mode
 * shows 5 rows for the dashboard; in full mode shows 20 rows per page
 * for the History page. Also supports CSV export of the current page.
 *
 * @module components/AttackHistory
 */

import { useEffect, useState, useCallback, useMemo } from 'react'
import { ChevronUp, ChevronDown, ChevronLeft, ChevronRight, Download } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { getAttacks } from '../api/client.js'
import { ATTACK_COLORS, FALLBACK_COLOR } from '../utils/constants.js'
import { formatTime, formatConfidence, protocolName, formatEndpoint } from '../utils/format.js'

/** Column definitions — keys must match API field names. */
const COLUMNS = [
  { key: 'timestamp_utc', label: 'Time', sortable: true, width: '90px' },
  { key: 'attack_type', label: 'Type', sortable: true, width: '90px' },
  { key: 'src_ip', label: 'Source', sortable: true, width: '1fr' },
  { key: 'dst_ip', label: 'Destination', sortable: true, width: '1fr' },
  { key: 'protocol', label: 'Proto', sortable: true, width: '60px' },
  { key: 'confidence', label: 'Confidence', sortable: true, width: '100px' },
]

/**
 * Compare two row values for sorting.
 *
 * @param {any} a - First value.
 * @param {any} b - Second value.
 * @param {('asc'|'desc')} dir - Sort direction.
 * @returns {number} Comparison result.
 */
function compareValues(a, b, dir) {
  let aVal = a
  let bVal = b
  if (typeof aVal === 'string') aVal = aVal.toLowerCase()
  if (typeof bVal === 'string') bVal = bVal.toLowerCase()
  if (aVal < bVal) return dir === 'asc' ? -1 : 1
  if (aVal > bVal) return dir === 'asc' ? -1 : 1
  return 0
}

/**
 * Convert an array of attack rows to a CSV string.
 *
 * @param {Array<object>} rows - Attack rows from the API.
 * @returns {string} CSV text.
 */
function rowsToCsv(rows) {
  const headers = COLUMNS.map(c => c.label)
  const lines = [headers.join(',')]
  for (const r of rows) {
    const vals = COLUMNS.map(c => {
      let v = r[c.key]
      if (c.key === 'timestamp_utc') v = formatTime(v)
      if (c.key === 'confidence') v = formatConfidence(v)
      if (c.key === 'protocol') v = protocolName(v)
      if (c.key === 'src_ip') v = formatEndpoint(r.src_ip, r.src_port)
      if (c.key === 'dst_ip') v = formatEndpoint(r.dst_ip, r.dst_port)
      const s = String(v ?? '')
      return s.includes(',') ? `"${s}"` : s
    })
    lines.push(vals.join(','))
  }
  return lines.join('\n')
}

/**
 * Trigger a browser download of a CSV file.
 *
 * @param {string} csv - CSV text.
 * @param {string} filename - Download filename.
 */
function downloadCsv(csv, filename) {
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export default function AttackHistory({ compact = false, showFilters = false }) {
  const { recentAttacks } = useDashboard()
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [sortKey, setSortKey] = useState('timestamp_utc')
  const [sortDir, setSortDir] = useState('desc')
  const [filter, setFilter] = useState('All')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const pageSize = compact ? 5 : 20

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getAttacks(pageSize, page * pageSize, filter === 'All' ? null : filter)
      setRows(data.attacks || [])
      setTotal(data.total || 0)
    } catch (err) {
      setError(err.message || 'Failed to fetch attacks')
      setRows([])
    } finally {
      setLoading(false)
    }
  }, [page, filter, pageSize])

  useEffect(() => {
    if (!compact) {
      fetchData()
    }
  }, [fetchData, compact])

  // Base rows for display: live context data in compact mode, fetched rows otherwise.
  const baseRows = compact ? recentAttacks.slice(0, pageSize) : rows

  // Apply sorting to base rows.  This works for both compact and full modes.
  const displayRows = useMemo(() => {
    return [...baseRows].sort((a, b) => compareValues(a[sortKey], b[sortKey], sortDir))
  }, [baseRows, sortKey, sortDir])

  const handleSort = (key) => {
    if (sortKey === key) {
      setSortDir(prev => prev === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('desc')
    }
  }

  const handleExport = () => {
    const csv = rowsToCsv(displayRows)
    const ts = new Date().toISOString().replace(/[:.]/g, '-')
    downloadCsv(csv, `netshield_attacks_${ts}.csv`)
  }

  const totalPages = Math.ceil(total / pageSize)

  return (
    <div className="glass-card history-card">
      <div className="chart-header">
        <span className="chart-title">
          {compact ? 'Recent Attacks' : 'Attack History'}
        </span>
        <div className="history-header-actions">
          {showFilters && (
            <select
              className="history-filter"
              value={filter}
              onChange={(e) => { setFilter(e.target.value); setPage(0) }}
            >
              <option value="All">All Types</option>
              <option value="DDoS">DDoS</option>
              <option value="DoS">DoS</option>
              <option value="PortScan">Port Scan</option>
              <option value="BruteForce">Brute Force</option>
              <option value="Bot">Bot</option>
              <option value="WebAttack">Web Attack</option>
              <option value="Infiltration">Infiltration</option>
              <option value="Heartbleed">Heartbleed</option>
            </select>
          )}
          {displayRows.length > 0 && (
            <button className="history-export-btn" onClick={handleExport} title="Export CSV">
              <Download size={14} />
              CSV
            </button>
          )}
        </div>
      </div>

      <div className="history-table-wrap">
        <table className="history-table">
          <thead>
            <tr>
              {COLUMNS.map(col => (
                <th
                  key={col.key}
                  onClick={() => col.sortable && handleSort(col.key)}
                  style={{ cursor: col.sortable ? 'pointer' : 'default', width: col.width }}
                >
                  <span className="th-content">
                    {col.label}
                    {sortKey === col.key && (
                      sortDir === 'asc'
                        ? <ChevronUp size={12} />
                        : <ChevronDown size={12} />
                    )}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={COLUMNS.length} className="history-empty">Loading…</td></tr>
            ) : error ? (
              <tr>
                <td colSpan={COLUMNS.length} className="history-error">
                  {error} — <button className="retry-link" onClick={fetchData}>retry</button>
                </td>
              </tr>
            ) : displayRows.length === 0 ? (
              <tr><td colSpan={COLUMNS.length} className="history-empty">No attacks recorded</td></tr>
            ) : (
              displayRows.map((row, i) => {
                const isAttack = row.is_attack === 1 || row.is_attack === true
                const color = isAttack
                  ? (ATTACK_COLORS[row.attack_type] || FALLBACK_COLOR)
                  : 'var(--accent-green)'
                return (
                  <tr key={row.id || i}>
                    <td className="mono text-faint">
                      {formatTime(row.timestamp_utc)}
                    </td>
                    <td>
                      <span className="type-badge" style={{ color, borderColor: color + '50', background: color + '15' }}>
                        {row.attack_type}
                      </span>
                    </td>
                    <td className="mono">
                      {formatEndpoint(row.src_ip, row.src_port)}
                    </td>
                    <td className="mono">
                      {formatEndpoint(row.dst_ip, row.dst_port)}
                    </td>
                    <td className="text-muted">
                      {protocolName(row.protocol)}
                    </td>
                    <td>
                      <div className="conf-cell">
                        <div className="conf-bar-bg">
                          <div
                            className="conf-bar-fill"
                            style={{
                              width: `${(row.confidence || 0) * 100}%`,
                              background: color,
                            }}
                          />
                        </div>
                        <span className="mono text-muted">
                          {formatConfidence(row.confidence)}
                        </span>
                      </div>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {!compact && totalPages > 1 && (
        <div className="history-pagination">
          <button
            disabled={page === 0}
            onClick={() => setPage(p => Math.max(0, p - 1))}
            className="page-btn"
          >
            <ChevronLeft size={16} />
          </button>
          <span className="page-info mono">
            Page {page + 1} of {totalPages} ({total.toLocaleString()} total)
          </span>
          <button
            disabled={page >= totalPages - 1}
            onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
            className="page-btn"
          >
            <ChevronRight size={16} />
          </button>
        </div>
      )}

      <style>{`
        .history-card {
          padding: 16px;
          display: flex;
          flex-direction: column;
          height: 100%;
        }
        .history-header-actions {
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .history-filter {
          background: var(--bg-tertiary);
          color: var(--text-primary);
          border: 1px solid var(--border-default);
          border-radius: 6px;
          padding: 4px 8px;
          font-size: 0.8rem;
          cursor: pointer;
        }
        .history-export-btn {
          display: flex;
          align-items: center;
          gap: 4px;
          background: var(--bg-tertiary);
          color: var(--text-secondary);
          border: 1px solid var(--border-default);
          border-radius: 6px;
          padding: 4px 10px;
          font-size: 0.72rem;
          cursor: pointer;
          transition: all 0.2s;
        }
        .history-export-btn:hover {
          background: var(--bg-hover);
          border-color: var(--accent-cyan);
          color: var(--accent-cyan);
        }
        .history-table-wrap {
          flex: 1;
          overflow-x: auto;
          overflow-y: auto;
        }
        .history-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.78rem;
        }
        .history-table th {
          text-align: left;
          padding: 8px 10px;
          color: var(--text-secondary);
          font-weight: 500;
          font-size: 0.72rem;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          border-bottom: 1px solid var(--border-default);
          white-space: nowrap;
        }
        .th-content {
          display: flex;
          align-items: center;
          gap: 3px;
        }
        .history-table td {
          padding: 7px 10px;
          border-bottom: 1px solid rgba(30,41,59,0.5);
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }
        .history-table tr:hover td {
          background: var(--bg-tertiary);
        }
        .history-empty {
          text-align: center !important;
          padding: 24px !important;
          color: var(--text-tertiary);
        }
        .history-error {
          text-align: center !important;
          padding: 24px !important;
          color: var(--accent-crimson);
        }
        .retry-link {
          background: none;
          border: none;
          color: var(--accent-cyan);
          cursor: pointer;
          text-decoration: underline;
          font-size: inherit;
        }
        .type-badge {
          display: inline-block;
          padding: 2px 8px;
          border-radius: 8px;
          font-size: 0.7rem;
          font-weight: 600;
          border: 1px solid;
        }
        .conf-cell {
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .conf-bar-bg {
          width: 50px;
          height: 4px;
          background: var(--bg-hover);
          border-radius: 2px;
          overflow: hidden;
          flex-shrink: 0;
        }
        .conf-bar-fill {
          height: 100%;
          border-radius: 2px;
          transition: width 0.3s;
        }
        .history-pagination {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 12px;
          padding: 10px 0 0;
        }
        .page-btn {
          background: var(--bg-tertiary);
          border: 1px solid var(--border-default);
          border-radius: 6px;
          padding: 4px 8px;
          color: var(--text-primary);
          cursor: pointer;
          display: flex;
          align-items: center;
          transition: all 0.2s;
        }
        .page-btn:hover:not(:disabled) {
          background: var(--bg-hover);
          border-color: var(--accent-cyan);
        }
        .page-btn:disabled {
          opacity: 0.3;
          cursor: not-allowed;
        }
        .page-info {
          font-size: 0.75rem;
          color: var(--text-secondary);
        }
      `}</style>
    </div>
  )
}
