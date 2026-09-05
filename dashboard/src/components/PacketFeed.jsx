/**
 * NetShield AI — Live packet feed component.
 *
 * Live scrolling feed of recent packet predictions with animated badges,
 * glowing attack indicators, and smart scroll controls.
 *
 * @module components/PacketFeed
 */

import { useEffect, useRef, useState } from 'react'
import { Radio } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { formatTime, formatEndpoint, formatConfidence, protocolName } from '../utils/format.js'
import { ATTACK_COLORS } from '../utils/constants.js'

export default function PacketFeed() {
  const { packets } = useDashboard()
  const listRef = useRef(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [pendingCount, setPendingCount] = useState(0)

  useEffect(() => {
    if (autoScroll && listRef.current) {
      listRef.current.scrollTop = 0
      setPendingCount(0)
    } else {
      setPendingCount(prev => prev + 1)
    }
  }, [packets])

  const handleScroll = () => {
    if (!listRef.current) return
    const atTop = listRef.current.scrollTop === 0
    setAutoScroll(atTop)
    if (atTop) setPendingCount(0)
  }

  const resumeScroll = () => {
    setAutoScroll(true)
    if (listRef.current) listRef.current.scrollTop = 0
    setPendingCount(0)
  }

  return (
    <div className="glass-card feed-card">
      <div className="feed-header">
        <div className="feed-title-wrap">
          <Radio size={16} className="text-cyan pulse-icon" />
          <span className="chart-title">Live Packet Feed</span>
        </div>
        <span className="feed-count text-muted mono">{packets.length}</span>
      </div>

      <div ref={listRef} className="feed-list" onScroll={handleScroll}>
        {packets.length === 0 ? (
          <div className="feed-empty text-muted">Listening for live packet flows…</div>
        ) : (
          packets.map((pkt, i) => {
            const isAttack = pkt.is_attack
            const color = isAttack
              ? (ATTACK_COLORS[pkt.label] || '#ff2a5f')
              : 'var(--accent-cyan)'
            const ctx = pkt.context || {}
            return (
              <div
                key={`${pkt.timestamp_utc}-${i}`}
                className={`feed-item ${isAttack ? 'feed-item-attack' : ''}`}
              >
                <span className="feed-dot" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
                <span className="feed-label" style={{ color, borderColor: `${color}40`, background: `${color}12` }}>
                  {pkt.label}
                </span>
                <span className="feed-ip mono">
                  {formatEndpoint(ctx.src_ip, ctx.src_port)}
                  <span className="arrow"> → </span>
                  {formatEndpoint(ctx.dst_ip, ctx.dst_port)}
                </span>
                <span className="feed-proto text-muted">{protocolName(ctx.protocol)}</span>
                <span className="feed-conf mono text-muted">
                  {formatConfidence(pkt.confidence)}
                </span>
                <span className="feed-time mono text-faint">
                  {formatTime(pkt.timestamp_utc)}
                </span>
              </div>
            )
          })
        )}
      </div>

      {pendingCount > 0 && (
        <div className="feed-new-packets" onClick={resumeScroll}>
          ↓ {pendingCount} new packet{pendingCount !== 1 ? 's' : ''}
        </div>
      )}

      <style>{`
        .feed-card {
          padding: 20px;
          display: flex;
          flex-direction: column;
          height: 425px;
        }
        .feed-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 12px;
        }
        .feed-title-wrap {
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .chart-title {
          font-family: var(--font-heading);
          font-size: 0.95rem;
          font-weight: 700;
          color: var(--text-primary);
        }
        .pulse-icon {
          animation: pulse-ring 2s infinite;
        }
        .feed-count {
          font-size: 0.75rem;
          background: rgba(30, 41, 59, 0.6);
          border: 1px solid rgba(255, 255, 255, 0.08);
          padding: 2px 8px;
          border-radius: 12px;
        }
        .feed-list {
          flex: 1;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 3px;
        }
        .feed-empty {
          text-align: center;
          padding: 60px 0;
          font-size: 0.85rem;
        }
        .feed-item {
          display: grid;
          grid-template-columns: 8px 80px 1fr 40px 60px 70px;
          align-items: center;
          gap: 8px;
          padding: 7px 10px;
          border-radius: 8px;
          font-size: 0.75rem;
          background: rgba(15, 23, 42, 0.3);
          border: 1px solid transparent;
          animation: fade-in 0.25s ease;
          transition: all 0.2s;
        }
        .feed-item:hover {
          background: rgba(30, 41, 59, 0.5);
          border-color: rgba(56, 189, 248, 0.2);
        }
        .feed-item-attack {
          background: rgba(255, 42, 95, 0.08);
          border: 1px solid rgba(255, 42, 95, 0.25);
          box-shadow: inset 3px 0 0 var(--accent-crimson);
        }
        .feed-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          flex-shrink: 0;
        }
        .feed-label {
          font-weight: 700;
          font-size: 0.68rem;
          text-align: center;
          padding: 1px 6px;
          border-radius: 6px;
          border: 1px solid;
          white-space: nowrap;
        }
        .feed-ip {
          font-size: 0.72rem;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }
        .arrow {
          color: var(--accent-cyan);
          opacity: 0.7;
        }
        .feed-proto {
          font-size: 0.7rem;
          text-align: center;
        }
        .feed-conf {
          font-size: 0.7rem;
          text-align: right;
        }
        .feed-time {
          font-size: 0.68rem;
          text-align: right;
          white-space: nowrap;
        }
        .feed-new-packets {
          text-align: center;
          padding: 6px;
          background: rgba(0, 240, 255, 0.1);
          border: 1px solid rgba(0, 240, 255, 0.3);
          border-radius: 8px;
          color: var(--accent-cyan);
          font-size: 0.78rem;
          font-weight: 600;
          cursor: pointer;
          margin-top: 6px;
          transition: all 0.2s;
        }
        .feed-new-packets:hover {
          background: rgba(0, 240, 255, 0.2);
        }
        @media (max-width: 768px) {
          .feed-item {
            grid-template-columns: 8px 70px 1fr 50px;
          }
          .feed-proto, .feed-conf { display: none; }
        }
      `}</style>
    </div>
  )
}
