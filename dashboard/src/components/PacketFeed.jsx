/**
 * NetShield AI — Packet feed component.
 *
 * Live scrolling feed of recent packet predictions. New packets are
 * prepended to the top with a fade-in animation. Holds a maximum of 50
 * items. If the user scrolls up, auto-scroll is paused until they click
 * the "new packets" indicator.
 *
 * @module components/PacketFeed
 */

import { useEffect, useRef, useState } from 'react'
import { Radio } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { formatTime, formatEndpoint, formatConfidence, protocolName } from '../utils/format.js'
import { ATTACK_COLORS, MAX_PACKET_FEED } from '../utils/constants.js'

export default function PacketFeed() {
  const { packets } = useDashboard()
  const listRef = useRef(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [pendingCount, setPendingCount] = useState(0)

  // Auto-scroll to top when new packets arrive if not paused
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
        <span className="chart-title">
          <Radio size={15} style={{ display: 'inline', verticalAlign: 'middle', marginRight: 6 }} />
          Live Packet Feed
        </span>
        <span className="feed-count text-muted mono">{packets.length}</span>
      </div>

      <div
        ref={listRef}
        className="feed-list"
        onScroll={handleScroll}
      >
        {packets.length === 0 ? (
          <div className="feed-empty text-muted">Waiting for packets…</div>
        ) : (
          packets.map((pkt, i) => {
            const isAttack = pkt.is_attack
            const color = isAttack
              ? (ATTACK_COLORS[pkt.label] || '#ef4444')
              : 'var(--accent-cyan)'
            const ctx = pkt.context || {}
            return (
              <div
                key={`${pkt.timestamp_utc}-${i}`}
                className={`feed-item ${isAttack ? 'feed-item-attack' : ''}`}
                style={{ animationDelay: i < 5 ? `${i * 0.03}s` : '0s' }}
              >
                <span className="feed-dot" style={{ background: color }} />
                <span className="feed-label" style={{ color }}>{pkt.label}</span>
                <span className="feed-ip mono">
                  {formatEndpoint(ctx.src_ip, ctx.src_port)}
                  {' → '}
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
          padding: 16px;
          display: flex;
          flex-direction: column;
          height: 420px;
        }
        .feed-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 8px;
        }
        .feed-count {
          font-size: 0.8rem;
          background: var(--bg-tertiary);
          padding: 2px 8px;
          border-radius: 8px;
        }
        .feed-list {
          flex: 1;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 2px;
        }
        .feed-empty {
          text-align: center;
          padding: 40px 0;
          font-size: 0.85rem;
        }
        .feed-item {
          display: grid;
          grid-template-columns: 8px 70px 1fr 40px 60px 70px;
          align-items: center;
          gap: 8px;
          padding: 6px 8px;
          border-radius: 6px;
          font-size: 0.75rem;
          animation: fade-in 0.3s ease;
          transition: background 0.2s;
        }
        .feed-item:hover {
          background: var(--bg-tertiary);
        }
        .feed-item-attack {
          background: rgba(239,68,68,0.06);
          border-left: 2px solid var(--accent-crimson);
        }
        .feed-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          flex-shrink: 0;
        }
        .feed-label {
          font-weight: 600;
          font-size: 0.72rem;
          white-space: nowrap;
        }
        .feed-ip {
          font-size: 0.72rem;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
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
          background: var(--bg-tertiary);
          border-radius: 6px;
          color: var(--accent-cyan);
          font-size: 0.8rem;
          cursor: pointer;
          margin-top: 4px;
          transition: background 0.2s;
        }
        .feed-new-packets:hover {
          background: var(--bg-hover);
        }
        @media (max-width: 768px) {
          .feed-item {
            grid-template-columns: 8px 60px 1fr 50px;
          }
          .feed-proto, .feed-conf { display: none; }
        }
      `}</style>
    </div>
  )
}
