/**
 * NetShield AI — Alert banner component.
 *
 * Full-width flashing red banner that slides down from the top when an
 * attack is detected. Auto-dismisses after 10 seconds. Queues multiple
 * alerts and shows one at a time.
 *
 * @module components/AlertBanner
 */

import { useEffect, useState, useRef } from 'react'
import { AlertOctagon, X } from 'lucide-react'
import { useDashboard } from '../context/DashboardContext.jsx'
import { formatConfidence, formatEndpoint } from '../utils/format.js'
import { ALERT_DISMISS_MS } from '../utils/constants.js'

export default function AlertBanner() {
  const { lastAttack } = useDashboard()
  const [queue, setQueue] = useState([])
  const [current, setCurrent] = useState(null)
  const seenRef = useRef(new Set())
  const timerRef = useRef(null)

  // Add new attacks to the queue
  useEffect(() => {
    if (!lastAttack || !lastAttack.is_attack) return
    const id = lastAttack.timestamp_utc + '_' + (lastAttack.context?.flow_id || '')
    if (seenRef.current.has(id)) return
    seenRef.current.add(id)
    // Keep the set from growing forever
    if (seenRef.current.size > 200) {
      const arr = Array.from(seenRef.current)
      seenRef.current = new Set(arr.slice(-100))
    }
    setQueue(prev => [...prev, { ...lastAttack, _alertId: id }])
  }, [lastAttack])

  // Promote next from queue
  useEffect(() => {
    if (!current && queue.length > 0) {
      setCurrent(queue[0])
      setQueue(prev => prev.slice(1))
    }
  }, [current, queue])

  // Auto-dismiss
  useEffect(() => {
    if (!current) return
    timerRef.current = setTimeout(() => setCurrent(null), ALERT_DISMISS_MS)
    return () => clearTimeout(timerRef.current)
  }, [current])

  const dismiss = () => {
    clearTimeout(timerRef.current)
    setCurrent(null)
  }

  if (!current) return null

  const ctx = current.context || {}
  const src = formatEndpoint(ctx.src_ip, ctx.src_port)
  const dst = formatEndpoint(ctx.dst_ip, ctx.dst_port)

  return (
    <div className="alert-banner" onClick={dismiss}>
      <AlertOctagon size={22} className="alert-icon" />
      <span className="alert-text">
        <strong>{current.label}</strong> detected from{' '}
        <span className="mono">{src}</span>
        {' → '}
        <span className="mono">{dst}</span>
        {' — '}
        Confidence: <strong>{formatConfidence(current.confidence)}</strong>
      </span>
      <X size={18} className="alert-close" />
      <span className="alert-hint">Click to dismiss</span>

      <style>{`
        .alert-banner {
          position: fixed;
          top: var(--header-height);
          left: 0;
          right: 0;
          z-index: 500;
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 24px;
          background: linear-gradient(90deg, rgba(239,68,68,0.95), rgba(220,38,38,0.95));
          color: white;
          cursor: pointer;
          animation: slide-down 0.3s ease, flash-red 2s infinite;
          box-shadow: 0 4px 20px rgba(239,68,68,0.3);
        }
        .alert-icon {
          flex-shrink: 0;
          animation: pulse-dot 1s infinite;
        }
        .alert-text {
          flex: 1;
          font-size: 0.9rem;
        }
        .alert-close {
          flex-shrink: 0;
          opacity: 0.7;
          transition: opacity 0.2s;
        }
        .alert-banner:hover .alert-close {
          opacity: 1;
        }
        .alert-hint {
          font-size: 0.7rem;
          opacity: 0.6;
          white-space: nowrap;
        }
        @media (max-width: 768px) {
          .alert-hint { display: none; }
          .alert-text { font-size: 0.8rem; }
        }
      `}</style>
    </div>
  )
}
