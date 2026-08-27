/**
 * NetShield AI — Constants and configuration values.
 *
 * @module utils/constants
 */

/** Threat level to colour mapping. */
export const THREAT_COLORS = {
  SAFE: '#22c55e',
  ELEVATED: '#f59e0b',
  CRITICAL: '#ef4444',
}

/** Threat level to background colour mapping (with opacity). */
export const THREAT_BG_COLORS = {
  SAFE: 'rgba(34, 197, 94, 0.15)',
  ELEVATED: 'rgba(245, 158, 11, 0.15)',
  CRITICAL: 'rgba(239, 68, 68, 0.15)',
}

/** Attack type to colour mapping for pie chart and badges. */
export const ATTACK_COLORS = {
  DDoS: '#ef4444',
  DoS: '#f97316',
  PortScan: '#f59e0b',
  BruteForce: '#eab308',
  Bot: '#a855f7',
  WebAttack: '#ec4899',
  Infiltration: '#6366f1',
  Heartbleed: '#14b8a6',
  BENIGN: '#22c55e',
}

/** Protocol number to name mapping. */
export const PROTOCOL_MAP = {
  6: 'TCP',
  17: 'UDP',
  1: 'ICMP',
}

/** Fallback colour palette for unknown attack types. */
export const FALLBACK_COLOR = '#64748b'

/** Base URL for REST API (Node.js server). */
const NODE_URL = import.meta.env.VITE_NODE_URL || 'http://localhost:3001'

export const API_BASE_URL = NODE_URL

/** Socket.io connection URL. */
export const SOCKET_URL = NODE_URL

/** Static model accuracy from training metadata (for display). */
export const MODEL_ACCURACY = '99.92%'

/** Max items in the packet feed buffer. */
export const MAX_PACKET_FEED = 50

/** Max data points in the live traffic chart (rolling window in seconds). */
export const MAX_CHART_POINTS = 60

/** Interval for periodic stats refresh (ms). */
export const STATS_REFRESH_INTERVAL = 30000

/** Alert banner auto-dismiss time (ms). */
export const ALERT_DISMISS_MS = 10000
