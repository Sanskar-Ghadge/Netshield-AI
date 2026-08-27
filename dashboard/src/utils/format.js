/**
 * NetShield AI — Formatting utility functions.
 *
 * @module utils/format
 */

/**
 * Format a Unix timestamp (seconds) to "HH:MM:SS UTC".
 *
 * @param {number} utc - Unix epoch in seconds.
 * @returns {string} Formatted time string.
 */
export function formatTime(utc) {
  if (!utc || typeof utc !== 'number') return '--:--:--'
  const d = new Date(utc * 1000)
  return d.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone: 'UTC',
  }) + ' UTC'
}

/**
 * Format a Unix timestamp to a full date-time string.
 *
 * @param {number} utc - Unix epoch in seconds.
 * @returns {string} Formatted date-time string.
 */
export function formatDateTime(utc) {
  if (!utc || typeof utc !== 'number') return 'N/A'
  const d = new Date(utc * 1000)
  return d.toLocaleString('en-GB', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone: 'UTC',
  }) + ' UTC'
}

/**
 * Format a number with thousands separators.
 *
 * @param {number} n - The number to format.
 * @returns {string} Number with commas, e.g. "1,234,567".
 */
export function formatNumber(n) {
  if (n === null || n === undefined || typeof n !== 'number') return '0'
  return n.toLocaleString('en-US')
}

/**
 * Format a confidence float as a percentage string.
 *
 * @param {number} c - Confidence value (0–1).
 * @returns {string} Percentage string, e.g. "95.43%".
 */
export function formatConfidence(c) {
  if (c === null || c === undefined || typeof c !== 'number') return '0.00%'
  return (c * 100).toFixed(2) + '%'
}

/**
 * Map a protocol number to its name.
 *
 * @param {number} p - Protocol number.
 * @returns {string} Protocol name.
 */
export function protocolName(p) {
  const map = { 6: 'TCP', 17: 'UDP', 1: 'ICMP' }
  return map[p] || `Proto-${p || '?'}`
}

/**
 * Truncate a string to a max length with ellipsis.
 *
 * @param {string} str - The string to truncate.
 * @param {number} maxLen - Maximum length.
 * @returns {string} Truncated string.
 */
export function truncateStr(str, maxLen) {
  if (!str || typeof str !== 'string') return ''
  if (str.length <= maxLen) return str
  return str.substring(0, maxLen - 1) + '…'
}

/**
 * Format flow duration from microseconds to a human-readable string.
 *
 * @param {number} us - Duration in microseconds.
 * @returns {string} Human-readable duration.
 */
export function formatDuration(us) {
  if (!us || typeof us !== 'number' || us <= 0) return '0 μs'
  if (us < 1000) return `${Math.round(us)} μs`
  if (us < 1_000_000) return `${(us / 1000).toFixed(1)} ms`
  return `${(us / 1_000_000).toFixed(2)} s`
}

/**
 * Format an IP:port pair for display.
 *
 * @param {string} ip - IP address.
 * @param {number} port - Port number.
 * @returns {string} "ip:port" string.
 */
export function formatEndpoint(ip, port) {
  if (!ip) return 'unknown'
  return port ? `${ip}:${port}` : ip
}
