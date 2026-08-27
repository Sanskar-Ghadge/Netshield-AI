/**
 * NetShield AI — Axios HTTP client and API functions.
 *
 * All REST calls go through the Node.js backend on port 3001.
 * No direct calls to the Python FastAPI server are made from the browser.
 *
 * @module api/client
 */

import axios from 'axios'
import { API_BASE_URL } from '../utils/constants.js'

/** Configured axios instance with default timeout and base URL. */
const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

/**
 * Fetch the current system status.
 *
 * @returns {Promise<object>} Status response.
 */
export async function getStatus() {
  const { data } = await client.get('/api/status')
  return data
}

/**
 * Fetch aggregate statistics including attack distribution.
 *
 * @returns {Promise<object>} Stats response.
 */
export async function getStats() {
  const { data } = await client.get('/api/stats')
  return data
}

/**
 * Fetch paginated attack history.
 *
 * @param {number} [limit=50] - Max rows.
 * @param {number} [offset=0] - Pagination offset.
 * @param {string|null} [attackType=null] - Filter by attack type.
 * @returns {Promise<object>} { attacks, total, limit, offset }
 */
export async function getAttacks(limit = 50, offset = 0, attackType = null) {
  const params = { limit, offset }
  if (attackType && attackType !== 'All') {
    params.attack_type = attackType
  }
  const { data } = await client.get('/api/attacks', { params })
  return data
}

/**
 * Send a query to the Gemini-powered chatbot.
 *
 * @param {string} query - User's question.
 * @returns {Promise<string>} Chatbot response text.
 */
export async function sendChatbotQuery(query) {
  const { data } = await client.post('/api/chatbot', { query }, { timeout: 120000 })
  return data.response
}

/**
 * Check whether the Gemini chatbot is available (API key set + model loaded).
 *
 * @returns {Promise<object>} { available, model, api_key_configured }
 */
export async function getChatbotStatus() {
  const { data } = await client.get('/api/chatbot/status')
  return data
}

/**
 * Test all alert channels (Telegram, Email, Voice).
 *
 * @returns {Promise<object>} { telegram: {...}, email: {...}, voice: {...} }
 */
export async function testAlerts() {
  const { data } = await client.post('/api/alerts/test', {})
  return data
}

/**
 * Get alert channel configuration status.
 *
 * @returns {Promise<object>} { channels: { telegram, email, voice } }
 */
export async function getAlertStatus() {
  const { data } = await client.get('/api/alerts/status')
  return data
}

/**
 * Trigger PDF report generation.
 *
 * @returns {Promise<object>} { path, filename }
 */
export async function generateReport() {
  const { data } = await client.post('/api/reports', {})
  return data
}

/**
 * Check Node.js backend health.
 *
 * @returns {Promise<object>} Health response.
 */
export async function getNodeHealth() {
  const { data } = await client.get('/api/node-health')
  return data
}
