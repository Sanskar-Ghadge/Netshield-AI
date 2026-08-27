/**
 * Python WebSocket client — connects to Python FastAPI /ws/packets.
 *
 * Receives live prediction results and attack alerts, forwards them
 * to the callback for Socket.io broadcasting.
 *
 * @module utils/pythonWs
 */

import WebSocket from 'ws';

/**
 * Manages a persistent WebSocket connection to the Python backend
 * with automatic reconnection.
 */
class PythonWsClient {
  /**
   * Create the WebSocket client.
   *
   * @param {string} url - Python WebSocket URL (e.g. ws://localhost:8000/ws/packets).
   * @param {function} onMessage - Callback for each received message (parsed JSON).
   * @param {function} [onStatusChange] - Callback for connection status changes ('connected' | 'disconnected').
   */
  constructor(url, onMessage, onStatusChange) {
    this.url = url;
    this.onMessage = onMessage;
    this.onStatusChange = onStatusChange || (() => {});
    this.ws = null;
    this.reconnectDelay = 1000;
    this.maxReconnectDelay = 30000;
    this.heartbeatInterval = null;
    this.shouldReconnect = true;
  }

  /**
   * Connect to the Python WebSocket and start listening.
   */
  connect() {
    if (!this.shouldReconnect) return;

    try {
      this.ws = new WebSocket(this.url);
    } catch (err) {
      console.error(`[PythonWS] Failed to create WebSocket: ${err.message}`);
      this._scheduleReconnect();
      return;
    }

    this.ws.on('open', () => {
      console.log('[PythonWS] Connected to Python WebSocket');
      this.reconnectDelay = 1000;
      this.onStatusChange('connected');
      this._startHeartbeat();
    });

    this.ws.on('message', (data) => {
      try {
        const parsed = JSON.parse(data.toString());
        this.onMessage(parsed);
      } catch (err) {
        console.error(`[PythonWS] Failed to parse message: ${err.message}`);
      }
    });

    this.ws.on('close', () => {
      console.warn('[PythonWS] Disconnected from Python WebSocket');
      this.onStatusChange('disconnected');
      this._stopHeartbeat();
      this._scheduleReconnect();
    });

    this.ws.on('error', (err) => {
      console.error(`[PythonWS] WebSocket error: ${err.message}`);
    });
  }

  /**
   * Disconnect and stop reconnection attempts.
   */
  disconnect() {
    this.shouldReconnect = false;
    this._stopHeartbeat();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  /**
   * Schedule a reconnection with exponential backoff.
   * @private
   */
  _scheduleReconnect() {
    if (!this.shouldReconnect) return;

    const delay = this.reconnectDelay;
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
    console.log(`[PythonWS] Reconnecting in ${delay / 1000}s...`);

    setTimeout(() => this.connect(), delay);
  }

  /**
   * Start a heartbeat ping to keep the connection alive.
   * @private
   */
  _startHeartbeat() {
    this.heartbeatInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.ping();
      }
    }, 30000);
  }

  /**
   * Stop the heartbeat interval.
   * @private
   */
  _stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }
}

export default PythonWsClient;
