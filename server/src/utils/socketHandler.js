/**
 * Socket.io handler — manages browser connections and broadcasts
 * live data from the Python backend.
 *
 * @module utils/socketHandler
 */

import { Server } from 'socket.io';
import axios from 'axios';

/**
 * Manages Socket.io connections to the React dashboard.
 */
class SocketHandler {
  /**
   * Create the Socket.io server.
   *
   * @param {import('http').Server} httpServer - Node.js HTTP server.
   * @param {string} pythonApiUrl - Python FastAPI base URL.
   */
  constructor(httpServer, pythonApiUrl) {
    this.io = new Server(httpServer, {
      cors: { origin: '*', methods: ['GET', 'POST'] },
    });
    this.pythonApiUrl = pythonApiUrl;
    this.connectedClients = 0;
    this._setupConnectionHandler();
  }

  /**
   * Set up the connection handler for new browser clients.
   * @private
   */
  _setupConnectionHandler() {
    this.io.on('connection', (socket) => {
      this.connectedClients++;
      console.log(`[SocketIO] Client connected; total=${this.connectedClients}`);

      // Send initial state on connect
      this._sendInitialState(socket);

      socket.on('disconnect', () => {
        this.connectedClients--;
        console.log(`[SocketIO] Client disconnected; total=${this.connectedClients}`);
      });
    });
  }

  /**
   * Send initial state to a newly connected client.
   *
   * @param {import('socket.io').Socket} socket - The connected socket.
   * @private
   */
  async _sendInitialState(socket) {
    try {
      const [statusResp, attacksResp] = await Promise.all([
        axios.get(`${this.pythonApiUrl}/api/status`, { timeout: 5000 }),
        axios.get(`${this.pythonApiUrl}/api/attacks?limit=10`, { timeout: 5000 }),
      ]);

      socket.emit('initial:state', {
        status: statusResp.data,
        recentAttacks: attacksResp.data.attacks,
        threatLevel: statusResp.data.threat_level,
      });
    } catch (err) {
      console.error(`[SocketIO] Failed to fetch initial state: ${err.message}`);
      socket.emit('initial:state', {
        status: null,
        recentAttacks: [],
        threatLevel: 'SAFE',
        error: 'Python backend unavailable',
      });
    }
  }

  /**
   * Broadcast a prediction result to all connected clients.
   *
   * @param {object} data - PredictionResult dictionary from Python.
   */
  broadcastPacket(data) {
    this.io.emit('packet:data', data);
  }

  /**
   * Broadcast an attack alert to all connected clients.
   *
   * @param {object} data - Attack PredictionResult dictionary from Python.
   */
  broadcastAttackAlert(data) {
    this.io.emit('attack:alert', data);
  }

  /**
   * Broadcast a threat level update to all connected clients.
   *
   * @param {string} level - Current threat level ('SAFE'|'ELEVATED'|'CRITICAL').
   * @param {object} [extra={}] - Additional data to include.
   */
  broadcastThreatUpdate(level, extra = {}) {
    this.io.emit('threat:update', { threatLevel: level, ...extra });
  }

  /**
   * Get the number of connected browser clients.
   *
   * @returns {number} Connected client count.
   */
  getConnectedCount() {
    return this.connectedClients;
  }

  /**
   * Close the Socket.io server.
   */
  close() {
    this.io.close();
  }
}

export default SocketHandler;
