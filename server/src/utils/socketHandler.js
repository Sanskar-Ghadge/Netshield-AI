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
   * @param {object} [db=null] - Database instance for user/agent lookups.
   */
  constructor(httpServer, pythonApiUrl, db = null) {
    this.io = new Server(httpServer, {
      cors: { origin: '*', methods: ['GET', 'POST'] },
    });
    this.pythonApiUrl = pythonApiUrl;
    this.db = db;
    this.connectedClients = 0;
    
    // Map of apiKey -> agent details { socketId, hostname, ip, user, status }
    this.activeAgents = new Map();
    // Map of socketId -> apiKey
    this.socketToApiKey = new Map();

    this._setupConnectionHandler();
  }

  /**
   * Inject or update Database instance.
   */
  setDb(db) {
    this.db = db;
  }

  /**
   * Set up the connection handler for browser clients & laptop agents.
   * @private
   */
  _setupConnectionHandler() {
    this.io.on('connection', (socket) => {
      this.connectedClients++;
      console.log(`[SocketIO] Connection established: ${socket.id}; total=${this.connectedClients}`);

      // Send initial state to browser clients
      this._sendInitialState(socket);

      // ── Agent Event Handlers ─────────────────────────────────────
      
      /** Handle Agent Handshake */
      socket.on('agent:handshake', (data) => {
        const { apiKey, hostname, ip, os } = data || {};
        if (!apiKey) {
          return socket.emit('agent:handshake_ack', { success: false, error: 'API Key missing' });
        }

        if (this.db) {
          const user = this.db.findUserByApiKey(apiKey);
          if (!user) {
            console.warn(`[AgentSocket] Rejected agent handshake: Invalid API Key (${apiKey.slice(0, 10)}...)`);
            return socket.emit('agent:handshake_ack', { success: false, error: 'Invalid or revoked API Key' });
          }

          const agentInfo = {
            socketId: socket.id,
            apiKey,
            hostname: hostname || 'Unknown Laptop',
            ip: ip || '127.0.0.1',
            os: os || 'Windows',
            username: user.username,
            userId: user.id,
            status: data.status || 'STANDBY',
            lastSeen: Date.now(),
          };

          this.activeAgents.set(apiKey, agentInfo);
          this.socketToApiKey.set(socket.id, apiKey);

          console.log(`[AgentSocket] 🟢 Agent paired successfully for user "${user.username}" (${agentInfo.hostname})`);
          
          socket.emit('agent:handshake_ack', { success: true, user: { username: user.username, email: user.email } });
          
          // Broadcast status change to dashboard
          this.io.emit('agent:status_changed', { apiKey, agent: agentInfo });
        } else {
          // Default accept if DB not bound yet
          socket.emit('agent:handshake_ack', { success: true });
        }
      });

      /** Handle Agent Status Update */
      socket.on('agent:status_update', (data) => {
        const { apiKey, status } = data || {};
        if (apiKey && this.activeAgents.has(apiKey)) {
          const agent = this.activeAgents.get(apiKey);
          agent.status = status;
          agent.lastSeen = Date.now();
          this.activeAgents.set(apiKey, agent);

          console.log(`[AgentSocket] Agent status update for "${agent.username}": ${status}`);
          this.io.emit('agent:status_changed', { apiKey, agent });
        }
      });

      /** Streamed packet data from Agent */
      socket.on('agent:packet', (data) => {
        this.broadcastPacket(data);
      });

      /** Streamed attack alert from Agent */
      socket.on('agent:attack_alert', (data) => {
        this.broadcastAttackAlert(data);
      });

      // ── Dashboard Control Handlers ────────────────────────────────
      
      /** Handle Web Dashboard sending START_SNIFFING / STOP_SNIFFING commands */
      socket.on('dashboard:agent_control', (data) => {
        const { apiKey, action } = data || {};
        if (!apiKey) return;

        console.log(`[AgentSocket] Web dashboard triggered "${action}" for API Key ${apiKey.slice(0, 10)}...`);

        const agent = this.activeAgents.get(apiKey);
        if (agent && agent.socketId) {
          // Relay control command to the paired agent socket
          this.io.to(agent.socketId).emit('agent:control', { action });
        } else {
          socket.emit('dashboard:control_error', { error: 'No active laptop agent connected for this API Key.' });
        }
      });

      /** Query Agent Status from Dashboard */
      socket.on('dashboard:query_agent_status', (data) => {
        const { apiKey } = data || {};
        if (apiKey && this.activeAgents.has(apiKey)) {
          socket.emit('agent:status_changed', { apiKey, agent: this.activeAgents.get(apiKey) });
        } else {
          socket.emit('agent:status_changed', { apiKey, agent: null });
        }
      });

      // ── Disconnect Handler ────────────────────────────────────────
      socket.on('disconnect', () => {
        this.connectedClients--;
        
        // If disconnected socket was an Agent
        if (this.socketToApiKey.has(socket.id)) {
          const apiKey = this.socketToApiKey.get(socket.id);
          const agent = this.activeAgents.get(apiKey);
          if (agent) {
            console.log(`[AgentSocket] 🔴 Agent disconnected for user "${agent.username}" (${agent.hostname})`);
            agent.status = 'OFFLINE';
            this.io.emit('agent:status_changed', { apiKey, agent: { ...agent, status: 'OFFLINE' } });
          }
          this.activeAgents.delete(apiKey);
          this.socketToApiKey.delete(socket.id);
        }

        console.log(`[SocketIO] Connection closed; total=${this.connectedClients}`);
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
   * @param {object} data - PredictionResult dictionary.
   */
  broadcastPacket(data) {
    this.io.emit('packet:data', data);
  }

  /**
   * Broadcast an attack alert to all connected clients.
   *
   * @param {object} data - Attack PredictionResult dictionary.
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
