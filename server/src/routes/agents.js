/**
 * Express Agent & Devices Router — NetShield AI.
 *
 * Provides endpoints to list, inspect, and revoke paired laptop agent devices.
 *
 * @module routes/agents
 */

import express from 'express';
import { authenticateToken } from './auth.js';

const router = express.Router();

// Protect all /api/agents routes with JWT auth
router.use(authenticateToken);

// ── GET /api/agents ─────────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const db = req.app.get('db');
    const user = db.findUserById(req.user.id);

    if (!user) {
      return res.status(404).json({ error: 'User account not found.' });
    }

    // Get SocketHandler active agents
    const socketHandler = req.app.get('socketHandler');
    const activeAgent = socketHandler && user.api_key ? socketHandler.activeAgents.get(user.api_key) : null;

    const devices = [];

    if (activeAgent) {
      devices.push({
        id: activeAgent.socketId || 1,
        hostname: activeAgent.hostname,
        ip: activeAgent.ip,
        os: activeAgent.os || 'Windows',
        status: activeAgent.status || 'STANDBY',
        apiKey: activeAgent.apiKey,
        lastSeen: activeAgent.lastSeen || Date.now(),
        isCurrentSession: true,
      });
    } else {
      // Return standby device placeholder if registered but offline
      devices.push({
        id: 1,
        hostname: 'Primary Laptop Agent',
        ip: '127.0.0.1',
        os: 'Windows',
        status: 'OFFLINE',
        apiKey: user.api_key,
        lastSeen: user.last_login || Date.now(),
        isCurrentSession: false,
      });
    }

    res.json({ devices });
  } catch (err) {
    console.error('[AgentsAPI] Fetch devices error:', err);
    res.status(500).json({ error: 'Failed to fetch connected devices.' });
  }
});

// ── DELETE /api/agents/:id ──────────────────────────────────────
router.delete('/:id', (req, res) => {
  try {
    const db = req.app.get('db');
    const user = db.findUserById(req.user.id);

    if (!user) {
      return res.status(404).json({ error: 'User account not found.' });
    }

    const socketHandler = req.app.get('socketHandler');
    if (socketHandler && user.api_key) {
      const activeAgent = socketHandler.activeAgents.get(user.api_key);
      if (activeAgent && activeAgent.socketId) {
        // Disconnect active socket
        const socket = socketHandler.io.sockets.sockets.get(activeAgent.socketId);
        if (socket) {
          socket.disconnect(true);
        }
      }
      socketHandler.activeAgents.delete(user.api_key);
    }

    res.json({ message: 'Device disconnected successfully.' });
  } catch (err) {
    console.error('[AgentsAPI] Disconnect agent error:', err);
    res.status(500).json({ error: 'Failed to disconnect agent.' });
  }
});

export default router;
