/**
 * NetShield AI — Node.js Backend Server.
 *
 * Express REST API + Socket.io real-time push.
 * Bridges the Python FastAPI backend to the React dashboard.
 *
 * Run:
 *   npm start
 *   node src/index.js
 *   node --watch src/index.js  (dev mode with auto-reload)
 *
 * @module index
 */

import express from 'express';
import http from 'http';
import cors from 'cors';
import dotenv from 'dotenv';
import axios from 'axios';

import SocketHandler from './utils/socketHandler.js';
import PythonWsClient from './utils/pythonWs.js';
import attacksRouter from './routes/attacks.js';
import statsRouter from './routes/stats.js';
import reportsRouter from './routes/reports.js';
import chatbotRouter from './routes/chatbot.js';
import alertsRouter from './routes/alerts.js';

// ── Load environment ────────────────────────────────────────────
dotenv.config();

const PORT = parseInt(process.env.NODE_PORT || '3001', 10);
const PYTHON_API_URL = process.env.PYTHON_API_URL || 'http://localhost:8000';
const PYTHON_WS_URL = process.env.PYTHON_WS_URL || 'ws://localhost:8000/ws/packets';

// ── Create Express app ──────────────────────────────────────────
const app = express();
const server = http.createServer(app);

// ── Middleware ──────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

// Inject Python API URL into every request for route handlers
app.use((req, _res, next) => {
  req.pythonApiUrl = PYTHON_API_URL;
  next();
});

// ── REST Routes ─────────────────────────────────────────────────
app.use('/api/attacks', attacksRouter);
app.use('/api/stats', statsRouter);
app.use('/api/reports', reportsRouter);
app.use('/api/chatbot', chatbotRouter);
app.use('/api/alerts', alertsRouter);

// Direct status route (not under /api/stats)
app.get('/api/status', async (_req, res) => {
  try {
    const resp = await axios.get(`${PYTHON_API_URL}/api/status`, { timeout: 10000 });
    res.json(resp.data);
  } catch (err) {
    if (err.code === 'ECONNREFUSED' || err.code === 'ECONNRESET') {
      return res.status(503).json({ error: 'Python backend unavailable' });
    }
    const status = err.response?.status || 500;
    const message = err.response?.data?.detail || err.message;
    res.status(status).json({ error: message });
  }
});

// Reset session data (0 packets, 0 attacks)
app.post('/api/reset', async (_req, res) => {
  try {
    const resp = await axios.post(`${PYTHON_API_URL}/api/reset`, {}, { timeout: 10000 });
    res.json(resp.data);
  } catch (err) {
    if (err.code === 'ECONNREFUSED' || err.code === 'ECONNRESET') {
      return res.status(503).json({ error: 'Python backend unavailable' });
    }
    const status = err.response?.status || 500;
    const message = err.response?.data?.detail || err.message;
    res.status(status).json({ error: message });
  }
});

// Health check for Node.js itself
app.get('/api/node-health', (_req, res) => {
  res.json({
    status: 'ok',
    node_port: PORT,
    python_api_url: PYTHON_API_URL,
    python_ws_url: PYTHON_WS_URL,
    connected_clients: socketHandler ? socketHandler.getConnectedCount() : 0,
    python_ws_connected: pythonWsConnected,
  });
});

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

// ── Socket.io handler ───────────────────────────────────────────
const socketHandler = new SocketHandler(server, PYTHON_API_URL);

// ── Python WebSocket client ─────────────────────────────────────
let pythonWsConnected = false;

const pythonWs = new PythonWsClient(
  PYTHON_WS_URL,
  (message) => {
    // ── Envelope events from Python's ws_manager ───────────
    if (message.event === 'attack:alert' && message.data) {
      socketHandler.broadcastAttackAlert(message.data);
      return;
    }

    if (message.event === 'connected') {
      // Initial welcome from Python — ignore, we send our own.
      return;
    }

    // ── Raw PredictionResult (no envelope) ────────────────
    if (message.status && message.label !== undefined) {
      socketHandler.broadcastPacket(message);
      if (message.is_attack) {
        socketHandler.broadcastAttackAlert(message);
      }
      return;
    }

    // ── Unknown format — broadcast as generic packet ──────
    socketHandler.broadcastPacket(message);
  },
  (status) => {
    pythonWsConnected = status === 'connected';
  }
);

pythonWs.connect();

// ── Threat level polling (every 10 seconds) ─────────────────────
setInterval(async () => {
  try {
    const resp = await axios.get(`${PYTHON_API_URL}/api/status`, { timeout: 5000 });
    socketHandler.broadcastThreatUpdate(resp.data.threat_level, {
      total_packets: resp.data.total_packets,
      attack_count: resp.data.attack_count,
    });
  } catch (err) {
    // Python backend might be down — don't spam logs
  }
}, 10000);

// ── Startup ─────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\n╔════════════════════════════════════════════╗`);
  console.log(`║   NetShield AI — Node.js Backend           ║`);
  console.log(`╠════════════════════════════════════════════╣`);
  console.log(`║   Port:           ${PORT.toString().padEnd(24)}║`);
  console.log(`║   Python API:     ${PYTHON_API_URL.padEnd(24)}║`);
  console.log(`║   Python WS:      ${PYTHON_WS_URL.padEnd(24)}║`);
  console.log(`║   Dashboard:      http://localhost:${PORT}     ║`);
  console.log(`╚════════════════════════════════════════════╝\n`);
});

// ── Graceful shutdown ──────────────────────────────────────────
function shutdown() {
  console.log('\n[Server] Shutting down...');
  pythonWs.disconnect();
  socketHandler.close();
  server.close(() => {
    console.log('[Server] HTTP server closed.');
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
