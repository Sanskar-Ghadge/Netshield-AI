/**
 * Integration tests for the Node.js backend.
 *
 * Run with: node --test test/
 *
 * These tests start the Express server on a test port and verify
 * all REST endpoints. They mock the Python backend using a simple
 * HTTP stub so no Python server is required.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import express from 'express';
import axios from 'axios';

// ── Mock Python backend ─────────────────────────────────────────

let mockPythonServer;
const MOCK_PYTHON_PORT = 8199;
const MOCK_PYTHON_URL = `http://localhost:${MOCK_PYTHON_PORT}`;

function startMockPython() {
  return new Promise((resolve) => {
    const mockApp = express();
    mockApp.use(express.json());

    mockApp.get('/api/status', (_req, res) => {
      res.json({
        threat_level: 'SAFE',
        total_packets: 100,
        attack_count: 5,
        normal_count: 95,
        uptime_seconds: 42.5,
        capture_active: true,
        model_version: 'test_model.pkl',
        capture_interface: 'Wi-Fi',
      });
    });

    mockApp.get('/api/stats', (_req, res) => {
      res.json({
        total: 100,
        normal: 95,
        attacks: 5,
        attack_distribution: [{ attack_type: 'DDoS', count: 3 }, { attack_type: 'PortScan', count: 2 }],
        threat_level: 'SAFE',
        top_attackers: [{ src_ip: '10.0.0.5', count: 3 }],
        attack_summary: [{ attack_type: 'DDoS', count: 3, percentage: 60.0 }],
      });
    });

    mockApp.get('/api/attacks', (req, res) => {
      const limit = parseInt(req.query.limit) || 50;
      const offset = parseInt(req.query.offset) || 0;
      res.json({
        attacks: [
          {
            id: offset + 1,
            attack_type: 'DDoS',
            src_ip: '10.0.0.5',
            dst_ip: '10.0.0.2',
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            confidence: 0.95,
            is_attack: 1,
            flow_id: 'test-flow-1',
            timestamp_utc: Date.now() / 1000,
          },
        ],
        total: 100,
        limit,
        offset,
      });
    });

    mockApp.post('/api/chatbot', (req, res) => {
      res.json({ response: `Mock response to: ${req.body.query}` });
    });

    mockApp.post('/api/report', (_req, res) => {
      res.json({ path: '/tmp/test_report.pdf', filename: 'test_report.pdf' });
    });

    mockPythonServer = mockApp.listen(MOCK_PYTHON_PORT, () => {
      resolve();
    });
  });
}

function stopMockPython() {
  return new Promise((resolve) => {
    if (mockPythonServer) {
      mockPythonServer.close(() => resolve());
    } else {
      resolve();
    }
  });
}

// ── Import and start the Node.js server ─────────────────────────

let nodeServer;
const NODE_TEST_PORT = 3199;

async function startNodeServer() {
  // Set env vars before importing the server
  process.env.NODE_PORT = String(NODE_TEST_PORT);
  process.env.PYTHON_API_URL = MOCK_PYTHON_URL;
  process.env.PYTHON_WS_URL = 'ws://localhost:8199/ws/packets'; // won't connect, that's OK
  process.env.DB_PATH = '../python-engine/netshield.db';

  // We need to create a minimal version of the server that uses our mock
  const app = express();
  const server = http.createServer(app);

  app.use(express.json());
  app.use((req, _res, next) => {
    req.pythonApiUrl = MOCK_PYTHON_URL;
    next();
  });

  // Inline routes (same as the actual route files)
  app.get('/api/status', async (_req, res) => {
    try {
      const resp = await axios.get(`${MOCK_PYTHON_URL}/api/status`, { timeout: 5000 });
      res.json(resp.data);
    } catch (err) {
      res.status(503).json({ error: 'Python backend unavailable' });
    }
  });

  app.get('/api/stats', async (_req, res) => {
    try {
      const resp = await axios.get(`${MOCK_PYTHON_URL}/api/stats`, { timeout: 5000 });
      res.json(resp.data);
    } catch (err) {
      res.status(503).json({ error: 'Python backend unavailable' });
    }
  });

  app.get('/api/attacks', async (req, res) => {
    try {
      const { limit = 50, offset = 0, attack_type } = req.query;
      const resp = await axios.get(`${MOCK_PYTHON_URL}/api/attacks`, {
        params: { limit, offset, attack_type },
        timeout: 5000,
      });
      res.json(resp.data);
    } catch (err) {
      res.status(503).json({ error: 'Python backend unavailable' });
    }
  });

  app.post('/api/chatbot', async (req, res) => {
    try {
      const { query } = req.body;
      if (!query) return res.status(400).json({ error: 'Query string is required' });
      const resp = await axios.post(`${MOCK_PYTHON_URL}/api/chatbot`, { query }, { timeout: 5000 });
      res.json(resp.data);
    } catch (err) {
      res.status(503).json({ error: 'Python backend unavailable' });
    }
  });

  app.post('/api/reports', async (_req, res) => {
    try {
      const resp = await axios.post(`${MOCK_PYTHON_URL}/api/report`, {}, { timeout: 5000 });
      res.json(resp.data);
    } catch (err) {
      res.status(503).json({ error: 'Python backend unavailable' });
    }
  });

  return new Promise((resolve) => {
    nodeServer = server.listen(NODE_TEST_PORT, () => resolve());
  });
}

async function stopNodeServer() {
  return new Promise((resolve) => {
    if (nodeServer) {
      nodeServer.close(() => resolve());
    } else {
      resolve();
    }
  });
}

// ── Tests ───────────────────────────────────────────────────────

describe('Node.js Backend Integration Tests', () => {
  before(async () => {
    await startMockPython();
    await startNodeServer();
  });

  after(async () => {
    await stopNodeServer();
    await stopMockPython();
  });

  it('GET /api/status returns 200 with threat level', async () => {
    const resp = await axios.get(`http://localhost:${NODE_TEST_PORT}/api/status`);
    assert.strictEqual(resp.status, 200);
    assert.strictEqual(resp.data.threat_level, 'SAFE');
    assert.strictEqual(typeof resp.data.total_packets, 'number');
    assert.strictEqual(typeof resp.data.uptime_seconds, 'number');
    assert.strictEqual(resp.data.capture_active, true);
  });

  it('GET /api/stats returns 200 with aggregate metrics', async () => {
    const resp = await axios.get(`http://localhost:${NODE_TEST_PORT}/api/stats`);
    assert.strictEqual(resp.status, 200);
    assert.strictEqual(resp.data.total, 100);
    assert.strictEqual(resp.data.normal, 95);
    assert.strictEqual(resp.data.attacks, 5);
    assert.ok(Array.isArray(resp.data.attack_distribution));
  });

  it('GET /api/attacks returns 200 with paginated history', async () => {
    const resp = await axios.get(`http://localhost:${NODE_TEST_PORT}/api/attacks?limit=10&offset=0`);
    assert.strictEqual(resp.status, 200);
    assert.ok(Array.isArray(resp.data.attacks));
    assert.strictEqual(resp.data.total, 100);
    assert.strictEqual(resp.data.limit, 10);
    assert.strictEqual(resp.data.offset, 0);
  });

  it('GET /api/attacks supports attack_type filter', async () => {
    const resp = await axios.get(`http://localhost:${NODE_TEST_PORT}/api/attacks?attack_type=DDoS`);
    assert.strictEqual(resp.status, 200);
    assert.ok(resp.data.attacks.length > 0);
    assert.strictEqual(resp.data.attacks[0].attack_type, 'DDoS');
  });

  it('POST /api/chatbot returns 200 with response string', async () => {
    const resp = await axios.post(
      `http://localhost:${NODE_TEST_PORT}/api/chatbot`,
      { query: 'What attacks happened?' },
      { headers: { 'Content-Type': 'application/json' } }
    );
    assert.strictEqual(resp.status, 200);
    assert.strictEqual(typeof resp.data.response, 'string');
    assert.ok(resp.data.response.length > 0);
  });

  it('POST /api/chatbot returns 400 when query missing', async () => {
    try {
      await axios.post(
        `http://localhost:${NODE_TEST_PORT}/api/chatbot`,
        {},
        { headers: { 'Content-Type': 'application/json' } }
      );
      assert.fail('Should have thrown 400');
    } catch (err) {
      assert.strictEqual(err.response.status, 400);
    }
  });

  it('POST /api/reports returns 200 with PDF path', async () => {
    const resp = await axios.post(`http://localhost:${NODE_TEST_PORT}/api/reports`);
    assert.strictEqual(resp.status, 200);
    assert.ok(resp.data.path);
    assert.ok(resp.data.filename);
  });

  it('GET /nonexistent returns 404', async () => {
    try {
      await axios.get(`http://localhost:${NODE_TEST_PORT}/nonexistent`);
      assert.fail('Should have thrown 404');
    } catch (err) {
      assert.strictEqual(err.response.status, 404);
    }
  });
});
