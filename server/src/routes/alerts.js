/**
 * Alert routes — proxies alert test/status endpoints to Python backend.
 *
 * @module routes/alerts
 */

import { Router } from 'express';
import axios from 'axios';

const router = Router();

/**
 * POST /api/alerts/test — test all alert channels.
 * Proxies to Python POST /api/alerts/test.
 */
router.post('/test', async (req, res) => {
  try {
    const resp = await axios.post(
      `${req.pythonApiUrl}/api/alerts/test`,
      {},
      { timeout: 30000 }
    );
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

/**
 * GET /api/alerts/status — return which alert channels are configured.
 * Proxies to Python GET /api/alerts/status.
 */
router.get('/status', async (req, res) => {
  try {
    const resp = await axios.get(
      `${req.pythonApiUrl}/api/alerts/status`,
      { timeout: 10000 }
    );
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

export default router;
