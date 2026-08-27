/**
 * Stats route — proxies to Python /api/stats and /api/status.
 *
 * @module routes/stats
 */

import { Router } from 'express';
import axios from 'axios';

const router = Router();

/**
 * GET /api/stats — aggregate statistics and attack distribution.
 */
router.get('/', async (req, res) => {
  try {
    const resp = await axios.get(`${req.pythonApiUrl}/api/stats`, { timeout: 10000 });
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
 * GET /api/status — current threat level, packet counts, uptime.
 */
router.get('/status', async (req, res) => {
  try {
    const resp = await axios.get(`${req.pythonApiUrl}/api/status`, { timeout: 10000 });
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
