/**
 * Chatbot route — proxies to Python /api/chatbot.
 *
 * @module routes/chatbot
 */

import { Router } from 'express';
import axios from 'axios';

const router = Router();

/**
 * POST /api/chatbot — query the Gemini-powered chatbot.
 *
 * Body: { query: "..." }
 */
router.post('/', async (req, res) => {
  try {
    const { query } = req.body;
    if (!query || typeof query !== 'string') {
      return res.status(400).json({ error: 'Query string is required' });
    }
    const resp = await axios.post(
      `${req.pythonApiUrl}/api/chatbot`,
      { query },
      { timeout: 90000 }
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
 * GET /api/chatbot/status — check if Gemini chatbot is available.
 */
router.get('/status', async (req, res) => {
  try {
    const resp = await axios.get(
      `${req.pythonApiUrl}/api/chatbot/status`,
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
