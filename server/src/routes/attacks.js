/**
 * Attacks route — proxies to Python /api/attacks.
 *
 * @module routes/attacks
 */

import { Router } from 'express';
import axios from 'axios';

const router = Router();

/**
 * GET /api/attacks — paginated attack/prediction history.
 *
 * Query params:
 *   limit (default 50, max 500)
 *   offset (default 0)
 *   attack_type (optional filter)
 */
router.get('/', async (req, res) => {
  try {
    const { limit = 50, offset = 0, attack_type } = req.query;
    const resp = await axios.get(`${req.pythonApiUrl}/api/attacks`, {
      params: { limit, offset, attack_type },
      timeout: 10000,
    });
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
