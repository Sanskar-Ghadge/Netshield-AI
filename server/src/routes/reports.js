/**
 * Reports route — proxies to Python /api/report.
 *
 * @module routes/reports
 */

import { Router } from 'express';
import axios from 'axios';

const router = Router();

/**
 * POST /api/reports — trigger PDF report generation.
 */
router.post('/', async (req, res) => {
  try {
    const resp = await axios.post(`${req.pythonApiUrl}/api/report`, {}, { timeout: 30000 });
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
