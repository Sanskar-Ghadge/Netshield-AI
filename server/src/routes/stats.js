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
    const resp = await axios.get(`${req.pythonApiUrl}/api/stats`, { timeout: 3000 });
    return res.json(resp.data);
  } catch (err) {
    try {
      const db = req.app.get('db');
      const stats = db.getStats();
      stats.threat_level = 'SAFE';
      stats.top_attackers = db.getTopAttackers();
      stats.attack_summary = db.getAttackSummary();
      return res.json(stats);
    } catch (fallbackErr) {
      return res.status(503).json({ error: 'Backend unavailable' });
    }
  }
});

/**
 * GET /api/status — current threat level, packet counts, uptime.
 */
router.get('/status', async (req, res) => {
  try {
    const resp = await axios.get(`${req.pythonApiUrl}/api/status`, { timeout: 3000 });
    return res.json(resp.data);
  } catch (err) {
    try {
      const db = req.app.get('db');
      const stats = db.getStats();
      return res.json({
        threat_level: 'SAFE',
        total_packets: stats.total,
        attack_count: stats.attacks,
        normal_count: stats.normal,
        uptime_seconds: process.uptime(),
        capture_active: false,
        model_version: 'v3',
      });
    } catch (fallbackErr) {
      return res.status(503).json({ error: 'Backend unavailable' });
    }
  }
});

export default router;
