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
    const { limit = 50, offset = 0, attack_type, only_attacks } = req.query;
    const params = { limit, offset };
    if (attack_type) params.attack_type = attack_type;
    if (only_attacks !== undefined) params.only_attacks = only_attacks;
    const resp = await axios.get(`${req.pythonApiUrl}/api/attacks`, {
      params,
      timeout: 3000,
    });
    return res.json(resp.data);
  } catch (err) {
    try {
      const db = req.app.get('db');
      const limit = Math.min(parseInt(req.query.limit || '50', 10), 500);
      const offset = parseInt(req.query.offset || '0', 10);
      const onlyAttacks = req.query.only_attacks !== 'false';
      const rows = db.getAttacks(limit, offset, req.query.attack_type, onlyAttacks);
      const stats = db.getStats();
      return res.json({
        attacks: rows,
        total: onlyAttacks ? stats.attacks : stats.total,
        limit,
        offset,
      });
    } catch (fallbackErr) {
      return res.status(503).json({ error: 'Backend unavailable' });
    }
  }
});

export default router;
