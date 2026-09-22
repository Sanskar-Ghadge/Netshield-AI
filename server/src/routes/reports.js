/**
 * Reports route — proxies to Python /api/report.
 *
 * @module routes/reports
 */

import { Router } from 'express';
import axios from 'axios';

const router = Router();

/**
 * GET /api/reports/download or POST /api/reports/download
 * Streams the PDF directly to the browser for instant download without saving to disk.
 */
async function handleDownload(req, res) {
  try {
    const resp = await axios.get(`${req.pythonApiUrl}/api/report/download`, {
      responseType: 'arraybuffer',
      timeout: 45000,
    });
    const disposition = resp.headers['content-disposition'] || 'attachment; filename="netshield_security_report.pdf"';
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', disposition);
    res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');
    return res.send(Buffer.from(resp.data));
  } catch (err) {
    if (err.code === 'ECONNREFUSED' || err.code === 'ECONNRESET') {
      return res.status(503).json({ error: 'Python backend unavailable' });
    }
    const status = err.response?.status || 500;
    const message = err.response?.data?.detail || err.message;
    return res.status(status).json({ error: message });
  }
}

router.get('/', handleDownload);
router.get('/download', handleDownload);
router.post('/download', handleDownload);

/**
 * POST /api/reports — trigger PDF report generation.
 * If ?download=true query is provided, streams the PDF file. Otherwise returns metadata.
 */
router.post('/', async (req, res) => {
  if (req.query.download === 'true') {
    return handleDownload(req, res);
  }

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
