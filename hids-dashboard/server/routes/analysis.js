const express = require('express');
const router = express.Router();
const FileHistory = require('../models/FileHistory');

const hasUserHistory = async (userId) => {
  const count = await FileHistory.countDocuments({ userId });
  return count > 0;
};

// GET /api/analysis/ips - Grouped by source_ip with threat stats
router.get('/ips', async (req, res) => {
  try {
    return res.json([]);
  } catch (error) {
    console.error('IP analysis error:', error);
    res.status(500).json({
      error: 'Data Error',
      message: error.message
    });
  }
});

// GET /api/analysis/timeline - Grouped by hour/day for time series
router.get('/timeline', async (req, res) => {
  try {
    if (!(await hasUserHistory(req.user.id))) {
      return res.json([]);
    }

    const files = await FileHistory.find({ userId: req.user.id, status: 'completed' }).lean();
    const timeline = {};

    files.forEach((file) => {
      const date = new Date(file.processedAt || file.uploadedAt || Date.now());
      const key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:00`;

      if (!timeline[key]) {
        timeline[key] = {
          timestamp: key,
          total: 0,
          threats: 0,
          normal: 0
        };
      }

      const total = Number(file?.results?.totalRequests || 0);
      const threats = Number(file?.results?.maliciousRequests || 0);

      timeline[key].total += total;
      timeline[key].threats += threats;
      timeline[key].normal += Math.max(total - threats, 0);
    });

    const result = Object.values(timeline).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    return res.json(result);
  } catch (error) {
    console.error('Timeline analysis error:', error);
    res.status(500).json({
      error: 'Data Error',
      message: error.message
    });
  }
});

// GET /api/analysis/features - Feature dataset for bar chart
router.get('/features', async (req, res) => {
  try {
    return res.json([]);
  } catch (error) {
    console.error('Features analysis error:', error);
    res.status(500).json({
      error: 'Data Error',
      message: error.message
    });
  }
});

// GET /api/analysis/methods - Detection method breakdown
router.get('/methods', async (req, res) => {
  try {
    if (!(await hasUserHistory(req.user.id))) {
      return res.json([
        { method: 'Regex', count: 0 },
        { method: 'Machine Learning', count: 0 },
        { method: 'Statistical', count: 0 }
      ]);
    }

    const files = await FileHistory.find({ userId: req.user.id, status: 'completed' }).lean();
    const total = files.reduce((sum, file) => sum + Number(file?.results?.totalRequests || 0), 0);

    return res.json([
      { method: 'Regex', count: 0 },
      { method: 'Machine Learning', count: total },
      { method: 'Statistical', count: 0 }
    ]);
  } catch (error) {
    console.error('Methods analysis error:', error);
    res.status(500).json({
      error: 'Data Error',
      message: error.message
    });
  }
});

module.exports = router;
