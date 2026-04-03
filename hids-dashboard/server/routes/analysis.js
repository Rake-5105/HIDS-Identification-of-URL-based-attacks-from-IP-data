const express = require('express');
const router = express.Router();
const { loadRequests, loadFeatures, loadSummary } = require('../utils/dataLoader');

// GET /api/analysis/ips - Grouped by source_ip with threat stats
router.get('/ips', async (req, res) => {
  try {
    const requests = await loadRequests();

    const ipStats = {};

    requests.forEach(req => {
      const ip = req.source_ip;
      if (!ipStats[ip]) {
        ipStats[ip] = {
          ip,
          total: 0,
          threats: 0,
          threat_percentage: 0,
          risk_level: 'Low'
        };
      }

      ipStats[ip].total++;
      if (req.classification && req.classification.toLowerCase() !== 'normal') {
        ipStats[ip].threats++;
      }
    });

    // Calculate percentages and risk levels
    Object.values(ipStats).forEach(stat => {
      stat.threat_percentage = (stat.threats / stat.total * 100).toFixed(2);

      const threat_pct = parseFloat(stat.threat_percentage);
      if (threat_pct > 80) {
        stat.risk_level = 'Critical';
      } else if (threat_pct > 50) {
        stat.risk_level = 'High';
      } else if (threat_pct > 20) {
        stat.risk_level = 'Medium';
      } else {
        stat.risk_level = 'Low';
      }
    });

    const result = Object.values(ipStats).sort((a, b) => b.threats - a.threats);
    res.json(result);
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
    const requests = await loadRequests();

    const timeline = {};

    requests.forEach(req => {
      if (!req.timestamp) return;

      // Group by hour
      const date = new Date(req.timestamp);
      const hourKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:00`;

      if (!timeline[hourKey]) {
        timeline[hourKey] = {
          timestamp: hourKey,
          total: 0,
          threats: 0,
          normal: 0
        };
      }

      timeline[hourKey].total++;
      if (req.classification && req.classification.toLowerCase() !== 'normal') {
        timeline[hourKey].threats++;
      } else {
        timeline[hourKey].normal++;
      }
    });

    const result = Object.values(timeline).sort((a, b) =>
      new Date(a.timestamp) - new Date(b.timestamp)
    );

    res.json(result);
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
    const features = await loadFeatures();

    if (features.length === 0) {
      return res.json([]);
    }

    // Calculate feature importance (variance-based)
    const featureNames = Object.keys(features[0]);
    const featureImportance = [];

    featureNames.forEach(name => {
      // Skip non-numeric columns
      if (name === 'url' || name === 'classification' || name === 'timestamp') return;

      const values = features.map(f => parseFloat(f[name]) || 0);
      const mean = values.reduce((a, b) => a + b, 0) / values.length;
      const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;

      featureImportance.push({
        feature: name,
        importance: variance
      });
    });

    // Sort by importance and take top 10
    const result = featureImportance
      .sort((a, b) => b.importance - a.importance)
      .slice(0, 10);

    res.json(result);
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
    const summary = await loadSummary();

    const methods = summary.detection_methods || { regex: 0, ml: 0, statistical: 0 };

    const result = [
      { method: 'Regex', count: methods.regex || 0 },
      { method: 'Machine Learning', count: methods.ml || 0 },
      { method: 'Statistical', count: methods.statistical || 0 }
    ];

    res.json(result);
  } catch (error) {
    console.error('Methods analysis error:', error);
    res.status(500).json({
      error: 'Data Error',
      message: error.message
    });
  }
});

module.exports = router;
