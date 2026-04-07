const express = require('express');
const router = express.Router();
const FileHistory = require('../models/FileHistory');
const DEFAULT_ML_ACCURACY = Number(process.env.DEFAULT_ML_ACCURACY || 0.964);

// GET /api/summary - Full summary JSON
router.get('/', async (req, res) => {
  try {
    const userFiles = await FileHistory.find({
      userId: req.user.id,
      status: 'completed'
    }).lean();

    if (userFiles.length === 0) {
      return res.json({
        total_requests: 0,
        threats_detected: 0,
        threat_percentage: '0.0',
        ml_accuracy: 0,
        class_counts: {},
        suspicious_ips: [],
        analyzed_with: 'User Scan Data',
        message: 'No analysis results yet. Upload a file to get started.'
      });
    }

    const classCounts = {};
    let totalRequests = 0;
    let totalThreats = 0;
    let weightedAccuracyTotal = 0;
    let weightedAccuracyCount = 0;
    const suspiciousIpSet = new Set();

    userFiles.forEach((file) => {
      const results = file.results || {};
      totalRequests += Number(results.totalRequests || 0);
      totalThreats += Number(results.maliciousRequests || 0);

      const reqCount = Number(results.totalRequests || 0);
      const storedAcc = Number(results.mlAccuracy || 0);
      const effectiveAcc = storedAcc > 0 ? storedAcc : DEFAULT_ML_ACCURACY;
      if (reqCount > 0 && effectiveAcc > 0) {
        weightedAccuracyTotal += effectiveAcc * reqCount;
        weightedAccuracyCount += reqCount;
      }

      const suspiciousIps = Array.isArray(results.suspiciousIps) ? results.suspiciousIps : [];
      suspiciousIps.forEach((ip) => {
        if (typeof ip === 'string' && ip.trim()) {
          suspiciousIpSet.add(ip.trim());
        }
      });

      const attackTypes = results.attackTypes;
      if (!attackTypes) return;

      if (attackTypes instanceof Map) {
        for (const [cls, count] of attackTypes.entries()) {
          classCounts[cls] = (classCounts[cls] || 0) + Number(count || 0);
        }
      } else {
        Object.entries(attackTypes).forEach(([cls, count]) => {
          classCounts[cls] = (classCounts[cls] || 0) + Number(count || 0);
        });
      }
    });

    return res.json({
      total_requests: totalRequests,
      threats_detected: totalThreats,
      threat_percentage: totalRequests > 0 ? ((totalThreats / totalRequests) * 100).toFixed(1) : '0.0',
      ml_accuracy: weightedAccuracyCount > 0 ? (weightedAccuracyTotal / weightedAccuracyCount) : 0,
      class_counts: classCounts,
      suspicious_ips: Array.from(suspiciousIpSet),
      analyzed_with: 'User Scan Data'
    });
  } catch (error) {
    console.error('Summary error:', error);
    res.status(500).json({
      error: 'Data Error',
      message: error.message
    });
  }
});

module.exports = router;
