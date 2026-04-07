const express = require('express');
const router = express.Router();
const FileHistory = require('../models/FileHistory');

/**
 * Build request list from FileHistory documents
 * Uses detailedRequests if available, falls back to aggregated data
 */
const buildUserRequests = (files) => {
  const rows = [];

  files.forEach((file) => {
    const timestamp = file.processedAt || file.uploadedAt || new Date();
    const baseUrl = file.fileName || 'uploaded-file';

    // Prefer detailedRequests if available
    if (file.detailedRequests && file.detailedRequests.length > 0) {
      file.detailedRequests.forEach((req) => {
        rows.push({
          timestamp: req.timestamp || timestamp,
          source_ip: req.source_ip || '0.0.0.0',
          url: req.url || baseUrl,
          classification: req.classification || 'unknown',
          confidence: req.confidence || 90,
          detection_method: req.detection_method || 'ML'
        });
      });
      return;
    }

    // Fallback: Use suspiciousIps + attackTypes to generate rows
    const attackTypes = file?.results?.attackTypes;
    const suspiciousIps = file?.results?.suspiciousIps || [];

    if (!attackTypes) return;

    const entries = attackTypes instanceof Map
      ? Array.from(attackTypes.entries())
      : Object.entries(attackTypes);

    entries.forEach(([cls, count]) => {
      const safeCount = Number(count || 0);
      if (safeCount <= 0) return;

      // Distribute across suspicious IPs if available
      if (suspiciousIps.length > 0 && cls.toLowerCase() !== 'normal') {
        // Assign IPs to malicious classifications
        const ipsPerClass = Math.ceil(safeCount / suspiciousIps.length);
        suspiciousIps.slice(0, safeCount).forEach((ip, idx) => {
          rows.push({
            timestamp,
            source_ip: ip,
            url: baseUrl,
            classification: cls,
            confidence: cls.toLowerCase() === 'normal' ? 100 : 90,
            detection_method: 'Aggregated'
          });
        });
        // Add remaining entries without specific IP
        const remaining = safeCount - suspiciousIps.length;
        if (remaining > 0) {
          rows.push({
            timestamp,
            source_ip: 'Multiple',
            url: baseUrl,
            classification: cls,
            confidence: cls.toLowerCase() === 'normal' ? 100 : 90,
            detection_method: 'Aggregated',
            count: remaining
          });
        }
      } else {
        // Normal traffic or no IPs available
        rows.push({
          timestamp,
          source_ip: cls.toLowerCase() === 'normal' ? '—' : (suspiciousIps[0] || 'Unknown'),
          url: baseUrl,
          classification: cls,
          confidence: cls.toLowerCase() === 'normal' ? 100 : 90,
          detection_method: 'Aggregated',
          count: safeCount
        });
      }
    });
  });

  return rows.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
};

// GET /api/requests - All detection rows
router.get('/', async (req, res) => {
  try {
    const files = await FileHistory.find({
      userId: req.user.id,
      status: 'completed'
    }).lean();

    const requests = buildUserRequests(files);
    res.json(requests);
  } catch (error) {
    console.error('Requests error:', error);
    res.status(500).json({
      error: 'Data Error',
      message: error.message
    });
  }
});

// GET /api/requests/:index - Single row by index
router.get('/:index', async (req, res) => {
  try {
    const index = parseInt(req.params.index);

    if (isNaN(index) || index < 0) {
      return res.status(400).json({
        error: 'Invalid Parameter',
        message: 'Index must be a non-negative integer'
      });
    }

    const files = await FileHistory.find({
      userId: req.user.id,
      status: 'completed'
    }).lean();
    const requests = buildUserRequests(files);

    if (index >= requests.length) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Request index out of range'
      });
    }

    res.json(requests[index]);
  } catch (error) {
    console.error('Request detail error:', error);
    res.status(500).json({
      error: 'Data Error',
      message: error.message
    });
  }
});

module.exports = router;
