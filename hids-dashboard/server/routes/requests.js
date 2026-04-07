const express = require('express');
const router = express.Router();
const FileHistory = require('../models/FileHistory');

const buildUserRequests = (files) => {
  const rows = [];

  files.forEach((file) => {
    const attackTypes = file?.results?.attackTypes;
    const timestamp = file.processedAt || file.uploadedAt || new Date();
    const baseUrl = file.fileName || 'uploaded-file';

    if (!attackTypes) return;

    const entries = attackTypes instanceof Map
      ? Array.from(attackTypes.entries())
      : Object.entries(attackTypes);

    entries.forEach(([cls, count]) => {
      const safeCount = Number(count || 0);
      if (safeCount <= 0) return;

      rows.push({
        timestamp,
        source_ip: 'N/A',
        url: baseUrl,
        classification: cls,
        confidence: cls.toLowerCase() === 'normal' ? 100 : 90,
        detection_method: 'aggregated',
        count: safeCount
      });
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
