const express = require('express');
const router = express.Router();
const { loadSummary } = require('../utils/dataLoader');

// GET /api/summary - Full summary JSON
router.get('/', async (req, res) => {
  try {
    const summary = await loadSummary();
    res.json(summary);
  } catch (error) {
    console.error('Summary error:', error);
    res.status(500).json({
      error: 'Data Error',
      message: error.message
    });
  }
});

module.exports = router;
