const express = require('express');
const router = express.Router();
const { loadRequests } = require('../utils/dataLoader');

// GET /api/requests - All detection rows
router.get('/', async (req, res) => {
  try {
    const requests = await loadRequests();
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

    const requests = await loadRequests();

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
