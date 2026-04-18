const express = require('express');
const router = express.Router();
const FileHistory = require('../models/FileHistory');
const { inferAttackOutcome, normalizeAttackOutcome } = require('../utils/attackOutcome');

const ipToInt = (ip) => {
  if (!ip || typeof ip !== 'string') return null;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;

  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;

  return ((nums[0] << 24) >>> 0) + (nums[1] << 16) + (nums[2] << 8) + nums[3];
};

const parseCidrRange = (cidr) => {
  const [base, prefixText] = String(cidr || '').split('/');
  const baseInt = ipToInt(base);
  const prefix = Number(prefixText);
  if (baseInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const start = baseInt & mask;
  const end = start | (~mask >>> 0);
  return { start, end };
};

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
        const savedOutcome = normalizeAttackOutcome(req.attack_outcome);
        rows.push({
          timestamp: req.timestamp || timestamp,
          source_ip: req.source_ip || '0.0.0.0',
          url: req.url || baseUrl,
          classification: req.classification || 'unknown',
          attack_outcome: savedOutcome || inferAttackOutcome(
            req.classification,
            req.status_code,
            req.url,
            req.payload || req.raw,
            req.response || req.response_body || req.body,
            req.response_headers || req.headers,
            req.response_time || req.latency || req.duration_ms
          ),
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
            attack_outcome: cls.toLowerCase() === 'normal' ? 'none' : 'attempt',
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
            attack_outcome: cls.toLowerCase() === 'normal' ? 'none' : 'attempt',
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
          attack_outcome: cls.toLowerCase() === 'normal' ? 'none' : 'attempt',
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

    let requests = buildUserRequests(files);

    const { classification, outcome, ip, ip_start: ipStart, ip_end: ipEnd, cidr } = req.query;

    if (classification) {
      const target = String(classification).toLowerCase();
      requests = requests.filter((r) => String(r.classification || '').toLowerCase() === target);
    }

    if (outcome) {
      const target = String(outcome).toLowerCase();
      requests = requests.filter((r) => String(r.attack_outcome || '').toLowerCase() === target);
    }

    if (ip) {
      const target = String(ip).trim();
      requests = requests.filter((r) => String(r.source_ip || '').trim() === target);
    }

    let rangeStart = null;
    let rangeEnd = null;
    if (cidr) {
      const parsed = parseCidrRange(cidr);
      if (parsed) {
        rangeStart = parsed.start;
        rangeEnd = parsed.end;
      }
    } else if (ipStart && ipEnd) {
      rangeStart = ipToInt(String(ipStart));
      rangeEnd = ipToInt(String(ipEnd));
      if (rangeStart !== null && rangeEnd !== null && rangeStart > rangeEnd) {
        const temp = rangeStart;
        rangeStart = rangeEnd;
        rangeEnd = temp;
      }
    }

    if (rangeStart !== null && rangeEnd !== null) {
      requests = requests.filter((r) => {
        const value = ipToInt(String(r.source_ip || ''));
        return value !== null && value >= rangeStart && value <= rangeEnd;
      });
    }

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
