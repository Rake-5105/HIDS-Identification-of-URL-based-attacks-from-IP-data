const rateLimit = require('express-rate-limit');

const toRetryAfterSeconds = (resetTime) => {
  if (!resetTime) return null;
  const deltaMs = Number(new Date(resetTime).getTime()) - Date.now();
  return Math.max(1, Math.ceil(deltaMs / 1000));
};

const createApiLimiter = ({ windowMs, max, message }) => {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      const retryAfterSec = toRetryAfterSeconds(req.rateLimit?.resetTime);
      return res.status(429).json({
        error: 'Too Many Requests',
        message,
        retryAfterSec,
      });
    },
  });
};

// Strict limiter for authentication endpoints.
const authRateLimiter = createApiLimiter({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_AUTH_MAX || 20),
  message: 'Too many authentication requests from this IP. Please try again later.',
});

// Medium limiter for upload-related endpoints (includes status polling).
const uploadRateLimiter = createApiLimiter({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_UPLOAD_MAX || 400),
  message: 'Too many upload requests from this IP. Please slow down and retry shortly.',
});

// Strict limiter for AI routes with enough headroom for status polling.
const aiRateLimiter = createApiLimiter({
  windowMs: 5 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_AI_MAX || 240),
  message: 'Too many AI requests from this IP. Please wait before trying again.',
});

module.exports = {
  authRateLimiter,
  uploadRateLimiter,
  aiRateLimiter,
};
