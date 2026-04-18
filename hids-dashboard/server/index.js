const path = require('path');
const dotenv = require('dotenv');

// Load environment from hids-dashboard/.env first, then fallback to workspace-root .env.
dotenv.config({ path: path.resolve(process.cwd(), '.env') });
if (
  !process.env.JWT_SECRET ||
  !process.env.MONGODB_URI ||
  !process.env.EMAIL_USER ||
  !process.env.EMAIL_PASS ||
  !process.env.SUPABASE_URL ||
  !process.env.SUPABASE_SERVICE_KEY
) {
  dotenv.config({ path: path.resolve(process.cwd(), '..', '.env') });
}
const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');

// Import routes
const authRoutes = require('./routes/auth');
const profileRoutes = require('./routes/profile');
const summaryRoutes = require('./routes/summary');
const requestsRoutes = require('./routes/requests');
const analysisRoutes = require('./routes/analysis');
const uploadRoutes = require('./routes/upload');
const aiRoutes = require('./routes/ai');
const auth = require('./middleware/auth');
const { initBuckets } = require('./utils/supabaseStorage');

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_CONNECT_RETRIES = Number(process.env.MONGO_CONNECT_RETRIES || 5);
const MONGO_RETRY_DELAY_MS = Number(process.env.MONGO_RETRY_DELAY_MS || 3000);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) {
      callback(null, true);
      return;
    }

    const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin);
    if (isLocalhost) {
      callback(null, true);
      return;
    }

    callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/summary', auth, summaryRoutes);
app.use('/api/requests', auth, requestsRoutes);
app.use('/api/analysis', auth, analysisRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.method} ${req.path} not found`
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${req.method} ${req.path}:`, err.stack || err.message || err);
  res.status(err.status || 500).json({
    error: 'Server Error',
    message: err.message || 'Internal server error'
  });
});

// Start server
const startServer = async () => {
  try {
    // Connect to MongoDB with retries for transient network issues.
    let connected = false;
    for (let attempt = 1; attempt <= MONGO_CONNECT_RETRIES; attempt += 1) {
      try {
        await connectDB();
        connected = true;
        break;
      } catch (error) {
        const isLastAttempt = attempt === MONGO_CONNECT_RETRIES;
        console.error(
          `[${new Date().toISOString()}] Mongo connection attempt ${attempt}/${MONGO_CONNECT_RETRIES} failed: ${error.message}`
        );
        if (!isLastAttempt) {
          await sleep(MONGO_RETRY_DELAY_MS);
        }
      }
    }

    if (!connected) {
      throw new Error('Unable to connect to MongoDB after multiple attempts.');
    }

    // Initialize Supabase storage buckets
    await initBuckets().catch(err => 
      console.log(`[${new Date().toISOString()}] Supabase storage: not configured (local storage only)`)  
    );

    app.listen(PORT, () => {
      console.log(`[${new Date().toISOString()}] Express server running on port ${PORT}`);
      console.log(`[${new Date().toISOString()}] Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
