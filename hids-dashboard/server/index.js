require('dotenv').config();
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

// Middleware
app.use(cors({
  origin: 'http://localhost:5173',
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
    // Connect to MongoDB
    await connectDB();

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
