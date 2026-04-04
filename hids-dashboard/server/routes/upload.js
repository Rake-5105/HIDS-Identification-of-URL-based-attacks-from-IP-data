const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const { spawn } = require('child_process');
const crypto = require('crypto');
const auth = require('../middleware/auth');
const FileHistory = require('../models/FileHistory');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads');
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = crypto.randomBytes(8).toString('hex');
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${uniqueSuffix}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = {
    logs: ['.log', '.txt'],
    pcap: ['.pcap', '.pcapng'],
    csv: ['.csv']
  };

  const fileType = req.params.type || 'logs';
  const ext = path.extname(file.originalname).toLowerCase();
  
  if (allowedTypes[fileType]?.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type. Allowed: ${allowedTypes[fileType]?.join(', ')}`));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Store processing jobs in memory (in production, use Redis)
const processingJobs = new Map();

// Upload endpoint for all file types
router.post('/:type', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const uploadId = crypto.randomBytes(16).toString('hex');
    const fileType = req.params.type;

    // Store file info in processing jobs
    processingJobs.set(uploadId, {
      status: 'uploaded',
      progress: 0,
      message: 'File uploaded successfully',
      filePath: req.file.path,
      fileName: req.file.originalname,
      fileType,
      userId: req.user.id,
      uploadedAt: new Date()
    });

    // Save to file history
    await FileHistory.create({
      userId: req.user.id,
      fileName: req.file.originalname,
      fileType: fileType === 'pcap' ? 'pcap' : fileType === 'csv' ? 'csv' : 'log',
      fileSize: req.file.size,
      status: 'uploaded'
    });

    res.json({
      success: true,
      upload_id: uploadId,
      filename: req.file.originalname,
      size: req.file.size,
      type: fileType
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: error.message || 'Upload failed' });
  }
});

// Start processing
router.post('/process/:uploadId', auth, async (req, res) => {
  try {
    const { uploadId } = req.params;
    const job = processingJobs.get(uploadId);

    if (!job) {
      return res.status(404).json({ error: 'Upload not found' });
    }

    if (job.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Update status to processing
    job.status = 'processing';
    job.progress = 10;
    job.message = 'Starting analysis...';

    // Run the Python analysis pipeline in background
    runAnalysisPipeline(uploadId, job);

    res.json({ success: true, message: 'Processing started' });
  } catch (error) {
    console.error('Process error:', error);
    res.status(500).json({ error: error.message || 'Processing failed' });
  }
});

// Get processing status
router.get('/process/status/:uploadId', auth, async (req, res) => {
  try {
    const { uploadId } = req.params;
    const job = processingJobs.get(uploadId);

    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }

    if (job.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    res.json({
      status: job.status,
      progress: job.progress,
      message: job.message,
      results: job.results || null
    });
  } catch (error) {
    console.error('Status error:', error);
    res.status(500).json({ error: error.message || 'Status check failed' });
  }
});

// Run the Python analysis pipeline
async function runAnalysisPipeline(uploadId, job) {
  const projectRoot = path.join(__dirname, '../../../');
  const outputDir = path.join(projectRoot, 'output', uploadId);

  try {
    await fs.mkdir(outputDir, { recursive: true });

    // Update progress
    job.progress = 20;
    job.message = 'Parsing file...';

    // Determine the Python command based on file type
    const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
    
    // Run the main.py script with --run-all flag
    const args = [
      path.join(projectRoot, 'main.py'),
      '--source', job.filePath,
      '--output', outputDir,
      '--run-all'
    ];

    const python = spawn(pythonCmd, args, {
      cwd: projectRoot,
      env: { ...process.env, PYTHONUNBUFFERED: '1' }
    });

    let stdout = '';
    let stderr = '';

    python.stdout.on('data', (data) => {
      stdout += data.toString();
      const output = data.toString();
      
      // Update progress based on output
      if (output.includes('Module 3') || output.includes('Feature Extraction')) {
        job.progress = 50;
        job.message = 'Extracting features...';
      } else if (output.includes('Module 4') || output.includes('Classification')) {
        job.progress = 75;
        job.message = 'Running classification...';
      }
    });

    python.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    python.on('close', async (code) => {
      if (code === 0) {
        // Read results
        try {
          const summaryPath = path.join(outputDir, 'module4_summary.json');
          const summaryContent = await fs.readFile(summaryPath, 'utf-8');
          const summary = JSON.parse(summaryContent);

          // Update file history
          await FileHistory.findOneAndUpdate(
            { userId: job.userId, fileName: job.fileName },
            {
              status: 'completed',
              processedAt: new Date(),
              results: {
                totalRequests: summary.rows,
                maliciousRequests: summary.rows - (summary.class_counts?.Normal || 0),
                attackTypes: summary.class_counts
              }
            }
          );

          job.status = 'completed';
          job.progress = 100;
          job.message = 'Analysis complete';
          job.results = summary;
        } catch (err) {
          job.status = 'completed';
          job.progress = 100;
          job.message = 'Analysis complete (partial results)';
          job.results = { stdout, note: 'Full summary not available' };
        }
      } else {
        job.status = 'failed';
        job.progress = 0;
        job.message = `Analysis failed: ${stderr || 'Unknown error'}`;
        
        await FileHistory.findOneAndUpdate(
          { userId: job.userId, fileName: job.fileName },
          { status: 'failed' }
        );
      }
    });

    python.on('error', async (err) => {
      job.status = 'failed';
      job.progress = 0;
      job.message = `Failed to start analysis: ${err.message}`;
      
      await FileHistory.findOneAndUpdate(
        { userId: job.userId, fileName: job.fileName },
        { status: 'failed' }
      );
    });

  } catch (error) {
    job.status = 'failed';
    job.progress = 0;
    job.message = `Analysis error: ${error.message}`;
  }
}

module.exports = router;
