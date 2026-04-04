const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const auth = require('../middleware/auth');
const FileHistory = require('../models/FileHistory');
const { BUCKETS, uploadToSupabase, saveReport } = require('../utils/supabaseStorage');
const { analyzeFile } = require('../utils/ollamaAnalyzer');

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

// ─── IMPORTANT: Specific routes MUST come before wildcard /:type ───

// Get processing status (must be before /:type)
router.get('/process/status/:uploadId', auth, async (req, res) => {
  try {
    const { uploadId } = req.params;
    const job = processingJobs.get(uploadId);

    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }

    // Compare as strings to avoid ObjectId mismatch
    if (String(job.userId) !== String(req.user.id)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Safely build response to avoid serialization errors
    const response = {
      status: job.status || 'unknown',
      progress: job.progress || 0,
      message: job.message || '',
      results: null,
      downloadAvailable: !!job.reportCsv
    };

    // Safely serialize results
    if (job.results) {
      try {
        JSON.stringify(job.results); // test serialization
        response.results = job.results;
      } catch {
        response.results = { note: 'Results available but cannot be displayed' };
      }
    }

    res.json(response);
  } catch (error) {
    console.error('Status error:', error.stack || error);
    res.status(500).json({ error: error.message || 'Status check failed' });
  }
});

// Download report as CSV (must be before /:type)
router.get('/download/csv/:uploadId', auth, async (req, res) => {
  try {
    const { uploadId } = req.params;
    const job = processingJobs.get(uploadId);

    if (!job || String(job.userId) !== String(req.user.id)) {
      return res.status(404).json({ error: 'Report not found' });
    }

    if (!job.reportCsv) {
      return res.status(400).json({ error: 'Report not ready yet' });
    }

    const fileName = `hids_report_${uploadId.substring(0, 8)}.csv`;
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.send(job.reportCsv);
  } catch (error) {
    res.status(500).json({ error: 'Download failed' });
  }
});

// Download report as TXT (must be before /:type)
router.get('/download/txt/:uploadId', auth, async (req, res) => {
  try {
    const { uploadId } = req.params;
    const job = processingJobs.get(uploadId);

    if (!job || String(job.userId) !== String(req.user.id)) {
      return res.status(404).json({ error: 'Report not found' });
    }

    if (!job.reportTxt) {
      return res.status(400).json({ error: 'Report not ready yet' });
    }

    const fileName = `hids_report_${uploadId.substring(0, 8)}.txt`;
    
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.send(job.reportTxt);
  } catch (error) {
    res.status(500).json({ error: 'Download failed' });
  }
});

// Start processing with Ollama Phi3 (must be before /:type)
router.post('/process/:uploadId', auth, async (req, res) => {
  try {
    const { uploadId } = req.params;
    const job = processingJobs.get(uploadId);

    if (!job) {
      return res.status(404).json({ error: 'Upload not found' });
    }

    if (String(job.userId) !== String(req.user.id)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Update status to processing
    job.status = 'processing';
    job.progress = 10;
    job.message = 'Starting Phi3 AI analysis...';

    // Run Ollama analysis in background
    runOllamaAnalysis(uploadId, job);

    res.json({ success: true, message: 'Phi3 analysis started' });
  } catch (error) {
    console.error('Process error:', error);
    res.status(500).json({ error: error.message || 'Processing failed' });
  }
});

// ─── Upload endpoint (wildcard - MUST be last) ───
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

    // Upload to Supabase Storage (non-blocking)
    const supabasePath = `${req.user.id}/${uploadId}/${req.file.originalname}`;
    uploadToSupabase(req.file.path, BUCKETS.UPLOADS, supabasePath)
      .then(result => {
        if (result.url) {
          console.log(`[Supabase] File uploaded: ${supabasePath}`);
        }
      })
      .catch(err => console.error('Supabase upload error:', err));

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

// ─── Ollama Phi3 analysis pipeline ───
async function runOllamaAnalysis(uploadId, job) {
  try {
    job.progress = 15;
    job.message = 'Reading uploaded file...';

    const onProgress = (progress, message) => {
      job.progress = progress;
      job.message = message;
    };

    // Run analysis with Ollama
    const result = await analyzeFile(job.filePath, job.fileType, onProgress);

    // Store reports for download
    job.reportCsv = result.csvContent;
    job.reportTxt = result.txtContent;

    // Save reports locally
    const outputDir = path.join(__dirname, '../../output', uploadId);
    await fs.mkdir(outputDir, { recursive: true });
    await fs.writeFile(path.join(outputDir, 'report.csv'), result.csvContent);
    await fs.writeFile(path.join(outputDir, 'report.txt'), result.txtContent);
    await fs.writeFile(path.join(outputDir, 'summary.json'), JSON.stringify(result.summary, null, 2));

    // Update file history in MongoDB
    await FileHistory.findOneAndUpdate(
      { userId: job.userId, fileName: job.fileName },
      {
        status: 'completed',
        processedAt: new Date(),
        results: {
          totalRequests: result.summary.total_requests,
          maliciousRequests: result.summary.threats_detected,
          attackTypes: result.summary.classification_breakdown
        }
      }
    );

    // Save to Supabase (non-blocking)
    saveReport(job.userId, uploadId, result.summary)
      .then(r => { if (r.url) job.reportUrl = r.url; })
      .catch(err => console.error('Supabase report error:', err));

    // Mark as completed
    job.status = 'completed';
    job.progress = 100;
    job.message = 'Phi3 AI analysis complete';
    job.results = result.summary;

    console.log(`[Ollama] Analysis complete for ${uploadId}: ${result.summary.total_requests} entries, ${result.summary.threats_detected} threats`);

  } catch (error) {
    console.error(`[Ollama] Analysis failed for ${uploadId}:`, error.message);
    job.status = 'failed';
    job.progress = 0;
    job.message = `Analysis failed: ${error.message}`;

    await FileHistory.findOneAndUpdate(
      { userId: job.userId, fileName: job.fileName },
      { status: 'failed' }
    ).catch(() => {});
  }
}

module.exports = router;
