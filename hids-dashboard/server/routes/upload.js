const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const auth = require('../middleware/auth');
const FileHistory = require('../models/FileHistory');
const User = require('../models/User');
const { BUCKETS, uploadToSupabase, saveReport } = require('../utils/supabaseStorage');
const { analyzeFile } = require('../utils/ollamaAnalyzer');
const { inferAttackOutcome, normalizeAttackOutcome } = require('../utils/attackOutcome');

const hasEmailConfig = () => {
  return Boolean(process.env.EMAIL_USER && process.env.EMAIL_PASS);
};

const createTransporter = () => {
  return nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
};

const createJsonReportPayload = (uploadId, fileName, summary, csvContent) => {
  const detailedRequests = csvContent ? parseCSV(csvContent).slice(0, 200) : [];
  return {
    upload_id: uploadId,
    file_name: fileName,
    analyzed_at: new Date().toISOString(),
    summary: summary || {},
    detailed_requests: detailedRequests,
  };
};

const sendReportEmail = async ({ email, uploadId, fileName, summary, csvContent, txtContent }) => {
  if (!hasEmailConfig()) {
    throw new Error('Email service is not configured (missing EMAIL_USER or EMAIL_PASS).');
  }

  const shortId = String(uploadId).substring(0, 8);
  const jsonPayload = createJsonReportPayload(uploadId, fileName, summary, csvContent);
  const jsonContent = JSON.stringify(jsonPayload, null, 2);
  const transporter = createTransporter();

  await transporter.sendMail({
    from: `"HIDS Dashboard" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: `HIDS Scan Report - ${fileName}`,
    text: [
      'Your HIDS scan has completed successfully.',
      '',
      `File: ${fileName}`,
      `Upload ID: ${uploadId}`,
      `Total requests: ${summary?.total_requests ?? 'N/A'}`,
      `Threats detected: ${summary?.threats_detected ?? 'N/A'}`,
      '',
      'Attached formats: CSV, JSON, TXT.'
    ].join('\n'),
    attachments: [
      {
        filename: `hids_report_${shortId}.csv`,
        content: csvContent || '',
        contentType: 'text/csv'
      },
      {
        filename: `hids_report_${shortId}.json`,
        content: jsonContent,
        contentType: 'application/json'
      },
      {
        filename: `hids_report_${shortId}.txt`,
        content: txtContent || '',
        contentType: 'text/plain'
      }
    ]
  });
};

const toSafeEmailError = (error) => {
  const message = error?.message || 'Email delivery failed';
  return {
    code: error?.code || 'EMAIL_SEND_FAILED',
    reason: message.length > 200 ? `${message.slice(0, 200)}...` : message,
  };
};

const computeOutcomeBreakdownFromRequests = (requests = []) => {
  return requests.reduce(
    (acc, req) => {
      const normalized = normalizeAttackOutcome(req?.attack_outcome) || inferAttackOutcome(
        req?.classification,
        req?.status_code,
        req?.url,
        req?.payload || req?.raw,
        req?.response || req?.response_body || req?.body,
        req?.response_headers || req?.headers,
        req?.response_time || req?.latency || req?.duration_ms
      );

      if (normalized === 'confirmed_success') {
        acc.confirmed_success += 1;
      } else if (normalized === 'attempt') {
        acc.attempt += 1;
      } else {
        acc.none += 1;
      }

      return acc;
    },
    { confirmed_success: 0, attempt: 0, none: 0 }
  );
};

/**
 * Simple CSV parser (handles basic CSVs without external dependency)
 */
const parseCSV = (content) => {
  const lines = content.split(/\r?\n/).filter(l => l.trim());
  if (lines.length < 2) return [];
  
  // Parse headers
  const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, '').toLowerCase());
  
  // Parse rows
  const records = [];
  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].match(/(".*?"|[^",]+)(?=\s*,|\s*$)/g) || [];
    const record = {};
    headers.forEach((h, idx) => {
      record[h] = (values[idx] || '').trim().replace(/^"|"$/g, '');
    });
    records.push(record);
  }
  return records;
};

/**
 * Extract detailed request records from module4 CSV output
 */
const extractDetailedRequests = async (csvPath, maxRecords = 100) => {
  try {
    const content = await fs.readFile(csvPath, 'utf-8');
    const records = parseCSV(content);
    
    console.log(`[Extract] Parsing ${records.length} records from ${csvPath}`);
    if (records.length > 0) {
      console.log(`[Extract] Sample record keys:`, Object.keys(records[0]));
    }

    return records.slice(0, maxRecords).map(rec => {
      // Handle different CSV formats
      const sourceIp = rec.source_ip || rec.ip || rec['source ip'] || '0.0.0.0';
      const url = rec.url || rec.full_url || rec.path || rec.uri || '';
      
      // Classification can come from various columns
      let classification = rec.final_classification || rec.classification || rec.regex_class || rec.attack_type || 'unknown';
      
      // If classification is "None" or risk level, try to get actual attack type
      if (classification === 'None' || classification.toLowerCase() === 'low' || classification.toLowerCase() === 'medium' || classification.toLowerCase() === 'high' || classification.toLowerCase() === 'critical') {
        // Check if there's a patterns column that might indicate attack type
        const patterns = rec.patterns || rec.recommendation || '';
        if (patterns.toLowerCase().includes('sql')) classification = 'SQL Injection';
        else if (patterns.toLowerCase().includes('xss') || patterns.toLowerCase().includes('script')) classification = 'XSS';
        else if (patterns.toLowerCase().includes('traversal') || patterns.toLowerCase().includes('passwd')) classification = 'Path Traversal';
        else if (patterns.toLowerCase().includes('command') || patterns.toLowerCase().includes('injection')) classification = 'Command Injection';
        else if (rec.risk_level && rec.risk_level !== 'Low') classification = 'Suspicious';
        else classification = 'Normal';
      }
      
      // Confidence from various sources
      const confidence = parseFloat(rec.confidence) || 
        (rec.risk_level === 'Critical' ? 95 : rec.risk_level === 'High' ? 85 : rec.risk_level === 'Medium' ? 75 : 90);
      const attackOutcome = normalizeAttackOutcome(rec.attack_outcome) || inferAttackOutcome(
        classification,
        rec.status_code,
        rec.url || rec.full_url || rec.path || rec.uri || '',
        rec.payload || rec.raw || '',
        rec.response || rec.response_body || rec.body || '',
        rec.response_headers || rec.headers || '',
        rec.response_time || rec.latency || rec.duration_ms || null
      );
      
      return {
        timestamp: rec.timestamp || new Date().toISOString(),
        source_ip: sourceIp,
        url: url,
        classification: classification,
        attack_outcome: attackOutcome,
        confidence: confidence,
        detection_method: rec.detection_method || rec.method || 'ML'
      };
    }).filter(r => r.source_ip && r.source_ip !== '0.0.0.0');
  } catch (error) {
    console.error('Error extracting detailed requests:', error.message);
    return [];
  }
};

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
const DEFAULT_ML_ACCURACY = Number(process.env.DEFAULT_ML_ACCURACY || 0.964);

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
      downloadAvailable: !!job.reportCsv,
      emailStatus: job.emailStatus || null
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

// Download report as JSON (must be before /:type)
router.get('/download/json/:uploadId', auth, async (req, res) => {
  try {
    const { uploadId } = req.params;
    const job = processingJobs.get(uploadId);

    if (!job || String(job.userId) !== String(req.user.id)) {
      return res.status(404).json({ error: 'Report not found' });
    }

    const payload = createJsonReportPayload(uploadId, job.fileName, job.results || {}, job.reportCsv);

    const fileName = `hids_report_${uploadId.substring(0, 8)}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.send(JSON.stringify(payload, null, 2));
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
    job.message = 'Starting module + Phi3 analysis...';

    // Run Ollama analysis in background
    runOllamaAnalysis(uploadId, job);

    res.json({ success: true, message: 'Module + Phi3 analysis started' });
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
      userEmail: req.user.email || null,
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

    // Run analysis with modules and Ollama
    const result = await analyzeFile(job.filePath, job.fileType, onProgress, uploadId);

    // Store reports for download
    job.reportCsv = result.csvContent;
    job.reportTxt = result.txtContent;

    // Save reports locally
    const outputDir = path.join(__dirname, '../../output', uploadId);
    await fs.mkdir(outputDir, { recursive: true });
    await fs.writeFile(path.join(outputDir, 'report.csv'), result.csvContent);
    await fs.writeFile(path.join(outputDir, 'report.txt'), result.txtContent);
    await fs.writeFile(path.join(outputDir, 'summary.json'), JSON.stringify(result.summary, null, 2));

    // Extract detailed requests from module4 CSV or report CSV
    let detailedRequests = [];
    
    // Try multiple paths for the CSV
    const possibleCsvPaths = [
      result.summary?.module_pipeline?.artifacts?.module4_csv,
      path.join(outputDir, 'report.csv'),
      result.summary?.module_pipeline?.output_csv
    ].filter(Boolean);
    
    console.log(`[Upload] Looking for CSV in paths:`, possibleCsvPaths);
    
    for (const csvPath of possibleCsvPaths) {
      try {
        await fs.access(csvPath);
        console.log(`[Upload] Found CSV at: ${csvPath}`);
        detailedRequests = await extractDetailedRequests(csvPath);
        if (detailedRequests.length > 0) {
          console.log(`[Upload] Extracted ${detailedRequests.length} detailed requests`);
          break;
        }
      } catch (e) {
        // File doesn't exist, try next path
      }
    }

    // Fallback: Use entries from result if available
    if (detailedRequests.length === 0 && result.entries && result.entries.length > 0) {
      console.log(`[Upload] Using ${result.entries.length} entries from result as fallback`);
      detailedRequests = result.entries.slice(0, 100).map(entry => ({
        timestamp: entry.timestamp || new Date().toISOString(),
        source_ip: entry.source_ip || entry.ip || '0.0.0.0',
        url: entry.url || entry.full_url || '',
        classification: entry.classification || 'unknown',
        attack_outcome: inferAttackOutcome(
          entry.classification,
          entry.status_code,
          entry.url || entry.full_url || '',
          entry.payload || entry.raw_content || '',
          entry.response || entry.response_body || entry.body || '',
          entry.response_headers || entry.headers || '',
          entry.response_time || entry.latency || entry.duration_ms || null
        ),
        confidence: parseFloat(entry.confidence) || 90,
        detection_method: entry.detection_method || 'ML'
      }));
    }
    
    console.log(`[Upload] Final detailedRequests count: ${detailedRequests.length}`);

    const outcomeBreakdown = computeOutcomeBreakdownFromRequests(detailedRequests);

    // Update file history in MongoDB with detailed requests
    await FileHistory.findOneAndUpdate(
      { userId: job.userId, fileName: job.fileName },
      {
        status: 'completed',
        processedAt: new Date(),
        results: {
          totalRequests: result.summary.total_requests,
          maliciousRequests: result.summary.threats_detected,
          attackTypes: result.summary.classification_breakdown,
          confirmedSuccessfulAttacks: outcomeBreakdown.confirmed_success,
          attackAttempts: outcomeBreakdown.attempt,
          mlAccuracy: Number(result.summary.ml_accuracy) > 0 ? Number(result.summary.ml_accuracy) : DEFAULT_ML_ACCURACY,
          suspiciousIps: Array.isArray(result.summary.suspicious_ips) ? result.summary.suspicious_ips : []
        },
        detailedRequests: detailedRequests
      }
    );

    // Keep live upload status response aligned with per-request outcomes used in Requests page.
    result.summary.confirmed_successful_attacks = outcomeBreakdown.confirmed_success;
    result.summary.attack_attempts = outcomeBreakdown.attempt;

    // Save to Supabase (non-blocking)
    saveReport(job.userId, uploadId, result.summary)
      .then(r => { if (r.url) job.reportUrl = r.url; })
      .catch(err => console.error('Supabase report error:', err));

    // Mark as finalizing while report email is being delivered.
    job.status = 'processing';
    job.progress = 98;
    job.message = 'Finalizing report and sending email...';
    job.results = result.summary;
    job.emailStatus = {
      state: 'pending',
      sent: false,
      message: 'Preparing report email...'
    };

    // Email report outputs (CSV/JSON/TXT) to the authenticated user.
    try {
      const user = await User.findById(job.userId).select('email');
      const recipientEmail = job.userEmail || user?.email || null;

      if (recipientEmail) {
        job.emailStatus = {
          state: 'pending',
          sent: false,
          recipient: recipientEmail,
          message: 'Sending report email...'
        };

        await sendReportEmail({
          email: recipientEmail,
          uploadId,
          fileName: job.fileName,
          summary: result.summary,
          csvContent: result.csvContent,
          txtContent: result.txtContent,
        });
        job.emailStatus = {
                  state: 'sent',
          sent: true,
          sentAt: new Date(),
          recipient: recipientEmail,
                  message: 'Report email sent successfully.'
        };
      } else {
        job.emailStatus = {
                  state: 'failed',
          sent: false,
                  reason: 'User email not found',
                  code: 'USER_EMAIL_NOT_FOUND',
                  message: 'Unable to send report email because account email is missing.'
        };
      }
    } catch (emailError) {
      console.error(`[Email] Failed to send report for ${uploadId}:`, emailError.message);
              const safeError = toSafeEmailError(emailError);
      job.emailStatus = {
                state: 'failed',
        sent: false,
                reason: safeError.reason,
                code: safeError.code,
                message: 'Report generated, but email delivery failed.'
      };
    }

            // Mark as completed only after email has been attempted.
            job.status = 'completed';
            job.progress = 100;
            job.message = 'Module + Phi3 analysis complete';

    console.log(`[Ollama] Analysis complete for ${uploadId}: ${result.summary.total_requests} entries, ${result.summary.threats_detected} threats, ${detailedRequests.length} detailed records`);

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
