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

const inferAttackOutcome = (
  classification,
  statusCode,
  urlValue = '',
  payloadValue = '',
  responseBody = '',
  responseHeaders = '',
  responseTime = null,
  thresholdMs = 3000
) => {
  const normalized = String(classification || '').trim().toLowerCase();
  if (!normalized || normalized === 'normal') {
    return 'none';
  }

  const code = Number(statusCode);
  if (!Number.isFinite(code) || code < 200 || code >= 300) {
    return 'attempt';
  }

  const responseText = String(responseBody || '').toLowerCase();
  const headersText = String(responseHeaders || '').toLowerCase();
  const combined = `${String(urlValue || '')} ${String(payloadValue || '')} ${responseText} ${headersText}`.toLowerCase();
  const rt = Number(responseTime);

  let hasSuccessEvidence = false;
  if (normalized.includes('sql injection') || normalized === 'sqli') {
    hasSuccessEvidence = combined.includes('welcome') || combined.includes('sql') || combined.includes('mysql_fetch') || combined.includes('sql syntax');
  } else if (normalized.includes('xss') || normalized.includes('cross-site scripting')) {
    hasSuccessEvidence = combined.includes('<script>');
  } else if (normalized.includes('local file inclusion') || normalized.includes('directory traversal') || normalized.includes('path traversal') || normalized.includes('lfi')) {
    hasSuccessEvidence = combined.includes('root:x:0:0') || /(\/etc\/passwd|\/proc\/self\/environ|win\.ini|boot\.ini|windows\/system32)/i.test(combined);
  } else if (normalized.includes('remote file inclusion') || normalized.includes('web shell')) {
    hasSuccessEvidence = combined.includes('shell') || combined.includes('cmd') || /(cmd\.jsp|backdoor\.asp|webshell|shell\.php|\.aspx?|\.jsp|\.php)/i.test(combined);
  } else if (normalized.includes('server-side request forgery') || normalized.includes('ssrf')) {
    hasSuccessEvidence = combined.includes('internal server') || combined.includes('admin panel') || /(169\.254\.169\.254|localhost|127\.0\.0\.1|2130706433)/i.test(combined);
  } else if (normalized.includes('command injection')) {
    hasSuccessEvidence = combined.includes('uid=') || combined.includes('www-data') || /(;|&&|\|)\s*(whoami|id|cat|uname|powershell|cmd\.exe)/i.test(combined);
  } else if (normalized.includes('ldap injection') || normalized.includes('ldap')) {
    hasSuccessEvidence =
      combined.includes('login success') ||
      /\*\)\(\|/.test(combined) ||
      /\(\|\(user=\*\)\)/.test(combined) ||
      /\(uid=\*\)/.test(combined) ||
      /\)\(\|\(password=\*\)\)/.test(combined) ||
      (combined.includes('pass=anything') && (combined.includes('user=*)') || combined.includes('(|(user=*))')));
  } else if (normalized.includes('header injection') || normalized.includes('http header injection')) {
    hasSuccessEvidence = headersText.includes('set-cookie') || combined.includes('set-cookie');
  } else if (normalized.includes('brute force')) {
    hasSuccessEvidence = combined.includes('login success');
  } else if (normalized.includes('dos') || normalized.includes('denial of service')) {
    hasSuccessEvidence = Number.isFinite(rt) && rt > Number(thresholdMs);
  } else if (normalized.includes('csrf') || normalized.includes('cross-site request forgery')) {
    hasSuccessEvidence = combined.includes('transaction successful');
  }

  if (hasSuccessEvidence) {
    return 'confirmed_success';
  }

  return 'attempt';
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
      const attackOutcome = rec.attack_outcome || inferAttackOutcome(
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

// Download report as JSON (must be before /:type)
router.get('/download/json/:uploadId', auth, async (req, res) => {
  try {
    const { uploadId } = req.params;
    const job = processingJobs.get(uploadId);

    if (!job || String(job.userId) !== String(req.user.id)) {
      return res.status(404).json({ error: 'Report not found' });
    }

    const detailedRequests = job.reportCsv ? parseCSV(job.reportCsv).slice(0, 200) : [];
    const payload = {
      upload_id: uploadId,
      file_name: job.fileName,
      analyzed_at: new Date().toISOString(),
      summary: job.results || {},
      detailed_requests: detailedRequests,
    };

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
          confirmedSuccessfulAttacks: Number(result.summary.confirmed_successful_attacks || 0),
          attackAttempts: Number(result.summary.attack_attempts || 0),
          mlAccuracy: Number(result.summary.ml_accuracy) > 0 ? Number(result.summary.ml_accuracy) : DEFAULT_ML_ACCURACY,
          suspiciousIps: Array.isArray(result.summary.suspicious_ips) ? result.summary.suspicious_ips : []
        },
        detailedRequests: detailedRequests
      }
    );

    // Save to Supabase (non-blocking)
    saveReport(job.userId, uploadId, result.summary)
      .then(r => { if (r.url) job.reportUrl = r.url; })
      .catch(err => console.error('Supabase report error:', err));

    // Mark as completed
    job.status = 'completed';
    job.progress = 100;
    job.message = 'Module + Phi3 analysis complete';
    job.results = result.summary;

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
