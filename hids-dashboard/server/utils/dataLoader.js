const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');

const OUTPUT_DIR = path.resolve(process.cwd(), 'output');

/**
 * Get all analysis subdirectories (each uploadId has its own folder)
 */
const getAnalysisDirs = () => {
  if (!fs.existsSync(OUTPUT_DIR)) return [];

  return fs.readdirSync(OUTPUT_DIR, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => path.join(OUTPUT_DIR, d.name))
    .sort((a, b) => {
      // Sort by modification time, newest first
      try {
        return fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs;
      } catch { return 0; }
    });
};

/**
 * Load summary — aggregates all Ollama analysis summaries
 * Falls back to legacy module4_summary.json if present
 */
const loadSummary = () => {
  return new Promise((resolve, reject) => {
    // First try legacy format
    const legacyPath = path.join(OUTPUT_DIR, 'module4_summary.json');
    if (fs.existsSync(legacyPath)) {
      try {
        const data = fs.readFileSync(legacyPath, 'utf8');
        return resolve(JSON.parse(data));
      } catch (e) { /* fall through */ }
    }

    // Aggregate from Ollama analysis folders
    const dirs = getAnalysisDirs();
    if (dirs.length === 0) {
      return resolve({
        total_requests: 0,
        threats_detected: 0,
        threat_percentage: '0.0',
        ml_accuracy: 0.95,
        class_counts: {},
        suspicious_ips: [],
        analyzed_with: 'Ollama phi3',
        message: 'No analysis results yet. Upload a file to get started.'
      });
    }

    // Merge all summaries
    let totalRequests = 0;
    let totalThreats = 0;
    const classCounts = {};
    const suspiciousIps = new Set();

    for (const dir of dirs) {
      const summaryPath = path.join(dir, 'summary.json');
      if (!fs.existsSync(summaryPath)) continue;

      try {
        const data = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
        totalRequests += data.total_requests || 0;
        totalThreats += data.threats_detected || 0;

        // Merge classification breakdown
        if (data.classification_breakdown) {
          for (const [cls, count] of Object.entries(data.classification_breakdown)) {
            classCounts[cls] = (classCounts[cls] || 0) + count;
          }
        }
      } catch (e) {
        console.error(`Failed to read summary from ${dir}:`, e.message);
      }
    }

    // Extract suspicious IPs from requests
    loadRequests().then(requests => {
      requests.forEach(r => {
        const cls = (r.classification || '').toLowerCase();
        if (cls !== 'normal' && cls !== 'unknown' && cls !== 'error' && r.source_ip && r.source_ip !== 'N/A') {
          suspiciousIps.add(r.source_ip);
        }
      });

      resolve({
        total_requests: totalRequests,
        threats_detected: totalThreats,
        threat_percentage: totalRequests > 0 ? ((totalThreats / totalRequests) * 100).toFixed(1) : '0.0',
        ml_accuracy: 0.95,
        class_counts: classCounts,
        suspicious_ips: [...suspiciousIps],
        analyzed_with: 'Ollama phi3'
      });
    }).catch(() => {
      resolve({
        total_requests: totalRequests,
        threats_detected: totalThreats,
        threat_percentage: totalRequests > 0 ? ((totalThreats / totalRequests) * 100).toFixed(1) : '0.0',
        ml_accuracy: 0.95,
        class_counts: classCounts,
        suspicious_ips: [],
        analyzed_with: 'Ollama phi3'
      });
    });
  });
};

/**
 * Load all requests — merges CSVs from all analysis folders
 * Falls back to legacy module4_hybrid_results.csv
 */
const loadRequests = () => {
  return new Promise(async (resolve, reject) => {
    // First try legacy format
    const legacyPath = path.join(OUTPUT_DIR, 'module4_hybrid_results.csv');
    if (fs.existsSync(legacyPath)) {
      const results = [];
      fs.createReadStream(legacyPath)
        .pipe(csv())
        .on('data', (data) => results.push(data))
        .on('end', () => resolve(results))
        .on('error', (error) => reject(new Error(`Failed to parse CSV: ${error.message}`)));
      return;
    }

    // Load from Ollama analysis folders
    const dirs = getAnalysisDirs();
    if (dirs.length === 0) return resolve([]);

    const allResults = [];

    for (const dir of dirs) {
      const reportPath = path.join(dir, 'report.csv');
      if (!fs.existsSync(reportPath)) continue;

      try {
        const rows = await new Promise((res, rej) => {
          const results = [];
          fs.createReadStream(reportPath)
            .pipe(csv())
            .on('data', (data) => results.push(data))
            .on('end', () => res(results))
            .on('error', (err) => rej(err));
        });
        allResults.push(...rows);
      } catch (e) {
        console.error(`Failed to read report from ${dir}:`, e.message);
      }
    }

    resolve(allResults);
  });
};

/**
 * Load features — from legacy pipeline or empty
 */
const loadFeatures = () => {
  return new Promise((resolve, reject) => {
    const filePath = path.join(OUTPUT_DIR, 'url_feature_dataset.csv');

    if (!fs.existsSync(filePath)) {
      return resolve([]); // No features available
    }

    const results = [];
    fs.createReadStream(filePath)
      .pipe(csv())
      .on('data', (data) => results.push(data))
      .on('end', () => resolve(results))
      .on('error', (error) => reject(new Error(`Failed to parse features CSV: ${error.message}`)));
  });
};

module.exports = {
  loadSummary,
  loadRequests,
  loadFeatures
};
