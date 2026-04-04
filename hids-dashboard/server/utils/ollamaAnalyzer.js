const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');

const OLLAMA_BASE_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
const MODEL = process.env.OLLAMA_MODEL || 'phi3';

/**
 * Analyze a single URL/request entry with Ollama phi3
 */
const analyzeEntry = async (entry, index, total) => {
  const prompt = `Analyze this HTTP request for security threats. Respond ONLY in this exact JSON format, no extra text:
{"classification":"Normal|SQL Injection|XSS|Path Traversal|Command Injection|Suspicious","risk_level":"None|Low|Medium|High|Critical","patterns":"brief description of suspicious patterns or None","recommendation":"brief action to take"}

Request data:
- URL: ${entry.url || entry.full_url || 'N/A'}
- Source IP: ${entry.source_ip || entry.ip || 'N/A'}
- Method: ${entry.method || 'GET'}
- Timestamp: ${entry.timestamp || 'N/A'}
${entry.user_agent ? `- User-Agent: ${entry.user_agent}` : ''}
${entry.payload ? `- Payload: ${entry.payload}` : ''}`;

  try {
    const response = await axios.post(`${OLLAMA_BASE_URL}/api/generate`, {
      model: MODEL,
      prompt: prompt,
      system: 'You are a URL security analyzer. Respond ONLY with valid JSON. No markdown, no explanation.',
      stream: false,
      options: {
        temperature: 0.2,
        num_predict: 256
      }
    }, { timeout: 120000 });

    // Parse JSON from response
    const text = response.data.response || '';
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
    return { classification: 'Unknown', risk_level: 'Unknown', patterns: 'Parse error', recommendation: 'Manual review needed' };
  } catch (error) {
    console.error(`[Ollama] Analysis failed for entry ${index + 1}/${total}:`, error.message);
    return { classification: 'Error', risk_level: 'Unknown', patterns: 'Analysis failed', recommendation: 'Retry analysis' };
  }
};

/**
 * Parse uploaded file into analyzable entries
 */
const parseFile = async (filePath, fileType) => {
  const content = await fs.readFile(filePath, 'utf-8');
  const entries = [];

  if (fileType === 'csv') {
    const lines = content.split('\n').filter(l => l.trim());
    if (lines.length === 0) return entries;

    const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/"/g, ''));

    for (let i = 1; i < lines.length; i++) {
      const values = lines[i].split(',').map(v => v.trim().replace(/"/g, ''));
      const entry = {};
      headers.forEach((h, idx) => {
        entry[h] = values[idx] || '';
      });
      entries.push(entry);
    }
  } else if (fileType === 'logs') {
    // Parse common log formats (Apache/Nginx)
    const logRegex = /(\d+\.\d+\.\d+\.\d+).*?"(\w+)\s+(\S+)\s+HTTP\/[\d.]+"\s+(\d+)/g;
    let match;
    while ((match = logRegex.exec(content)) !== null) {
      entries.push({
        source_ip: match[1],
        method: match[2],
        url: match[3],
        status_code: match[4],
        timestamp: new Date().toISOString()
      });
    }

    // If no standard log format matched, split by lines and treat each as a URL candidate
    if (entries.length === 0) {
      const lines = content.split('\n').filter(l => l.trim());
      for (const line of lines) {
        const urlMatch = line.match(/(https?:\/\/\S+|\/\S+\?\S+)/);
        if (urlMatch) {
          entries.push({ url: urlMatch[1], raw_line: line.substring(0, 200) });
        }
      }
    }

    // If still nothing, analyze raw content
    if (entries.length === 0) {
      entries.push({ url: 'N/A', raw_content: content.substring(0, 2000) });
    }
  } else if (fileType === 'pcap') {
    // PCAP files are binary - provide a basic note
    entries.push({
      url: 'N/A',
      raw_content: 'Binary PCAP file - requires packet-level analysis',
      note: 'PCAP analysis requires specialized parsing'
    });
  }

  return entries;
};

/**
 * Run full Ollama-powered analysis on an uploaded file
 * Returns { entries, summary, csvContent, txtContent }
 */
const analyzeFile = async (filePath, fileType, onProgress) => {
  // Parse the file
  const entries = await parseFile(filePath, fileType);

  if (entries.length === 0) {
    return {
      entries: [],
      summary: { total: 0, threats: 0, message: 'No analyzable entries found' },
      csvContent: 'No data to analyze',
      txtContent: 'No data to analyze'
    };
  }

  // Limit to 50 entries max to avoid long processing times
  const toAnalyze = entries.slice(0, 50);
  const results = [];

  // Analyze each entry with Ollama
  for (let i = 0; i < toAnalyze.length; i++) {
    if (onProgress) {
      onProgress(Math.round(25 + (i / toAnalyze.length) * 60), `Analyzing entry ${i + 1}/${toAnalyze.length} with Phi3...`);
    }

    const analysis = await analyzeEntry(toAnalyze[i], i, toAnalyze.length);
    results.push({
      ...toAnalyze[i],
      ...analysis
    });
  }

  // Build summary
  const threatCount = results.filter(r =>
    r.classification && r.classification.toLowerCase() !== 'normal' && r.classification.toLowerCase() !== 'unknown'
  ).length;

  const classificationCounts = {};
  results.forEach(r => {
    const cls = r.classification || 'Unknown';
    classificationCounts[cls] = (classificationCounts[cls] || 0) + 1;
  });

  const summary = {
    total_requests: results.length,
    threats_detected: threatCount,
    threat_percentage: ((threatCount / results.length) * 100).toFixed(1),
    classification_breakdown: classificationCounts,
    analyzed_with: `Ollama ${MODEL}`,
    analyzed_at: new Date().toISOString()
  };

  // Generate CSV content
  const csvHeaders = ['source_ip', 'url', 'method', 'classification', 'risk_level', 'patterns', 'recommendation', 'timestamp'];
  const csvRows = results.map(r =>
    csvHeaders.map(h => `"${(r[h] || '').toString().replace(/"/g, '""')}"`)
  );
  const csvContent = [csvHeaders.join(','), ...csvRows.map(r => r.join(','))].join('\n');

  // Generate TXT report
  const txtLines = [
    '═══════════════════════════════════════════════════════════════',
    '          HIDS - URL-Based Attack Detection Report',
    '              Powered by Ollama Phi3 AI Model',
    '═══════════════════════════════════════════════════════════════',
    '',
    `Analysis Date:        ${new Date().toLocaleString()}`,
    `File Type:            ${fileType.toUpperCase()}`,
    `Total Entries:        ${summary.total_requests}`,
    `Threats Detected:     ${summary.threats_detected} (${summary.threat_percentage}%)`,
    `AI Model Used:        ${MODEL}`,
    '',
    '───────────────────────────────────────────────────────────────',
    '  CLASSIFICATION BREAKDOWN',
    '───────────────────────────────────────────────────────────────',
    ...Object.entries(classificationCounts).map(([cls, count]) =>
      `  ${cls.padEnd(25)} ${count} entries`
    ),
    '',
    '───────────────────────────────────────────────────────────────',
    '  DETAILED FINDINGS',
    '───────────────────────────────────────────────────────────────',
    ''
  ];

  results.forEach((r, idx) => {
    txtLines.push(`  [${idx + 1}] ${r.url || 'N/A'}`);
    txtLines.push(`      Source IP:       ${r.source_ip || 'N/A'}`);
    txtLines.push(`      Classification:  ${r.classification || 'Unknown'}`);
    txtLines.push(`      Risk Level:      ${r.risk_level || 'Unknown'}`);
    txtLines.push(`      Patterns:        ${r.patterns || 'None'}`);
    txtLines.push(`      Recommendation:  ${r.recommendation || 'N/A'}`);
    txtLines.push('');
  });

  txtLines.push('═══════════════════════════════════════════════════════════════');
  txtLines.push('  End of Report — Generated by HIDS Dashboard');
  txtLines.push('═══════════════════════════════════════════════════════════════');

  const txtContent = txtLines.join('\n');

  return { entries: results, summary, csvContent, txtContent };
};

module.exports = { analyzeFile, analyzeEntry, parseFile };
