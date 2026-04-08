const axios = require('axios');
const { existsSync } = require('fs');
const fs = require('fs').promises;
const path = require('path');
const { execFile } = require('child_process');

const OLLAMA_BASE_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
const MODEL = process.env.OLLAMA_MODEL || 'phi3';
const PANDAS_ERROR = "No module named 'pandas'";

const normalizeClassificationLabel = (label) => {
  const text = String(label || '').trim().toLowerCase();
  if (!text) return 'Unknown';

  if (text === 'normal' || text === 'benign' || text === 'safe') return 'Normal';
  if (text.includes('sql')) return 'SQL Injection';
  if (text.includes('xss') || text.includes('cross-site') || text.includes('script')) return 'Cross-Site Scripting (XSS)';
  if (text.includes('traversal') || text.includes('path traversal')) return 'Directory Traversal';
  if (text.includes('command')) return 'Command Injection';
  if (text.includes('ssrf') || text.includes('server-side request forgery')) return 'Server-Side Request Forgery (SSRF)';
  if (text.includes('local file inclusion') || text === 'lfi') return 'Local File Inclusion (LFI)';
  if (text.includes('remote file inclusion') || text === 'rfi') return 'Remote File Inclusion (RFI)';
  if (text.includes('parameter pollution')) return 'HTTP Parameter Pollution';
  if (text.includes('xxe') || text.includes('xml external entity')) return 'XML External Entity Injection (XXE)';
  if (text.includes('web shell') || text.includes('backdoor')) return 'Web Shell Upload';
  if (text.includes('typosquat') || text.includes('spoof')) return 'Typosquatting / URL Spoofing';
  if (text.includes('brute') || text.includes('credential stuffing')) return 'Credential Stuffing / Brute Force';
  if (text.includes('suspicious')) return 'Suspicious Behavior';

  return String(label || 'Unknown');
};

const runExecFile = (command, args) => new Promise((resolve, reject) => {
  execFile(command, args, { maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
    if (error) {
      reject(new Error(`${command} failed: ${stderr || error.message}`));
      return;
    }
    resolve(stdout);
  });
});

const parseJsonLine = (stdout) => {
  const lines = stdout
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean);

  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      return JSON.parse(lines[i]);
    } catch {
      // Continue searching previous lines.
    }
  }

  throw new Error('Module pipeline returned no JSON payload');
};

const getPythonAttempts = (scriptPath, filePath, outputDir) => {
  const repoRoot = path.resolve(__dirname, '../../..');
  const dashboardRoot = path.resolve(__dirname, '../..');

  const venvCandidates = [
    path.join(repoRoot, '.venv', 'Scripts', 'python.exe'),
    path.join(repoRoot, 'venv', 'Scripts', 'python.exe'),
    path.join(dashboardRoot, '.venv', 'Scripts', 'python.exe'),
    path.join(dashboardRoot, 'venv', 'Scripts', 'python.exe')
  ];

  const attempts = [];
  const customPython = process.env.HIDS_PYTHON;

  if (customPython) {
    attempts.push({ command: customPython, prefixArgs: [] });
  }

  venvCandidates
    .filter(candidate => existsSync(candidate))
    .forEach(candidate => attempts.push({ command: candidate, prefixArgs: [] }));

  attempts.push({ command: 'python', prefixArgs: [] });
  attempts.push({ command: 'py', prefixArgs: ['-3'] });

  const seen = new Set();
  const dedupedAttempts = attempts.filter((attempt) => {
    const key = `${attempt.command}|${attempt.prefixArgs.join(' ')}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return dedupedAttempts.map(attempt => ({
    ...attempt,
    pipelineArgs: [...attempt.prefixArgs, scriptPath, '--input', filePath, '--output-dir', outputDir]
  }));
};

const buildInstallCommand = (attempt, requirementsPath) => {
  const quotedReq = `"${requirementsPath}"`;
  if (attempt.command === 'py') {
    return `py -3 -m pip install -r ${quotedReq}`;
  }
  return `"${attempt.command}" -m pip install -r ${quotedReq}`;
};

const getEligiblePythonAttempts = async (attempts, requirementsPath) => {
  const eligibleAttempts = [];
  const meaningfulErrors = [];
  const pandasMissingAttempts = [];
  let lastError = null;

  for (const attempt of attempts) {
    try {
      await runExecFile(attempt.command, [...attempt.prefixArgs, '-c', 'import pandas']);
      eligibleAttempts.push(attempt);
    } catch (error) {
      lastError = error;
      const message = String(error.message || '');
      const isCommandMissing = message.toLowerCase().includes('enoent');

      if (message.includes(PANDAS_ERROR)) {
        pandasMissingAttempts.push(attempt);
        continue;
      }

      if (!isCommandMissing) {
        meaningfulErrors.push(`${attempt.command}: ${message}`);
      }
    }
  }

  if (eligibleAttempts.length > 0) {
    return eligibleAttempts;
  }

  if (pandasMissingAttempts.length > 0) {
    const installCommand = buildInstallCommand(pandasMissingAttempts[0], requirementsPath);
    throw new Error(`Python is missing required dependency 'pandas'. Run: ${installCommand}`);
  }

  if (meaningfulErrors.length > 0) {
    throw new Error(`Python dependency check failed: ${meaningfulErrors[0]}`);
  }

  throw lastError || new Error('Unable to execute Python dependency check');
};

const runModulePipeline = async (filePath, uploadId) => {
  const scriptPath = path.join(__dirname, 'module_pipeline_runner.py');
  const outputDir = path.join(__dirname, '../../output', uploadId || 'manual');
  const requirementsPath = path.resolve(__dirname, '../../../requirements.txt');

  await fs.mkdir(outputDir, { recursive: true });

  const attempts = getPythonAttempts(scriptPath, filePath, outputDir);
  const eligibleAttempts = await getEligiblePythonAttempts(attempts, requirementsPath);

  let lastError = null;
  const meaningfulErrors = [];

  for (const attempt of eligibleAttempts) {
    try {
      const stdout = await runExecFile(attempt.command, attempt.pipelineArgs);
      const payload = parseJsonLine(stdout);
      return { payload, outputDir };
    } catch (error) {
      lastError = error;
      const message = String(error.message || '');
      const isCommandMissing = message.toLowerCase().includes('enoent');

      if (message.includes(PANDAS_ERROR)) {
        const installCommand = buildInstallCommand(attempt, requirementsPath);
        throw new Error(`Python is missing required dependency 'pandas'. Run: ${installCommand}`);
      }

      if (!isCommandMissing) {
        meaningfulErrors.push(`${attempt.command}: ${message}`);
      }
    }
  }

  if (meaningfulErrors.length > 0) {
    throw new Error(`Module pipeline failed: ${meaningfulErrors[0]}`);
  }

  throw lastError || new Error('Unable to execute module pipeline (no Python runtime found)');
};

/**
 * Analyze a single URL/request entry with Ollama phi3
 */
const analyzeEntry = async (entry, index, total) => {
  const prompt = `Analyze this HTTP request for security threats. Respond ONLY in this exact JSON format, no extra text:
{"classification":"Normal|SQL Injection|Cross-Site Scripting (XSS)|Directory Traversal|Command Injection|Server-Side Request Forgery (SSRF)|Local File Inclusion (LFI)|Remote File Inclusion (RFI)|HTTP Parameter Pollution|XML External Entity Injection (XXE)|Web Shell Upload|Typosquatting / URL Spoofing|Credential Stuffing / Brute Force|Suspicious Behavior","risk_level":"None|Low|Medium|High|Critical","patterns":"brief description of suspicious patterns or None","recommendation":"brief action to take"}

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
      const parsed = JSON.parse(jsonMatch[0]);
      parsed.classification = normalizeClassificationLabel(parsed.classification);
      return parsed;
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
  const entries = [];

  if (fileType === 'csv') {
    const content = await fs.readFile(filePath, 'utf-8');
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
    const content = await fs.readFile(filePath, 'utf-8');
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
const analyzeFile = async (filePath, fileType, onProgress, uploadId = 'manual') => {
  if (onProgress) {
    onProgress(10, 'Module 1: Data Collection...');
    onProgress(20, 'Module 2: URL Parsing...');
    onProgress(30, 'Module 3: Feature Extraction...');
    onProgress(40, 'Module 4: Classification...');
  }

  const moduleResult = await runModulePipeline(filePath, uploadId);
  const moduleSummary = moduleResult.payload.summary || {};

  if (onProgress) {
    onProgress(55, `Phi3 Enrichment (${MODEL})...`);
  }

  // Parse the file
  const entries = await parseFile(filePath, fileType);

  if (entries.length === 0) {
    const moduleCsvPath = moduleResult.payload.artifacts?.module4_csv;
    const csvContent = moduleCsvPath ? await fs.readFile(moduleCsvPath, 'utf-8') : 'No CSV generated';
    const txtContent = [
      'HIDS Hybrid Report',
      `Modules analyzed ${moduleSummary.total_requests || 0} requests.`,
      `Ollama enrichment was skipped for file type: ${fileType}.`
    ].join('\n');

    return {
      entries: [],
      summary: {
        ...moduleSummary,
        analyzed_with: `Modules 1-4 + Ollama ${MODEL}`,
        ollama_enriched_entries: 0,
        module_pipeline: moduleResult.payload
      },
      csvContent,
      txtContent
    };
  }

  // Limit to 50 entries max to avoid long processing times
  const toAnalyze = entries.slice(0, 50);
  const results = [];

  // Analyze each entry with Ollama
  for (let i = 0; i < toAnalyze.length; i++) {
    if (onProgress) {
      onProgress(Math.round(60 + (i / toAnalyze.length) * 30), `Phi3 analyzing entry ${i + 1}/${toAnalyze.length}...`);
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

  const ollamaSummary = {
    total_requests: results.length,
    threats_detected: threatCount,
    threat_percentage: Number(((threatCount / results.length) * 100).toFixed(1)),
    classification_breakdown: classificationCounts,
    analyzed_with: `Ollama ${MODEL}`,
    analyzed_at: new Date().toISOString()
  };

  const summary = {
    ...moduleSummary,
    analyzed_with: `Modules 1-4 + Ollama ${MODEL}`,
    analyzed_at: new Date().toISOString(),
    ollama_enriched_entries: results.length,
    ollama: ollamaSummary,
    module_pipeline: moduleResult.payload
  };

  // Generate CSV content
  const csvHeaders = ['source_ip', 'url', 'method', 'classification', 'risk_level', 'patterns', 'recommendation', 'timestamp'];
  const csvRows = results.map(r =>
    csvHeaders.map(h => `"${(r[h] || '').toString().replace(/"/g, '""')}"`)
  );
  // Generate TXT report
  const txtLines = [
    '═══════════════════════════════════════════════════════════════',
    '          HIDS - URL-Based Attack Detection Report',
    '              Powered by Ollama Phi3 AI Model',
    '═══════════════════════════════════════════════════════════════',
    '',
    `Analysis Date:        ${new Date().toLocaleString()}`,
    `File Type:            ${fileType.toUpperCase()}`,
    `Total Entries (Modules): ${summary.total_requests}`,
    `Threats Detected (Modules): ${summary.threats_detected} (${summary.threat_percentage}%)`,
    `Ollama Enriched Entries: ${summary.ollama_enriched_entries}`,
    `AI Model Used: ${MODEL}`,
    '',
    '───────────────────────────────────────────────────────────────',
    '  CLASSIFICATION BREAKDOWN',
    '───────────────────────────────────────────────────────────────',
    ...Object.entries(summary.classification_breakdown || {}).map(([cls, count]) =>
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

  const moduleCsvPath = moduleResult.payload.artifacts?.module4_csv;
  const csvContent = moduleCsvPath
    ? await fs.readFile(moduleCsvPath, 'utf-8')
    : [csvHeaders.join(','), ...csvRows.map(r => r.join(','))].join('\n');

  return { entries: results, summary, csvContent, txtContent };
};

module.exports = { analyzeFile, analyzeEntry, parseFile };
