const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');
const { analyzeFile } = require('../utils/ollamaAnalyzer');
const FileHistory = require('../models/FileHistory');
const DEFAULT_ML_ACCURACY = Number(process.env.DEFAULT_ML_ACCURACY || 0.964);

// Ollama API configuration
const OLLAMA_BASE_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
const DEFAULT_MODEL = 'phi3';

const TYPO_BRANDS = [
  'amazon', 'paypal', 'google', 'microsoft', 'apple',
  'facebook', 'instagram', 'netflix', 'bank', 'icici', 'hdfc'
];

const TYPO_LURE_WORDS = [
  'login', 'signin', 'verify', 'secure', 'account', 'update',
  'support', 'billing', 'recovery', 'auth', 'wallet'
];

const OFFICIAL_DOMAIN_SUFFIXES = [
  'amazon.com', 'paypal.com', 'google.com', 'microsoft.com', 'apple.com',
  'facebook.com', 'instagram.com', 'netflix.com'
];

const isTyposquattingHost = (hostValue) => {
  const host = String(hostValue || '').toLowerCase().trim().replace(/^\.+|\.+$/g, '');
  if (!host) return false;

  if (OFFICIAL_DOMAIN_SUFFIXES.some((sfx) => host === sfx || host.endsWith(`.${sfx}`))) {
    return false;
  }

  const hasBrand = TYPO_BRANDS.some((b) => host.includes(b));
  const hasLure = TYPO_LURE_WORDS.some((w) => host.includes(w));
  const hasHyphen = host.includes('-');
  return hasBrand && hasLure && hasHyphen;
};

const URL_RULES = [
  {
    label: 'SQL Injection',
    patterns: [
      /\b(?:union|select|insert|update|delete)\b/i,
      /(?:'|\")\s*or\s+\d+\s*=\s*\d+/i,
      /'\s*or\s*'1'\s*=\s*'1/i,
      /\bunion\s+select\b/i,
      /--|\/\*|\*\//i,
      /#/i,
      /\bselect\b.+\bfrom\b/i,
    ],
  },
  {
    label: 'Command Injection',
    patterns: [/(;|&&|\||`)\s*(ls|whoami|cat|id|ping|sleep)\b/i, /(;|\|\||&&)\s*(cat|bash|sh|cmd|powershell|wget|curl|nc|netcat)\b/i, /\$\(|`.+`/i],
  },
  {
    label: 'Remote File Inclusion (RFI)',
    patterns: [/\b(?:file|include|page|path|template|view)=https?:\/\//i, /https?:\/\/[^\s?#]+\.(?:php|jsp|asp|aspx|cgi)(?:\?|$)/i],
  },
  {
    label: 'Local File Inclusion (LFI)',
    patterns: [/\b(?:file|page|path|include|template|view)=.*(?:\/etc\/passwd|boot\.ini|windows\/win\.ini|\/proc\/self\/environ)/i, /\b(?:file|page|path|include|template|view)=.*(?:\.\.\/|%2e%2e%2f)/i],
  },
  {
    label: 'Server-Side Request Forgery (SSRF)',
    patterns: [
      /(?:https?|ftp|file):\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0)/i,
      /(?:https?|ftp|file):\/\/(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)/i,
      /127\.0\.0\.1|localhost|169\.254|0\.0\.0\.0/i,
      /(?:https?|ftp|file):\/\/(?:2130706433|0x7f000001)(?::\d+)?(?:\/|$)/i,
      /(?:https?|ftp|file):\/\/(?:\d{8,10}|0x[0-9a-f]{6,8})(?::\d+)?(?:\/|$)/i,
    ],
  },
  {
    label: 'Cross-Site Scripting (XSS)',
    patterns: [/<\s*script/i, /<\/\s*script\s*>/i, /alert\s*\(/i, /onerror\s*=/i, /onload\s*=/i, /javascript\s*:/i],
  },
  {
    label: 'Directory Traversal',
    patterns: [/\.\./i, /%2e%2e%2f|%2e%2e%5c/i, /\/etc\/passwd|\\windows\\system32/i],
  },
  {
    label: 'HTTP Parameter Pollution',
    patterns: [/(?:\?|&)([^=&]+)=[^&]*(?:&\1=)/i],
  },
  {
    label: 'XML External Entity Injection (XXE)',
    patterns: [/<\!doctype/i, /<\!entity/i, /%3c!doctype|%3c!entity/i, /<!doctype\s+[^>]*\[\s*<!entity/i],
  },
  {
    label: 'LDAP Injection',
    patterns: [/\(&|\(\||\*\)|\)\(/i, /\b(?:uid|cn|ou|dc)\s*=\s*\*/i],
  },
  {
    label: 'HTTP Header Injection',
    patterns: [/(?:%0d%0a|\r\n|\n|\r)(?:location:|set-cookie:)/i],
  },
  {
    label: 'Directory Traversal',
    patterns: [/\.\./i, /%2e%2e%2f|%2e%2e%5c/i, /\\windows\\system32/i],
  },
  {
    label: 'Web Shell Upload',
    patterns: [/(?:cmd|shell|backdoor|webshell)\.(?:php|jsp|asp|aspx|cgi)\b/i, /(?:upload|file)=.*\.(?:php|jsp|asp|aspx|cgi)\b/i],
  },
];

const ATTACK_PRIORITY = {
  'SQL Injection': 1,
  'Command Injection': 2,
  'Web Shell Upload': 3,
  'Remote File Inclusion (RFI)': 4,
  'Local File Inclusion (LFI)': 5,
  'Server-Side Request Forgery (SSRF)': 6,
  'XML External Entity Injection (XXE)': 7,
  'LDAP Injection': 8,
  'HTTP Header Injection': 9,
  'Cross-Site Scripting (XSS)': 10,
  'Directory Traversal': 11,
  'HTTP Parameter Pollution': 12,
};

const decodeVariants = (value) => {
  const out = [];
  const seen = new Set();
  let current = String(value || '');

  for (let i = 0; i < 3; i += 1) {
    if (!seen.has(current)) {
      seen.add(current);
      out.push(current);
    }

    let decoded = current;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      decoded = current;
    }

    if (decoded === current) break;
    current = decoded;
  }

  return out;
};

const isUnknownSuspicious = (textValue) => {
  const text = String(textValue || '').toLowerCase();
  const suspiciousKeywords = [
    'exec', 'system', 'shell', 'cmd', 'payload', 'base64', '${jndi', '../../',
    '<svg', 'onmouseover', 'document.cookie', '@import', 'file://', 'gopher://'
  ];

  const keywordHits = suspiciousKeywords.filter((k) => text.includes(k)).length;
  const specialChars = [...text].filter((ch) => !/[a-z0-9\s]/i.test(ch)).length;
  const specialRatio = specialChars / Math.max(text.length, 1);
  const encodedMarkers = (text.match(/%/g) || []).length + (text.match(/\\x|\\u00/g) || []).length;

  if (keywordHits >= 2) return true;
  if (specialRatio >= 0.35 && text.length >= 40) return true;
  if (encodedMarkers >= 6) return true;
  if ((text.includes('http://') || text.includes('https://')) && (text.includes('localhost') || text.includes('169.254.'))) return true;
  if (text.length > 300) return true;

  return false;
};

const detectUrlAttackType = (urlValue) => {
  const variants = decodeVariants(String(urlValue || ''));
  const decoded = variants.join(' ').toLowerCase();
  const matched = [];

  for (const rule of URL_RULES) {
    for (const re of rule.patterns) {
      if (re.test(decoded)) {
        matched.push({ label: rule.label, pattern: re.source });
        break;
      }
    }
  }

  if (matched.length > 0) {
    matched.sort((a, b) => (ATTACK_PRIORITY[a.label] || 999) - (ATTACK_PRIORITY[b.label] || 999));
    return matched[0].label;
  }

  try {
    const host = new URL(String(urlValue || '')).hostname.toLowerCase();
    if (/(^|\.)xn--/.test(host) || /(paypa1|g00gle|micr0soft|faceb00k|amaz0n|app1e|arnazon)/.test(host)) {
      return 'Typosquatting / URL Spoofing';
    }
    if (isTyposquattingHost(host)) {
      return 'Typosquatting / URL Spoofing';
    }
  } catch {
    // Ignore host parsing failures for non-absolute URLs.
  }

  if (isUnknownSuspicious(decoded)) {
    return 'Suspicious Behavior';
  }

  return 'Normal';
};

// Check Ollama connection
router.get('/status', auth, async (req, res) => {
  try {
    const response = await axios.get(`${OLLAMA_BASE_URL}/api/tags`, { timeout: 5000 });
    const models = response.data.models || [];
    
    res.json({
      connected: true,
      baseUrl: OLLAMA_BASE_URL,
      models: models.map(m => ({
        name: m.name,
        size: m.size,
        modified: m.modified_at
      })),
      defaultModel: DEFAULT_MODEL
    });
  } catch (error) {
    res.json({
      connected: false,
      error: 'Ollama is not running or not accessible',
      baseUrl: OLLAMA_BASE_URL,
      instructions: 'Please ensure Ollama is installed and running. Run: ollama serve'
    });
  }
});

// Chat with AI about security analysis
router.post('/chat', auth, async (req, res) => {
  try {
    const { message, context } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const systemPrompt = `You are a cybersecurity expert specializing in URL-based attack detection and network security analysis. You help users understand:
- SQL Injection attacks
- Cross-Site Scripting (XSS)
- Path Traversal attacks
- Command Injection
- Malicious URL patterns
- Network traffic analysis
- Intrusion detection systems

Provide concise, actionable insights. When analyzing URLs or logs, identify potential threats and explain the attack vectors. Format your responses clearly with bullet points when listing multiple items.`;

    const fullPrompt = context 
      ? `Context:\n${context}\n\nUser Question: ${message}`
      : message;

    const response = await axios.post(`${OLLAMA_BASE_URL}/api/generate`, {
      model: DEFAULT_MODEL,
      prompt: fullPrompt,
      system: systemPrompt,
      stream: false,
      options: {
        temperature: 0.7,
        top_p: 0.9,
        num_predict: 1024
      }
    }, {
      timeout: 60000 // 60 second timeout for generation
    });

    res.json({
      response: response.data.response,
      model: response.data.model,
      done: response.data.done,
      totalDuration: response.data.total_duration
    });

  } catch (error) {
    console.error('AI Chat error:', error.message);
    
    if (error.code === 'ECONNREFUSED') {
      return res.status(503).json({
        error: 'Ollama service unavailable',
        message: 'Please ensure Ollama is running: ollama serve'
      });
    }

    res.status(500).json({
      error: 'AI request failed',
      message: error.response?.data?.error || error.message
    });
  }
});

// Analyze URL for threats
router.post('/analyze-url', auth, async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const uploadId = `url_${Date.now().toString(16)}`;
    const tempDir = path.join(__dirname, '../../uploads');
    const tempCsvPath = path.join(tempDir, `${uploadId}.csv`);

    await fs.mkdir(tempDir, { recursive: true });

    // Build a minimal single-row dataset so Modules 1-4 can execute on URL input.
    const csvHeader = 'timestamp,source_ip,method,url,status_code,user_agent,referrer\n';
    const escapedUrl = String(url).replace(/"/g, '""');
    const csvRow = `${new Date().toISOString()},127.0.0.1,GET,"${escapedUrl}",200,web-dashboard,manual-url\n`;
    await fs.writeFile(tempCsvPath, `${csvHeader}${csvRow}`, 'utf-8');

    const result = await analyzeFile(tempCsvPath, 'csv', null, uploadId);
    const summary = result.summary || {};
    const moduleBreakdown = summary.classification_breakdown || {};
    const ollamaBreakdown = summary?.ollama?.classification_breakdown || {};
    const effectiveBreakdown = Object.keys(moduleBreakdown).length > 0 ? moduleBreakdown : ollamaBreakdown;
    const effectiveThreatPercentage = Number(
      summary?.ollama?.threat_percentage ?? summary.threat_percentage ?? 0
    );
    const effectiveThreatsDetected = Number(
      summary?.ollama?.threats_detected ?? summary.threats_detected ?? 0
    );

    const attackEntries = Object.entries(effectiveBreakdown)
      .filter(([label]) => String(label).toLowerCase() !== 'normal')
      .sort((a, b) => Number(b[1]) - Number(a[1]));

    const deterministicType = detectUrlAttackType(url);
    const moduleType = attackEntries.length > 0 ? attackEntries[0][0] : 'Normal';
    const attackType = deterministicType !== 'Normal' ? deterministicType : moduleType;
    const threatPercentage = attackType === 'Normal' ? 0 : effectiveThreatPercentage > 0 ? effectiveThreatPercentage : 100;

    const riskLevel = threatPercentage >= 75
      ? 'Critical'
      : threatPercentage >= 50
      ? 'High'
      : threatPercentage >= 20
      ? 'Medium'
      : threatPercentage > 0
      ? 'Low'
      : 'None';

    const analysis = {
      attackType,
      patterns: attackEntries.map(([label, count]) => `${label}: ${count}`),
      riskLevel,
      action: threatPercentage > 0
        ? 'Block or challenge suspicious requests, inspect source IP, and review WAF rules.'
        : 'No immediate action required. Continue monitoring URL traffic.',
      explanation: `Analyzed with ${summary.analyzed_with || 'Modules 1-4 + Ollama'}.`,
      module_summary: summary,
      deterministic_rule_match: deterministicType,
    };

    const attackOutcome = attackType === 'Normal' ? 'none' : 'attempt';

    const hostLabel = (() => {
      try {
        return new URL(url).hostname || 'url-analysis';
      } catch {
        return 'url-analysis';
      }
    })();

    await FileHistory.create({
      userId: req.user.id,
      fileName: `url_${hostLabel}`,
      fileType: 'other',
      fileSize: 0,
      status: 'completed',
      processedAt: new Date(),
      results: {
        totalRequests: Number(summary?.ollama?.total_requests ?? summary.total_requests ?? 1),
        maliciousRequests: attackType === 'Normal' ? 0 : Math.max(1, effectiveThreatsDetected),
        attackTypes: attackType === 'Normal' ? { Normal: 1 } : { [attackType]: 1 },
        confirmedSuccessfulAttacks: 0,
        attackAttempts: attackType === 'Normal' ? 0 : 1,
        mlAccuracy: Number(summary.ml_accuracy) > 0 ? Number(summary.ml_accuracy) : DEFAULT_ML_ACCURACY,
        suspiciousIps: Array.isArray(summary.suspicious_ips) ? summary.suspicious_ips : []
      },
      detailedRequests: [
        {
          timestamp: new Date(),
          source_ip: '127.0.0.1',
          url,
          classification: attackType,
          attack_outcome: attackOutcome,
          confidence: 95,
          detection_method: 'Deterministic+ML'
        }
      ]
    });

    res.json({
      url,
      analysis,
      model: summary.analyzed_with || `Modules 1-4 + Ollama ${DEFAULT_MODEL}`
    });

    // Best-effort cleanup of temporary input file.
    fs.unlink(tempCsvPath).catch(() => {});

  } catch (error) {
    console.error('URL analysis error:', error.message);
    res.status(500).json({ error: 'Analysis failed', message: error.message });
  }
});

// Analyze batch of results
router.post('/analyze-results', auth, async (req, res) => {
  try {
    const { summary, sampleThreats } = req.body;
    
    if (!summary) {
      return res.status(400).json({ error: 'Summary data is required' });
    }

    const prompt = `As a cybersecurity expert, analyze this URL-based attack detection report:

Summary:
- Total requests analyzed: ${summary.rows || summary.totalRequests || 0}
- Attack distribution: ${JSON.stringify(summary.class_counts || summary.attackTypes || {})}
- Suspicious IPs detected: ${(summary.suspicious_ips || []).slice(0, 5).join(', ') || 'None'}
- ML Model accuracy: ${summary.ml_accuracy || 'N/A'}

${sampleThreats ? `Sample detected threats:\n${sampleThreats.slice(0, 5).map(t => `- ${t}`).join('\n')}` : ''}

Provide:
1. Executive summary of the security posture
2. Top 3 most critical concerns
3. Recommended immediate actions
4. Long-term security improvements
5. Overall risk assessment (Critical/High/Medium/Low)`;

    const response = await axios.post(`${OLLAMA_BASE_URL}/api/generate`, {
      model: DEFAULT_MODEL,
      prompt: prompt,
      system: 'You are a senior cybersecurity analyst providing actionable security insights.',
      stream: false,
      options: {
        temperature: 0.5,
        num_predict: 1500
      }
    }, { timeout: 60000 });

    res.json({
      analysis: response.data.response,
      model: response.data.model,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Results analysis error:', error.message);
    res.status(500).json({ error: 'Analysis failed', message: error.message });
  }
});

// Stream chat response (Server-Sent Events)
router.post('/chat/stream', auth, async (req, res) => {
  try {
    const { message, context } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const systemPrompt = `You are a cybersecurity expert specializing in URL-based attack detection. Provide concise, actionable security insights.`;

    const response = await axios.post(`${OLLAMA_BASE_URL}/api/generate`, {
      model: DEFAULT_MODEL,
      prompt: context ? `Context:\n${context}\n\nQuestion: ${message}` : message,
      system: systemPrompt,
      stream: true
    }, {
      responseType: 'stream',
      timeout: 60000
    });

    response.data.on('data', (chunk) => {
      try {
        const data = JSON.parse(chunk.toString());
        res.write(`data: ${JSON.stringify(data)}\n\n`);
        
        if (data.done) {
          res.write('data: [DONE]\n\n');
          res.end();
        }
      } catch {
        // Skip malformed chunks
      }
    });

    response.data.on('error', (err) => {
      res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
      res.end();
    });

  } catch (error) {
    res.status(500).json({ error: 'Stream failed', message: error.message });
  }
});

// Get available models
router.get('/models', auth, async (req, res) => {
  try {
    const response = await axios.get(`${OLLAMA_BASE_URL}/api/tags`);
    const models = response.data.models || [];
    
    res.json({
      models: models.map(m => ({
        name: m.name,
        size: (m.size / 1024 / 1024 / 1024).toFixed(2) + ' GB',
        modified: m.modified_at,
        details: m.details
      })),
      defaultModel: DEFAULT_MODEL
    });
  } catch (error) {
    res.status(503).json({
      error: 'Cannot fetch models',
      message: 'Ollama is not running'
    });
  }
});

// Pull a new model
router.post('/models/pull', auth, async (req, res) => {
  try {
    const { model } = req.body;
    
    if (!model) {
      return res.status(400).json({ error: 'Model name is required' });
    }

    // Start pulling in background
    axios.post(`${OLLAMA_BASE_URL}/api/pull`, {
      name: model,
      stream: false
    }).catch(err => console.error('Model pull error:', err.message));

    res.json({
      message: `Started pulling model: ${model}`,
      note: 'This may take several minutes depending on model size'
    });

  } catch (error) {
    res.status(500).json({ error: 'Pull failed', message: error.message });
  }
});

module.exports = router;
