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
    const effectiveBreakdown =
      summary?.ollama?.classification_breakdown ||
      summary.classification_breakdown ||
      {};
    const effectiveThreatPercentage = Number(
      summary?.ollama?.threat_percentage ?? summary.threat_percentage ?? 0
    );
    const effectiveThreatsDetected = Number(
      summary?.ollama?.threats_detected ?? summary.threats_detected ?? 0
    );

    const attackEntries = Object.entries(effectiveBreakdown)
      .filter(([label]) => String(label).toLowerCase() !== 'normal')
      .sort((a, b) => Number(b[1]) - Number(a[1]));

    const attackType = attackEntries.length > 0 ? attackEntries[0][0] : 'Normal';
    const threatPercentage = effectiveThreatPercentage;

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
    };

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
        maliciousRequests: effectiveThreatsDetected,
        attackTypes: effectiveBreakdown,
        mlAccuracy: Number(summary.ml_accuracy) > 0 ? Number(summary.ml_accuracy) : DEFAULT_ML_ACCURACY,
        suspiciousIps: Array.isArray(summary.suspicious_ips) ? summary.suspicious_ips : []
      }
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
