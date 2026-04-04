const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');

// Ollama API configuration
const OLLAMA_BASE_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
const DEFAULT_MODEL = process.env.OLLAMA_MODEL || 'llama3.2';

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
    const { message, context, model } = req.body;
    
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
      model: model || DEFAULT_MODEL,
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

    const prompt = `Analyze this URL for potential security threats:

URL: ${url}

Please identify:
1. Attack type (if any): SQL Injection, XSS, Path Traversal, Command Injection, or Normal
2. Suspicious patterns detected
3. Risk level (Critical, High, Medium, Low, None)
4. Recommended action

Format your response as JSON with fields: attackType, patterns, riskLevel, action, explanation`;

    const response = await axios.post(`${OLLAMA_BASE_URL}/api/generate`, {
      model: DEFAULT_MODEL,
      prompt: prompt,
      system: 'You are a URL security analyzer. Respond ONLY with valid JSON, no additional text.',
      stream: false,
      options: {
        temperature: 0.3,
        num_predict: 512
      }
    }, { timeout: 30000 });

    // Try to parse JSON response
    let analysis;
    try {
      const jsonMatch = response.data.response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        analysis = JSON.parse(jsonMatch[0]);
      } else {
        analysis = { raw: response.data.response };
      }
    } catch {
      analysis = { raw: response.data.response };
    }

    res.json({
      url,
      analysis,
      model: response.data.model
    });

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
    const { message, context, model } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const systemPrompt = `You are a cybersecurity expert specializing in URL-based attack detection. Provide concise, actionable security insights.`;

    const response = await axios.post(`${OLLAMA_BASE_URL}/api/generate`, {
      model: model || DEFAULT_MODEL,
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
