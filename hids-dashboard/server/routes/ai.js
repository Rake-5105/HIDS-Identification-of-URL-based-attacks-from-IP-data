const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const axios = require('axios');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { analyzeFile } = require('../utils/ollamaAnalyzer');
const FileHistory = require('../models/FileHistory');
const User = require('../models/User');
const DEFAULT_ML_ACCURACY = Number(process.env.DEFAULT_ML_ACCURACY || 0.964);

// Ollama API configuration
const OLLAMA_BASE_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
const DEFAULT_MODEL = 'phi3';
const OLLAMA_REQUEST_TIMEOUT_MS = Number(process.env.OLLAMA_REQUEST_TIMEOUT_MS || 180000);
const AI_JOB_TTL_MS = Number(process.env.AI_JOB_TTL_MS || 30 * 60 * 1000);
const aiJobs = new Map();

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

const WEB_PLAYBOOKS = {
  sqli: {
    name: 'SQL Injection (SQLi)',
    description: 'Attackers inject malicious SQL code through user inputs to manipulate databases.',
    indicators: [
      'Unusual SQL keywords in URL parameters (UNION, SELECT, DROP, INSERT)',
      'Single quotes or double-dash comments in input fields',
      'Error messages revealing database schema',
      'Unexpected data returned from queries'
    ],
    remediation: [
      'Use parameterized queries / prepared statements for all DB interactions',
      'Implement strict input validation and sanitization',
      'Apply principle of least privilege to database accounts',
      'Deploy a Web Application Firewall (WAF) with SQLi rule sets',
      'Disable detailed error messages in production',
      'Regularly audit database access logs'
    ]
  },
  xss: {
    name: 'Cross-Site Scripting (XSS)',
    description: 'Malicious scripts are injected into web pages viewed by other users.',
    indicators: [
      '<script> tags or event handlers in URL parameters',
      'Encoded JavaScript payloads (%3Cscript%3E)',
      'DOM manipulation attempts via URL fragments',
      'Unusual iframe or image tags in user input'
    ],
    remediation: [
      'Encode all output data using context-appropriate encoding (HTML, JS, URL)',
      'Implement Content Security Policy (CSP) headers',
      'Use HTTPOnly and Secure flags on session cookies',
      'Validate and sanitize all user inputs server-side',
      'Use modern frameworks that auto-escape template output',
      'Regularly scan for XSS vulnerabilities with automated tools'
    ]
  },
  path_traversal: {
    name: 'Path Traversal',
    description: 'Attackers manipulate file paths to access files outside the intended directory.',
    indicators: [
      'Sequences like ../ or ..\\ in URL paths',
      'Encoded traversal patterns (%2e%2e%2f)',
      'Requests for /etc/passwd or win.ini',
      'Unusual file extensions in request paths'
    ],
    remediation: [
      'Validate and canonicalize all file paths before use',
      'Use a whitelist of allowed file paths or filenames',
      'Run applications with minimal filesystem permissions',
      'Implement chroot jails or containerization',
      'Never use user input directly in file path construction',
      'Monitor and alert on suspicious file access patterns'
    ]
  },
  typosquatting: {
    name: 'Typosquatting / URL Spoofing',
    description: 'Attackers register deceptive look-alike domains to phish users and steal credentials.',
    indicators: [
      'Brand names combined with lure words (login, verify, account) in hostname',
      'Hyphen-heavy suspicious domains (e.g., login-amazon-account.com)',
      'Punycode domains (xn--) and homoglyph substitutions',
      'Newly observed domains mimicking trusted services'
    ],
    remediation: [
      'Block look-alike domains at DNS and secure web gateways',
      'Enable anti-phishing URL filtering in email and browser security layers',
      'Use domain monitoring/takedown services for brand impersonation',
      'Train users to verify exact domain names before login',
      'Enforce MFA to reduce credential misuse impact',
      'Alert on typo-brand domains in outbound and inbound traffic logs'
    ]
  },
  phishing: {
    name: 'Phishing Link Detection',
    description: 'Attackers craft deceptive URLs/pages to steal credentials, OTPs, or financial details.',
    indicators: [
      'Login or verification lure words in suspicious domains/paths',
      'Credential collection hints (password, OTP, PIN, card, CVV)',
      'Brand impersonation mixed with urgent action wording',
      'Unexpected redirects to external identity/payment pages'
    ],
    remediation: [
      'Block phishing domains/URLs at DNS, proxy, and secure email gateway',
      'Force password reset and revoke active sessions for impacted users',
      'Enable or enforce MFA and monitor for anomalous sign-in activity',
      'Quarantine related emails/messages and notify potentially impacted users',
      'Hunt for IOCs across logs, endpoints, and browser history',
      'Submit confirmed phishing domains for takedown and threat intel sharing'
    ]
  },
  cmdi: {
    name: 'Command Injection',
    description: 'Attackers inject OS commands through application inputs to execute arbitrary commands.',
    indicators: [
      'Shell metacharacters (;, |, &&, ||) in parameters',
      'Common command patterns (cat, ls, whoami, ping)',
      'Backtick or $() substitution in inputs',
      'Unusual response times suggesting command execution'
    ],
    remediation: [
      'Avoid calling OS commands from application code when possible',
      'Use language-specific APIs instead of shell commands',
      'Implement strict input validation with allowlists',
      'Run applications in sandboxed environments',
      'Use parameterized command execution libraries',
      'Monitor system process creation for anomalies'
    ]
  },
  ldapi: {
    name: 'LDAP Injection',
    description: 'Attackers manipulate LDAP queries to bypass authentication or access unauthorized data.',
    indicators: [
      'LDAP special characters (*, (, ), \\, NUL) in inputs',
      'Authentication bypass attempts',
      'Unusual directory service query patterns',
      'Error messages revealing LDAP structure'
    ],
    remediation: [
      'Escape all LDAP special characters in user inputs',
      'Use parameterized LDAP queries',
      'Implement strong input validation',
      'Apply least privilege to LDAP service accounts',
      'Enable LDAP query logging and monitoring',
      'Use LDAPS (LDAP over SSL/TLS) for all connections'
    ]
  },
  ssrf: {
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'Attackers trick the server into making requests to unintended internal or external resources.',
    indicators: [
      'Internal IP addresses (127.0.0.1, 10.x, 192.168.x) in URL parameters',
      'Cloud metadata endpoints (169.254.169.254)',
      'Unusual URL schemes (file://, gopher://, dict://)',
      'DNS rebinding attempts'
    ],
    remediation: [
      'Validate and whitelist allowed destination URLs',
      'Block requests to internal/private IP ranges',
      'Disable unused URL schemes',
      'Use network segmentation to limit server outbound access',
      'Implement request timeouts and size limits',
      'Monitor outbound connections for anomalies'
    ]
  },
  rfi: {
    name: 'Remote File Inclusion (RFI)',
    description: 'Attackers include remote malicious files to execute code on the server.',
    indicators: [
      'External URLs in file inclusion parameters',
      'HTTP/HTTPS URLs in include/require paths',
      'Unexpected outbound connections from the web server',
      'PHP wrapper usage (php://input, data://)'
    ],
    remediation: [
      'Disable remote file inclusion in server configuration (allow_url_include=Off)',
      'Use absolute paths for all file inclusions',
      'Implement strict whitelist for includable files',
      'Validate all file paths against known-good patterns',
      'Monitor outbound network connections from web servers',
      'Keep server software and frameworks updated'
    ]
  },
  lfi: {
    name: 'Local File Inclusion (LFI)',
    description: 'Attackers exploit file inclusion mechanisms to read sensitive local files.',
    indicators: [
      'Path traversal sequences in include parameters',
      'Requests for sensitive files (/etc/shadow, config files)',
      'Null byte injection (%00) in file paths',
      'PHP filter/wrapper chains in parameters'
    ],
    remediation: [
      'Use a whitelist of allowed files for inclusion',
      'Store included files outside the web root',
      'Implement proper input validation and path canonicalization',
      'Apply strict file permissions',
      'Disable unnecessary PHP wrappers and functions',
      'Use containerization to limit filesystem access'
    ]
  },
  csrf: {
    name: 'Cross-Site Request Forgery (CSRF)',
    description: 'Attackers trick authenticated users into performing unintended actions.',
    indicators: [
      'State-changing requests without CSRF tokens',
      'Requests originating from different origins',
      'Missing or invalid Referer/Origin headers',
      'Automatic form submissions from external sites'
    ],
    remediation: [
      'Implement anti-CSRF tokens on all state-changing forms',
      'Use SameSite cookie attribute (Strict or Lax)',
      'Validate Referer and Origin headers',
      'Require re-authentication for sensitive operations',
      'Use CAPTCHA for critical actions',
      'Implement proper CORS policies'
    ]
  },
  xxe: {
    name: 'XML External Entity (XXE)',
    description: 'Attackers exploit XML parsers to access internal files or perform SSRF.',
    indicators: [
      'DOCTYPE declarations with ENTITY definitions in XML input',
      'External entity references (SYSTEM, PUBLIC)',
      'Unusual XML content in request bodies',
      'Error messages revealing file contents'
    ],
    remediation: [
      'Disable external entity processing in XML parsers',
      'Use less complex data formats (JSON) when possible',
      'Validate and sanitize all XML input',
      'Implement XML schema validation',
      'Keep XML parsing libraries updated',
      'Use allowlists for acceptable XML structures'
    ]
  },
  brute_force: {
    name: 'Brute Force / Credential Stuffing',
    description: 'Attackers systematically try credentials to gain unauthorized access.',
    indicators: [
      'High volume of failed login attempts from single IP',
      'Login attempts with common username/password lists',
      'Credential stuffing from multiple distributed IPs',
      'Abnormal request rates to authentication endpoints'
    ],
    remediation: [
      'Implement account lockout after failed attempts',
      'Use rate limiting on authentication endpoints',
      'Deploy CAPTCHA after consecutive failures',
      'Enforce strong password policies',
      'Implement multi-factor authentication (MFA)',
      'Monitor and alert on unusual login patterns'
    ]
  },
  header_injection: {
    name: 'HTTP Header Injection',
    description: 'Attackers inject malicious content into HTTP headers to manipulate responses.',
    indicators: [
      'CRLF characters (\\r\\n) in header values',
      'Set-Cookie or Location headers injected via input',
      'Response splitting attempts',
      'Unusual characters in Host or Referer headers'
    ],
    remediation: [
      'Validate and sanitize all inputs used in HTTP headers',
      'Strip CRLF characters from user input',
      'Use framework-provided header-setting functions',
      'Implement strict input validation',
      'Enable HSTS and other security headers',
      'Monitor for unusual response headers'
    ]
  },
  dos: {
    name: 'Denial of Service (DoS)',
    description: 'Attackers overwhelm services to make them unavailable to legitimate users.',
    indicators: [
      'Abnormally high request rates from single sources',
      'Large payload sizes in requests',
      'Slowloris-style partial HTTP requests',
      'Resource exhaustion (CPU, memory, connections)'
    ],
    remediation: [
      'Implement rate limiting and request throttling',
      'Use a CDN with DDoS protection (Cloudflare, AWS Shield)',
      'Configure connection timeouts and limits',
      'Deploy auto-scaling infrastructure',
      'Implement request size limits',
      'Use traffic analysis to identify and block attack patterns'
    ]
  },
  web_shell: {
    name: 'Web Shell Upload',
    description: 'Attackers upload executable web scripts (cmd.jsp, backdoor.asp, shell.php) for persistent remote control.',
    indicators: [
      'Uploads containing executable extensions (.jsp, .asp, .aspx, .php, .cgi)',
      'Filenames like cmd.jsp, backdoor.asp, shell.php, webshell.php',
      'Abnormal POST multipart requests to upload endpoints',
      'Unexpected command execution patterns after file upload'
    ],
    remediation: [
      'Allow only strict safe file extensions and verify MIME type server-side',
      'Store uploads outside web root and disable script execution in upload directories',
      'Rename uploaded files and scan content with AV/YARA signatures',
      'Block direct access to uploaded files unless explicitly required',
      'Audit upload endpoints with authentication and rate limiting',
      'Continuously monitor for suspicious executable files in web directories'
    ]
  }
};

const PLAYBOOK_ALIAS_MAP = {
  'sql injection': 'sqli',
  'cross-site scripting (xss)': 'xss',
  xss: 'xss',
  'directory traversal': 'path_traversal',
  'path traversal': 'path_traversal',
  'command injection': 'cmdi',
  'ldap injection': 'ldapi',
  'server-side request forgery (ssrf)': 'ssrf',
  ssrf: 'ssrf',
  'remote file inclusion (rfi)': 'rfi',
  rfi: 'rfi',
  'local file inclusion (lfi)': 'lfi',
  lfi: 'lfi',
  'csrf (possible)': 'csrf',
  'cross-site request forgery': 'csrf',
  'xml external entity injection (xxe)': 'xxe',
  xxe: 'xxe',
  'credential stuffing / brute force': 'brute_force',
  'brute force': 'brute_force',
  'http header injection': 'header_injection',
  'denial of service (dos)': 'dos',
  dos: 'dos',
  'typosquatting / url spoofing': 'typosquatting',
  'url spoofing': 'typosquatting',
  typosquatting: 'typosquatting',
  phishing: 'phishing',
  phising: 'phishing',
  'phishing link detection': 'phishing',
  'web shell upload': 'web_shell'
};

const buildDynamicPlaybook = (attackType) => ({
  name: String(attackType || 'Unmapped Attack Pattern'),
  description: 'Detected attack type does not have a dedicated static playbook yet. Use generic containment and triage guidance below.',
  indicators: [
    `Hybrid engine classified traffic as: ${String(attackType || 'Unknown')}`,
    'Request payload or URL exhibits suspicious patterns',
    'Potential mismatch between static playbook mapping and new detection class',
    'Review full request context, headers, and source IP behavior'
  ],
  remediation: [
    'Treat as potentially malicious and isolate the source if repeated',
    'Apply rate limiting and temporary blocking rules at WAF/firewall',
    'Inspect request payloads, response bodies, and logs for exploit confirmation',
    'Map this new class to a dedicated playbook entry for future automation',
    'Add class-specific detection and success indicators after validation',
    'Document the incident and update SOC triage runbooks'
  ]
});

const getPlaybookTemplate = (attackType) => {
  const key = String(attackType || '').toLowerCase().trim();
  const mappedId = PLAYBOOK_ALIAS_MAP[key] || key;
  if (WEB_PLAYBOOKS[mappedId]) return WEB_PLAYBOOKS[mappedId];

  const directMatch = Object.values(WEB_PLAYBOOKS).find((pb) => {
    const pbName = String(pb.name || '').toLowerCase();
    return key === pbName || key.includes(pbName) || pbName.includes(key);
  });

  return directMatch || buildDynamicPlaybook(attackType);
};

const buildSecurityPlaybookText = ({ attackType, fileName, uploadId, summary }) => {
  const template = getPlaybookTemplate(attackType);
  const totalRequests = summary?.total_requests ?? summary?.ollama?.total_requests ?? 'N/A';
  const threatsDetected = summary?.threats_detected ?? summary?.ollama?.threats_detected ?? 'N/A';
  const lines = [
    'HIDS Security Playbook (Web Version)',
    `Generated At: ${new Date().toISOString()}`,
    `Upload ID: ${uploadId}`,
    `Source: ${fileName}`,
    `Detected Attack: ${template.name}`,
    `Total Requests: ${totalRequests}`,
    `Threats Detected: ${threatsDetected}`,
    '',
    'Description:',
    template.description,
    '',
    'Indicators of Compromise:',
    ...template.indicators.map((indicator, idx) => `${idx + 1}. ${indicator}`),
    '',
    'Remediation Steps:',
    ...template.remediation.map((step, idx) => `${idx + 1}. ${step}`),
    '',
    'Validation Checklist:',
    '- Confirm malicious traffic has been blocked or challenged.',
    '- Verify no unauthorized data access or code execution occurred.',
    '- Document IOC(s), timeline, and mitigation actions for audit.',
    '- Re-run analysis after mitigations to confirm reduced threat level.'
  ];

  return lines.join('\n');
};

const buildSecurityPlaybookPdfBuffer = ({ textContent, fileName, uploadId, attackType }) => {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'A4',
        margin: 50,
        info: {
          Title: 'HIDS Security Playbook',
          Author: 'HIDS Dashboard',
          Subject: `Playbook for ${attackType || 'Detected Attack'}`,
          Keywords: 'hids,security,playbook,incident-response'
        }
      });

      const chunks = [];
      doc.on('data', (chunk) => chunks.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      doc.font('Helvetica-Bold').fontSize(16).text('HIDS Security Playbook', { align: 'left' });
      doc.moveDown(0.4);
      doc.font('Helvetica').fontSize(10).fillColor('#444444').text(`File: ${fileName}`);
      doc.text(`Upload ID: ${uploadId}`);
      doc.text(`Generated At: ${new Date().toISOString()}`);
      doc.moveDown(0.8);

      doc.fillColor('#000000').font('Helvetica').fontSize(11);
      const lines = String(textContent || '').split(/\r?\n/);
      lines.forEach((line) => {
        if (!line.trim()) {
          doc.moveDown(0.4);
          return;
        }

        if (line.endsWith(':') || line.startsWith('HIDS Security Playbook')) {
          doc.font('Helvetica-Bold').text(line, { align: 'left' });
          doc.font('Helvetica');
        } else {
          doc.text(line, {
            align: 'left',
            lineGap: 2
          });
        }
      });

      doc.end();
    } catch (error) {
      reject(error);
    }
  });
};

const sendReportEmail = async ({ email, uploadId, fileName, summary, csvContent, txtContent, attackType }) => {
  if (!hasEmailConfig()) {
    throw new Error('Email service is not configured (missing EMAIL_USER or EMAIL_PASS).');
  }

  const shortId = String(uploadId).substring(0, 8);
  const jsonPayload = {
    upload_id: uploadId,
    file_name: fileName,
    analyzed_at: new Date().toISOString(),
    summary: summary || {},
  };
  const threatsDetected = Number(summary?.threats_detected ?? summary?.ollama?.threats_detected ?? 0);
  const hasAttack = String(attackType || '').toLowerCase() !== 'normal' || threatsDetected > 0;
  const playbookText = hasAttack
    ? buildSecurityPlaybookText({ attackType, fileName, uploadId, summary })
    : null;
  const playbookPdfBuffer = playbookText
    ? await buildSecurityPlaybookPdfBuffer({ textContent: playbookText, fileName, uploadId, attackType })
    : null;
  const transporter = createTransporter();

  const attachments = [
    {
      filename: `hids_report_${shortId}.csv`,
      content: csvContent || '',
      contentType: 'text/csv'
    },
    {
      filename: `hids_report_${shortId}.json`,
      content: JSON.stringify(jsonPayload, null, 2),
      contentType: 'application/json'
    },
    {
      filename: `hids_report_${shortId}.txt`,
      content: txtContent || '',
      contentType: 'text/plain'
    }
  ];

  if (playbookPdfBuffer) {
    attachments.push({
      filename: `hids_security_playbook_${shortId}.pdf`,
      content: playbookPdfBuffer,
      contentType: 'application/pdf'
    });
  }

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
      playbookText
        ? 'Attack detected: Security playbook attached with immediate response actions.'
        : 'No attack-specific playbook attached (no confirmed threats detected).',
      '',
      `Attached formats: CSV, JSON, TXT${playbookText ? ', Security Playbook' : ''}.`
    ].join('\n'),
    attachments
  });
};

const mapAiErrorMessage = (error) => {
  if (error?.code === 'ECONNREFUSED') {
    return 'Ollama service unavailable. Please ensure Ollama is running: ollama serve';
  }

  if (error?.code === 'ECONNABORTED') {
    return 'AI response timed out while waiting for Ollama. Model may still be loading; please retry in a few seconds.';
  }

  return error?.response?.data?.error || error?.message || 'AI request failed';
};

const cleanupAiJobs = () => {
  const now = Date.now();
  for (const [jobId, job] of aiJobs.entries()) {
    const createdAt = Number(job.createdAt || now);
    if (now - createdAt > AI_JOB_TTL_MS) {
      aiJobs.delete(jobId);
    }
  }
};

const createAiJob = (userId, type) => {
  cleanupAiJobs();
  const id = crypto.randomBytes(12).toString('hex');
  const job = {
    id,
    userId: String(userId),
    type,
    status: 'processing',
    createdAt: Date.now(),
    updatedAt: Date.now(),
    result: null,
    error: null
  };
  aiJobs.set(id, job);
  return job;
};

const resolveAiChat = async (message, context) => {
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

  const response = await axios.post(
    `${OLLAMA_BASE_URL}/api/generate`,
    {
      model: DEFAULT_MODEL,
      prompt: fullPrompt,
      system: systemPrompt,
      stream: false,
      options: {
        temperature: 0.7,
        top_p: 0.9,
        num_predict: 1024
      }
    },
    {
      timeout: OLLAMA_REQUEST_TIMEOUT_MS
    }
  );

  return {
    response: response.data.response,
    model: response.data.model,
    done: response.data.done,
    totalDuration: response.data.total_duration
  };
};

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

const isPhishingUrl = (urlValue, hostValue) => {
  const value = String(urlValue || '').toLowerCase();
  const host = String(hostValue || '').toLowerCase();
  const credentialTerms = ['password', 'otp', 'pin', 'card', 'cvv', 'verify now', 'signin now'];

  const brandHit = TYPO_BRANDS.some((b) => value.includes(b) || host.includes(b));
  const lureHit = TYPO_LURE_WORDS.some((w) => value.includes(w) || host.includes(w));
  const credentialHit = credentialTerms.some((t) => value.includes(t));

  if (brandHit && lureHit) return true;
  if (brandHit && credentialHit) return true;
  if (/\/(verify|signin|login|account\/secure|update-billing)/i.test(value) && (credentialHit || brandHit)) {
    return true;
  }

  return false;
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
    if (isPhishingUrl(urlValue, host)) {
      return 'Phishing';
    }
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
  if (!normalized || normalized === 'normal') return 'none';

  const code = Number(statusCode);
  if (!Number.isFinite(code) || code < 200 || code >= 300) return 'attempt';

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
  } else if (normalized.includes('xml external entity') || normalized.includes('xxe')) {
    hasSuccessEvidence =
      combined.includes('<!doctype') ||
      combined.includes('<!entity') ||
      /system\s+['\"](?:file|http|ftp):\/\//i.test(combined);
  } else if (normalized.includes('http parameter pollution') || normalized.includes('parameter pollution')) {
    hasSuccessEvidence = /(?:\?|&)([^=&\s]+)=[^&]*(?:&\1=)/i.test(combined);
  } else if (normalized.includes('typosquatting') || normalized.includes('url spoofing')) {
    hasSuccessEvidence =
      /xn--|paypa1|g00gle|micr0soft|faceb00k|amaz0n|app1e|arnazon/i.test(combined) ||
      /(?:login|verify|secure|account).*(?:amazon|paypal|google)/i.test(combined);
  } else if (normalized.includes('phishing') || normalized.includes('phising')) {
    hasSuccessEvidence =
      /(?:verify|login|signin|secure|account|update).*(?:password|otp|pin|card|cvv)/i.test(combined) ||
      /xn--|paypa1|g00gle|micr0soft|faceb00k|amaz0n/i.test(combined);
  }

  if (hasSuccessEvidence) return 'confirmed_success';
  return 'attempt';
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

    const result = await resolveAiChat(message, context);
    res.json(result);

  } catch (error) {
    console.error('AI Chat error:', error.message);
    
    if (error.code === 'ECONNREFUSED') {
      return res.status(503).json({
        error: 'Ollama service unavailable',
        message: 'Please ensure Ollama is running: ollama serve'
      });
    }

    if (error.code === 'ECONNABORTED') {
      return res.status(504).json({
        error: 'AI timeout',
        message: mapAiErrorMessage(error)
      });
    }

    res.status(500).json({
      error: 'AI request failed',
      message: mapAiErrorMessage(error)
    });
  }
});

// Start background chat job
router.post('/chat/start', auth, async (req, res) => {
  try {
    const { message, context } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const job = createAiJob(req.user.id, 'chat');

    res.json({
      jobId: job.id,
      status: job.status
    });

    (async () => {
      try {
        const result = await resolveAiChat(message, context);
        const existing = aiJobs.get(job.id);
        if (!existing) return;
        existing.status = 'completed';
        existing.result = result;
        existing.updatedAt = Date.now();
      } catch (error) {
        const existing = aiJobs.get(job.id);
        if (!existing) return;
        existing.status = 'failed';
        existing.error = mapAiErrorMessage(error);
        existing.updatedAt = Date.now();
      }
    })();
  } catch (error) {
    res.status(500).json({
      error: 'Failed to start chat job',
      message: error.message
    });
  }
});

// Get background chat job status
router.get('/chat/status/:jobId', auth, async (req, res) => {
  const { jobId } = req.params;
  const job = aiJobs.get(jobId);

  if (!job || String(job.userId) !== String(req.user.id)) {
    return res.status(404).json({
      error: 'Not Found',
      message: 'Chat job not found'
    });
  }

  res.json({
    jobId: job.id,
    status: job.status,
    result: job.result,
    error: job.error,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt
  });
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

    const attackOutcome = inferAttackOutcome(
      attackType,
      200,
      url,
      Array.isArray(analysis.patterns) ? analysis.patterns.join(' ') : '',
      '',
      '',
      null
    );
    const confirmedSuccessfulAttacks = attackOutcome === 'confirmed_success' ? 1 : 0;
    const attackAttempts = attackOutcome === 'attempt' ? 1 : 0;

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
        confirmedSuccessfulAttacks,
        attackAttempts,
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

    let emailStatus = {
      state: 'pending',
      sent: false,
      message: 'Preparing report email...'
    };

    try {
      const user = await User.findById(req.user.id).select('email');
      const recipientEmail = req.user.email || user?.email || null;
      if (recipientEmail) {
        await sendReportEmail({
          email: recipientEmail,
          uploadId,
          fileName: `url_${hostLabel}`,
          summary,
          csvContent: result.csvContent,
          txtContent: result.txtContent,
          attackType,
        });

        emailStatus = {
          state: 'sent',
          sent: true,
          recipient: recipientEmail,
          sentAt: new Date(),
          message: 'Report email sent successfully.'
        };
      } else {
        emailStatus = {
          state: 'failed',
          sent: false,
          code: 'USER_EMAIL_NOT_FOUND',
          reason: 'User email not found',
          message: 'Unable to send report email because account email is missing.'
        };
        console.warn(`[Email] URL analysis completed but user email missing for ${uploadId}`);
      }
    } catch (emailError) {
      console.error(`[Email] URL analysis email failed for ${uploadId}:`, emailError.message);
      emailStatus = {
        state: 'failed',
        sent: false,
        code: emailError?.code || 'EMAIL_SEND_FAILED',
        reason: emailError?.message || 'Email delivery failed',
        message: 'Report generated, but email delivery failed.'
      };
    }

    res.json({
      url,
      analysis,
      model: summary.analyzed_with || `Modules 1-4 + Ollama ${DEFAULT_MODEL}`,
      emailStatus
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
    }, { timeout: OLLAMA_REQUEST_TIMEOUT_MS });

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
      timeout: OLLAMA_REQUEST_TIMEOUT_MS
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
