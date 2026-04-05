import { useState, useMemo } from 'react';
import {
  ShieldAlert, ShieldCheck, ChevronDown, ChevronRight,
  AlertTriangle, Bug, Terminal, Globe, Code2, Database,
  FileWarning, KeyRound, Fingerprint, Server, Wifi, Lock, Eye
} from 'lucide-react';

/* ──────────────────────────────────────────────────────────────
   Complete playbook data for all 13+ attack patterns relevant
   to URL-based / HTTP intrusion detection.
   ────────────────────────────────────────────────────────────── */
const ATTACK_PLAYBOOKS = [
  {
    id: 'sqli',
    name: 'SQL Injection (SQLi)',
    icon: Database,
    severity: 'critical',
    color: 'from-red-500 to-rose-600',
    badgeColor: 'bg-red-100 text-red-800',
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
  {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS)',
    icon: Code2,
    severity: 'high',
    color: 'from-orange-500 to-amber-600',
    badgeColor: 'bg-orange-100 text-orange-800',
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
  {
    id: 'path_traversal',
    name: 'Path Traversal',
    icon: FileWarning,
    severity: 'high',
    color: 'from-yellow-500 to-orange-500',
    badgeColor: 'bg-yellow-100 text-yellow-800',
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
  {
    id: 'cmdi',
    name: 'Command Injection',
    icon: Terminal,
    severity: 'critical',
    color: 'from-purple-500 to-violet-600',
    badgeColor: 'bg-purple-100 text-purple-800',
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
  {
    id: 'ldapi',
    name: 'LDAP Injection',
    icon: KeyRound,
    severity: 'high',
    color: 'from-indigo-500 to-blue-600',
    badgeColor: 'bg-indigo-100 text-indigo-800',
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
  {
    id: 'ssrf',
    name: 'Server-Side Request Forgery (SSRF)',
    icon: Server,
    severity: 'high',
    color: 'from-teal-500 to-cyan-600',
    badgeColor: 'bg-teal-100 text-teal-800',
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
  {
    id: 'rfi',
    name: 'Remote File Inclusion (RFI)',
    icon: Globe,
    severity: 'critical',
    color: 'from-red-600 to-pink-600',
    badgeColor: 'bg-red-100 text-red-800',
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
  {
    id: 'lfi',
    name: 'Local File Inclusion (LFI)',
    icon: FileWarning,
    severity: 'high',
    color: 'from-amber-500 to-yellow-600',
    badgeColor: 'bg-amber-100 text-amber-800',
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
  {
    id: 'csrf',
    name: 'Cross-Site Request Forgery (CSRF)',
    icon: Fingerprint,
    severity: 'medium',
    color: 'from-emerald-500 to-green-600',
    badgeColor: 'bg-emerald-100 text-emerald-800',
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
  {
    id: 'xxe',
    name: 'XML External Entity (XXE)',
    icon: Bug,
    severity: 'high',
    color: 'from-rose-500 to-red-600',
    badgeColor: 'bg-rose-100 text-rose-800',
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
  {
    id: 'brute_force',
    name: 'Brute Force / Credential Stuffing',
    icon: Lock,
    severity: 'medium',
    color: 'from-slate-500 to-gray-600',
    badgeColor: 'bg-slate-100 text-slate-800',
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
  {
    id: 'header_injection',
    name: 'HTTP Header Injection',
    icon: Wifi,
    severity: 'medium',
    color: 'from-sky-500 to-blue-500',
    badgeColor: 'bg-sky-100 text-sky-800',
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
  {
    id: 'dos',
    name: 'Denial of Service (DoS)',
    icon: AlertTriangle,
    severity: 'high',
    color: 'from-red-400 to-orange-500',
    badgeColor: 'bg-red-100 text-red-800',
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
  }
];

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_STYLES = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  low: 'bg-green-500/20 text-green-300 border-green-500/30',
};

/* ──────────────────────────────────────────────────────────────
   PlaybookCard – expandable card for a single attack type
   ────────────────────────────────────────────────────────────── */
const PlaybookCard = ({ playbook, isDetected, defaultExpanded = false }) => {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const Icon = playbook.icon;

  return (
    <div
      className={`rounded-xl border transition-all duration-300 overflow-hidden ${
        isDetected
          ? 'border-red-400/50 bg-gradient-to-br from-red-950/50 to-gray-900/80 shadow-lg shadow-red-500/10'
          : 'border-gray-700/50 bg-gray-900/60 hover:border-gray-600/50'
      }`}
    >
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left group"
      >
        <div className={`p-2 rounded-lg bg-gradient-to-br ${playbook.color} bg-opacity-20 flex-shrink-0`}>
          <Icon size={18} className="text-white" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-white text-sm">{playbook.name}</span>
            {isDetected && (
              <span className="px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider rounded-full bg-red-500/30 text-red-300 border border-red-500/40 animate-pulse">
                Detected
              </span>
            )}
            <span className={`px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider rounded-full border ${SEVERITY_STYLES[playbook.severity]}`}>
              {playbook.severity}
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1 line-clamp-1">{playbook.description}</p>
        </div>
        <div className="flex-shrink-0 text-gray-500 group-hover:text-gray-300 transition-colors">
          {expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
        </div>
      </button>

      {/* Expanded Content */}
      {expanded && (
        <div className="px-4 pb-4 space-y-4 border-t border-gray-700/40 pt-4 animate-fadeIn">
          {/* Description */}
          <p className="text-sm text-gray-300">{playbook.description}</p>

          {/* Indicators of Compromise */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-yellow-400 mb-2 flex items-center gap-1.5">
              <Eye size={13} />
              Indicators of Compromise
            </h4>
            <ul className="space-y-1.5">
              {playbook.indicators.map((indicator, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs text-gray-400">
                  <span className="mt-1 w-1.5 h-1.5 rounded-full bg-yellow-500/70 flex-shrink-0" />
                  {indicator}
                </li>
              ))}
            </ul>
          </div>

          {/* Remediation Steps */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400 mb-2 flex items-center gap-1.5">
              <ShieldCheck size={13} />
              Remediation Steps
            </h4>
            <ol className="space-y-1.5">
              {playbook.remediation.map((step, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs text-gray-400">
                  <span className="mt-0.5 w-4 h-4 rounded-full bg-emerald-500/20 text-emerald-400 flex-shrink-0 flex items-center justify-center text-[10px] font-bold">
                    {idx + 1}
                  </span>
                  {step}
                </li>
              ))}
            </ol>
          </div>
        </div>
      )}
    </div>
  );
};

/* ──────────────────────────────────────────────────────────────
   Playbook – main component
   detectedAttacks: an object like { sqli: 5, xss: 3, normal: 100 }
                     (the classification_breakdown from analysis results)
   ────────────────────────────────────────────────────────────── */
const Playbook = ({ detectedAttacks = null }) => {
  const [filter, setFilter] = useState('all'); // 'all' | 'detected' | 'precautionary'

  // Determine which attacks from the playbook were detected
  const detectedSet = useMemo(() => {
    if (!detectedAttacks) return new Set();
    const set = new Set();
    Object.keys(detectedAttacks).forEach(cls => {
      const key = cls.toLowerCase().trim();
      if (key === 'normal') return;
      // Match playbook IDs or partial matches
      ATTACK_PLAYBOOKS.forEach(pb => {
        if (
          key === pb.id ||
          key.includes(pb.id) ||
          pb.id.includes(key) ||
          pb.name.toLowerCase().includes(key) ||
          key.includes(pb.name.toLowerCase().split(' ')[0].toLowerCase())
        ) {
          set.add(pb.id);
        }
      });
      // Fallback — If something doesn't match, still mark it
    });
    return set;
  }, [detectedAttacks]);

  const hasDetections = detectedSet.size > 0;

  const filteredPlaybooks = useMemo(() => {
    let list = [...ATTACK_PLAYBOOKS];
    if (filter === 'detected') {
      list = list.filter(pb => detectedSet.has(pb.id));
    } else if (filter === 'precautionary') {
      list = list.filter(pb => !detectedSet.has(pb.id));
    }
    // Sort: detected first, then by severity
    list.sort((a, b) => {
      const aDetected = detectedSet.has(a.id) ? 0 : 1;
      const bDetected = detectedSet.has(b.id) ? 0 : 1;
      if (aDetected !== bDetected) return aDetected - bDetected;
      return (SEVERITY_ORDER[a.severity] || 3) - (SEVERITY_ORDER[b.severity] || 3);
    });
    return list;
  }, [filter, detectedSet]);

  return (
    <div className="bg-gray-900/50 backdrop-blur-sm rounded-2xl border border-gray-700/50 overflow-hidden flex flex-col h-full">
      {/* Header */}
      <div className="p-5 border-b border-gray-700/50 bg-gradient-to-r from-gray-900 to-gray-800">
        <div className="flex items-center gap-3 mb-3">
          <div className="p-2 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600">
            <ShieldAlert size={20} className="text-white" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">Security Playbook</h2>
            <p className="text-xs text-gray-400">
              {hasDetections
                ? `${detectedSet.size} attack type${detectedSet.size > 1 ? 's' : ''} detected — review remediation steps`
                : 'Precautionary guides for all attack patterns'
              }
            </p>
          </div>
        </div>

        {/* Filter tabs */}
        {hasDetections && (
          <div className="flex gap-1 bg-gray-800/50 rounded-lg p-1">
            {[
              { id: 'all', label: 'All' },
              { id: 'detected', label: `Detected (${detectedSet.size})` },
              { id: 'precautionary', label: 'Precautionary' }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setFilter(tab.id)}
                className={`flex-1 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  filter === tab.id
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700/50'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Playbook Cards */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
        {filteredPlaybooks.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <ShieldCheck size={48} className="text-emerald-500/50 mb-3" />
            <p className="text-gray-400 text-sm">No matching attack patterns.</p>
          </div>
        ) : (
          filteredPlaybooks.map(pb => (
            <PlaybookCard
              key={pb.id}
              playbook={pb}
              isDetected={detectedSet.has(pb.id)}
              defaultExpanded={detectedSet.has(pb.id)}
            />
          ))
        )}
      </div>

      {/* Footer summary */}
      <div className="px-5 py-3 border-t border-gray-700/50 bg-gray-900/80">
        <p className="text-[11px] text-gray-500 text-center">
          {ATTACK_PLAYBOOKS.length} attack patterns covered • HIDS Security Playbook v1.0
        </p>
      </div>
    </div>
  );
};

export { ATTACK_PLAYBOOKS };
export default Playbook;
