const normalizeAttackOutcome = (value) => {
  const normalized = String(value || '').trim().toLowerCase().replace(/\s+/g, '_');
  if (normalized === 'confirmed_success') return 'confirmed_success';
  if (normalized === 'attempt') return 'attempt';
  if (normalized === 'none') return 'none';
  return null;
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
  const normalizedClassification = String(classification || '').trim().toLowerCase();
  if (!normalizedClassification || normalizedClassification === 'normal') {
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

  if (normalizedClassification.includes('sql injection') || normalizedClassification === 'sqli') {
    // Avoid generic "sql" token checks; only treat concrete DB leak/error evidence as success.
    hasSuccessEvidence =
      /sql syntax|mysql_fetch|odbc sql server driver|unclosed quotation mark|quoted string not properly terminated|postgresql.*error|sqlite_error/i.test(responseText) ||
      /information_schema|union\s+select|@@version|database\(\)|user\(\)/i.test(responseText);
  } else if (normalizedClassification.includes('xss') || normalizedClassification.includes('cross-site scripting')) {
    hasSuccessEvidence = responseText.includes('<script>');
  } else if (normalizedClassification.includes('local file inclusion') || normalizedClassification.includes('directory traversal') || normalizedClassification.includes('path traversal') || normalizedClassification.includes('lfi')) {
    hasSuccessEvidence =
      combined.includes('root:x:0:0') ||
      /(\/etc\/passwd|\/proc\/self\/environ|win\.ini|boot\.ini|windows\/system32)/i.test(combined);
  } else if (normalizedClassification.includes('remote file inclusion') || normalizedClassification.includes('web shell')) {
    hasSuccessEvidence = combined.includes('shell') || combined.includes('cmd') || /(cmd\.jsp|backdoor\.asp|webshell|shell\.php|\.aspx?|\.jsp|\.php)/i.test(combined);
  } else if (normalizedClassification.includes('server-side request forgery') || normalizedClassification.includes('ssrf')) {
    hasSuccessEvidence = combined.includes('internal server') || combined.includes('admin panel') || /(169\.254\.169\.254|localhost|127\.0\.0\.1|2130706433)/i.test(combined);
  } else if (normalizedClassification.includes('command injection')) {
    hasSuccessEvidence = combined.includes('uid=') || combined.includes('www-data') || /(;|&&|\|)\s*(whoami|id|cat|uname|powershell|cmd\.exe)/i.test(combined);
  } else if (normalizedClassification.includes('ldap injection') || normalizedClassification.includes('ldap')) {
    hasSuccessEvidence =
      combined.includes('login success') ||
      /\*\)\(\|/.test(combined) ||
      /\(\|\(user=\*\)\)/.test(combined) ||
      /\(uid=\*\)/.test(combined) ||
      /\)\(\|\(password=\*\)\)/.test(combined) ||
      (combined.includes('pass=anything') && (combined.includes('user=*)') || combined.includes('(|(user=*))')));
  } else if (normalizedClassification.includes('header injection') || normalizedClassification.includes('http header injection')) {
    hasSuccessEvidence = headersText.includes('set-cookie') || combined.includes('set-cookie');
  } else if (normalizedClassification.includes('brute force')) {
    hasSuccessEvidence = combined.includes('login success');
  } else if (normalizedClassification.includes('dos') || normalizedClassification.includes('denial of service')) {
    hasSuccessEvidence = Number.isFinite(rt) && rt > Number(thresholdMs);
  } else if (normalizedClassification.includes('csrf') || normalizedClassification.includes('cross-site request forgery')) {
    hasSuccessEvidence = combined.includes('transaction successful');
  } else if (normalizedClassification.includes('xml external entity') || normalizedClassification.includes('xxe')) {
    hasSuccessEvidence =
      combined.includes('<!doctype') ||
      combined.includes('<!entity') ||
      /system\s+['\"](?:file|http|ftp):\/\//i.test(combined);
  } else if (normalizedClassification.includes('http parameter pollution') || normalizedClassification.includes('parameter pollution')) {
    hasSuccessEvidence = /(?:\?|&)([^=&\s]+)=[^&]*(?:&\1=)/i.test(combined);
  } else if (normalizedClassification.includes('typosquatting') || normalizedClassification.includes('url spoofing')) {
    hasSuccessEvidence =
      /xn--|paypa1|g00gle|micr0soft|faceb00k|amaz0n|app1e|arnazon/i.test(combined) ||
      /(?:login|verify|secure|account).*(?:amazon|paypal|google)/i.test(combined);
  } else if (normalizedClassification.includes('phishing') || normalizedClassification.includes('phising')) {
    hasSuccessEvidence =
      /(?:verify|login|signin|secure|account|update).*(?:password|otp|pin|card|cvv)/i.test(combined) ||
      /xn--|paypa1|g00gle|micr0soft|faceb00k|amaz0n/i.test(combined);
  }

  if (hasSuccessEvidence) return 'confirmed_success';
  return 'attempt';
};

module.exports = {
  inferAttackOutcome,
  normalizeAttackOutcome
};
