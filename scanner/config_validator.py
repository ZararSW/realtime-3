"""
Configuration Validation for Advanced Intelligent Web Crawler
Validates configuration files and environment variables
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
from enum import Enum
import re
import ipaddress
from urllib.parse import urlparse

class ValidationSeverity(Enum):
    """Validation severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class ValidationIssue:
    """Represents a configuration validation issue"""
    field: str
    message: str
    severity: ValidationSeverity
    suggested_fix: Optional[str] = None

class ConfigValidator:
    """Validates configuration files and environment variables"""
    
    def __init__(self):
        self.issues: List[ValidationIssue] = []
        self.required_fields = {
            'ai': ['provider'],
            'browser': ['headless', 'user_agent'],
            'security': ['max_payloads_per_type', 'test_timeout'],
            'network': ['request_timeout', 'max_redirects'],
            'performance': ['max_concurrent_requests', 'rate_limit']
        }
        
        self.field_validators = {
            'ai.provider': self._validate_ai_provider,
            'ai.groq.api_key': self._validate_api_key,
            'ai.gemini.api_key': self._validate_api_key,
            'ai.openai.api_key': self._validate_api_key,
            'ai.anthropic.api_key': self._validate_api_key,
            'browser.headless': self._validate_boolean,
            'browser.user_agent': self._validate_user_agent,
            'browser.window_size': self._validate_window_size,
            'security.max_payloads_per_type': self._validate_positive_integer,
            'security.test_timeout': self._validate_positive_integer,
            'network.request_timeout': self._validate_positive_integer,
            'network.max_redirects': self._validate_positive_integer,
            'performance.max_concurrent_requests': self._validate_positive_integer,
            'performance.rate_limit': self._validate_positive_float,
            'logging.level': self._validate_log_level,
            'privacy.sanitize_logs': self._validate_boolean,
            'privacy.mask_sensitive_data': self._validate_boolean,
        }
    
    def validate_config(self, config: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate entire configuration"""
        self.issues.clear()
        
        # Check required fields
        self._check_required_fields(config)
        
        # Validate individual fields
        self._validate_fields(config)
        
        # Check for security issues
        self._check_security_issues(config)
        
        # Check for performance issues
        self._check_performance_issues(config)
        
        # Check for best practices
        self._check_best_practices(config)
        
        return self.issues
    
    def _check_required_fields(self, config: Dict[str, Any]) -> None:
        """Check for required configuration fields"""
        for section, fields in self.required_fields.items():
            if section not in config:
                self.issues.append(ValidationIssue(
                    field=section,
                    message=f"Required section '{section}' is missing",
                    severity=ValidationSeverity.ERROR,
                    suggested_fix=f"Add '{section}' section to configuration"
                ))
                continue
            
            for field in fields:
                if field not in config[section]:
                    self.issues.append(ValidationIssue(
                        field=f"{section}.{field}",
                        message=f"Required field '{field}' is missing from '{section}' section",
                        severity=ValidationSeverity.ERROR,
                        suggested_fix=f"Add '{field}' to '{section}' section"
                    ))
    
    def _validate_fields(self, config: Dict[str, Any], prefix: str = "") -> None:
        """Validate individual configuration fields"""
        for key, value in config.items():
            field_path = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                self._validate_fields(value, field_path)
            else:
                if field_path in self.field_validators:
                    validator = self.field_validators[field_path]
                    try:
                        validator(value, field_path)
                    except Exception as e:
                        self.issues.append(ValidationIssue(
                            field=field_path,
                            message=f"Validation failed: {str(e)}",
                            severity=ValidationSeverity.ERROR
                        ))
    
    def _check_security_issues(self, config: Dict[str, Any]) -> None:
        """Check for security-related configuration issues"""
        # Check for hardcoded API keys
        self._check_hardcoded_secrets(config)
        
        # Check for insecure browser settings
        self._check_browser_security(config)
        
        # Check for privacy settings
        self._check_privacy_settings(config)
    
    def _check_hardcoded_secrets(self, config: Dict[str, Any]) -> None:
        """Check for hardcoded secrets in configuration"""
        sensitive_fields = [
            'ai.groq.api_key',
            'ai.gemini.api_key', 
            'ai.openai.api_key',
            'ai.anthropic.api_key'
        ]
        
        for field_path in sensitive_fields:
            value = self._get_nested_value(config, field_path)
            if value and isinstance(value, str) and len(value) > 10:
                # Check if it's not an environment variable reference
                if not value.startswith('${') and not value.startswith('$'):
                    self.issues.append(ValidationIssue(
                        field=field_path,
                        message="Hardcoded API key detected",
                        severity=ValidationSeverity.CRITICAL,
                        suggested_fix="Use environment variable instead: api_key_env: 'API_KEY_NAME'"
                    ))
    
    def _check_browser_security(self, config: Dict[str, Any]) -> None:
        """Check browser security settings"""
        browser_config = config.get('browser', {})
        
        # Check for dangerous Chrome options
        chrome_options = browser_config.get('chrome_options', [])
        dangerous_options = [
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--no-sandbox'
        ]
        
        for option in chrome_options:
            if option in dangerous_options:
                self.issues.append(ValidationIssue(
                    field='browser.chrome_options',
                    message=f"Dangerous Chrome option detected: {option}",
                    severity=ValidationSeverity.WARNING,
                    suggested_fix="Consider removing this option for production use"
                ))
        
        # Check headless mode
        if not browser_config.get('headless', False):
            self.issues.append(ValidationIssue(
                field='browser.headless',
                message="Browser is not running in headless mode",
                severity=ValidationSeverity.INFO,
                suggested_fix="Consider setting headless: true for production"
            ))
    
    def _check_privacy_settings(self, config: Dict[str, Any]) -> None:
        """Check privacy-related settings"""
        privacy_config = config.get('privacy', {})
        
        if not privacy_config.get('sanitize_logs', True):
            self.issues.append(ValidationIssue(
                field='privacy.sanitize_logs',
                message="Log sanitization is disabled",
                severity=ValidationSeverity.WARNING,
                suggested_fix="Enable log sanitization to protect sensitive data"
            ))
        
        if not privacy_config.get('mask_sensitive_data', True):
            self.issues.append(ValidationIssue(
                field='privacy.mask_sensitive_data',
                message="Sensitive data masking is disabled",
                severity=ValidationSeverity.WARNING,
                suggested_fix="Enable sensitive data masking for security"
            ))
    
    def _check_performance_issues(self, config: Dict[str, Any]) -> None:
        """Check for performance-related issues"""
        performance_config = config.get('performance', {})
        
        # Check concurrent requests limit
        max_concurrent = performance_config.get('max_concurrent_requests', 5)
        if max_concurrent > 10:
            self.issues.append(ValidationIssue(
                field='performance.max_concurrent_requests',
                message=f"High concurrent request limit: {max_concurrent}",
                severity=ValidationSeverity.WARNING,
                suggested_fix="Consider reducing to 5-10 for better stability"
            ))
        
        # Check rate limit
        rate_limit = performance_config.get('rate_limit', 1.0)
        if rate_limit < 0.5:
            self.issues.append(ValidationIssue(
                field='performance.rate_limit',
                message=f"Very low rate limit: {rate_limit}",
                severity=ValidationSeverity.INFO,
                suggested_fix="Consider increasing rate limit for better performance"
            ))
    
    def _check_best_practices(self, config: Dict[str, Any]) -> None:
        """Check for best practices"""
        # Check logging configuration
        logging_config = config.get('logging', {})
        if not logging_config.get('structured_logging', False):
            self.issues.append(ValidationIssue(
                field='logging.structured_logging',
                message="Structured logging is disabled",
                severity=ValidationSeverity.INFO,
                suggested_fix="Enable structured logging for better log analysis"
            ))
        
        # Check for robots.txt respect
        privacy_config = config.get('privacy', {})
        if not privacy_config.get('respect_robots_txt', True):
            self.issues.append(ValidationIssue(
                field='privacy.respect_robots_txt',
                message="robots.txt is not being respected",
                severity=ValidationSeverity.WARNING,
                suggested_fix="Enable robots.txt respect for ethical crawling"
            ))
    
    def _get_nested_value(self, config: Dict[str, Any], field_path: str) -> Any:
        """Get value from nested dictionary using dot notation"""
        keys = field_path.split('.')
        value = config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value
    
    # Field validators
    def _validate_ai_provider(self, value: Any, field_path: str) -> None:
        """Validate AI provider"""
        valid_providers = ['groq', 'gemini', 'openai', 'anthropic']
        if value not in valid_providers:
            raise ValueError(f"Invalid AI provider '{value}'. Must be one of: {valid_providers}")
    
    def _validate_api_key(self, value: Any, field_path: str) -> None:
        """Validate API key format"""
        if value and isinstance(value, str):
            if len(value) < 10:
                raise ValueError("API key appears to be too short")
            if value.startswith('your_') or value.startswith('test_'):
                raise ValueError("API key appears to be a placeholder")
    
    def _validate_boolean(self, value: Any, field_path: str) -> None:
        """Validate boolean value"""
        if not isinstance(value, bool):
            raise ValueError(f"Expected boolean, got {type(value).__name__}")
    
    def _validate_user_agent(self, value: Any, field_path: str) -> None:
        """Validate user agent string"""
        if not isinstance(value, str) or len(value) < 10:
            raise ValueError("User agent must be a non-empty string")
    
    def _validate_window_size(self, value: Any, field_path: str) -> None:
        """Validate window size format"""
        if not isinstance(value, str):
            raise ValueError("Window size must be a string")
        
        if 'x' not in value:
            raise ValueError("Window size must be in format 'WIDTHxHEIGHT'")
        
        try:
            width, height = value.split('x')
            int(width)
            int(height)
        except ValueError:
            raise ValueError("Window size must be in format 'WIDTHxHEIGHT'")
    
    def _validate_positive_integer(self, value: Any, field_path: str) -> None:
        """Validate positive integer"""
        if not isinstance(value, int) or value <= 0:
            raise ValueError(f"Expected positive integer, got {value}")
    
    def _validate_positive_float(self, value: Any, field_path: str) -> None:
        """Validate positive float"""
        if not isinstance(value, (int, float)) or value <= 0:
            raise ValueError(f"Expected positive number, got {value}")
    
    def _validate_log_level(self, value: Any, field_path: str) -> None:
        """Validate log level"""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if value.upper() not in valid_levels:
            raise ValueError(f"Invalid log level '{value}'. Must be one of: {valid_levels}")

def validate_config_file(config_path: str) -> List[ValidationIssue]:
    """Validate configuration file"""
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        
        validator = ConfigValidator()
        return validator.validate_config(config)
    
    except FileNotFoundError:
        return [ValidationIssue(
            field='config_file',
            message=f"Configuration file not found: {config_path}",
            severity=ValidationSeverity.ERROR
        )]
    except yaml.YAMLError as e:
        return [ValidationIssue(
            field='config_file',
            message=f"Invalid YAML syntax: {str(e)}",
            severity=ValidationSeverity.ERROR
        )]
    except Exception as e:
        return [ValidationIssue(
            field='config_file',
            message=f"Unexpected error: {str(e)}",
            severity=ValidationSeverity.ERROR
        )]

def validate_environment() -> List[ValidationIssue]:
    """Validate environment variables"""
    issues = []
    
    # Check for required environment variables
    required_env_vars = [
        'GROQ_API_KEY',
        'GOOGLE_API_KEY', 
        'OPENAI_API_KEY',
        'ANTHROPIC_API_KEY'
    ]
    
    missing_vars = []
    for var in required_env_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        issues.append(ValidationIssue(
            field='environment',
            message=f"Missing environment variables: {', '.join(missing_vars)}",
            severity=ValidationSeverity.WARNING,
            suggested_fix="Set the missing environment variables or use config file"
        ))
    
    return issues

def print_validation_report(issues: List[ValidationIssue]) -> None:
    """Print validation report"""
    if not issues:
        print("✅ Configuration validation passed!")
        return
    
    print(f"\n📋 Configuration Validation Report ({len(issues)} issues found):")
    print("=" * 60)
    
    # Group by severity
    by_severity = {}
    for issue in issues:
        severity = issue.severity.value
        if severity not in by_severity:
            by_severity[severity] = []
        by_severity[severity].append(issue)
    
    # Print by severity
    severity_order = ['critical', 'error', 'warning', 'info']
    for severity in severity_order:
        if severity in by_severity:
            print(f"\n{severity.upper()} ({len(by_severity[severity])} issues):")
            for issue in by_severity[severity]:
                print(f"  • {issue.field}: {issue.message}")
                if issue.suggested_fix:
                    print(f"    💡 {issue.suggested_fix}")
    
    print("\n" + "=" * 60)