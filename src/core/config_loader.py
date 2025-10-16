"""
Secure Configuration Loader for Advanced Intelligent Web Crawler
Handles environment variables and configuration validation securely
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

@dataclass
class SecurityConfig:
    """Security-related configuration"""
    sanitize_logs: bool = True
    mask_sensitive_data: bool = True
    sensitive_patterns: list = None
    exclude_domains: list = None
    respect_robots_txt: bool = True
    
    def __post_init__(self):
        if self.sensitive_patterns is None:
            self.sensitive_patterns = [
                "password", "api_key", "token", "secret", 
                "key", "credential", "auth"
            ]
        if self.exclude_domains is None:
            self.exclude_domains = []

@dataclass
class AIConfig:
    """AI provider configuration"""
    provider: str = "groq"
    api_key: Optional[str] = None
    model: str = "llama-3.1-8b-instant"
    max_retries: int = 3
    timeout: int = 30
    context_window: int = 2000

class SecureConfigLoader:
    """Secure configuration loader with environment variable support"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(__name__)
        self._config_cache = None
        
    def load_config(self) -> Dict[str, Any]:
        """Load and validate configuration"""
        if self._config_cache is not None:
            return self._config_cache
            
        try:
            with open(self.config_path, 'r') as file:
                config = yaml.safe_load(file)
            
            # Override with environment variables
            config = self._override_with_env_vars(config)
            
            # Validate configuration
            self._validate_config(config)
            
            self._config_cache = config
            return config
            
        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {self.config_path}")
            raise
        except yaml.YAMLError as e:
            self.logger.error(f"Invalid YAML configuration: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Configuration loading failed: {e}")
            raise
    
    def _override_with_env_vars(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Override configuration with environment variables"""
        # AI API Keys
        ai_providers = ['groq', 'gemini', 'openai', 'anthropic']
        for provider in ai_providers:
            if provider in config.get('ai', {}):
                env_key = f"{provider.upper()}_API_KEY"
                env_value = os.getenv(env_key)
                if env_value:
                    config['ai'][provider]['api_key'] = env_value
                    # Remove hardcoded keys for security
                    if 'api_key' in config['ai'][provider]:
                        config['ai'][provider]['api_key_env'] = env_key
                        del config['ai'][provider]['api_key']
        
        # Security settings
        if 'privacy' in config:
            config['privacy']['sanitize_logs'] = os.getenv('SANITIZE_LOGS', 
                str(config['privacy'].get('sanitize_logs', True))).lower() == 'true'
            config['privacy']['mask_sensitive_data'] = os.getenv('MASK_SENSITIVE_DATA',
                str(config['privacy'].get('mask_sensitive_data', True))).lower() == 'true'
        
        # Performance settings
        if 'performance' in config:
            config['performance']['max_concurrent_requests'] = int(
                os.getenv('MAX_CONCURRENT_REQUESTS', 
                config['performance'].get('max_concurrent_requests', 5)))
            config['performance']['rate_limit'] = float(
                os.getenv('RATE_LIMIT', 
                config['performance'].get('rate_limit', 1.0)))
        
        return config
    
    def _validate_config(self, config: Dict[str, Any]) -> None:
        """Validate configuration for security and correctness"""
        # Check for hardcoded API keys
        self._check_hardcoded_secrets(config)
        
        # Validate AI configuration
        if 'ai' in config:
            self._validate_ai_config(config['ai'])
        
        # Validate security settings
        if 'privacy' in config:
            self._validate_security_config(config['privacy'])
    
    def _check_hardcoded_secrets(self, config: Dict[str, Any]) -> None:
        """Check for hardcoded secrets in configuration"""
        sensitive_patterns = [
            'api_key', 'secret', 'password', 'token', 'key'
        ]
        
        def check_dict(d, path=""):
            for key, value in d.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, dict):
                    check_dict(value, current_path)
                elif isinstance(value, str):
                    for pattern in sensitive_patterns:
                        if pattern in key.lower() and len(value) > 10:
                            self.logger.warning(
                                f"Potential hardcoded secret found at {current_path}. "
                                f"Consider using environment variables instead."
                            )
        
        check_dict(config)
    
    def _validate_ai_config(self, ai_config: Dict[str, Any]) -> None:
        """Validate AI configuration"""
        required_providers = ['groq', 'gemini', 'openai', 'anthropic']
        for provider in required_providers:
            if provider in ai_config:
                provider_config = ai_config[provider]
                if 'api_key' in provider_config and 'api_key_env' not in provider_config:
                    self.logger.warning(
                        f"Hardcoded API key found for {provider}. "
                        f"Consider using environment variables for security."
                    )
    
    def _validate_security_config(self, security_config: Dict[str, Any]) -> None:
        """Validate security configuration"""
        if not security_config.get('sanitize_logs', True):
            self.logger.warning("Log sanitization is disabled. This may expose sensitive data.")
        
        if not security_config.get('mask_sensitive_data', True):
            self.logger.warning("Sensitive data masking is disabled. This may expose sensitive data.")
    
    def get_api_key(self, provider: str) -> Optional[str]:
        """Get API key for a specific provider"""
        config = self.load_config()
        ai_config = config.get('ai', {})
        
        if provider in ai_config:
            provider_config = ai_config[provider]
            # Try environment variable first
            env_key = provider_config.get('api_key_env')
            if env_key:
                return os.getenv(env_key)
            # Fallback to direct api_key (not recommended)
            return provider_config.get('api_key')
        
        return None
    
    def is_ai_enabled(self) -> bool:
        """Check if AI is enabled and properly configured"""
        config = self.load_config()
        ai_config = config.get('ai', {})
        
        # Check if any provider has a valid API key
        for provider in ['groq', 'gemini', 'openai', 'anthropic']:
            if self.get_api_key(provider):
                return True
        
        return False
    
    def get_security_config(self) -> SecurityConfig:
        """Get security configuration"""
        config = self.load_config()
        privacy_config = config.get('privacy', {})
        
        return SecurityConfig(
            sanitize_logs=privacy_config.get('sanitize_logs', True),
            mask_sensitive_data=privacy_config.get('mask_sensitive_data', True),
            sensitive_patterns=privacy_config.get('sensitive_patterns', []),
            exclude_domains=privacy_config.get('exclude_domains', []),
            respect_robots_txt=privacy_config.get('respect_robots_txt', True)
        )

# Global configuration loader instance
config_loader = SecureConfigLoader()

def get_config() -> Dict[str, Any]:
    """Get the current configuration"""
    return config_loader.load_config()

def get_api_key(provider: str) -> Optional[str]:
    """Get API key for a specific provider"""
    return config_loader.get_api_key(provider)

def is_ai_enabled() -> bool:
    """Check if AI is enabled"""
    return config_loader.is_ai_enabled()

def get_security_config() -> SecurityConfig:
    """Get security configuration"""
    return config_loader.get_security_config()