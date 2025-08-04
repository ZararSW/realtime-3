"""
Configuration management for Advanced Intelligent Web Crawler
Production-grade configuration handling with validation and defaults
"""

import os
import yaml
import argparse
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field
from typing import List


@dataclass
class AIConfig:
    """AI configuration settings"""
    model: str = "gemini-2.0-flash-exp"
    api_key_env: str = "GOOGLE_API_KEY"
    max_retries: int = 3
    timeout: int = 30
    context_window: int = 2000


@dataclass
class BrowserConfig:
    """Browser configuration settings"""
    headless: bool = False
    stealth_mode: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    window_size: str = "1920x1080"
    page_load_timeout: int = 30
    implicit_wait: int = 10
    chrome_options: List[str] = field(default_factory=lambda: [
        "--disable-blink-features=AutomationControlled",
        "--disable-web-security",
        "--no-sandbox",
        "--disable-gpu"
    ])


@dataclass
class MonitoringConfig:
    """Real-time monitoring configuration"""
    interval: int = 2
    dom_monitoring: bool = True
    console_monitoring: bool = True
    network_monitoring: bool = True
    max_dom_size: int = 2000
    max_console_entries: int = 100
    max_network_events: int = 50


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file_enabled: bool = True
    file_path: str = "logs/crawler.log"
    json_format: bool = True
    max_file_size: str = "10MB"
    backup_count: int = 5
    console_output: bool = True
    structured_logging: bool = True


@dataclass
class SecurityConfig:
    """Security testing configuration"""
    max_payloads_per_type: int = 10
    test_timeout: int = 10
    retry_failed_tests: bool = True
    max_retries: int = 3
    vulnerability_threshold: int = 5
    risk_scoring: Dict[str, int] = field(default_factory=lambda: {
        "critical": 9,
        "high": 7,
        "medium": 5,
        "low": 3,
        "info": 1
    })


@dataclass
class NetworkConfig:
    """Network configuration"""
    request_timeout: int = 30
    max_redirects: int = 5
    retry_strategy: Dict[str, Any] = field(default_factory=lambda: {
        "total": 3,
        "backoff_factor": 0.3,
        "status_forcelist": [429, 500, 502, 503, 504]
    })


@dataclass
class PerformanceConfig:
    """Performance configuration"""
    max_concurrent_requests: int = 5
    rate_limit: float = 1.0
    memory_limit: str = "2GB"
    cpu_limit: int = 80


@dataclass
class OutputConfig:
    """Output configuration"""
    save_screenshots: bool = False
    screenshot_path: str = "screenshots/"
    save_reports: bool = True
    report_format: str = "json"
    report_path: str = "reports/"
    include_ai_analysis: bool = True
    include_technical_details: bool = True


@dataclass
class PrivacyConfig:
    """Privacy and security configuration"""
    sanitize_logs: bool = True
    mask_sensitive_data: bool = True
    sensitive_patterns: List[str] = field(default_factory=lambda: [
        "password", "api_key", "token", "secret"
    ])
    exclude_domains: List[str] = field(default_factory=list)
    respect_robots_txt: bool = True


@dataclass
class AdvancedConfig:
    """Advanced features configuration"""
    enable_ai_analysis: bool = True
    enable_visual_analysis: bool = False
    enable_behavioral_analysis: bool = True
    enable_threat_intelligence: bool = False
    enable_machine_learning: bool = False
    custom_payloads_file: Optional[str] = None
    custom_headers_file: Optional[str] = None


class Config:
    """
    Main configuration class that manages all settings
    Supports loading from YAML files, environment variables, and CLI arguments
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration
        
        Args:
            config_path: Path to YAML configuration file
        """
        self.config_path = config_path or "config.yaml"
        
        # Initialize all configuration sections
        self.ai = AIConfig()
        self.browser = BrowserConfig()
        self.monitoring = MonitoringConfig()
        self.logging = LoggingConfig()
        self.security = SecurityConfig()
        self.network = NetworkConfig()
        self.performance = PerformanceConfig()
        self.output = OutputConfig()
        self.privacy = PrivacyConfig()
        self.advanced = AdvancedConfig()
        
        # Load configuration
        self._load_config()
        self._load_environment_variables()
        self._create_directories()
    
    def _load_config(self) -> None:
        """Load configuration from YAML file"""
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config_data = yaml.safe_load(f)
                
                if config_data:
                    self._update_from_dict(config_data)
                    print(f"✅ Configuration loaded from {self.config_path}")
            else:
                print(f"⚠️  Configuration file {self.config_path} not found, using defaults")
        except Exception as e:
            print(f"❌ Error loading configuration: {e}")
    
    def _update_from_dict(self, config_data: Dict[str, Any]) -> None:
        """Update configuration from dictionary"""
        for section_name, section_data in config_data.items():
            if hasattr(self, section_name) and section_data:
                section = getattr(self, section_name)
                for key, value in section_data.items():
                    if hasattr(section, key):
                        setattr(section, key, value)
    
    def _load_environment_variables(self) -> None:
        """Load configuration from environment variables"""
        # AI Configuration
        if os.getenv('AI_MODEL'):
            self.ai.model = os.getenv('AI_MODEL')
        if os.getenv('AI_TIMEOUT'):
            self.ai.timeout = int(os.getenv('AI_TIMEOUT'))
        
        # Browser Configuration
        if os.getenv('BROWSER_HEADLESS'):
            self.browser.headless = os.getenv('BROWSER_HEADLESS').lower() == 'true'
        if os.getenv('BROWSER_USER_AGENT'):
            self.browser.user_agent = os.getenv('BROWSER_USER_AGENT')
        
        # Logging Configuration
        if os.getenv('LOG_LEVEL'):
            self.logging.level = os.getenv('LOG_LEVEL')
        if os.getenv('LOG_FILE_PATH'):
            self.logging.file_path = os.getenv('LOG_FILE_PATH')
        
        # Monitoring Configuration
        if os.getenv('MONITORING_INTERVAL'):
            self.monitoring.interval = int(os.getenv('MONITORING_INTERVAL'))
    
    def _create_directories(self) -> None:
        """Create necessary directories for logs, reports, etc."""
        directories = [
            Path(self.logging.file_path).parent,
            Path(self.output.report_path),
            Path(self.output.screenshot_path)
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def get_api_key(self) -> Optional[str]:
        """Get API key from environment"""
        return os.getenv(self.ai.api_key_env)
    
    def validate(self) -> bool:
        """Validate configuration settings"""
        errors = []
        
        # Validate AI configuration
        if not self.get_api_key() and self.advanced.enable_ai_analysis:
            errors.append("AI analysis enabled but no API key found")
        
        # Validate file paths
        if self.logging.file_enabled and not self.logging.file_path:
            errors.append("File logging enabled but no file path specified")
        
        # Validate performance settings
        if self.performance.rate_limit <= 0:
            errors.append("Rate limit must be positive")
        
        if errors:
            print("❌ Configuration validation errors:")
            for error in errors:
                print(f"  • {error}")
            return False
        
        print("✅ Configuration validation passed")
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'ai': self.ai.__dict__,
            'browser': self.browser.__dict__,
            'monitoring': self.monitoring.__dict__,
            'logging': self.logging.__dict__,
            'security': self.security.__dict__,
            'network': self.network.__dict__,
            'performance': self.performance.__dict__,
            'output': self.output.__dict__,
            'privacy': self.privacy.__dict__,
            'advanced': self.advanced.__dict__
        }
    
    @classmethod
    def from_cli_args(cls) -> 'Config':
        """Create configuration from command line arguments"""
        parser = argparse.ArgumentParser(
            description="Advanced Intelligent Web Crawler & AI Penetration Tester"
        )
        
        parser.add_argument(
            '--config', '-c',
            type=str,
            help='Path to configuration file'
        )
        parser.add_argument(
            '--target', '-t',
            type=str,
            required=True,
            help='Target URL to test'
        )
        parser.add_argument(
            '--headless',
            action='store_true',
            help='Run browser in headless mode'
        )
        parser.add_argument(
            '--log-level',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
            help='Logging level'
        )
        parser.add_argument(
            '--output-dir',
            type=str,
            help='Output directory for reports and logs'
        )
        parser.add_argument(
            '--no-ai',
            action='store_true',
            help='Disable AI analysis'
        )
        
        args = parser.parse_args()
        
        # Create configuration
        config = cls(args.config)
        
        # Override with CLI arguments
        if args.headless:
            config.browser.headless = True
        if args.log_level:
            config.logging.level = args.log_level
        if args.output_dir:
            config.output.report_path = args.output_dir
        if args.no_ai:
            config.advanced.enable_ai_analysis = False
        
        return config, args.target 