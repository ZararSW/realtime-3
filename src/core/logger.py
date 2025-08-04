"""
Production-grade logging system for Advanced Intelligent Web Crawler
Features structured logging, file rotation, privacy protection, and multiple output formats
"""

import logging
import logging.handlers
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict


@dataclass
class LogEvent:
    """Structured log event"""
    timestamp: str
    level: str
    module: str
    message: str
    event_type: str
    data: Dict[str, Any] = None
    target_url: Optional[str] = None
    session_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), default=str)


class PrivacyFilter(logging.Filter):
    """Filter to mask sensitive data in logs"""
    
    def __init__(self, sensitive_patterns: List[str]):
        super().__init__()
        self.sensitive_patterns = sensitive_patterns
        self.mask_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in sensitive_patterns]
    
    def filter(self, record):
        """Filter and mask sensitive data"""
        if hasattr(record, 'msg'):
            record.msg = self._mask_sensitive_data(str(record.msg))
        if hasattr(record, 'args'):
            record.args = tuple(self._mask_sensitive_data(str(arg)) for arg in record.args)
        return True
    
    def _mask_sensitive_data(self, text: str) -> str:
        """Mask sensitive data in text"""
        for pattern in self.mask_patterns:
            text = pattern.sub('[REDACTED]', text)
        return text


class StructuredFormatter(logging.Formatter):
    """Structured JSON formatter for logs"""
    
    def __init__(self, include_timestamp: bool = True):
        super().__init__()
        self.include_timestamp = include_timestamp
    
    def format(self, record):
        """Format log record as structured JSON"""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'module': record.module,
            'message': record.getMessage(),
            'event_type': getattr(record, 'event_type', 'general'),
            'data': getattr(record, 'data', {}),
            'target_url': getattr(record, 'target_url', None),
            'session_id': getattr(record, 'session_id', None)
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human-readable console formatter"""
    
    def __init__(self):
        super().__init__()
        self.colors = {
            'DEBUG': '\033[36m',    # Cyan
            'INFO': '\033[32m',     # Green
            'WARNING': '\033[33m',  # Yellow
            'ERROR': '\033[31m',    # Red
            'CRITICAL': '\033[35m', # Magenta
            'RESET': '\033[0m'      # Reset
        }
    
    def format(self, record):
        """Format log record for console output"""
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        level_color = self.colors.get(record.levelname, self.colors['RESET'])
        
        # Base format
        formatted = f"{level_color}[{timestamp}] {record.levelname:8} {record.module:15} {record.getMessage()}{self.colors['RESET']}"
        
        # Add event type if present
        if hasattr(record, 'event_type'):
            formatted += f" [{record.event_type}]"
        
        # Add data if present
        if hasattr(record, 'data') and record.data:
            formatted += f" | Data: {json.dumps(record.data, default=str)[:100]}"
        
        return formatted


class Logger:
    """
    Production-grade logger with multiple outputs and privacy protection
    """
    
    def __init__(self, config):
        """
        Initialize logger with configuration
        
        Args:
            config: Configuration object with logging settings
        """
        self.config = config
        self.logger = logging.getLogger('AdvancedCrawler')
        self.logger.setLevel(getattr(logging, config.logging.level))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Setup handlers
        self._setup_console_handler()
        if config.logging.file_enabled:
            self._setup_file_handler()
        
        # Setup privacy filter
        if config.privacy.sanitize_logs:
            privacy_filter = PrivacyFilter(config.privacy.sensitive_patterns)
            self.logger.addFilter(privacy_filter)
        
        self.session_id = self._generate_session_id()
    
    def _setup_console_handler(self):
        """Setup console handler with colored output"""
        if self.config.logging.console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(getattr(logging, self.config.logging.level))
            console_handler.setFormatter(ConsoleFormatter())
            self.logger.addHandler(console_handler)
    
    def _setup_file_handler(self):
        """Setup file handler with rotation"""
        try:
            # Create log directory
            log_path = Path(self.config.logging.file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Parse max file size
            max_bytes = self._parse_size(self.config.logging.max_file_size)
            
            # Setup rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                filename=log_path,
                maxBytes=max_bytes,
                backupCount=self.config.logging.backup_count,
                encoding='utf-8'
            )
            
            file_handler.setLevel(getattr(logging, self.config.logging.level))
            
            # Use structured formatter for file
            if self.config.logging.json_format:
                file_handler.setFormatter(StructuredFormatter())
            else:
                file_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(message)s'
                ))
            
            self.logger.addHandler(file_handler)
            
        except Exception as e:
            print(f"❌ Error setting up file logging: {e}")
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string to bytes"""
        size_str = size_str.upper()
        if size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _log_with_context(self, level: str, message: str, event_type: str = 'general', 
                         data: Dict[str, Any] = None, target_url: str = None):
        """Log with additional context"""
        extra = {
            'event_type': event_type,
            'data': data or {},
            'target_url': target_url,
            'session_id': self.session_id
        }
        
        log_method = getattr(self.logger, level.lower())
        log_method(message, extra=extra)
    
    def info(self, message: str, event_type: str = 'general', data: Dict[str, Any] = None, 
             target_url: str = None):
        """Log info message"""
        self._log_with_context('INFO', message, event_type, data, target_url)
    
    def warning(self, message: str, event_type: str = 'general', data: Dict[str, Any] = None, 
                target_url: str = None):
        """Log warning message"""
        self._log_with_context('WARNING', message, event_type, data, target_url)
    
    def error(self, message: str, event_type: str = 'general', data: Dict[str, Any] = None, 
              target_url: str = None):
        """Log error message"""
        self._log_with_context('ERROR', message, event_type, data, target_url)
    
    def debug(self, message: str, event_type: str = 'general', data: Dict[str, Any] = None, 
              target_url: str = None):
        """Log debug message"""
        self._log_with_context('DEBUG', message, event_type, data, target_url)
    
    def critical(self, message: str, event_type: str = 'general', data: Dict[str, Any] = None, 
                 target_url: str = None):
        """Log critical message"""
        self._log_with_context('CRITICAL', message, event_type, data, target_url)
    
    def log_security_event(self, event_type: str, message: str, severity: str, 
                          data: Dict[str, Any] = None, target_url: str = None):
        """Log security-specific event"""
        security_data = {
            'severity': severity,
            'event_type': event_type,
            **(data or {})
        }
        
        level = 'ERROR' if severity in ['critical', 'high'] else 'WARNING'
        self._log_with_context(level, message, 'security', security_data, target_url)
    
    def log_ai_event(self, message: str, model: str, response: Dict[str, Any], 
                     target_url: str = None):
        """Log AI analysis event"""
        ai_data = {
            'model': model,
            'response': response
        }
        self._log_with_context('INFO', message, 'ai_analysis', ai_data, target_url)
    
    def log_network_event(self, event_type: str, url: str, method: str = None, 
                         status_code: int = None, data: Dict[str, Any] = None):
        """Log network event"""
        network_data = {
            'url': url,
            'method': method,
            'status_code': status_code,
            **(data or {})
        }
        self._log_with_context('INFO', f"Network {event_type}", 'network', network_data, url)
    
    def log_dom_event(self, event_type: str, content: str, target_url: str = None):
        """Log DOM change event"""
        dom_data = {
            'content_length': len(content),
            'content_preview': content[:200] + '...' if len(content) > 200 else content
        }
        self._log_with_context('DEBUG', f"DOM {event_type}", 'dom_change', dom_data, target_url)
    
    def get_session_id(self) -> str:
        """Get current session ID"""
        return self.session_id
    
    def close(self):
        """Close all handlers"""
        for handler in self.logger.handlers:
            handler.close()
            self.logger.removeHandler(handler) 