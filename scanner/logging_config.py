"""
Advanced Logging Configuration for Advanced Intelligent Web Crawler
Provides structured logging, log rotation, and security features
"""

import logging
import logging.handlers
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime
import traceback
import re

class SecurityFilter(logging.Filter):
    """Filter to sanitize sensitive information from logs"""
    
    def __init__(self, sensitive_patterns: Optional[List[str]] = None):
        super().__init__()
        self.sensitive_patterns = sensitive_patterns or [
            r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            r'password["\']?\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?',
            r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            r'secret["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{10,})["\']?',
            r'credential["\']?\s*[:=]\s*["\']?([^"\'\s]{5,})["\']?',
            r'auth["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{10,})["\']?',
        ]
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.sensitive_patterns]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and sanitize log records"""
        if hasattr(record, 'msg'):
            record.msg = self._sanitize_message(str(record.msg))
        
        if hasattr(record, 'args') and record.args:
            sanitized_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    sanitized_args.append(self._sanitize_message(arg))
                else:
                    sanitized_args.append(arg)
            record.args = tuple(sanitized_args)
        
        return True
    
    def _sanitize_message(self, message: str) -> str:
        """Sanitize sensitive information from message.

        Replaces only the captured secret *value* with a placeholder while
        keeping the surrounding text (e.g. the key name) intact. The previous
        implementation echoed the secret value back, which leaked it.
        """
        for pattern in self.compiled_patterns:
            message = pattern.sub(
                lambda m: m.group(0).replace(m.group(1), "***REDACTED***"), message
            )
        return message

class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured JSON logging"""
    
    def __init__(self, include_stack_trace: bool = True):
        super().__init__()
        self.include_stack_trace = include_stack_trace
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON"""
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread': record.thread,
            'process': record.process
        }
        
        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'traceback': traceback.format_exception(*record.exc_info) if self.include_stack_trace else None
            }
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'getMessage', 'exc_info', 
                          'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)

class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors"""
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # Format the message
        formatted = super().format(record)
        
        # Add colors
        if record.levelname in self.COLORS:
            formatted = f"{color}{formatted}{reset}"
        
        return formatted

class LoggingManager:
    """Centralized logging management"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._get_default_config()
        self.loggers: Dict[str, logging.Logger] = {}
        self._setup_logging()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default logging configuration"""
        return {
            'level': 'INFO',
            'file_enabled': True,
            'file_path': 'logs/crawler.log',
            'json_format': True,
            'max_file_size': '10MB',
            'backup_count': 5,
            'console_output': True,
            'structured_logging': True,
            'sanitize_logs': True,
            'sensitive_patterns': [
                'api_key', 'password', 'token', 'secret', 'credential', 'auth'
            ]
        }
    
    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        # Create logs directory
        log_path = Path(self.config['file_path'])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.config['level'].upper()))
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Add console handler
        if self.config.get('console_output', True):
            console_handler = self._create_console_handler()
            root_logger.addHandler(console_handler)
        
        # Add file handler
        if self.config.get('file_enabled', True):
            file_handler = self._create_file_handler()
            root_logger.addHandler(file_handler)
        
        # Add security filter if enabled
        if self.config.get('sanitize_logs', True):
            security_filter = SecurityFilter(
                self.config.get('sensitive_patterns', [])
            )
            for handler in root_logger.handlers:
                handler.addFilter(security_filter)
    
    def _create_console_handler(self) -> logging.StreamHandler:
        """Create console handler with colored output"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        if self.config.get('structured_logging', False):
            formatter = StructuredFormatter(include_stack_trace=False)
        else:
            formatter = ColoredFormatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        console_handler.setFormatter(formatter)
        return console_handler
    
    def _create_file_handler(self) -> logging.Handler:
        """Create file handler with rotation"""
        log_path = Path(self.config['file_path'])
        
        # Parse file size
        max_bytes = self._parse_file_size(self.config.get('max_file_size', '10MB'))
        backup_count = self.config.get('backup_count', 5)
        
        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        
        file_handler.setLevel(logging.DEBUG)
        
        # Set formatter
        if self.config.get('json_format', True):
            formatter = StructuredFormatter(include_stack_trace=True)
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        file_handler.setFormatter(formatter)
        return file_handler
    
    def _parse_file_size(self, size_str: str) -> int:
        """Parse file size string to bytes"""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get logger for specific component"""
        if name not in self.loggers:
            logger = logging.getLogger(name)
            self.loggers[name] = logger
        return self.loggers[name]
    
    def set_level(self, level: str) -> None:
        """Set logging level for all loggers"""
        level_upper = level.upper()
        for logger in self.loggers.values():
            logger.setLevel(getattr(logging, level_upper))
        
        # Also set root logger level
        logging.getLogger().setLevel(getattr(logging, level_upper))
    
    def add_file_handler(self, logger_name: str, file_path: str, level: str = 'DEBUG') -> None:
        """Add file handler to specific logger"""
        logger = self.get_logger(logger_name)
        
        # Create file handler
        file_handler = logging.FileHandler(file_path, encoding='utf-8')
        file_handler.setLevel(getattr(logging, level.upper()))
        
        # Set formatter
        if self.config.get('json_format', True):
            formatter = StructuredFormatter(include_stack_trace=True)
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    def cleanup_old_logs(self, days: int = 30) -> None:
        """Clean up log files older than specified days"""
        log_dir = Path(self.config['file_path']).parent
        cutoff_time = datetime.now().timestamp() - (days * 24 * 60 * 60)
        
        for log_file in log_dir.glob('*.log*'):
            if log_file.stat().st_mtime < cutoff_time:
                try:
                    log_file.unlink()
                    print(f"Removed old log file: {log_file}")
                except Exception as e:
                    print(f"Failed to remove {log_file}: {e}")

# Global logging manager instance
logging_manager = LoggingManager()

def get_logger(name: str) -> logging.Logger:
    """Get logger for specific component"""
    return logging_manager.get_logger(name)

def setup_logging(config: Dict[str, Any]) -> None:
    """Setup logging with custom configuration"""
    global logging_manager
    logging_manager = LoggingManager(config)

def log_function_call(func: Callable) -> Callable:
    """Decorator to log function calls"""
    logger = get_logger(func.__module__)
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
        try:
            result = func(*args, **kwargs)
            logger.debug(f"{func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"{func.__name__} failed with error: {e}", exc_info=True)
            raise
    return wrapper

def log_performance(func: Callable) -> Callable:
    """Decorator to log function performance"""
    logger = get_logger(func.__module__)
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.info(f"{func.__name__} executed in {execution_time:.2f} seconds")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"{func.__name__} failed after {execution_time:.2f} seconds: {e}")
            raise
    return wrapper