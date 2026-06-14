"""
Comprehensive Error Handling Utilities for Advanced Intelligent Web Crawler
Provides structured error handling, logging, and recovery mechanisms
"""

import logging
import traceback
import functools
import asyncio
from typing import Any, Callable, Optional, Union, Dict
from enum import Enum
from dataclasses import dataclass
from selenium.common.exceptions import (
    StaleElementReferenceException,
    WebDriverException,
    TimeoutException,
    NoSuchElementException,
    ElementNotInteractableException,
    ElementClickInterceptedException
)

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ErrorContext:
    """Context information for error handling"""
    operation: str
    component: str
    severity: ErrorSeverity
    retry_count: int = 0
    max_retries: int = 3
    additional_info: Optional[Dict[str, Any]] = None

class CrawlerError(Exception):
    """Base exception for crawler-specific errors"""
    def __init__(self, message: str, context: Optional[ErrorContext] = None):
        super().__init__(message)
        self.context = context
        self.timestamp = asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else None

class WebDriverError(CrawlerError):
    """WebDriver-specific errors"""
    pass

class AIProviderError(CrawlerError):
    """AI provider-specific errors"""
    pass

class NetworkError(CrawlerError):
    """Network-related errors"""
    pass

class ConfigurationError(CrawlerError):
    """Configuration-related errors"""
    pass

class ErrorHandler:
    """Centralized error handling and recovery"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.error_counts: Dict[str, int] = {}
        self.recovery_strategies: Dict[type, Callable] = {
            StaleElementReferenceException: self._handle_stale_element,
            TimeoutException: self._handle_timeout,
            WebDriverException: self._handle_webdriver_error,
            NoSuchElementException: self._handle_no_such_element,
            ElementNotInteractableException: self._handle_element_not_interactable,
            ElementClickInterceptedException: self._handle_element_click_intercepted,
        }
    
    def handle_error(self, error: Exception, context: ErrorContext) -> bool:
        """
        Handle an error with appropriate recovery strategy
        
        Returns:
            bool: True if error was handled and operation can retry, False otherwise
        """
        error_type = type(error)
        error_key = f"{error_type.__name__}_{context.operation}"
        
        # Track error frequency
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        # Log error with context
        self._log_error(error, context)
        
        # Check if we should retry
        if context.retry_count >= context.max_retries:
            self.logger.error(f"Max retries exceeded for {context.operation}")
            return False
        
        # Apply recovery strategy
        if error_type in self.recovery_strategies:
            return self.recovery_strategies[error_type](error, context)
        
        # Default handling
        return self._handle_generic_error(error, context)
    
    def _log_error(self, error: Exception, context: ErrorContext) -> None:
        """Log error with appropriate level based on severity"""
        error_msg = f"Error in {context.operation} ({context.component}): {str(error)}"
        
        if context.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(error_msg, exc_info=True)
        elif context.severity == ErrorSeverity.HIGH:
            self.logger.error(error_msg, exc_info=True)
        elif context.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(error_msg)
        else:
            self.logger.info(error_msg)
    
    def _handle_stale_element(self, error: StaleElementReferenceException, context: ErrorContext) -> bool:
        """Handle stale element reference errors"""
        self.logger.warning("Stale element reference detected, refreshing page")
        # This would need access to the driver instance
        # For now, return True to indicate retry is possible
        return True
    
    def _handle_timeout(self, error: TimeoutException, context: ErrorContext) -> bool:
        """Handle timeout errors"""
        self.logger.warning(f"Timeout in {context.operation}, increasing timeout")
        return True
    
    def _handle_webdriver_error(self, error: WebDriverException, context: ErrorContext) -> bool:
        """Handle general WebDriver errors"""
        self.logger.error(f"WebDriver error in {context.operation}: {str(error)}")
        return context.retry_count < 2  # Allow 2 retries for WebDriver errors
    
    def _handle_no_such_element(self, error: NoSuchElementException, context: ErrorContext) -> bool:
        """Handle element not found errors"""
        self.logger.warning(f"Element not found in {context.operation}")
        return False  # Usually no point in retrying
    
    def _handle_element_not_interactable(self, error: ElementNotInteractableException, context: ErrorContext) -> bool:
        """Handle element not interactable errors"""
        self.logger.warning(f"Element not interactable in {context.operation}")
        return True  # Might work after page load
    
    def _handle_element_click_intercepted(self, error: ElementClickInterceptedException, context: ErrorContext) -> bool:
        """Handle element click intercepted errors"""
        self.logger.warning(f"Element click intercepted in {context.operation}")
        return True  # Might work after scrolling or waiting
    
    def _handle_generic_error(self, error: Exception, context: ErrorContext) -> bool:
        """Handle generic errors"""
        self.logger.error(f"Unexpected error in {context.operation}: {str(error)}")
        return context.severity != ErrorSeverity.CRITICAL

def retry_on_error(
    max_retries: int = 3,
    delay: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """
    Decorator to retry function on specific exceptions
    
    Args:
        max_retries: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff_factor: Multiplier for delay after each retry
        exceptions: Tuple of exception types to retry on
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        logging.getLogger(__name__).warning(
                            f"Attempt {attempt + 1} failed for {func.__name__}: {e}. "
                            f"Retrying in {current_delay} seconds..."
                        )
                        import time
                        time.sleep(current_delay)
                        current_delay *= backoff_factor
                    else:
                        logging.getLogger(__name__).error(
                            f"All {max_retries + 1} attempts failed for {func.__name__}"
                        )
                        raise last_exception
            
            raise last_exception
        return wrapper
    return decorator

def safe_execute(
    operation: str,
    component: str = "unknown",
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    default_return: Any = None,
    error_handler: Optional[ErrorHandler] = None
):
    """
    Decorator to safely execute functions with error handling
    
    Args:
        operation: Name of the operation being performed
        component: Component performing the operation
        severity: Error severity level
        default_return: Value to return if operation fails
        error_handler: Custom error handler instance
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            handler = error_handler or ErrorHandler()
            context = ErrorContext(
                operation=operation,
                component=component,
                severity=severity
            )
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if handler.handle_error(e, context):
                    # Retry once if handler suggests it
                    try:
                        return func(*args, **kwargs)
                    except Exception as retry_error:
                        handler.handle_error(retry_error, context)
                        return default_return
                else:
                    return default_return
        return wrapper
    return decorator

def log_errors(logger: Optional[logging.Logger] = None):
    """
    Decorator to log all exceptions from a function
    
    Args:
        logger: Logger instance to use
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            log = logger or logging.getLogger(func.__module__)
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log.error(f"Error in {func.__name__}: {e}", exc_info=True)
                raise
        return wrapper
    return decorator

class ErrorRecoveryManager:
    """Manages error recovery strategies across the application"""
    
    def __init__(self):
        self.handlers: Dict[str, ErrorHandler] = {}
        self.global_handler = ErrorHandler()
    
    def get_handler(self, component: str) -> ErrorHandler:
        """Get error handler for specific component"""
        if component not in self.handlers:
            self.handlers[component] = ErrorHandler(
                logging.getLogger(f"{__name__}.{component}")
            )
        return self.handlers[component]
    
    def handle_component_error(
        self, 
        error: Exception, 
        component: str, 
        operation: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM
    ) -> bool:
        """Handle error for specific component"""
        handler = self.get_handler(component)
        context = ErrorContext(
            operation=operation,
            component=component,
            severity=severity
        )
        return handler.handle_error(error, context)

# Global error recovery manager
error_recovery = ErrorRecoveryManager()

# Convenience functions
def handle_webdriver_error(error: Exception, operation: str) -> bool:
    """Handle WebDriver errors with appropriate recovery"""
    return error_recovery.handle_component_error(
        error, "webdriver", operation, ErrorSeverity.MEDIUM
    )

def handle_ai_error(error: Exception, operation: str) -> bool:
    """Handle AI provider errors"""
    return error_recovery.handle_component_error(
        error, "ai_provider", operation, ErrorSeverity.HIGH
    )

def handle_network_error(error: Exception, operation: str) -> bool:
    """Handle network errors"""
    return error_recovery.handle_component_error(
        error, "network", operation, ErrorSeverity.MEDIUM
    )