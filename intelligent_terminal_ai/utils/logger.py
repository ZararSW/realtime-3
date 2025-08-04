"""
Logging utilities for the intelligent terminal AI
"""

import logging
import sys
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    Set up a logger with rich formatting
    
    Args:
        name: Logger name
        level: Logging level
        
    Returns:
        Configured logger
    """
    # Create logger
    logger = logging.getLogger(name)
    
    # Avoid adding multiple handlers
    if logger.handlers:
        return logger
    
    # Set level
    logger.setLevel(getattr(logging, level.upper()))
    
    # Create rich handler
    console = Console()
    handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        tracebacks_show_locals=True
    )
    
    # Set format
    formatter = logging.Formatter(
        fmt="%(message)s",
        datefmt="[%X]"
    )
    handler.setFormatter(formatter)
    
    # Add handler
    logger.addHandler(handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get an existing logger or create a new one"""
    return logging.getLogger(name)
