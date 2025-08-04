"""
Advanced Intelligent Web Crawler & AI Penetration Tester
Production-grade modular security testing framework
"""

__version__ = "2.0.0"
__author__ = "Security Research Team"
__description__ = "Next-generation autonomous security testing with AI-powered analysis"

from .core.crawler import AdvancedIntelligentCrawler
from .core.config import Config
from .core.logger import Logger
from .core.ai_analyzer import AIAnalyzer
from .core.browser_manager import BrowserManager
from .core.network_monitor import NetworkMonitor
from .core.security_tester import SecurityTester
from .core.report_generator import ReportGenerator

__all__ = [
    "AdvancedIntelligentCrawler",
    "Config", 
    "Logger",
    "AIAnalyzer",
    "BrowserManager",
    "NetworkMonitor",
    "SecurityTester",
    "ReportGenerator"
] 