"""
Intelligent Terminal AI Tool

An AI-powered tool that can execute commands, analyze responses, 
automate browser testing, and self-correct errors using artificial intelligence.

Features:
- Terminal command execution with error analysis
- Browser automation and visual inspection
- API testing and response analysis
- AI-powered self-correction and iteration
- Real-time feedback and suggestions
"""

from .core.terminal_executor import TerminalExecutor
from .core.browser_automator import BrowserAutomator
from .core.ai_analyzer import AIAnalyzer
from .core.response_inspector import ResponseInspector
from .main import IntelligentTerminalAI

__version__ = "1.0.0"
__author__ = "Your Name"

__all__ = [
    "IntelligentTerminalAI",
    "TerminalExecutor",
    "BrowserAutomator",
    "AIAnalyzer",
    "ResponseInspector"
]
