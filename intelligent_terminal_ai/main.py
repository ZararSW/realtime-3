"""
Main orchestrator for the Intelligent Terminal AI Tool
"""

import asyncio
import logging
import os
from typing import Dict, Any, Optional, List
from datetime import datetime

from .core.terminal_executor import TerminalExecutor
from .core.browser_automator import BrowserAutomator
from .core.ai_analyzer import AIAnalyzer
from .core.response_inspector import ResponseInspector
from .core.autonomous_pentester import AutonomousPenTester
from .models.command_result import CommandResult, AnalysisResult
from .utils.logger import setup_logger
from .utils.config import config


class IntelligentTerminalAI:
    """
    Main class that orchestrates terminal execution, browser automation,
    and AI analysis for intelligent command execution and error correction.
    """
    
    def __init__(self, 
                 ai_model: str = "gpt-4",
                 headless_browser: bool = False,
                 log_level: str = "INFO"):
        """
        Initialize the Intelligent Terminal AI
        
        Args:
            ai_model: AI model to use for analysis ("gpt-4", "claude-3", etc.)
            headless_browser: Whether to run browser in headless mode
            log_level: Logging level
        """
        self.logger = setup_logger(__name__, log_level)
        
        # Initialize components
        self.terminal_executor = TerminalExecutor()
        self.browser_automator = BrowserAutomator(headless=headless_browser)
        
        # Get AI configuration from config
        ai_provider = config.get("ai", "provider", "groq")
        ai_config = config.get("ai", ai_provider, {})
        
        # Force Groq as default since it's the one with working API key
        if ai_provider not in ["groq"] and not os.getenv("GOOGLE_API_KEY") and not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"):
            ai_provider = "groq"
            ai_config = config.get("ai", "groq", {})
        
        # Get model and API key based on provider
        if ai_provider == "groq":
            ai_model = f"groq-{ai_config.get('model', 'llama-3.1-8b-instant')}"
            api_key = ai_config.get("api_key") or os.getenv("GROQ_API_KEY")
        elif ai_provider == "gemini":
            ai_model = f"gemini-{ai_config.get('model', 'gemini-2.0-flash-exp')}"
            api_key = ai_config.get("api_key") or os.getenv(ai_config.get("api_key_env", "GOOGLE_API_KEY"))
        elif ai_provider == "openai":
            ai_model = ai_config.get("model", "gpt-4")
            api_key = ai_config.get("api_key") or os.getenv(ai_config.get("api_key_env", "OPENAI_API_KEY"))
        elif ai_provider == "anthropic":
            ai_model = ai_config.get("model", "claude-3-sonnet-20240229")
            api_key = ai_config.get("api_key") or os.getenv(ai_config.get("api_key_env", "ANTHROPIC_API_KEY"))
        else:
            # Fallback to groq
            ai_model = "groq-llama-3.1-8b-instant"
            api_key = config.get("ai", "groq", {}).get("api_key")
        
        self.ai_analyzer = AIAnalyzer(model=ai_model, api_key=api_key)
        self.response_inspector = ResponseInspector()
        self.autonomous_pentester = AutonomousPenTester(
            self.ai_analyzer, 
            self.browser_automator, 
            self.terminal_executor
        )
        
        # Session tracking
        self.session_history: List[Dict[str, Any]] = []
        self.current_context: Dict[str, Any] = {}
        
        self.logger.info("Intelligent Terminal AI initialized")
    
    async def execute_intelligent_command(self, 
                                        command: str,
                                        target_url: Optional[str] = None,
                                        max_iterations: int = 3) -> AnalysisResult:
        """
        Execute a command with intelligent analysis and self-correction
        
        Args:
            command: Command to execute
            target_url: Optional URL to test/analyze
            max_iterations: Maximum number of self-correction attempts
            
        Returns:
            AnalysisResult with final outcome and suggestions
        """
        self.logger.info(f"Starting intelligent execution of: {command}")
        
        iteration = 0
        current_command = command
        
        while iteration < max_iterations:
            iteration += 1
            self.logger.info(f"Iteration {iteration}/{max_iterations}")
            
            # Execute the command
            result = await self.terminal_executor.execute_command(current_command)
            
            # Log the execution
            execution_log = {
                "iteration": iteration,
                "command": current_command,
                "timestamp": datetime.now().isoformat(),
                "result": result.dict()
            }
            self.session_history.append(execution_log)
            
            # If command succeeded and no URL to test, we're done
            if result.success and not target_url:
                analysis = AnalysisResult(
                    success=True,
                    message="Command executed successfully",
                    suggestions=[],
                    final_command=current_command,
                    iterations_used=iteration
                )
                self.logger.info("Command completed successfully")
                return analysis
            
            # If we have a target URL, test it with browser
            browser_result = None
            if target_url:
                browser_result = await self.browser_automator.test_url(target_url)
                execution_log["browser_result"] = browser_result.dict() if browser_result else None
            
            # Analyze results with AI
            analysis = await self.ai_analyzer.analyze_execution(
                command_result=result,
                browser_result=browser_result,
                context=self.current_context,
                history=self.session_history[-3:]  # Last 3 attempts for context
            )
            
            # If analysis suggests we're done or successful
            if analysis.success or not analysis.suggested_command:
                analysis.iterations_used = iteration
                self.logger.info(f"Analysis complete after {iteration} iterations")
                return analysis
            
            # Use AI's suggested command for next iteration
            current_command = analysis.suggested_command
            self.logger.info(f"AI suggested refinement: {current_command}")
        
        # Max iterations reached
        final_analysis = AnalysisResult(
            success=False,
            message=f"Max iterations ({max_iterations}) reached without resolution",
            suggestions=["Consider breaking down the task into smaller steps",
                        "Review the command syntax and parameters",
                        "Check if all dependencies are properly installed"],
            final_command=current_command,
            iterations_used=max_iterations
        )
        
        self.logger.warning("Max iterations reached without resolution")
        return final_analysis
    
    async def test_api_endpoint(self, 
                              url: str,
                              method: str = "GET",
                              headers: Optional[Dict[str, str]] = None,
                              data: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        """
        Test an API endpoint with intelligent analysis
        
        Args:
            url: API endpoint URL
            method: HTTP method
            headers: Request headers
            data: Request data
            
        Returns:
            AnalysisResult with API test results and suggestions
        """
        self.logger.info(f"Testing API endpoint: {method} {url}")
        
        # Execute API request
        api_result = await self.terminal_executor.execute_api_request(
            url=url, method=method, headers=headers, data=data
        )
        
        # Test with browser if it's a web endpoint
        browser_result = None
        if method == "GET":
            browser_result = await self.browser_automator.test_url(url)
        
        # Analyze with AI
        analysis = await self.ai_analyzer.analyze_api_response(
            api_result=api_result,
            browser_result=browser_result
        )
        
        # Log the test
        test_log = {
            "type": "api_test",
            "url": url,
            "method": method,
            "timestamp": datetime.now().isoformat(),
            "api_result": api_result.dict(),
            "browser_result": browser_result.dict() if browser_result else None,
            "analysis": analysis.dict()
        }
        self.session_history.append(test_log)
        
        self.logger.info(f"API test completed: {analysis.message}")
        return analysis
    
    async def autonomous_pentest(self, target_url: str, 
                               depth: int = 3,
                               max_tests: int = 20) -> Dict[str, Any]:
        """
        Perform autonomous AI-driven penetration testing
        
        Args:
            target_url: Target website URL
            depth: Exploration depth
            max_tests: Maximum tests to perform
            
        Returns:
            Comprehensive pentest report
        """
        self.logger.info(f"🎯 Starting autonomous pentest of {target_url}")
        
        report = await self.autonomous_pentester.autonomous_pentest(
            target_url, depth, max_tests
        )
        
        self.logger.info("🎉 Autonomous pentest completed")
        return report
    
    async def autonomous_pentest_visual(self, target_url: str, depth: int = 3) -> Dict[str, Any]:
        """
        Perform autonomous AI-driven penetration testing with real-time visual feedback
        
        Args:
            target_url: Target website URL
            depth: Exploration depth
            
        Returns:
            Comprehensive pentest report with visual testing
        """
        self.logger.info(f"🎯 Starting visual autonomous pentest of {target_url}")
        
        report = await self.autonomous_pentester.autonomous_pentest_visual(
            target_url, depth
        )
        
        self.logger.info("🎉 Visual autonomous pentest completed")
        return report

    async def interactive_session(self):
        """
        Start an interactive session where user can input commands
        and get intelligent feedback
        """
        self.logger.info("Starting interactive session")
        print("🤖 Intelligent Terminal AI - Interactive Mode")
        print("Type 'help' for commands, 'exit' to quit")
        print("-" * 50)
        
        while True:
            try:
                user_input = input("\n💭 Enter command or URL to test: ").strip()
                
                if user_input.lower() in ['exit', 'quit']:
                    break
                elif user_input.lower() == 'help':
                    self._show_help()
                    continue
                elif user_input.lower() == 'history':
                    self._show_history()
                    continue
                elif user_input.lower().startswith('pentest '):
                    # Autonomous pentest mode
                    target_url = user_input[8:].strip()
                    if target_url:
                        print(f"🎯 Starting autonomous pentest of {target_url}")
                        print("This may take a few minutes...")
                        result = await self.autonomous_pentest(target_url)
                        self._display_pentest_result(result)
                    else:
                        print("❌ Please provide a target URL: pentest http://example.com")
                    continue
                elif user_input.startswith('http'):
                    # URL provided - test it
                    result = await self.test_api_endpoint(user_input)
                else:
                    # Command provided - execute intelligently
                    result = await self.execute_intelligent_command(user_input)
                
                # Display results
                self._display_result(result)
                
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                self.logger.error(f"Error in interactive session: {e}")
                print(f"❌ Error: {e}")
    
    def _show_help(self):
        """Display help information"""
        help_text = """
🤖 Intelligent Terminal AI - Commands:

• Enter any terminal command - AI will execute and auto-correct if needed
• Enter a URL (http/https) - AI will test and analyze the endpoint
• 'pentest <URL>' - Start autonomous penetration testing
• 'history' - Show session history
• 'help' - Show this help
• 'exit' or 'quit' - Exit the session

Examples:
  curl https://api.example.com/users
  https://www.example.com
  pentest http://testphp.vulnweb.com/
  npm start
  python script.py
        """
        print(help_text)
    
    def _show_history(self):
        """Display session history"""
        if not self.session_history:
            print("📝 No history available")
            return
        
        print("📝 Session History:")
        for i, entry in enumerate(self.session_history[-10:], 1):
            timestamp = entry.get('timestamp', 'Unknown')
            if entry.get('type') == 'api_test':
                print(f"{i}. [{timestamp}] API Test: {entry.get('method', 'GET')} {entry.get('url')}")
            else:
                print(f"{i}. [{timestamp}] Command: {entry.get('command')}")
    
    def _display_result(self, result: AnalysisResult):
        """Display analysis result in a user-friendly format"""
        if result.success:
            print(f"✅ {result.message}")
        else:
            print(f"❌ {result.message}")
        
        if result.suggestions:
            print("\n💡 Suggestions:")
            for suggestion in result.suggestions:
                print(f"  • {suggestion}")
        
        if hasattr(result, 'iterations_used') and result.iterations_used:
            print(f"\n🔄 Iterations used: {result.iterations_used}")
    
    def _display_pentest_result(self, result: Dict[str, Any]):
        """Display pentest result in a user-friendly format"""
        print("\n" + "="*60)
        print("🛡️  AUTONOMOUS PENETRATION TEST REPORT")
        print("="*60)
        
        print(f"🎯 Target: {result.get('target', 'Unknown')}")
        print(f"📊 Risk Score: {result.get('risk_score', 0)}/10")
        
        # Show phases completed
        phases = result.get('phases', [])
        print(f"\n📋 Phases Completed: {len(phases)}")
        for i, phase in enumerate(phases, 1):
            print(f"  {i}. {phase.get('name', 'Unknown Phase')}")
        
        # Show vulnerabilities found
        vulns = result.get('vulnerabilities', [])
        if vulns:
            print(f"\n🚨 Vulnerabilities Found: {len(vulns)}")
            for vuln in vulns[:5]:  # Show top 5
                print(f"  • {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
        
        # Show AI summary
        summary = result.get('summary', '')
        if summary:
            print(f"\n🤖 AI Analysis Summary:")
            print(f"   {summary[:200]}...")
        
        # Show recommendations
        recommendations = result.get('recommendations', [])
        if recommendations:
            print(f"\n💡 Top Recommendations:")
            for rec in recommendations[:3]:
                print(f"  • {rec}")
        
        print("="*60)
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.browser_automator.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.browser_automator.__aexit__(exc_type, exc_val, exc_tb)
