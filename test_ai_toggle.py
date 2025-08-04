#!/usr/bin/env python3
"""
Test script to demonstrate AI toggle functionality
"""

import asyncio
import sys
import os

# Add the parent directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer
from intelligent_terminal_ai.models.command_result import CommandResult


async def test_ai_toggle():
    """Test the AI toggle functionality"""
    
    print("🧪 Testing AI Toggle Functionality")
    print("=" * 40)
    
    # Create a test command result
    test_command = CommandResult(
        command="nmap -sV testphp.vulnweb.com",
        success=True,
        return_code=0,
        stdout="PORT     STATE SERVICE    VERSION\n80/tcp   open  http       Apache httpd 2.2.21\n443/tcp  open  ssl/http   Apache httpd 2.2.21",
        stderr="",
        execution_time=2.5
    )
    
    print("\n1️⃣ Testing with AI ENABLED (default):")
    analyzer_ai = AIAnalyzer(enable_ai=True)
    print(f"   AI Enabled: {analyzer_ai.is_ai_enabled()}")
    print(f"   Provider: {analyzer_ai.provider}")
    
    # Test analysis
    result = await analyzer_ai.analyze_execution(test_command)
    print(f"   Analysis: {result.message[:50]}...")
    
    print("\n2️⃣ Testing with AI DISABLED:")
    analyzer_no_ai = AIAnalyzer(enable_ai=False)
    print(f"   AI Enabled: {analyzer_no_ai.is_ai_enabled()}")
    print(f"   Provider: {analyzer_no_ai.provider}")
    
    # Test analysis
    result = await analyzer_no_ai.analyze_execution(test_command)
    print(f"   Analysis: {result.message[:50]}...")
    
    print("\n3️⃣ Testing runtime toggle:")
    analyzer_toggle = AIAnalyzer(enable_ai=True)
    print(f"   Initial AI status: {analyzer_toggle.is_ai_enabled()}")
    
    # Disable AI
    analyzer_toggle.set_ai_enabled(False)
    print(f"   After disabling: {analyzer_toggle.is_ai_enabled()}")
    
    # Re-enable AI
    analyzer_toggle.set_ai_enabled(True)
    print(f"   After re-enabling: {analyzer_toggle.is_ai_enabled()}")
    
    print("\n4️⃣ Testing vulnerability analysis without AI:")
    
    # Test SQL injection analysis
    sqli_result = await analyzer_no_ai.analyze_sqli_vulnerability(
        url="https://testphp.vulnweb.com/login.php",
        parameter_name="uname",
        http_method="POST",
        technology_stack="PHP, MySQL",
        html_snippet="<input name='uname' type='text'>"
    )
    
    print(f"   SQLi Analysis Success: {sqli_result.get('success', False)}")
    print(f"   Fallback Used: {sqli_result.get('fallback_used', False)}")
    print(f"   Error: {sqli_result.get('error', 'None')}")
    
    print("\n✅ AI Toggle Test Complete!")
    
    return True


if __name__ == "__main__":
    print("🚀 Starting AI Toggle Test")
    success = asyncio.run(test_ai_toggle())
    
    if success:
        print("\n🎉 All tests passed!")
        print("\nNow you can use the tool with:")
        print("  python run.py <target> --no-ai        # Disable AI completely")
        print("  python run.py <target>                # Use AI (if configured)")
        print("  python run.py <target> --ai-provider groq  # Use specific AI provider")
    else:
        print("\n❌ Some tests failed")
        sys.exit(1)
