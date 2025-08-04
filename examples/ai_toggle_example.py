#!/usr/bin/env python3
"""
Example demonstrating how to enable/disable AI analysis in the Intelligent Terminal AI tool
"""

import asyncio
import sys
import os

# Add the parent directory to Python path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer
from intelligent_terminal_ai.models.command_result import CommandResult


async def demonstrate_ai_toggle():
    """Demonstrate enabling and disabling AI analysis"""
    
    print("🤖 AI Toggle Demonstration")
    print("=" * 50)
    
    # Example command result to analyze
    test_command = CommandResult(
        command="curl -X GET https://httpbin.org/get",
        success=True,
        return_code=200,
        stdout='{"url": "https://httpbin.org/get", "headers": {"User-Agent": "curl/7.68.0"}}',
        stderr="",
        execution_time=0.5
    )
    
    # Test 1: AI Enabled (default)
    print("\n1️⃣ Testing with AI ENABLED:")
    analyzer_with_ai = AIAnalyzer(
        model="groq",  # Using Groq as example
        api_key="your-api-key-here",  # Replace with your actual API key
        enable_ai=True  # Explicitly enable AI
    )
    
    print(f"   AI Status: {'✅ ENABLED' if analyzer_with_ai.is_ai_enabled() else '❌ DISABLED'}")
    
    # Analyze with AI
    result_with_ai = await analyzer_with_ai.analyze_execution(test_command)
    print(f"   Analysis Success: {result_with_ai.success}")
    print(f"   Message: {result_with_ai.message}")
    print(f"   Provider: {analyzer_with_ai.provider}")
    
    # Test 2: AI Disabled from initialization
    print("\n2️⃣ Testing with AI DISABLED (from init):")
    analyzer_no_ai = AIAnalyzer(
        model="groq",
        api_key="your-api-key-here",
        enable_ai=False  # Disable AI from start
    )
    
    print(f"   AI Status: {'✅ ENABLED' if analyzer_no_ai.is_ai_enabled() else '❌ DISABLED'}")
    
    # Analyze without AI
    result_no_ai = await analyzer_no_ai.analyze_execution(test_command)
    print(f"   Analysis Success: {result_no_ai.success}")
    print(f"   Message: {result_no_ai.message}")
    print(f"   Provider: {analyzer_no_ai.provider}")
    
    # Test 3: Runtime Toggle
    print("\n3️⃣ Testing RUNTIME AI TOGGLE:")
    analyzer_toggle = AIAnalyzer(
        model="groq",
        api_key="your-api-key-here",
        enable_ai=True  # Start with AI enabled
    )
    
    print(f"   Initial AI Status: {'✅ ENABLED' if analyzer_toggle.is_ai_enabled() else '❌ DISABLED'}")
    
    # Disable AI at runtime
    analyzer_toggle.set_ai_enabled(False)
    print(f"   After disabling: {'✅ ENABLED' if analyzer_toggle.is_ai_enabled() else '❌ DISABLED'}")
    
    # Test analysis with AI disabled
    result_disabled = await analyzer_toggle.analyze_execution(test_command)
    print(f"   Analysis with AI disabled: {result_disabled.message}")
    
    # Re-enable AI at runtime
    analyzer_toggle.set_ai_enabled(True)
    print(f"   After re-enabling: {'✅ ENABLED' if analyzer_toggle.is_ai_enabled() else '❌ DISABLED'}")
    
    # Test 4: Vulnerability Analysis with AI Disabled
    print("\n4️⃣ Testing VULNERABILITY ANALYSIS with AI disabled:")
    
    # Test SQL injection analysis without AI
    sqli_result = await analyzer_no_ai.analyze_sqli_vulnerability(
        url="https://example.com/login",
        parameter_name="username",
        http_method="POST",
        technology_stack="PHP, MySQL",
        html_snippet="<input name='username' type='text'>"
    )
    
    print(f"   SQLi Analysis Success: {sqli_result.get('success', False)}")
    print(f"   Error: {sqli_result.get('error', 'None')}")
    print(f"   Fallback Used: {sqli_result.get('fallback_used', False)}")
    
    # Test XSS analysis without AI
    xss_result = await analyzer_no_ai.analyze_xss_vulnerability(
        url="https://example.com/search",
        parameter_name="query",
        technology_hints="PHP, jQuery",
        full_page_html="<div>Search results for: [USER_INPUT]</div>"
    )
    
    print(f"   XSS Analysis Success: {xss_result.get('success', False)}")
    print(f"   Error: {xss_result.get('error', 'None')}")
    print(f"   Fallback Used: {xss_result.get('fallback_used', False)}")
    
    print("\n✅ AI Toggle Demonstration Complete!")
    print("\nKey Features:")
    print("- ✅ Enable/disable AI from initialization")
    print("- ✅ Runtime AI toggle with set_ai_enabled()")
    print("- ✅ Check AI status with is_ai_enabled()")
    print("- ✅ Graceful fallback when AI is disabled")
    print("- ✅ All analysis methods respect AI settings")


async def demonstrate_configuration_options():
    """Show different ways to configure AI settings"""
    
    print("\n🔧 Configuration Options")
    print("=" * 30)
    
    # Option 1: No AI from start
    print("\n📝 Option 1: Disable AI completely")
    analyzer1 = AIAnalyzer(enable_ai=False)
    print(f"   Status: {analyzer1.provider}")
    
    # Option 2: AI with no API key (will fallback)
    print("\n📝 Option 2: AI enabled but no API key")
    analyzer2 = AIAnalyzer(model="groq", enable_ai=True)  # No API key provided
    print(f"   Status: {analyzer2.provider}")
    
    # Option 3: AI enabled with API key
    print("\n📝 Option 3: AI fully enabled")
    analyzer3 = AIAnalyzer(
        model="groq",
        api_key="your-api-key-here",
        enable_ai=True
    )
    print(f"   Status: {analyzer3.provider}")
    
    # Option 4: Runtime configuration
    print("\n📝 Option 4: Runtime configuration")
    analyzer4 = AIAnalyzer()
    print(f"   Initial: {analyzer4.provider}")
    analyzer4.set_ai_enabled(False)
    print(f"   After disable: AI enabled = {analyzer4.is_ai_enabled()}")


if __name__ == "__main__":
    print("🚀 Starting AI Toggle Example")
    asyncio.run(demonstrate_ai_toggle())
    asyncio.run(demonstrate_configuration_options())
