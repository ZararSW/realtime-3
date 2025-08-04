#!/usr/bin/env python3
"""
Test Groq AI integration
"""

import asyncio
from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer

async def test_groq():
    """Test Groq AI functionality"""
    
    print("🤖 Testing Groq AI Integration...")
    
    # Initialize AI analyzer with Groq
    analyzer = AIAnalyzer(
        model="groq-llama", 
        api_key="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"
    )
    
    # Test prompt
    test_prompt = """
    Analyze this penetration testing scenario:
    Target: http://testphp.vulnweb.com/
    Found: SQL injection vulnerability in search parameter
    Evidence: Error message "mysql_fetch_array() expects parameter 1 to be resource"
    
    Provide analysis in JSON format with:
    - success: true/false
    - message: summary
    - suggestions: list of recommendations
    - analysis: detailed technical analysis
    """
    
    try:
        print("📡 Sending request to Groq...")
        result = await analyzer.analyze_text_prompt(test_prompt)
        
        print(f"✅ Success: {result.success}")
        print(f"📋 Message: {result.message}")
        print(f"💡 Suggestions: {result.suggestions}")
        print(f"🔍 Analysis: {result.analysis[:200]}...")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_groq())
