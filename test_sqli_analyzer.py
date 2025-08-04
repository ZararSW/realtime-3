#!/usr/bin/env python3
"""
Test script for SQL injection analysis using the AI provider system
"""

import asyncio
import json
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer
from intelligent_terminal_ai.utils.config import config

async def test_sqli_analysis():
    """Test the SQL injection analysis functionality"""
    
    print("🛡️ SQL INJECTION ANALYSIS TEST")
    print("=" * 50)
    
    # Get AI configuration
    provider = config.get("ai", "provider", "groq")
    provider_config = config.get("ai", provider, {})
    
    print(f"🤖 Using AI Provider: {provider.upper()}")
    
    # Initialize AI analyzer
    if provider == "groq":
        model = f"groq-{provider_config.get('model', 'llama-3.1-8b-instant')}"
        api_key = provider_config.get("api_key") or os.getenv("GROQ_API_KEY")
    elif provider == "gemini":
        model = f"gemini-{provider_config.get('model', 'gemini-2.0-flash-exp')}"
        api_key = provider_config.get("api_key") or os.getenv("GOOGLE_API_KEY")
    elif provider == "openai":
        model = provider_config.get("model", "gpt-4")
        api_key = provider_config.get("api_key") or os.getenv("OPENAI_API_KEY")
    elif provider == "anthropic":
        model = provider_config.get("model", "claude-3-sonnet-20240229")
        api_key = provider_config.get("api_key") or os.getenv("ANTHROPIC_API_KEY")
    
    if not api_key:
        print("❌ No API key configured!")
        return
    
    print(f"🧠 Model: {model}")
    
    # Initialize analyzer
    analyzer = AIAnalyzer(model=model, api_key=api_key)
    
    if analyzer.client is None:
        print("❌ Failed to initialize AI client")
        return
    
    print("✅ AI client initialized successfully")
    
    # Test data - simulating a vulnerable search form
    test_cases = [
        {
            "name": "Search Form SQL Injection",
            "url": "http://testphp.vulnweb.com/search.php",
            "parameter_name": "query",
            "http_method": "GET",
            "technology_stack": "PHP, Apache, MySQL",
            "html_snippet": '''<form method="GET" action="search.php">
    <input type="text" name="query" placeholder="Search products..." value="">
    <input type="submit" value="Search">
</form>'''
        },
        {
            "name": "Login Form SQL Injection",
            "url": "http://example.com/login.php",
            "parameter_name": "username",
            "http_method": "POST",
            "technology_stack": "PHP, Nginx, MySQL, WordPress",
            "html_snippet": '''<form method="POST" action="login.php">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <input type="submit" value="Login">
</form>'''
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🎯 Test Case {i}: {test_case['name']}")
        print("-" * 40)
        
        try:
            # Run SQL injection analysis
            result = await analyzer.analyze_sqli_vulnerability(
                url=test_case["url"],
                parameter_name=test_case["parameter_name"],
                http_method=test_case["http_method"],
                technology_stack=test_case["technology_stack"],
                html_snippet=test_case["html_snippet"]
            )
            
            if result.get("success", False):
                sqli_analysis = result.get("sqli_analysis", [])
                
                print(f"✅ Analysis completed: {len(sqli_analysis)} payloads generated")
                print(f"🤖 Provider: {result.get('provider', 'Unknown')}")
                
                # Display payloads
                for j, payload_obj in enumerate(sqli_analysis, 1):
                    print(f"\n  📋 Payload {j}:")
                    print(f"    🔧 Technique: {payload_obj.get('technique', 'Unknown')}")
                    print(f"    💾 Payload: {payload_obj.get('payload', 'N/A')}")
                    print(f"    📊 Confidence: {payload_obj.get('confidence_score', 0)}/10")
                    print(f"    💡 Rationale: {payload_obj.get('rationale', 'No rationale provided')}")
                
                # Save results to file
                output_file = f"sqli_analysis_test_{i}.json"
                with open(output_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"\n💾 Results saved to: {output_file}")
                
            else:
                print(f"❌ Analysis failed: {result.get('error', 'Unknown error')}")
                if result.get("raw_response"):
                    print(f"📝 Raw response: {result['raw_response'][:200]}...")
                
        except Exception as e:
            print(f"❌ Test case failed: {e}")
    
    print(f"\n🎯 SQL Injection Analysis Test Complete!")

if __name__ == "__main__":
    import os
    asyncio.run(test_sqli_analysis())
