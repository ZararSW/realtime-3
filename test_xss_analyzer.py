#!/usr/bin/env python3
"""
Test script for XSS vulnerability analysis functionality
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

async def test_xss_analysis():
    """Test XSS vulnerability analysis with realistic scenario"""
    
    print("🔍 XSS VULNERABILITY ANALYSIS TEST")
    print("=" * 50)
    
    # Get AI configuration
    try:
        provider = config.get("ai", "provider", "groq")
        provider_config = config.get("ai", provider, {})
        
        if provider == "groq":
            model = f"groq-{provider_config.get('model', 'llama-3.1-8b-instant')}"
            api_key = provider_config.get("api_key")
        elif provider == "gemini":
            model = f"gemini-{provider_config.get('model', 'gemini-2.0-flash-exp')}"
            api_key = provider_config.get("api_key") or os.getenv("GOOGLE_API_KEY")
        else:
            model = "groq-llama-3.1-8b-instant"
            api_key = provider_config.get("api_key", "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")
        
        print(f"🤖 AI Provider: {provider}")
        print(f"🧠 Model: {model}")
        
        # Initialize AI analyzer
        analyzer = AIAnalyzer(model=model, api_key=api_key)
        
        if analyzer.client is None:
            print("❌ Failed to initialize AI client")
            return
        
        print("✅ AI analyzer initialized successfully")
        print()
        
        # Test scenario: Search form with reflected XSS
        test_url = "http://testphp.vulnweb.com/search.php"
        test_parameter = "searchFor"
        test_technology = "PHP 7.4, Apache, MySQL"
        test_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Search Results</title>
    <meta charset="UTF-8">
</head>
<body>
    <div id="header">
        <h1>Search Results</h1>
    </div>
    <div id="content">
        <form method="GET" action="search.php">
            <input type="text" name="searchFor" value="<script>alert('xss')</script>" placeholder="Search...">
            <input type="submit" value="Search">
        </form>
        <div id="results">
            <p>You searched for: <strong><script>alert('xss')</script></strong></p>
            <p>No results found for your search term.</p>
        </div>
    </div>
    <script>
        // Some JavaScript functionality
        function validateSearch() {
            var query = document.getElementsByName('searchFor')[0].value;
            if (query.length < 3) {
                alert('Search term must be at least 3 characters');
                return false;
            }
            return true;
        }
    </script>
</body>
</html>
        """
        
        print(f"🎯 Target: {test_url}")
        print(f"📋 Parameter: {test_parameter}")
        print(f"💻 Technology: {test_technology}")
        print(f"📄 HTML Context: Reflected in input value and search results")
        print()
        
        print("🔬 Analyzing XSS vulnerability...")
        
        # Perform XSS analysis
        result = await analyzer.analyze_xss_vulnerability(
            url=test_url,
            parameter_name=test_parameter,
            technology_hints=test_technology,
            full_page_html=test_html
        )
        
        if result.get("success", False):
            xss_analysis = result.get("xss_analysis", [])
            
            print(f"✅ Analysis completed! Found {len(xss_analysis)} XSS payloads")
            print()
            
            for i, payload in enumerate(xss_analysis, 1):
                print(f"🎯 PAYLOAD #{i}")
                print(f"   Type: {payload.get('payload_type', 'Unknown')}")
                print(f"   Technique: {payload.get('bypass_technique', 'Unknown')}")
                print(f"   Confidence: {payload.get('confidence_score', 0)}/10")
                print(f"   Payload: {payload.get('payload', 'None')}")
                print(f"   Rationale: {payload.get('rationale', 'No explanation')}")
                print("-" * 60)
            
            # Show raw AI response for debugging
            if result.get("raw_response"):
                print("\n🔍 RAW AI RESPONSE:")
                print("=" * 30)
                print(result["raw_response"][:500] + "..." if len(result["raw_response"]) > 500 else result["raw_response"])
                
        else:
            print(f"❌ Analysis failed: {result.get('error', 'Unknown error')}")
            if result.get("raw_response"):
                print(f"Raw response: {result['raw_response'][:200]}...")
                
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

async def test_dom_xss_scenario():
    """Test DOM-based XSS scenario"""
    
    print("\n" + "=" * 50)
    print("🔍 DOM-BASED XSS ANALYSIS TEST")
    print("=" * 50)
    
    try:
        # Get AI configuration
        provider = config.get("ai", "provider", "groq")
        provider_config = config.get("ai", provider, {})
        
        if provider == "groq":
            model = f"groq-{provider_config.get('model', 'llama-3.1-8b-instant')}"
            api_key = provider_config.get("api_key")
        else:
            model = "groq-llama-3.1-8b-instant"
            api_key = "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"
        
        analyzer = AIAnalyzer(model=model, api_key=api_key)
        
        # DOM XSS scenario with jQuery
        dom_url = "http://example.com/dashboard.php"
        dom_parameter = "username"
        dom_technology = "jQuery 3.6, Bootstrap 4, PHP"
        dom_html = """
<!DOCTYPE html>
<html>
<head>
    <title>User Dashboard</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <div class="container">
        <h1>Welcome Dashboard</h1>
        <div id="welcome-message"></div>
        <input type="hidden" id="username" value="admin&lt;img src=x onerror=alert(1)&gt;">
    </div>
    
    <script>
        $(document).ready(function() {
            var username = $('#username').val();
            $('#welcome-message').html('Welcome back, ' + username + '!');
            
            // Potentially vulnerable: direct HTML insertion
            var urlParams = new URLSearchParams(window.location.search);
            var message = urlParams.get('message');
            if (message) {
                $('.container').append('<div class="alert">' + message + '</div>');
            }
        });
    </script>
</body>
</html>
        """
        
        print(f"🎯 Target: {dom_url}")
        print(f"📋 Parameter: {dom_parameter}")
        print(f"💻 Technology: {dom_technology}")
        print(f"📄 Context: DOM manipulation with jQuery")
        print()
        
        result = await analyzer.analyze_xss_vulnerability(
            url=dom_url,
            parameter_name=dom_parameter,
            technology_hints=dom_technology,
            full_page_html=dom_html
        )
        
        if result.get("success", False):
            xss_analysis = result.get("xss_analysis", [])
            
            print(f"✅ DOM XSS analysis completed! Found {len(xss_analysis)} payloads")
            print()
            
            for i, payload in enumerate(xss_analysis, 1):
                print(f"🎯 DOM PAYLOAD #{i}")
                print(f"   Type: {payload.get('payload_type', 'Unknown')}")
                print(f"   Technique: {payload.get('bypass_technique', 'Unknown')}")
                print(f"   Confidence: {payload.get('confidence_score', 0)}/10")
                print(f"   Payload: {payload.get('payload', 'None')}")
                print(f"   Rationale: {payload.get('rationale', 'No explanation')}")
                print("-" * 60)
                
        else:
            print(f"❌ DOM XSS analysis failed: {result.get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"❌ DOM XSS test failed: {e}")

async def test_attribute_xss_scenario():
    """Test attribute-based XSS scenario"""
    
    print("\n" + "=" * 50)
    print("🔍 ATTRIBUTE-BASED XSS ANALYSIS TEST")
    print("=" * 50)
    
    try:
        provider = config.get("ai", "provider", "groq")
        provider_config = config.get("ai", provider, {})
        
        if provider == "groq":
            model = f"groq-{provider_config.get('model', 'llama-3.1-8b-instant')}"
            api_key = provider_config.get("api_key")
        else:
            model = "groq-llama-3.1-8b-instant"
            api_key = "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"
        
        analyzer = AIAnalyzer(model=model, api_key=api_key)
        
        # Attribute XSS scenario
        attr_url = "http://vulnerable-site.com/profile.php"
        attr_parameter = "name"
        attr_technology = "React 18, Node.js, Express"
        attr_html = """
<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
</head>
<body>
    <div class="profile">
        <img src="avatar.png" alt="Profile picture of javascript:alert(document.domain)" class="avatar">
        <h2>Profile: javascript:alert(document.domain)</h2>
        <a href="mailto:user@javascript:alert(document.domain).com">Contact</a>
        <input type="text" value="javascript:alert(document.domain)" onmouseover="showTooltip(this.value)">
        <div onclick="updateProfile('javascript:alert(document.domain)')">Update Profile</div>
    </div>
    
    <script>
        function showTooltip(text) {
            // Potentially vulnerable function
            document.getElementById('tooltip').innerHTML = text;
        }
        
        function updateProfile(name) {
            console.log('Updating profile for: ' + name);
        }
    </script>
    
    <div id="tooltip" style="display:none;"></div>
</body>
</html>
        """
        
        print(f"🎯 Target: {attr_url}")
        print(f"📋 Parameter: {attr_parameter}")
        print(f"💻 Technology: {attr_technology}")
        print(f"📄 Context: Multiple attribute contexts (alt, href, value, onclick)")
        print()
        
        result = await analyzer.analyze_xss_vulnerability(
            url=attr_url,
            parameter_name=attr_parameter,
            technology_hints=attr_technology,
            full_page_html=attr_html
        )
        
        if result.get("success", False):
            xss_analysis = result.get("xss_analysis", [])
            
            print(f"✅ Attribute XSS analysis completed! Found {len(xss_analysis)} payloads")
            print()
            
            for i, payload in enumerate(xss_analysis, 1):
                print(f"🎯 ATTRIBUTE PAYLOAD #{i}")
                print(f"   Type: {payload.get('payload_type', 'Unknown')}")
                print(f"   Technique: {payload.get('bypass_technique', 'Unknown')}")
                print(f"   Confidence: {payload.get('confidence_score', 0)}/10")
                print(f"   Payload: {payload.get('payload', 'None')}")
                print(f"   Rationale: {payload.get('rationale', 'No explanation')}")
                print("-" * 60)
                
        else:
            print(f"❌ Attribute XSS analysis failed: {result.get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"❌ Attribute XSS test failed: {e}")

async def main():
    """Run all XSS analysis tests"""
    
    print("🛡️ XSS VULNERABILITY ANALYZER - COMPREHENSIVE TEST SUITE")
    print("🤖 Testing advanced AI-powered XSS payload generation")
    print("=" * 70)
    
    # Test different XSS scenarios
    await test_xss_analysis()
    await test_dom_xss_scenario()
    await test_attribute_xss_scenario()
    
    print("\n" + "=" * 70)
    print("✅ All XSS analysis tests completed!")
    print("💡 The AI analyzer can now generate targeted XSS payloads based on HTML context")
    print("🔥 Use this in your penetration testing workflow for advanced XSS detection")

if __name__ == "__main__":
    asyncio.run(main())
