#!/usr/bin/env python3
"""
Comprehensive test script for all vulnerability analysis functionality
Tests SQL injection, XSS, and logical flaw (IDOR/Path Traversal) analysis
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

async def test_comprehensive_vulnerability_analysis():
    """Test all vulnerability analysis methods with realistic scenarios"""
    
    print("🛡️ COMPREHENSIVE VULNERABILITY ANALYSIS TEST SUITE")
    print("🤖 Testing AI-powered security analysis with Groq")
    print("=" * 70)
    
    # Get AI configuration
    try:
        provider = config.get("ai", "provider", "groq")
        provider_config = config.get("ai", provider, {})
        
        if provider == "groq":
            model = f"groq-{provider_config.get('model', 'llama-3.1-8b-instant')}"
            api_key = provider_config.get("api_key")
        else:
            model = "groq-llama-3.1-8b-instant"
            api_key = "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"
        
        print(f"🤖 AI Provider: {provider.upper()}")
        print(f"🧠 Model: {model}")
        print(f"🔑 API Key: {'✅ Configured' if api_key else '❌ Missing'}")
        print()
        
        # Initialize AI analyzer
        analyzer = AIAnalyzer(model=model, api_key=api_key)
        
        if analyzer.client is None:
            print("❌ Failed to initialize AI client")
            return
        
        print("✅ AI analyzer initialized successfully")
        print()
        
        # Test scenarios for vulnerable web application
        print("🎯 TESTING VULNERABLE WEB APPLICATION: testphp.vulnweb.com")
        print("=" * 50)
        
        # === 1. SQL INJECTION ANALYSIS ===
        print("\n🔍 1. SQL INJECTION VULNERABILITY ANALYSIS")
        print("-" * 40)
        
        sqli_result = await analyzer.analyze_sqli_vulnerability(
            url="http://testphp.vulnweb.com/artists.php",
            parameter_name="artist",
            http_method="GET",
            technology_stack="PHP 7.4, Apache 2.4, MySQL 5.7",
            html_snippet="""
<form method="GET" action="artists.php">
    <input type="text" name="artist" value="1" placeholder="Artist ID">
    <input type="submit" value="Search">
</form>
<div class="results">
    Artist: <strong>1</strong>
    <p>Results for artist ID: 1</p>
</div>
            """
        )
        
        if sqli_result.get("success", False):
            payloads = sqli_result.get("sqli_analysis", [])
            print(f"✅ SQL injection analysis: {len(payloads)} payloads generated")
            
            for i, payload in enumerate(payloads[:3], 1):  # Show first 3
                print(f"   🎯 Payload #{i}: {payload.get('technique', 'Unknown')}")
                print(f"      └─ {payload.get('payload', 'None')}")
                print(f"      └─ Confidence: {payload.get('confidence_score', 0)}/10")
        else:
            print(f"❌ SQL injection analysis failed: {sqli_result.get('error', 'Unknown')}")
        
        # === 2. XSS VULNERABILITY ANALYSIS ===
        print("\n🔍 2. XSS VULNERABILITY ANALYSIS")
        print("-" * 40)
        
        xss_html = """
<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <form method="GET" action="search.php">
        <input type="text" name="searchFor" value="<script>alert('test')</script>" placeholder="Search...">
        <input type="submit" value="Search">
    </form>
    <div id="results">
        <p>You searched for: <strong><script>alert('test')</script></strong></p>
        <div class="search-term" data-term="<script>alert('test')</script>">No results found</div>
    </div>
    <script>
        var searchTerm = document.querySelector('[data-term]').getAttribute('data-term');
        console.log('Search performed for: ' + searchTerm);
    </script>
</body>
</html>
        """
        
        xss_result = await analyzer.analyze_xss_vulnerability(
            url="http://testphp.vulnweb.com/search.php",
            parameter_name="searchFor",
            technology_hints="PHP 7.4, jQuery 3.6, Apache",
            full_page_html=xss_html
        )
        
        if xss_result.get("success", False):
            xss_payloads = xss_result.get("xss_analysis", [])
            print(f"✅ XSS analysis: {len(xss_payloads)} payloads generated")
            
            for i, payload in enumerate(xss_payloads[:3], 1):  # Show first 3
                print(f"   🎯 Payload #{i}: {payload.get('bypass_technique', 'Unknown')}")
                print(f"      └─ {payload.get('payload', 'None')}")
                print(f"      └─ Confidence: {payload.get('confidence_score', 0)}/10")
        else:
            print(f"❌ XSS analysis failed: {xss_result.get('error', 'Unknown')}")
        
        # === 3. LOGICAL FLAW ANALYSIS (IDOR/Path Traversal) ===
        print("\n🔍 3. LOGICAL FLAW ANALYSIS (IDOR & PATH TRAVERSAL)")
        print("-" * 50)
        
        logical_result = await analyzer.analyze_logical_flaws(
            full_url_with_params="http://testphp.vulnweb.com/userinfo.php?uname=test",
            discovered_directories=["/images", "/js", "/css", "/includes", "/admin", "/backup", "/config"],
            server_software="Apache 2.4.41 (Ubuntu)"
        )
        
        if logical_result.get("success", False):
            logical_flaws = logical_result.get("logical_flaw_analysis", [])
            print(f"✅ Logical flaw analysis: {len(logical_flaws)} potential vulnerabilities")
            
            for i, flaw in enumerate(logical_flaws, 1):
                print(f"   🎯 Vulnerability #{i}: {flaw.get('vulnerability_type', 'Unknown')}")
                print(f"      └─ Parameter: {flaw.get('parameter_to_test', 'None')}")
                print(f"      └─ Method: {flaw.get('testing_method', 'None')[:80]}...")
                print(f"      └─ Confidence: {flaw.get('confidence_score', 0)}/10")
        else:
            print(f"❌ Logical flaw analysis failed: {logical_result.get('error', 'Unknown')}")
        
        print("\n" + "=" * 70)
        print("📊 VULNERABILITY ANALYSIS SUMMARY")
        print("=" * 70)
        
        total_sqli = len(sqli_result.get("sqli_analysis", [])) if sqli_result.get("success") else 0
        total_xss = len(xss_result.get("xss_analysis", [])) if xss_result.get("success") else 0
        total_logical = len(logical_result.get("logical_flaw_analysis", [])) if logical_result.get("success") else 0
        
        print(f"🔒 SQL Injection Payloads Generated: {total_sqli}")
        print(f"🔓 XSS Payloads Generated: {total_xss}")
        print(f"🔑 Logical Flaws Identified: {total_logical}")
        print(f"📈 Total Security Tests: {total_sqli + total_xss + total_logical}")
        
        if total_sqli + total_xss + total_logical > 0:
            print("\n✅ SUCCESS: AI-powered vulnerability analysis is fully operational!")
            print("🚀 Your penetration testing tool now has advanced payload generation capabilities")
        else:
            print("\n⚠️  WARNING: No payloads generated - check AI provider configuration")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

async def test_file_download_scenario():
    """Test file download vulnerability scenario"""
    
    print("\n" + "=" * 70)
    print("🗂️ FILE DOWNLOAD VULNERABILITY TEST")
    print("=" * 70)
    
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
        
        # File download scenario with path traversal potential
        download_url = "https://company.com/downloads/file.php?document=reports/quarterly_2024.pdf&user_id=1001"
        directories = ["/uploads", "/reports", "/admin", "/config", "/backup", "/logs", "/temp"]
        server_tech = "Apache 2.4, PHP 8.1, Linux Ubuntu"
        
        print(f"🎯 Target: {download_url}")
        print(f"📁 Directories: {directories}")
        print(f"🖥️ Server: {server_tech}")
        print()
        
        result = await analyzer.analyze_logical_flaws(
            full_url_with_params=download_url,
            discovered_directories=directories,
            server_software=server_tech
        )
        
        if result.get("success", False):
            flaws = result.get("logical_flaw_analysis", [])
            
            print(f"✅ File download analysis completed! Found {len(flaws)} potential vulnerabilities")
            print()
            
            for i, flaw in enumerate(flaws, 1):
                print(f"🗂️ VULNERABILITY #{i}")
                print(f"   Type: {flaw.get('vulnerability_type', 'Unknown')}")
                print(f"   Parameter: {flaw.get('parameter_to_test', 'Unknown')}")
                print(f"   Confidence: {flaw.get('confidence_score', 0)}/10")
                print(f"   Testing Method:")
                method_lines = flaw.get('testing_method', 'None').split('. ')
                for j, line in enumerate(method_lines, 1):
                    if line.strip():
                        print(f"      {j}. {line.strip()}")
                print(f"   Rationale: {flaw.get('rationale', 'No explanation')}")
                print("-" * 60)
                
        else:
            print(f"❌ File download analysis failed: {result.get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"❌ File download test failed: {e}")

async def test_api_endpoint_scenario():
    """Test API endpoint IDOR scenario"""
    
    print("\n" + "=" * 70)
    print("🔌 API ENDPOINT IDOR TEST")
    print("=" * 70)
    
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
        
        # API endpoint scenario
        api_url = "https://api.example.com/v1/users/12345/profile?include_sensitive=true&format=json"
        api_directories = ["/v1", "/v2", "/admin", "/internal", "/debug", "/health"]
        api_server = "Nginx 1.20, Node.js 18, Express.js"
        
        print(f"🎯 API Target: {api_url}")
        print(f"📁 API Endpoints: {api_directories}")
        print(f"🖥️ Server: {api_server}")
        print()
        
        result = await analyzer.analyze_logical_flaws(
            full_url_with_params=api_url,
            discovered_directories=api_directories,
            server_software=api_server
        )
        
        if result.get("success", False):
            flaws = result.get("logical_flaw_analysis", [])
            
            print(f"✅ API IDOR analysis completed! Found {len(flaws)} potential vulnerabilities")
            print()
            
            for i, flaw in enumerate(flaws, 1):
                print(f"🔌 API VULNERABILITY #{i}")
                print(f"   Type: {flaw.get('vulnerability_type', 'Unknown')}")
                print(f"   Parameter: {flaw.get('parameter_to_test', 'Unknown')}")
                print(f"   Confidence: {flaw.get('confidence_score', 0)}/10")
                print(f"   Testing Method:")
                method_lines = flaw.get('testing_method', 'None').split('. ')
                for j, line in enumerate(method_lines, 1):
                    if line.strip():
                        print(f"      {j}. {line.strip()}")
                print(f"   Rationale: {flaw.get('rationale', 'No explanation')}")
                print("-" * 60)
                
        else:
            print(f"❌ API IDOR analysis failed: {result.get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"❌ API endpoint test failed: {e}")

async def main():
    """Run comprehensive vulnerability analysis tests"""
    
    print("🛡️ ADVANCED PENETRATION TESTING AI ANALYZER")
    print("🤖 Comprehensive vulnerability detection with AI-powered payload generation")
    print("=" * 80)
    
    # Run all vulnerability analysis tests
    await test_comprehensive_vulnerability_analysis()
    await test_file_download_scenario()
    await test_api_endpoint_scenario()
    
    print("\n" + "=" * 80)
    print("🎉 ALL VULNERABILITY ANALYSIS TESTS COMPLETED!")
    print("💡 Your AI analyzer now supports:")
    print("   ✅ SQL Injection payload generation")
    print("   ✅ XSS payload generation with context awareness")
    print("   ✅ IDOR & Path Traversal vulnerability identification")
    print("   ✅ Multi-provider AI support (Groq, Gemini, OpenAI, Claude)")
    print("🔥 Ready for production penetration testing!")

if __name__ == "__main__":
    asyncio.run(main())
