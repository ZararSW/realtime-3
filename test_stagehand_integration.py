#!/usr/bin/env python3
"""
Test Stagehand Integration with Advanced Intelligent Crawler
Comprehensive test suite for AI-powered browser automation
"""

import asyncio
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from stagehand_integration import StagehandWebCrawler, create_stagehand_crawler
    from ai_policy import AIPolicy
    DEPENDENCIES_AVAILABLE = True
except ImportError as e:
    print(f"❌ Dependencies not available: {e}")
    DEPENDENCIES_AVAILABLE = False

async def test_stagehand_basic():
    """Test basic Stagehand functionality"""
    print("🧪 Testing Stagehand Basic Functionality")
    print("=" * 50)
    
    if not DEPENDENCIES_AVAILABLE:
        print("❌ Stagehand dependencies not available")
        return False
    
    try:
        # Create AI policy for testing
        ai_policy = AIPolicy(enable_ai=False)  # Test no-AI mode first
        
        # Create Stagehand crawler
        crawler = await create_stagehand_crawler(
            ai_policy=ai_policy,
            headless=True,
            screenshots_dir="test_screenshots"
        )
        
        print("✅ Stagehand crawler created successfully")
        
        # Test navigation
        test_url = "https://httpbin.org/forms/post"
        nav_result = await crawler.navigate_to(test_url)
        
        if nav_result.success:
            print(f"✅ Navigation successful: {nav_result.title}")
            print(f"📊 Found: {nav_result.forms_found} forms, {nav_result.links_found} links")
        else:
            print(f"❌ Navigation failed: {nav_result.errors}")
            return False
        
        # Test form discovery
        forms = await crawler.intelligent_form_discovery()
        print(f"✅ Form discovery: {len(forms)} forms found")
        
        for form in forms:
            form_id = form.get('id', 'unknown')
            fields = form.get('fields', [])
            print(f"  📝 Form {form_id}: {len(fields)} fields")
        
        # Test form interaction (if forms found)
        if forms:
            test_result = await crawler.intelligent_form_testing(forms[0])
            if test_result.success:
                print(f"✅ Form testing: {len(test_result.fields_filled)} fields tested")
                if test_result.vulnerability_indicators:
                    print(f"🚨 Vulnerabilities: {len(test_result.vulnerability_indicators)} found")
            else:
                print(f"❌ Form testing failed: {test_result.errors}")
        
        # Get summary
        summary = crawler.get_navigation_summary()
        print(f"📊 Summary: {summary}")
        
        # Cleanup
        await crawler.close()
        print("✅ Stagehand basic test completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Stagehand basic test failed: {e}")
        return False

async def test_stagehand_with_ai():
    """Test Stagehand with AI enabled"""
    print("\n🤖 Testing Stagehand with AI")
    print("=" * 50)
    
    if not DEPENDENCIES_AVAILABLE:
        print("❌ Stagehand dependencies not available")
        return False
    
    # Check for AI API key
    api_key = os.getenv('GROQ_API_KEY') or os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("⚠️  No AI API key found - testing with AI disabled")
        ai_enabled = False
    else:
        print(f"✅ AI API key found - testing with AI enabled")
        ai_enabled = True
    
    try:
        # Create AI policy
        ai_policy = AIPolicy(enable_ai=ai_enabled)
        
        # Create Stagehand crawler with AI
        crawler = await create_stagehand_crawler(
            ai_policy=ai_policy,
            headless=True,
            screenshots_dir="test_screenshots_ai"
        )
        
        print("✅ AI-enabled Stagehand crawler created")
        
        # Test with a more complex site
        test_url = "https://demo.testfire.net/"
        nav_result = await crawler.navigate_to(test_url)
        
        if nav_result.success:
            print(f"✅ AI navigation successful: {nav_result.title}")
        else:
            print(f"❌ AI navigation failed: {nav_result.errors}")
            return False
        
        # Test AI form discovery
        forms = await crawler.intelligent_form_discovery()
        print(f"✅ AI form discovery: {len(forms)} forms found")
        
        # Test AI link discovery
        links = await crawler.intelligent_link_discovery()
        print(f"✅ AI link discovery: {len(links)} links found")
        
        # Test AI form interaction with security payloads
        if forms:
            for i, form in enumerate(forms[:2]):  # Test first 2 forms
                print(f"🔍 AI testing form {i+1}")
                test_result = await crawler.intelligent_form_testing(form)
                
                if test_result.success:
                    print(f"  ✅ AI form test: {len(test_result.fields_filled)} fields")
                    if test_result.vulnerability_indicators:
                        for vuln in test_result.vulnerability_indicators:
                            vuln_type = vuln.get('type', 'unknown')
                            confidence = vuln.get('confidence', 0.0)
                            print(f"  🚨 {vuln_type.upper()}: confidence {confidence:.2f}")
                else:
                    print(f"  ❌ AI form test failed: {test_result.errors}")
        
        # Get final summary
        summary = crawler.get_navigation_summary()
        print(f"📊 AI Summary: {summary}")
        
        # Cleanup
        await crawler.close()
        print("✅ Stagehand AI test completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Stagehand AI test failed: {e}")
        return False

async def test_payload_generation():
    """Test AI Policy payload generation"""
    print("\n🎯 Testing AI Policy Payload Generation")
    print("=" * 50)
    
    try:
        # Test rule-based payloads (no-AI mode)
        ai_policy = AIPolicy(enable_ai=False)
        
        # Test form metadata
        form_metadata = {
            'fields': [
                {'name': 'username', 'type': 'text'},
                {'name': 'password', 'type': 'password'},
                {'name': 'email', 'type': 'email'},
                {'name': 'search', 'type': 'search'},
                {'name': 'url', 'type': 'url'},
                {'name': 'comment', 'type': 'textarea'}
            ],
            'action': '/login',
            'method': 'POST'
        }
        
        payloads = ai_policy.get_payloads(form_metadata)
        print(f"✅ Generated {len(payloads)} rule-based payloads")
        
        # Test vulnerability analysis
        test_responses = [
            ("XSS", "<script>alert('XSS')</script>", "Test page with <script>alert('XSS')</script> executed"),
            ("SQLi", "' OR 1=1--", "MySQL Error: You have an error in your SQL syntax near"),
            ("SSRF", "http://169.254.169.254/", "ami-id: ami-12345678\ninstance-id: i-abcdef"),
        ]
        
        for attack_type, payload, response in test_responses:
            result = ai_policy.analyze_response(response, payload, attack_type)
            print(f"✅ {attack_type} detection: {result.detected} (confidence: {result.confidence:.2f})")
            if result.detected:
                print(f"  🎯 Heuristic: {result.heuristic_fired}")
                print(f"  📋 Evidence: {len(result.evidence)} indicators")
        
        print("✅ AI Policy payload generation test completed")
        return True
        
    except Exception as e:
        print(f"❌ AI Policy test failed: {e}")
        return False

async def test_integration_workflow():
    """Test complete integration workflow"""
    print("\n🔄 Testing Complete Integration Workflow")
    print("=" * 50)
    
    if not DEPENDENCIES_AVAILABLE:
        print("❌ Dependencies not available for integration test")
        return False
    
    try:
        from advanced_intelligent_crawler import AdvancedIntelligentCrawler
        
        # Create crawler with AI policy
        crawler = AdvancedIntelligentCrawler(ai_analyzer=None)  # No AI for testing
        
        # Test browser setup
        await crawler.setup_advanced_browser()
        print("✅ Browser setup completed")
        
        # Test with a simple target
        test_url = "https://httpbin.org/forms/post"
        
        # Simple navigation test
        crawler.driver.get(test_url)
        print(f"✅ Navigation to {test_url} completed")
        
        # Test form discovery
        forms = crawler.driver.find_elements("tag name", "form")
        print(f"✅ Found {len(forms)} forms using standard method")
        
        # If Stagehand is available, test enhanced discovery
        if crawler.use_stagehand and crawler.stagehand_crawler:
            print("🤖 Testing Stagehand enhanced discovery...")
            await crawler._stagehand_enhanced_discovery(test_url)
            print("✅ Stagehand enhanced discovery completed")
        else:
            print("⚠️  Stagehand not available, using standard methods")
        
        # Cleanup
        crawler.driver.quit()
        if crawler.stagehand_crawler:
            await crawler.stagehand_crawler.close()
        
        print("✅ Integration workflow test completed")
        return True
        
    except Exception as e:
        print(f"❌ Integration workflow test failed: {e}")
        return False

async def run_all_tests():
    """Run all Stagehand integration tests"""
    print("🚀 Starting Stagehand Integration Test Suite")
    print("=" * 70)
    
    results = []
    
    # Test 1: Basic Stagehand functionality
    results.append(await test_stagehand_basic())
    
    # Test 2: Stagehand with AI
    results.append(await test_stagehand_with_ai())
    
    # Test 3: Payload generation
    results.append(await test_payload_generation())
    
    # Test 4: Integration workflow
    results.append(await test_integration_workflow())
    
    # Summary
    print("\n" + "=" * 70)
    print("🎯 TEST RESULTS SUMMARY")
    print("=" * 70)
    
    test_names = [
        "Stagehand Basic Functionality",
        "Stagehand with AI",
        "AI Policy Payload Generation", 
        "Integration Workflow"
    ]
    
    passed = sum(results)
    total = len(results)
    
    for i, (name, result) in enumerate(zip(test_names, results)):
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{i+1}. {name}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 All tests passed! Stagehand integration is ready.")
        return True
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--quick":
        # Quick test - just payload generation
        asyncio.run(test_payload_generation())
    else:
        # Full test suite
        success = asyncio.run(run_all_tests())
        sys.exit(0 if success else 1)
