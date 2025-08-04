#!/usr/bin/env python3
"""
Example integration of SQL injection analysis into penetration testing workflow
"""

import asyncio
import json
from typing import Dict, List, Any

async def integrate_sqli_analysis_example():
    """
    Example showing how to integrate SQL injection analysis into your crawler
    """
    
    print("🔍 SQL INJECTION INTEGRATION EXAMPLE")
    print("=" * 50)
    
    # This would be integrated into your AdvancedIntelligentCrawler
    # Example of how to use it when a form is discovered
    
    discovered_forms = [
        {
            "url": "http://testphp.vulnweb.com/search.php",
            "method": "GET",
            "inputs": [
                {"name": "query", "type": "text", "placeholder": "Search..."}
            ],
            "html": '''<form method="GET" action="search.php">
                <input type="text" name="query" placeholder="Search..." value="">
                <input type="submit" value="Search">
            </form>''',
            "technology_stack": "PHP, Apache, MySQL"
        },
        {
            "url": "http://example.com/admin/users.php",
            "method": "POST", 
            "inputs": [
                {"name": "user_id", "type": "hidden", "value": "123"},
                {"name": "action", "type": "hidden", "value": "delete"}
            ],
            "html": '''<form method="POST" action="admin/users.php">
                <input type="hidden" name="user_id" value="123">
                <input type="hidden" name="action" value="delete">
                <input type="submit" value="Delete User">
            </form>''',
            "technology_stack": "PHP, Nginx, MySQL, Custom CMS"
        }
    ]
    
    # Simulate AI analyzer initialization (this would come from your main system)
    from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer
    from intelligent_terminal_ai.utils.config import config
    
    # Get configured AI provider
    provider = config.get("ai", "provider", "groq")
    provider_config = config.get("ai", provider, {})
    
    if provider == "groq":
        model = f"groq-{provider_config.get('model', 'llama-3.1-8b-instant')}"
        api_key = provider_config.get("api_key")
    else:
        print(f"⚠️  Using fallback - provider {provider} not configured for this example")
        return
    
    if not api_key:
        print("❌ No API key configured for Groq")
        return
    
    analyzer = AIAnalyzer(model=model, api_key=api_key)
    
    # Analyze each discovered form for SQL injection vulnerabilities
    for i, form in enumerate(discovered_forms, 1):
        print(f"\n🎯 Analyzing Form #{i}: {form['url']}")
        print("-" * 40)
        
        # Test each input parameter for SQL injection
        for input_field in form['inputs']:
            param_name = input_field['name']
            
            print(f"🔍 Testing parameter: {param_name}")
            
            try:
                # Use the new SQL injection analysis method
                sqli_result = await analyzer.analyze_sqli_vulnerability(
                    url=form['url'],
                    parameter_name=param_name,
                    http_method=form['method'],
                    technology_stack=form['technology_stack'],
                    html_snippet=form['html']
                )
                
                if sqli_result.get("success", False):
                    payloads = sqli_result.get("sqli_analysis", [])
                    
                    if payloads:
                        print(f"  ✅ Generated {len(payloads)} SQL injection payloads")
                        
                        # Show top 3 highest confidence payloads
                        sorted_payloads = sorted(payloads, key=lambda x: x.get('confidence_score', 0), reverse=True)
                        
                        print("  🎯 Top SQL injection payloads:")
                        for j, payload in enumerate(sorted_payloads[:3], 1):
                            print(f"    {j}. [{payload.get('confidence_score', 0)}/10] {payload.get('technique', 'Unknown')}")
                            print(f"       Payload: {payload.get('payload', 'N/A')}")
                            print(f"       Rationale: {payload.get('rationale', 'No explanation')[:100]}...")
                        
                        # Here you would integrate with your testing engine
                        print(f"  🚀 Ready to test {len(payloads)} payloads against {param_name}")
                        
                        # Example of how you might structure the testing
                        test_queue = []
                        for payload in payloads:
                            test_queue.append({
                                "url": form['url'],
                                "method": form['method'],
                                "parameter": param_name,
                                "payload": payload['payload'],
                                "technique": payload['technique'],
                                "confidence": payload['confidence_score'],
                                "expected_outcome": payload['rationale']
                            })
                        
                        print(f"  📋 Added {len(test_queue)} tests to queue")
                        
                    else:
                        print("  ⚠️  No payloads generated")
                else:
                    print(f"  ❌ Analysis failed: {sqli_result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                print(f"  ❌ Error analyzing {param_name}: {e}")
    
    print("\n✅ SQL Injection Analysis Integration Example Complete!")
    
    # Example output structure for integration
    integration_example = {
        "vulnerability_type": "sql_injection",
        "analysis_method": "ai_powered",
        "provider": analyzer.provider,
        "payloads_generated": "dynamic",
        "integration_points": [
            "Form Discovery Phase",
            "Parameter Enumeration", 
            "Payload Generation",
            "Automated Testing",
            "Results Analysis"
        ],
        "usage_pattern": """
        # In your AdvancedIntelligentCrawler:
        
        async def analyze_discovered_form(self, form_data):
            for input_field in form_data['inputs']:
                sqli_analysis = await self.ai_analyzer.analyze_sqli_vulnerability(
                    url=form_data['url'],
                    parameter_name=input_field['name'],
                    http_method=form_data['method'], 
                    technology_stack=self.detected_technologies,
                    html_snippet=form_data['html']
                )
                
                if sqli_analysis.get('success'):
                    payloads = sqli_analysis['sqli_analysis']
                    await self.test_sql_injection_payloads(payloads, form_data, input_field)
        """
    }
    
    print(f"\n📋 Integration Pattern:")
    print(json.dumps(integration_example, indent=2))

if __name__ == "__main__":
    asyncio.run(integrate_sqli_analysis_example())
