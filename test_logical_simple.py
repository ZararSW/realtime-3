#!/usr/bin/env python3
"""
Simple test for logical flaw analysis functionality
"""

import asyncio
import json
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer

async def test_logical_flaw_simple():
    """Simple test of logical flaw analysis"""
    
    print("🔍 TESTING LOGICAL FLAW ANALYSIS")
    print("=" * 40)
    
    # Use Groq with your API key
    analyzer = AIAnalyzer(
        model="groq-llama-3.1-8b-instant", 
        api_key="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"
    )
    
    if analyzer.client is None:
        print("❌ Failed to initialize AI client")
        return
    
    print("✅ AI analyzer initialized")
    
    # Test IDOR scenario
    test_url = "https://example.com/profile.php?user_id=1234&view=private"
    test_dirs = ["/admin", "/uploads", "/config", "/backup"]
    test_server = "Apache 2.4, PHP 8.1"
    
    print(f"🎯 Testing URL: {test_url}")
    print(f"📁 Directories: {test_dirs}")
    print()
    
    try:
        result = await analyzer.analyze_logical_flaws(
            full_url_with_params=test_url,
            discovered_directories=test_dirs,
            server_software=test_server
        )
        
        print("📊 ANALYSIS RESULT:")
        if result.get("success", False):
            flaws = result.get("logical_flaw_analysis", [])
            print(f"✅ Success! Found {len(flaws)} potential vulnerabilities")
            
            for i, flaw in enumerate(flaws, 1):
                print(f"\n🎯 VULNERABILITY #{i}")
                print(f"   Type: {flaw.get('vulnerability_type', 'Unknown')}")
                print(f"   Parameter: {flaw.get('parameter_to_test', 'Unknown')}")
                print(f"   Confidence: {flaw.get('confidence_score', 0)}/10")
                print(f"   Method: {flaw.get('testing_method', 'None')[:100]}...")
                print(f"   Rationale: {flaw.get('rationale', 'None')[:100]}...")
        else:
            print(f"❌ Analysis failed: {result.get('error', 'Unknown error')}")
            if result.get("raw_response"):
                print(f"Raw response: {result['raw_response'][:200]}...")
                
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_logical_flaw_simple())
