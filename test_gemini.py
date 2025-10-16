#!/usr/bin/env python3
"""
Test Google Gemini integration
"""

import asyncio
import sys
from pathlib import Path

# Add current directory to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer
from intelligent_terminal_ai.models.command_result import CommandResult
from intelligent_terminal_ai.utils.logger import setup_logger


async def test_gemini():
    """Test Gemini AI integration"""
    
    print("🤖 Testing Google Gemini Integration")
    print("=" * 50)
    
    # Setup
    logger = setup_logger("gemini_test", "INFO")
    
    try:
        # Initialize with Gemini
        analyzer = AIAnalyzer(model="gemini-pro", api_key=os.getenv("GOOGLE_API_KEY", "test_key_placeholder"))
        print("✅ Gemini analyzer initialized")
        
        # Create a test command result
        test_result = CommandResult(
            command="curl https://httpbin.org/status/404",
            success=False,
            return_code=404,
            stdout='{"status": 404, "message": "Not Found"}',
            stderr="HTTP 404 error",
            execution_time=0.5,
            timestamp="2025-01-01T00:00:00"
        )
        
        print("\n🔍 Testing command analysis...")
        analysis = await analyzer.analyze_execution(test_result)
        
        print(f"✅ Analysis completed!")
        print(f"   Success: {analysis.success}")
        print(f"   Message: {analysis.message}")
        print(f"   Provider: {analyzer.provider}")
        
        if analysis.suggestions:
            print("   Suggestions:")
            for suggestion in analysis.suggestions[:3]:
                print(f"     • {suggestion}")
        
        if analysis.suggested_command:
            print(f"   Suggested command: {analysis.suggested_command}")
        
        print("\n🎉 Gemini integration working perfectly!")
        
    except Exception as e:
        print(f"❌ Error testing Gemini: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_gemini())
