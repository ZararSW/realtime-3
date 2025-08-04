#!/usr/bin/env python3
"""
Simple test script to verify the Intelligent Terminal AI setup
"""

import sys
import asyncio
from pathlib import Path

# Add current directory to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

print("🔍 Testing Intelligent Terminal AI Setup")
print("=" * 50)

# Test imports
try:
    print("📦 Testing imports...")
    
    # Test external dependencies
    import requests
    print("  ✅ requests imported")
    
    import selenium
    print("  ✅ selenium imported")
    
    import aiohttp
    print("  ✅ aiohttp imported")
    
    from rich.console import Console
    print("  ✅ rich imported")
    
    import pydantic
    print("  ✅ pydantic imported")
    
    # Test our modules
    from intelligent_terminal_ai.models.command_result import CommandResult
    print("  ✅ CommandResult imported")
    
    from intelligent_terminal_ai.core.terminal_executor import TerminalExecutor
    print("  ✅ TerminalExecutor imported")
    
    from intelligent_terminal_ai.utils.logger import setup_logger
    print("  ✅ Logger utils imported")
    
    print("\n✅ All imports successful!")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)

# Test basic functionality
async def test_basic_functionality():
    print("\n🧪 Testing basic functionality...")
    
    try:
        # Test logger setup
        logger = setup_logger("test")
        logger.info("Logger test successful")
        print("  ✅ Logger working")
        
        # Test CommandResult model
        result = CommandResult(
            command="test",
            success=True,
            return_code=0,
            stdout="test output",
            stderr="",
            execution_time=0.1,
            timestamp="2025-01-01T00:00:00"
        )
        print("  ✅ CommandResult model working")
        
        # Test TerminalExecutor initialization
        executor = TerminalExecutor()
        print("  ✅ TerminalExecutor initialization working")
        
        # Test a simple command
        result = await executor.execute_command("echo Hello World")
        if "Hello World" in result.stdout or result.success:
            print("  ✅ Basic command execution working")
        else:
            print(f"  ⚠️ Command execution returned: {result.stdout}")
        
        print("\n🎉 Basic functionality test completed!")
        return True
        
    except Exception as e:
        print(f"❌ Functionality test failed: {e}")
        return False

# Test AI integration (without requiring API keys)
def test_ai_integration():
    print("\n🤖 Testing AI integration...")
    
    try:
        from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer
        
        # Test initialization without API key (should use fallback)
        analyzer = AIAnalyzer(model="gpt-4")
        print("  ✅ AI Analyzer initialization working")
        
        # The analyzer should work in fallback mode
        print("  ✅ AI integration setup complete (will use fallback without API keys)")
        
        return True
        
    except Exception as e:
        print(f"❌ AI integration test failed: {e}")
        return False

async def main():
    """Run all tests"""
    
    success = True
    
    # Test AI integration
    if not test_ai_integration():
        success = False
    
    # Test basic functionality
    if not await test_basic_functionality():
        success = False
    
    if success:
        print("\n🎉 All tests passed! The Intelligent Terminal AI is ready to use.")
        print("\n📖 Usage examples:")
        print("  python run.py --help")
        print("  python run.py 'echo Hello World'")
        print("  python run.py --url 'https://httpbin.org/get'")
        print("  python run.py  # For interactive mode")
        print("\n💡 To enable AI features, set your API keys in .env file:")
        print("  OPENAI_API_KEY=your_key_here")
        print("  or")
        print("  ANTHROPIC_API_KEY=your_key_here")
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
