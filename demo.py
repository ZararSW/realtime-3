#!/usr/bin/env python3
"""
Demo script showing the Intelligent Terminal AI capabilities
"""

import asyncio
import sys
from pathlib import Path

# Add current directory to path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

from intelligent_terminal_ai.core.terminal_executor import TerminalExecutor
from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer
from intelligent_terminal_ai.models.command_result import CommandResult
from intelligent_terminal_ai.utils.logger import setup_logger


async def demo_terminal_execution():
    """Demo terminal command execution with analysis"""
    
    print("🚀 Intelligent Terminal AI - Demo")
    print("=" * 60)
    
    # Setup
    logger = setup_logger("demo", "INFO")
    executor = TerminalExecutor()
    analyzer = AIAnalyzer(model="gpt-4")  # Will use fallback without API key
    
    print("\n1. 📋 Testing Basic Commands")
    print("-" * 30)
    
    commands = [
        "echo Hello from Intelligent Terminal AI!",
        "python --version",
        "dir" if sys.platform == "win32" else "ls -la",
        "ping -n 1 8.8.8.8" if sys.platform == "win32" else "ping -c 1 8.8.8.8"
    ]
    
    for i, command in enumerate(commands, 1):
        print(f"\n🔧 Command {i}: {command}")
        
        try:
            # Execute command
            result = await executor.execute_command(command)
            
            # Show result
            status = "✅ SUCCESS" if result.success else "❌ FAILED"
            print(f"Status: {status}")
            print(f"Return Code: {result.return_code}")
            print(f"Execution Time: {result.execution_time:.2f}s")
            
            if result.stdout:
                print(f"Output: {result.stdout[:200]}...")
            
            if result.stderr:
                print(f"Error: {result.stderr[:100]}...")
            
            # AI Analysis (fallback mode)
            print("\n🤖 AI Analysis:")
            analysis = await analyzer.analyze_execution(result)
            print(f"   Success: {analysis.success}")
            print(f"   Message: {analysis.message}")
            
            if analysis.suggestions:
                print("   Suggestions:")
                for suggestion in analysis.suggestions[:2]:
                    print(f"     • {suggestion}")
            
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("🎉 Demo completed!")
    print("\n💡 This was running in FALLBACK mode (no AI API key)")
    print("   To enable full AI features, add your API key to .env:")
    print("   OPENAI_API_KEY=your_key_here")
    print("\n📖 Full usage examples:")
    print("   python run.py 'curl https://httpbin.org/get'")
    print("   python run.py --url 'https://example.com'")
    print("   python run.py  # Interactive mode")


if __name__ == "__main__":
    asyncio.run(demo_terminal_execution())
