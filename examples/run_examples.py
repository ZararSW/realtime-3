"""
Example scripts demonstrating the Intelligent Terminal AI Tool
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from intelligent_terminal_ai.main import IntelligentTerminalAI


async def example_api_testing():
    """Example: Test multiple API endpoints"""
    
    print("🔍 Example: API Testing with Browser Verification")
    print("-" * 50)
    
    async with IntelligentTerminalAI(ai_model="gpt-4", headless_browser=True) as ai_tool:
        
        # Test different API endpoints
        apis_to_test = [
            "https://jsonplaceholder.typicode.com/posts/1",
            "https://api.github.com/users/octocat",
            "https://httpbin.org/status/200",
            "https://httpbin.org/json"
        ]
        
        for api_url in apis_to_test:
            print(f"\n🌐 Testing: {api_url}")
            result = await ai_tool.test_api_endpoint(api_url)
            
            if result.success:
                print(f"✅ Success: {result.message}")
            else:
                print(f"❌ Failed: {result.message}")
            
            if result.suggestions:
                print("💡 Suggestions:")
                for suggestion in result.suggestions[:2]:  # Show first 2
                    print(f"  • {suggestion}")


async def example_command_correction():
    """Example: Command execution with self-correction"""
    
    print("\n🔧 Example: Command Execution with Self-Correction")
    print("-" * 50)
    
    async with IntelligentTerminalAI(ai_model="gpt-4") as ai_tool:
        
        # Commands that might need correction
        commands_to_test = [
            "curl https://httpbin.org/get",  # Should work
            "curl https://httpbin.org/status/404",  # Will get 404
            "ping -c 3 google.com" if sys.platform != "win32" else "ping -n 3 google.com",
            "python --version"
        ]
        
        for command in commands_to_test:
            print(f"\n⚡ Executing: {command}")
            result = await ai_tool.execute_intelligent_command(
                command, 
                max_iterations=2
            )
            
            print(f"Result: {'✅ Success' if result.success else '❌ Failed'}")
            print(f"Message: {result.message}")
            
            if hasattr(result, 'iterations_used'):
                print(f"Iterations: {result.iterations_used}")


async def example_web_testing():
    """Example: Web application testing"""
    
    print("\n🌐 Example: Web Application Testing")
    print("-" * 50)
    
    async with IntelligentTerminalAI(ai_model="gpt-4", headless_browser=False) as ai_tool:
        
        # Test different types of websites
        websites_to_test = [
            "https://httpbin.org",
            "https://example.com",
            "https://github.com",
            "https://httpstat.us/500"  # Will return server error
        ]
        
        for website in websites_to_test:
            print(f"\n🔍 Testing website: {website}")
            
            # Test using API call first
            api_result = await ai_tool.test_api_endpoint(website)
            print(f"API Test: {'✅' if api_result.success else '❌'} {api_result.message}")
            
            # Show suggestions
            if api_result.suggestions:
                print("💡 Suggestions:")
                for suggestion in api_result.suggestions[:2]:
                    print(f"  • {suggestion}")


async def example_development_workflow():
    """Example: Development workflow simulation"""
    
    print("\n⚙️ Example: Development Workflow Simulation")
    print("-" * 50)
    
    async with IntelligentTerminalAI(ai_model="gpt-4") as ai_tool:
        
        # Simulate a typical development workflow
        workflow_steps = [
            ("Check Python version", "python --version"),
            ("Check pip version", "pip --version"),
            ("List current directory", "dir" if sys.platform == "win32" else "ls -la"),
            ("Check git status", "git --version"),
            ("Test internet connection", "ping -n 1 8.8.8.8" if sys.platform == "win32" else "ping -c 1 8.8.8.8")
        ]
        
        for step_name, command in workflow_steps:
            print(f"\n📋 Step: {step_name}")
            print(f"Command: {command}")
            
            result = await ai_tool.execute_intelligent_command(command, max_iterations=1)
            
            status = "✅ Success" if result.success else "❌ Failed"
            print(f"Result: {status}")
            
            if not result.success and result.suggestions:
                print("💡 AI Suggestions:")
                for suggestion in result.suggestions[:1]:
                    print(f"  • {suggestion}")


async def run_all_examples():
    """Run all examples"""
    
    print("🤖 Intelligent Terminal AI - Examples")
    print("=" * 60)
    
    examples = [
        example_api_testing,
        example_command_correction,
        example_web_testing,
        example_development_workflow
    ]
    
    for example in examples:
        try:
            await example()
            print("\n" + "=" * 60)
        except KeyboardInterrupt:
            print("\n👋 Examples interrupted by user")
            break
        except Exception as e:
            print(f"\n❌ Example failed: {e}")
            continue
    
    print("🎉 Examples completed!")


if __name__ == "__main__":
    asyncio.run(run_all_examples())
