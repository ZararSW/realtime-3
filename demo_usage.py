#!/usr/bin/env python3
"""
Example demonstrating both command-line and GUI usage of the Intelligent Terminal AI Tool
"""

import os
import sys
import time
import subprocess
from pathlib import Path

def show_usage_examples():
    """Show usage examples for the tool"""
    
    print("🛡️ Intelligent Terminal AI Tool - Usage Examples")
    print("=" * 60)
    
    print("\n📋 Command Line Usage:")
    print("-" * 25)
    
    examples = [
        {
            "description": "Basic scan with AI (Groq)",
            "command": "python run.py https://testphp.vulnweb.com --ai-provider groq"
        },
        {
            "description": "Deep scan without AI",
            "command": "python run.py https://example.com --scan-depth 3 --no-ai"
        },
        {
            "description": "Scan with HTML output",
            "command": "python run.py https://example.com --output report.html"
        },
        {
            "description": "Launch Web GUI",
            "command": "python run.py --gui"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n{i}. {example['description']}:")
        print(f"   {example['command']}")
    
    print("\n🌐 Web GUI Usage:")
    print("-" * 20)
    print("1. Launch GUI: python run.py --gui")
    print("2. Open browser: http://localhost:5000")
    print("3. Configure scan options in the web interface")
    print("4. Start scan and monitor progress")
    print("5. View results with interactive interface")
    
    print("\n🔧 AI Configuration:")
    print("-" * 22)
    print("Set up environment variables for AI providers:")
    print("   export GROQ_API_KEY='your-groq-api-key'")
    print("   export OPENAI_API_KEY='your-openai-api-key'")
    print("   export ANTHROPIC_API_KEY='your-anthropic-api-key'")
    print("   export GOOGLE_API_KEY='your-google-api-key'")

def demonstrate_command_line():
    """Demonstrate command line usage"""
    
    print("\n🖥️ Command Line Demonstration")
    print("=" * 35)
    
    print("This will show how to use the tool from the command line.")
    
    # Check if we have required dependencies
    try:
        import requests
        print("✅ Dependencies available")
    except ImportError:
        print("❌ Missing dependencies. Please run: pip install -r requirements.txt")
        return
    
    # Example commands to demonstrate
    demo_commands = [
        {
            "name": "Help",
            "command": ["python", "run.py", "--help"],
            "description": "Show all available options"
        },
        {
            "name": "AI Status Check",
            "command": ["python", "-c", "import os; print('AI Keys:', {k:v[:10]+'...' if v else 'Not Set' for k,v in {'GROQ':os.getenv('GROQ_API_KEY'), 'OPENAI':os.getenv('OPENAI_API_KEY')}.items()})"],
            "description": "Check AI provider configuration"
        }
    ]
    
    for demo in demo_commands:
        print(f"\n📌 {demo['name']}: {demo['description']}")
        print(f"Command: {' '.join(demo['command'])}")
        
        try:
            result = subprocess.run(
                demo['command'], 
                capture_output=True, 
                text=True, 
                timeout=10,
                cwd=Path(__file__).parent
            )
            
            if result.returncode == 0:
                output = result.stdout[:500]  # Limit output
                if output.strip():
                    print("Output:")
                    print(output)
                else:
                    print("✅ Command executed successfully (no output)")
            else:
                print(f"⚠️ Command failed with return code {result.returncode}")
                if result.stderr:
                    print(f"Error: {result.stderr[:200]}")
                    
        except subprocess.TimeoutExpired:
            print("⏱️ Command timed out")
        except Exception as e:
            print(f"❌ Error running command: {e}")

def demonstrate_gui():
    """Demonstrate GUI usage"""
    
    print("\n🌐 Web GUI Demonstration")
    print("=" * 30)
    
    print("This will launch the web GUI for interactive demonstration.")
    
    choice = input("\nLaunch GUI now? (y/n): ").lower().strip()
    
    if choice == 'y':
        print("\n🚀 Launching GUI...")
        print("📱 The web interface will open at: http://localhost:5000")
        print("🛑 Press Ctrl+C to stop the server when done")
        print("-" * 50)
        
        try:
            # Launch GUI
            subprocess.run([
                "python", "run.py", "--gui"
            ], cwd=Path(__file__).parent)
            
        except KeyboardInterrupt:
            print("\n✅ GUI demonstration completed!")
        except FileNotFoundError:
            print("❌ Error: run.py not found. Make sure you're in the correct directory.")
        except Exception as e:
            print(f"❌ Error launching GUI: {e}")
    else:
        print("⏭️ Skipping GUI demonstration")

def check_environment():
    """Check environment setup"""
    
    print("\n🔍 Environment Check")
    print("=" * 22)
    
    checks = []
    
    # Check Python version
    python_version = sys.version_info
    if python_version >= (3, 8):
        checks.append(("Python Version", True, f"{python_version.major}.{python_version.minor}.{python_version.micro}"))
    else:
        checks.append(("Python Version", False, f"{python_version.major}.{python_version.minor}.{python_version.micro} (requires 3.8+)"))
    
    # Check required files
    required_files = ["run.py", "gui_app.py", "requirements.txt"]
    for file in required_files:
        file_path = Path(__file__).parent / file
        checks.append((file, file_path.exists(), str(file_path)))
    
    # Check AI keys
    ai_keys = {
        "GROQ_API_KEY": os.getenv("GROQ_API_KEY"),
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
        "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
        "GOOGLE_API_KEY": os.getenv("GOOGLE_API_KEY")
    }
    
    for key_name, key_value in ai_keys.items():
        checks.append((key_name, bool(key_value), "Set" if key_value else "Not set"))
    
    # Check Python packages
    required_packages = ["requests", "selenium", "beautifulsoup4", "flask"]
    for package in required_packages:
        try:
            __import__(package)
            checks.append((f"Package: {package}", True, "Available"))
        except ImportError:
            checks.append((f"Package: {package}", False, "Not installed"))
    
    # Display results
    all_good = True
    for name, status, details in checks:
        status_icon = "✅" if status else "❌"
        print(f"{status_icon} {name}: {details}")
        if not status:
            all_good = False
    
    if all_good:
        print("\n🎉 Environment is ready!")
    else:
        print("\n⚠️ Some issues found. Please fix them before proceeding.")
        print("\nTo install missing packages:")
        print("   pip install -r requirements.txt")
    
    return all_good

def interactive_menu():
    """Interactive menu for demonstrations"""
    
    while True:
        print("\n🎯 Choose a demonstration:")
        print("1. 📋 Show usage examples")
        print("2. 🔍 Check environment")
        print("3. 🖥️ Command line demo")
        print("4. 🌐 Web GUI demo") 
        print("5. 🚪 Exit")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == "1":
            show_usage_examples()
        elif choice == "2":
            check_environment()
        elif choice == "3":
            demonstrate_command_line()
        elif choice == "4":
            demonstrate_gui()
        elif choice == "5":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter 1-5.")

def main():
    """Main function"""
    
    print("🛡️ Intelligent Terminal AI Tool - Demo & Examples")
    print("=" * 55)
    print("This script demonstrates both command-line and GUI usage")
    print("of the penetration testing tool.")
    
    # Quick environment check
    if not check_environment():
        print("\n⚠️ Environment issues detected.")
        print("Please fix them before continuing with demonstrations.")
        
        fix_choice = input("\nContinue anyway? (y/n): ").lower().strip()
        if fix_choice != 'y':
            return
    
    # Run interactive menu
    try:
        interactive_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()
