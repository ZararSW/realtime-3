#!/usr/bin/env python3
"""
AI Provider Configuration Utility
Easily switch between different AI providers
"""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from intelligent_terminal_ai.utils.config import config

def show_current_config():
    """Show current AI configuration"""
    print("\n🤖 CURRENT AI CONFIGURATION")
    print("=" * 50)
    
    current_provider = config.get("ai", "provider", "groq")
    print(f"📡 Active Provider: {current_provider.upper()}")
    
    # Show provider-specific settings
    provider_config = config.get("ai", current_provider, {})
    if provider_config:
        print(f"🧠 Model: {provider_config.get('model', 'Not specified')}")
        
        # Show API key status (masked)
        api_key = provider_config.get('api_key')
        if api_key:
            masked_key = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "***"
            print(f"🔑 API Key: {masked_key}")
        else:
            env_var = provider_config.get('api_key_env', f"{current_provider.upper()}_API_KEY")
            env_key = os.getenv(env_var)
            if env_key:
                masked_env = f"{env_key[:8]}...{env_key[-4:]}" if len(env_key) > 12 else "***"
                print(f"🔑 API Key (from {env_var}): {masked_env}")
            else:
                print(f"⚠️  API Key: Not configured (set {env_var})")
    
    print("\n📋 AVAILABLE PROVIDERS")
    print("-" * 30)
    
    providers = ["groq", "gemini", "openai", "anthropic"]
    for provider in providers:
        status = "✅ ACTIVE" if provider == current_provider else "⚪ Available"
        provider_conf = config.get("ai", provider, {})
        model = provider_conf.get("model", "default")
        print(f"{status} {provider.upper()}: {model}")

def switch_provider(provider: str):
    """Switch to a different AI provider"""
    valid_providers = ["groq", "gemini", "openai", "anthropic"]
    
    if provider not in valid_providers:
        print(f"❌ Invalid provider: {provider}")
        print(f"Valid options: {', '.join(valid_providers)}")
        return False
    
    # Update configuration
    config.set("ai", "provider", provider)
    
    print(f"\n✅ Switched to {provider.upper()}")
    
    # Check if API key is configured
    provider_config = config.get("ai", provider, {})
    api_key = provider_config.get('api_key')
    env_var = provider_config.get('api_key_env', f"{provider.upper()}_API_KEY")
    
    if not api_key and not os.getenv(env_var):
        print(f"⚠️  Warning: No API key configured for {provider}")
        print(f"💡 Set {env_var} environment variable or update config.yaml")
    
    return True

def quick_test(provider: str = None):
    """Test the current or specified AI provider"""
    if provider:
        switch_provider(provider)
    
    print(f"\n🧪 TESTING AI PROVIDER")
    print("=" * 30)
    
    try:
        from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer
        
        current_provider = config.get("ai", "provider", "groq")
        provider_config = config.get("ai", current_provider, {})
        
        # Get model and API key
        if current_provider == "groq":
            model = f"groq-{provider_config.get('model', 'llama-3.1-8b-instant')}"
            api_key = provider_config.get("api_key") or os.getenv("GROQ_API_KEY")
        elif current_provider == "gemini":
            model = f"gemini-{provider_config.get('model', 'gemini-2.0-flash-exp')}"
            api_key = provider_config.get("api_key") or os.getenv(provider_config.get("api_key_env", "GOOGLE_API_KEY"))
        elif current_provider == "openai":
            model = provider_config.get("model", "gpt-4")
            api_key = provider_config.get("api_key") or os.getenv(provider_config.get("api_key_env", "OPENAI_API_KEY"))
        elif current_provider == "anthropic":
            model = provider_config.get("model", "claude-3-sonnet-20240229")
            api_key = provider_config.get("api_key") or os.getenv(provider_config.get("api_key_env", "ANTHROPIC_API_KEY"))
        
        print(f"🤖 Provider: {current_provider.upper()}")
        print(f"🧠 Model: {model}")
        print(f"🔑 API Key: {'Configured' if api_key else 'Missing'}")
        
        if not api_key:
            print("❌ Cannot test - API key not configured")
            return False
        
        # Initialize analyzer
        analyzer = AIAnalyzer(model=model, api_key=api_key)
        
        if analyzer.client is None:
            print("❌ Failed to initialize AI client")
            return False
        
        print("✅ AI client initialized successfully")
        print(f"📡 Provider: {analyzer.provider}")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def main():
    """Main CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AI Provider Configuration Utility")
    parser.add_argument("--show", action="store_true", help="Show current configuration")
    parser.add_argument("--switch", choices=["groq", "gemini", "openai", "anthropic"], help="Switch to provider")
    parser.add_argument("--test", nargs="?", const=True, help="Test current provider or specific provider")
    
    args = parser.parse_args()
    
    if args.show:
        show_current_config()
    elif args.switch:
        switch_provider(args.switch)
        show_current_config()
    elif args.test:
        if isinstance(args.test, str):
            quick_test(args.test)
        else:
            quick_test()
    else:
        # Interactive mode
        while True:
            print("\n🤖 AI PROVIDER MANAGER")
            print("=" * 30)
            print("1. Show current configuration")
            print("2. Switch provider")
            print("3. Test provider")
            print("4. Exit")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == "1":
                show_current_config()
            elif choice == "2":
                print("\nAvailable providers:")
                providers = ["groq", "gemini", "openai", "anthropic"]
                for i, p in enumerate(providers, 1):
                    print(f"{i}. {p.upper()}")
                
                try:
                    idx = int(input("\nSelect provider: ")) - 1
                    if 0 <= idx < len(providers):
                        switch_provider(providers[idx])
                    else:
                        print("❌ Invalid selection")
                except ValueError:
                    print("❌ Invalid input")
            elif choice == "3":
                quick_test()
            elif choice == "4":
                break
            else:
                print("❌ Invalid option")

if __name__ == "__main__":
    main()
