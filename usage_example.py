#!/usr/bin/env python3
"""
Usage example for the enhanced real-time pentester
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from enhanced_run import EnhancedPentester
from realtime_pentester import RealTimePentester

async def example_enhanced_pentest():
    """Example of using the enhanced pentester"""
    print("🚀 Enhanced Real-Time Pentester Example")
    print("=" * 50)
    
    # Example target URL (replace with your target)
    target_url = "http://testphp.vulnweb.com"
    
    print(f"Target: {target_url}")
    print("Features:")
    print("  ✅ Real-time crawling and endpoint discovery")
    print("  ✅ Live vulnerability auditing")
    print("  ✅ Browser confirmation of findings")
    print("  ✅ Real-time progress monitoring")
    print("  ✅ Comprehensive reporting")
    print()
    
    # Create enhanced pentester
    pentester = EnhancedPentester(
        target_url=target_url,
        headless=True,  # Run in headless mode for automation
        ai_enabled=True
    )
    
    try:
        print("Initializing enhanced pentester...")
        await pentester.initialize()
        
        print("Starting enhanced scan...")
        await pentester.start_enhanced_scan()
        
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        await pentester.stop()
        print("\n✅ Enhanced pentest completed")

async def example_realtime_pentest():
    """Example of using the real-time pentester"""
    print("🎯 Real-Time Pentester Example")
    print("=" * 50)
    
    # Example target URL
    target_url = "http://testphp.vulnweb.com"
    
    print(f"Target: {target_url}")
    print("Features:")
    print("  ✅ Real-time endpoint discovery")
    print("  ✅ Live vulnerability testing")
    print("  ✅ Browser confirmation")
    print("  ✅ Real-time monitoring display")
    print("  ✅ JSON report generation")
    print()
    
    # Create real-time pentester
    pentester = RealTimePentester(
        target_url=target_url,
        headless=True,
        ai_enabled=True
    )
    
    try:
        print("Initializing real-time pentester...")
        await pentester.initialize()
        
        print("Starting real-time scan...")
        await pentester.start_realtime_scan()
        
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        await pentester.stop()
        print("\n✅ Real-time pentest completed")

def show_usage_instructions():
    """Show usage instructions"""
    print("📖 Usage Instructions")
    print("=" * 50)
    print()
    print("1. Enhanced Pentester (recommended):")
    print("   python enhanced_run.py http://target.com")
    print("   python enhanced_run.py http://target.com --headless")
    print("   python enhanced_run.py http://target.com --no-ai")
    print()
    print("2. Real-Time Pentester:")
    print("   python realtime_pentester.py http://target.com")
    print("   python realtime_pentester.py http://target.com --headless")
    print()
    print("3. Original run.py (for comparison):")
    print("   python run.py --advanced-crawl http://target.com")
    print("   python run.py --visual-pentest http://target.com")
    print()
    print("Key Features:")
    print("  🔍 Real-time endpoint discovery")
    print("  🛡️  Live vulnerability testing")
    print("  🌐 Browser confirmation")
    print("  📊 Real-time progress monitoring")
    print("  📝 Comprehensive reporting")
    print()
    print("Output Files:")
    print("  📄 enhanced_pentest_report_YYYYMMDD_HHMMSS.json")
    print("  📄 realtime_pentest_report_YYYYMMDD_HHMMSS.json")
    print("  📄 enhanced_pentest.log")
    print("  📄 realtime_pentest.log")
    print("  📸 screenshots/ (browser screenshots)")

async def main():
    """Main function to demonstrate usage"""
    print("🚀 Enhanced Real-Time Pentester - Usage Examples")
    print("=" * 60)
    print()
    
    # Show usage instructions
    show_usage_instructions()
    print()
    
    # Ask user which example to run
    print("Choose an example to run:")
    print("1. Enhanced Pentester (recommended)")
    print("2. Real-Time Pentester")
    print("3. Show usage instructions only")
    print("4. Exit")
    
    try:
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == "1":
            await example_enhanced_pentest()
        elif choice == "2":
            await example_realtime_pentest()
        elif choice == "3":
            show_usage_instructions()
        elif choice == "4":
            print("Goodbye!")
            return
        else:
            print("Invalid choice. Running enhanced pentester example...")
            await example_enhanced_pentest()
            
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())