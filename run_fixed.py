#!/usr/bin/env python3
"""
Fixed Entry point for the Intelligent Terminal AI Tool with working visual pentest
"""

import asyncio
import argparse
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import the working visual pentest demo
from visual_pentest_demo import VisualPenTest

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Intelligent Terminal AI - Execute commands with AI analysis and self-correction"
    )
    
    parser.add_argument(
        "--url",
        help="URL to test/analyze"
    )
    
    parser.add_argument(
        "--visual-pentest",
        action="store_true",
        help="Perform real-time visual penetration testing with browser feedback"
    )
    
    parser.add_argument(
        "--pentest",
        action="store_true", 
        help="Perform autonomous penetration testing on the URL"
    )
    
    args = parser.parse_args()
    
    if args.url and args.visual_pentest:
        print("🚀 Starting Visual Penetration Testing...")
        visual_pentester = VisualPenTest()
        await visual_pentester.visual_pentest(args.url)
    elif args.url and args.pentest:
        print("❌ Regular pentest is currently disabled due to file corruption.")
        print("💡 Use --visual-pentest instead for real-time browser testing!")
    elif args.url:
        print("🔗 URL provided but no test type specified.")
        print("💡 Use --visual-pentest for real-time browser testing!")
        print("💡 Use --pentest for autonomous testing (currently disabled)")
    else:
        print("🤖 Intelligent Terminal AI")
        print("Usage examples:")
        print("  python run_fixed.py --visual-pentest --url http://testphp.vulnweb.com/")
        print("  python run_fixed.py --pentest --url http://testphp.vulnweb.com/")

if __name__ == "__main__":
    asyncio.run(main())
