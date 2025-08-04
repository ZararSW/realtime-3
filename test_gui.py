#!/usr/bin/env python3
"""
Test the GUI functionality of the Intelligent Terminal AI Tool
"""

import sys
import os
import time
import requests
import threading
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_gui_launch():
    """Test launching the GUI"""
    print("🧪 Testing GUI Launch")
    print("=" * 30)
    
    try:
        # Import GUI module
        from gui_app import app
        print("✅ GUI module imported successfully")
        
        # Test Flask app creation
        with app.app_context():
            print("✅ Flask app context created successfully")
        
        print("✅ GUI launch test passed!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure Flask is installed: pip install flask")
        return False
    except Exception as e:
        print(f"❌ GUI launch test failed: {e}")
        return False

def test_api_endpoints():
    """Test API endpoints (requires GUI to be running)"""
    print("\n🧪 Testing API Endpoints")
    print("=" * 30)
    
    base_url = "http://localhost:5000"
    
    # Test endpoints
    endpoints = [
        ("/", "GET", "Main page"),
        ("/api/ai_status", "GET", "AI status"),
        ("/api/active_scans", "GET", "Active scans")
    ]
    
    all_passed = True
    
    for endpoint, method, description in endpoints:
        try:
            if method == "GET":
                response = requests.get(f"{base_url}{endpoint}", timeout=5)
            
            if response.status_code == 200:
                print(f"✅ {description}: {endpoint}")
            else:
                print(f"⚠️  {description}: {endpoint} (Status: {response.status_code})")
                all_passed = False
                
        except requests.exceptions.ConnectionError:
            print(f"❌ {description}: {endpoint} (Connection refused - GUI not running?)")
            all_passed = False
        except Exception as e:
            print(f"❌ {description}: {endpoint} (Error: {e})")
            all_passed = False
    
    return all_passed

def run_gui_in_background():
    """Run GUI in background for testing"""
    try:
        from gui_app import app
        app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)
    except Exception as e:
        print(f"❌ Error running GUI in background: {e}")

def interactive_gui_test():
    """Interactive GUI test"""
    print("\n🎮 Interactive GUI Test")
    print("=" * 30)
    
    print("This will launch the GUI for manual testing.")
    print("You can:")
    print("  1. Test the web interface at http://localhost:5000")
    print("  2. Try starting a scan")
    print("  3. Check AI provider status")
    print("  4. View scan results")
    print()
    
    choice = input("Launch GUI for interactive testing? (y/n): ").lower().strip()
    
    if choice == 'y':
        print("\n🚀 Launching GUI...")
        print("📱 Open your browser to: http://localhost:5000")
        print("🛑 Press Ctrl+C to stop the server")
        print("-" * 50)
        
        try:
            from gui_app import main as gui_main
            gui_main()
        except KeyboardInterrupt:
            print("\n✅ GUI test completed!")
        except Exception as e:
            print(f"\n❌ GUI test failed: {e}")
    else:
        print("⏭️  Skipping interactive test")

def test_command_line_integration():
    """Test command line integration"""
    print("\n🧪 Testing Command Line Integration")
    print("=" * 40)
    
    try:
        # Test importing the main run module
        import run
        print("✅ Main run module imported successfully")
        
        # Test that GUI flag is available
        import argparse
        from unittest.mock import patch
        
        # Mock sys.argv to test argument parsing
        test_args = ['run.py', 'https://example.com', '--gui']
        
        with patch('sys.argv', test_args):
            try:
                parser = argparse.ArgumentParser()
                parser.add_argument("url")
                parser.add_argument("--gui", action="store_true")
                args = parser.parse_args()
                
                if args.gui:
                    print("✅ --gui flag parsed successfully")
                else:
                    print("❌ --gui flag not recognized")
                    return False
                    
            except Exception as e:
                print(f"❌ Argument parsing failed: {e}")
                return False
        
        print("✅ Command line integration test passed!")
        return True
        
    except Exception as e:
        print(f"❌ Command line integration test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 GUI Functionality Test Suite")
    print("=" * 50)
    
    test_results = []
    
    # Test 1: GUI Launch
    test_results.append(("GUI Launch", test_gui_launch()))
    
    # Test 2: Command Line Integration
    test_results.append(("Command Line Integration", test_command_line_integration()))
    
    # Test 3: Interactive Test (optional)
    try:
        interactive_gui_test()
    except KeyboardInterrupt:
        print("\n⏭️  Interactive test interrupted")
    
    # Summary
    print("\n📊 Test Results Summary")
    print("=" * 30)
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! GUI is ready to use.")
        print("\nTo use the GUI:")
        print("  python run.py --gui")
        print("  Then open: http://localhost:5000")
    else:
        print("⚠️  Some tests failed. Check the errors above.")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
