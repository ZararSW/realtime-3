#!/usr/bin/env python3
"""
Test the GUI API endpoints to verify they work correctly
"""
import requests
import json
import sys

def test_api_endpoint(endpoint, expected_status=200):
    """Test a specific API endpoint"""
    base_url = "http://localhost:5000"
    url = f"{base_url}{endpoint}"
    
    try:
        print(f"🔍 Testing: {endpoint}")
        response = requests.get(url, timeout=10)
        
        print(f"   Status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('content-type', 'unknown')}")
        
        if response.status_code == expected_status:
            if 'application/json' in response.headers.get('content-type', ''):
                try:
                    data = response.json()
                    print(f"   ✅ JSON Response: {data.get('success', 'no success field')}")
                    return True
                except json.JSONDecodeError:
                    print("   ❌ Invalid JSON response")
                    return False
            else:
                print("   ✅ Non-JSON response received")
                return True
        else:
            print(f"   ❌ Unexpected status code: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("   ❌ Connection failed - is the server running?")
        return False
    except requests.exceptions.Timeout:
        print("   ❌ Request timeout")
        return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def main():
    """Test various API endpoints"""
    print("🚀 Testing GUI API Endpoints")
    print("=" * 50)
    
    # Test basic endpoints
    tests = [
        ("/api/ai_status", 200),
        ("/api/active_scans", 200),
        ("/api/debug/scan_1753820397_0", 200),
        ("/api/scan_results/scan_1753820397_0", 200),  # This should now work with historical data
    ]
    
    results = []
    for endpoint, expected_status in tests:
        success = test_api_endpoint(endpoint, expected_status)
        results.append(success)
    
    print("=" * 50)
    
    if all(results):
        print("✅ All API tests passed!")
        print("🌐 The GUI should now work correctly")
    else:
        print("❌ Some API tests failed")
        print("💡 Make sure the Flask server is running: python start_gui.py")
    
    print("=" * 50)

if __name__ == "__main__":
    main()
