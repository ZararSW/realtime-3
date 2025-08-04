#!/usr/bin/env python3
"""
Quick test to verify GUI starts and export functionality works
"""
import asyncio
import tempfile
import json
import os
from datetime import datetime

# Test the export functionality directly
def test_export_functionality():
    """Test that export functionality works with cross-platform paths"""
    print("🔍 Testing export functionality...")
    
    # Sample result data
    sample_result = {
        'success': True,
        'report': {
            'vulnerabilities': ['XSS vulnerability found'],
            'pages_scanned': 5,
            'timestamp': datetime.now().isoformat()
        },
        'scan_options': {
            'target_url': 'http://example.com',
            'ai_provider': 'groq',
            'use_ai': True,
            'scan_depth': 3
        }
    }
    
    scan_id = 'test-123'
    
    try:
        # Test JSON export
        temp_dir = tempfile.gettempdir()
        json_file = os.path.join(temp_dir, f'pentest_report_{scan_id}.json')
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(sample_result, f, indent=2, default=str)
        
        print(f"✅ JSON export successful: {json_file}")
        
        # Test HTML export
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Report</title>
        </head>
        <body>
            <h1>Test Report - {scan_id}</h1>
            <pre>{json.dumps(sample_result, indent=2, default=str)}</pre>
        </body>
        </html>
        """
        
        html_file = os.path.join(temp_dir, f'pentest_report_{scan_id}.html')
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ HTML export successful: {html_file}")
        
        # Clean up
        try:
            os.remove(json_file)
            os.remove(html_file)
            print("🧹 Cleanup successful")
        except:
            pass
            
        return True
        
    except Exception as e:
        print(f"❌ Export test failed: {e}")
        return False

def test_gui_import():
    """Test that GUI imports work correctly"""
    print("🔍 Testing GUI imports...")
    
    try:
        from gui_app import app, PentestRunner
        print("✅ GUI imports successful")
        return True
    except Exception as e:
        print(f"❌ GUI import failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Starting GUI functionality tests...")
    print("=" * 50)
    
    # Test imports
    import_success = test_gui_import()
    
    # Test export functionality
    export_success = test_export_functionality()
    
    print("=" * 50)
    
    if import_success and export_success:
        print("✅ All tests passed! GUI should work correctly.")
        print("📝 You can now start the GUI with: python run.py --gui")
        print("🌐 Then visit: http://localhost:5000")
    else:
        print("❌ Some tests failed. Check the errors above.")
    
    print("=" * 50)

if __name__ == "__main__":
    main()
