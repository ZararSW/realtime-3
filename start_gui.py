#!/usr/bin/env python3
"""
Simple GUI startup script
"""
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from gui_app import app
    
    print("🚀 Starting Intelligent Terminal AI - Web GUI")
    print("=" * 50)
    print("🌐 GUI will be available at: http://localhost:5000")
    print("📋 Features:")
    print("   • Real-time penetration testing")
    print("   • AI-powered vulnerability analysis")
    print("   • Interactive scan management")
    print("   • Export results (JSON/HTML)")
    print("=" * 50)
    print("🔍 Starting Flask server...")
    
    # Start the Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("💡 Make sure all dependencies are installed:")
    print("   pip install flask")
    
except Exception as e:
    print(f"❌ Error starting GUI: {e}")
    print("💡 Check the logs for more details")
