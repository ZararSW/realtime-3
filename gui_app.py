#!/usr/bin/env python3
"""
Web GUI for the Intelligent Terminal AI Tool
Flask-based web interface for penetration testing
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.serving import run_simple
import threading
import time

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer
from intelligent_terminal_ai.utils.config import config
from advanced_intelligent_crawler import AdvancedIntelligentCrawler

app = Flask(__name__)
app.secret_key = 'pentest-gui-secret-key-2024'

# Global variables for managing scans
active_scans = {}
scan_results = {}

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

class PentestRunner:
    """Class to handle penetration testing operations"""
    
    def __init__(self):
        self.crawler = None
        self.ai_analyzer = None
    
    async def run_pentest(self, target_url, scan_options):
        """Run penetration test with given options"""
        try:
            # Initialize AI analyzer if enabled
            if scan_options.get('use_ai', False) and not scan_options.get('no_ai', False):
                provider = scan_options.get('ai_provider', 'groq')
                model = self.get_ai_model(provider)
                api_key = self.get_api_key(provider)
                
                if api_key:
                    self.ai_analyzer = AIAnalyzer(
                        model=model,
                        api_key=api_key,
                        enable_ai=True
                    )
                else:
                    self.ai_analyzer = None
            else:
                self.ai_analyzer = None
            
            # Initialize crawler
            if self.ai_analyzer:
                self.crawler = AdvancedIntelligentCrawler(
                    log_to_file=True,
                    ai_analyzer=self.ai_analyzer
                )
            else:
                self.crawler = AdvancedIntelligentCrawler(log_to_file=True)
            
            # Run the scan
            scan_depth = scan_options.get('scan_depth', '2')
            report = await self.crawler.comprehensive_crawl_and_test(target_url)
            
            return {
                'success': True,
                'report': report,
                'scan_options': scan_options
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'scan_options': scan_options
            }
    
    def get_ai_model(self, provider):
        """Get AI model for provider"""
        models = {
            'groq': 'groq',
            'openai': 'gpt-4',
            'anthropic': 'claude-3-sonnet-20240229',
            'gemini': 'gemini-pro'
        }
        return models.get(provider, 'groq')
    
    def get_api_key(self, provider):
        """Get API key for provider"""
        env_vars = {
            'groq': 'GROQ_API_KEY',
            'openai': 'OPENAI_API_KEY',
            'anthropic': 'ANTHROPIC_API_KEY',
            'gemini': 'GOOGLE_API_KEY'
        }
        return os.getenv(env_vars.get(provider))

# Routes
@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    """Start a new penetration test scan"""
    try:
        data = request.get_json()
        target_url = data.get('target_url', '').strip()
        
        if not target_url:
            return jsonify({'success': False, 'error': 'Target URL is required'})
        
        # Validate URL format
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        scan_options = {
            'use_ai': data.get('use_ai', False),
            'no_ai': data.get('no_ai', False),
            'ai_provider': data.get('ai_provider', 'groq'),
            'scan_depth': data.get('scan_depth', '2'),
            'mode': data.get('mode', 'advanced')
        }
        
        # Generate scan ID
        scan_id = f"scan_{int(time.time())}_{len(active_scans)}"
        
        # Store scan info
        active_scans[scan_id] = {
            'target_url': target_url,
            'start_time': datetime.now().isoformat(),
            'status': 'running',
            'scan_options': scan_options
        }
        
        # Start scan in background thread
        def run_scan():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            runner = PentestRunner()
            result = loop.run_until_complete(runner.run_pentest(target_url, scan_options))
            
            # Update scan status
            active_scans[scan_id]['status'] = 'completed' if result['success'] else 'failed'
            active_scans[scan_id]['end_time'] = datetime.now().isoformat()
            
            # Store results
            scan_results[scan_id] = result
            
            loop.close()
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/scan_status/<scan_id>')
def scan_status(scan_id):
    """Get scan status"""
    try:
        if scan_id not in active_scans:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404
        
        scan_info = active_scans[scan_id].copy()
        
        # Add result if available
        if scan_id in scan_results:
            # Ensure result is serializable
            result = scan_results[scan_id]
            serializable_result = json.loads(json.dumps(result, default=str))
            scan_info['result'] = serializable_result
        
        # Ensure scan_info is serializable
        serializable_scan_info = json.loads(json.dumps(scan_info, default=str))
        
        return jsonify({'success': True, 'scan': serializable_scan_info})
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'error': f'Failed to get scan status: {str(e)}'
        }), 500

@app.route('/api/scan_results/<scan_id>')
def get_scan_results(scan_id):
    """Get detailed scan results"""
    try:
        # First check in-memory results
        if scan_id in scan_results:
            results = scan_results[scan_id]
            scan_info = active_scans.get(scan_id, {})
        else:
            # Try to load from historical reports if not in memory
            results, scan_info = load_historical_scan_results(scan_id)
            if not results:
                return jsonify({'success': False, 'error': 'Results not found'}), 404
        
        # Convert to JSON-serializable format
        serializable_results = json.loads(json.dumps(results, default=str))
        serializable_scan_info = json.loads(json.dumps(scan_info, default=str))
        
        return jsonify({
            'success': True,
            'results': serializable_results,
            'scan_info': serializable_scan_info
        })
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'error': f'Failed to load results: {str(e)}'
        }), 500

def load_historical_scan_results(scan_id):
    """Load scan results from historical reports directory"""
    try:
        reports_dir = Path(__file__).parent / 'reports'
        
        # Look for any report files
        for report_file in reports_dir.glob('*.json'):
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                # Create a synthetic scan result structure
                results = {
                    'success': True,
                    'report': report_data,
                    'scan_options': {
                        'target_url': report_data.get('target_url', 'Unknown'),
                        'ai_provider': 'historical',
                        'use_ai': True,
                        'scan_depth': 'Unknown'
                    }
                }
                
                scan_info = {
                    'target_url': report_data.get('target_url', 'Unknown'),
                    'start_time': report_file.stem.replace('report_', '').replace('_', ' '),
                    'status': 'completed',
                    'scan_options': results['scan_options']
                }
                
                return results, scan_info
                
            except (json.JSONDecodeError, Exception):
                continue
        
        return None, None
        
    except Exception as e:
        print(f"Error loading historical results: {e}")
        return None, None

@app.route('/api/active_scans')
def get_active_scans():
    """Get list of all scans"""
    scans = []
    for scan_id, scan_info in active_scans.items():
        scan_data = scan_info.copy()
        scan_data['scan_id'] = scan_id
        scans.append(scan_data)
    
    return jsonify({'success': True, 'scans': scans})

@app.route('/api/debug/<scan_id>')
def debug_scan(scan_id):
    """Debug endpoint to check scan data"""
    debug_info = {
        'scan_id': scan_id,
        'scan_exists_in_active': scan_id in active_scans,
        'scan_exists_in_results': scan_id in scan_results,
        'active_scans_keys': list(active_scans.keys()),
        'scan_results_keys': list(scan_results.keys()),
        'total_active_scans': len(active_scans),
        'total_results': len(scan_results)
    }
    
    if scan_id in active_scans:
        debug_info['scan_info'] = active_scans[scan_id]
    
    if scan_id in scan_results:
        debug_info['has_results'] = True
        debug_info['result_type'] = str(type(scan_results[scan_id]))
    else:
        debug_info['has_results'] = False
    
    return jsonify({'success': True, 'debug': debug_info})

@app.route('/api/ai_status')
def ai_status():
    """Check AI provider status"""
    providers = {}
    
    # Check available providers
    ai_providers = ['groq', 'openai', 'anthropic', 'gemini']
    
    for provider in ai_providers:
        env_vars = {
            'groq': 'GROQ_API_KEY',
            'openai': 'OPENAI_API_KEY',
            'anthropic': 'ANTHROPIC_API_KEY',
            'gemini': 'GOOGLE_API_KEY'
        }
        
        api_key = os.getenv(env_vars.get(provider))
        providers[provider] = {
            'available': bool(api_key),
            'status': 'configured' if api_key else 'no_api_key'
        }
    
    return jsonify({'success': True, 'providers': providers})

@app.route('/results/<scan_id>')
def view_results(scan_id):
    """View results page"""
    return render_template('results.html', scan_id=scan_id)

@app.route('/api/export_results/<scan_id>/<format>')
def export_results(scan_id, format):
    """Export results in different formats"""
    try:
        # First check in-memory results
        if scan_id in scan_results:
            result = scan_results[scan_id]
        else:
            # Try to load from historical reports
            result, _ = load_historical_scan_results(scan_id)
            if not result:
                return jsonify({'success': False, 'error': 'Results not found'}), 404
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Use a cross-platform temporary directory
        import tempfile
        temp_dir = tempfile.gettempdir()
        
        if format == 'json':
            filename = f"pentest_results_{scan_id}_{timestamp}.json"
            filepath = os.path.join(temp_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, default=str)
            
            return send_file(filepath, as_attachment=True, download_name=filename)
        
        elif format == 'html':
            # Generate HTML report
            html_content = generate_html_report(result, scan_id)
            filename = f"pentest_report_{scan_id}_{timestamp}.html"
            filepath = os.path.join(temp_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return send_file(filepath, as_attachment=True, download_name=filename)
        
        else:
            return jsonify({'success': False, 'error': 'Unsupported format'}), 400
    
    except FileNotFoundError:
        return jsonify({'success': False, 'error': 'Export file not found'}), 404
    except PermissionError:
        return jsonify({'success': False, 'error': 'Permission denied writing export file'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': f'Export failed: {str(e)}'}), 500

def generate_html_report(result, scan_id):
    """Generate HTML report"""
    try:
        report_data = result.get('report', {})
        scan_options = result.get('scan_options', {})
        
        # Safely convert to JSON strings
        report_json = json.dumps(report_data, indent=2, default=str)
        options_json = json.dumps(scan_options, indent=2, default=str)
        
        # Extract key information
        target_url = scan_options.get('target_url', 'Unknown')
        ai_provider = scan_options.get('ai_provider', 'None')
        use_ai = scan_options.get('use_ai', False)
        scan_depth = scan_options.get('scan_depth', 'Unknown')
        success = result.get('success', False)
        error = result.get('error', 'None')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Penetration Test Report - {scan_id}</title>
            <meta charset="UTF-8">
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 20px; 
                    background: #f5f5f5;
                }}
                .container {{ 
                    max-width: 1200px; 
                    margin: 0 auto; 
                    background: white; 
                    border-radius: 8px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1); 
                    overflow: hidden;
                }}
                .header {{ 
                    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); 
                    color: white; 
                    padding: 30px; 
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0 0 10px 0;
                    font-size: 2.5rem;
                }}
                .section {{ 
                    margin: 0; 
                    padding: 30px; 
                    border-bottom: 1px solid #eee; 
                }}
                .section:last-child {{
                    border-bottom: none;
                }}
                .section h2 {{
                    color: #2c3e50;
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 2px solid #3498db;
                }}
                .info-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 20px;
                }}
                .info-card {{
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 8px;
                    border-left: 4px solid #3498db;
                }}
                .info-card h3 {{
                    margin: 0 0 10px 0;
                    color: #2c3e50;
                }}
                .info-card p {{
                    margin: 0;
                    color: #7f8c8d;
                }}
                .status-success {{
                    color: #27ae60;
                    font-weight: bold;
                }}
                .status-failed {{
                    color: #e74c3c;
                    font-weight: bold;
                }}
                pre {{ 
                    background: #f8f9fa; 
                    padding: 20px; 
                    border-radius: 8px;
                    border: 1px solid #dee2e6;
                    overflow-x: auto; 
                    font-size: 14px;
                    line-height: 1.4;
                }}
                .error-section {{
                    background: #f8d7da;
                    color: #721c24;
                    padding: 20px;
                    border-radius: 8px;
                    border: 1px solid #f5c6cb;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Penetration Test Report</h1>
                    <p>Scan ID: {scan_id}</p>
                    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div class="section">
                    <h2>📋 Scan Summary</h2>
                    <div class="info-grid">
                        <div class="info-card">
                            <h3>🎯 Target</h3>
                            <p>{target_url}</p>
                        </div>
                        <div class="info-card">
                            <h3>📊 Status</h3>
                            <p class="{'status-success' if success else 'status-failed'}">
                                {'✅ Completed Successfully' if success else '❌ Failed'}
                            </p>
                        </div>
                        <div class="info-card">
                            <h3>🤖 AI Analysis</h3>
                            <p>{'✅ Enabled (' + ai_provider.upper() + ')' if use_ai else '❌ Disabled'}</p>
                        </div>
                        <div class="info-card">
                            <h3>🔍 Scan Depth</h3>
                            <p>Level {scan_depth}</p>
                        </div>
                    </div>
                </div>
                
                {'<div class="error-section"><h3>❌ Scan Error</h3><p>' + str(error) + '</p></div>' if not success and error != 'None' else ''}
                
                <div class="section">
                    <h2>🔧 Scan Configuration</h2>
                    <pre>{options_json}</pre>
                </div>
                
                <div class="section">
                    <h2>📊 Detailed Results</h2>
                    <pre>{report_json}</pre>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        # Fallback simple HTML if generation fails
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Report Generation Error</title>
        </head>
        <body>
            <h1>❌ Report Generation Error</h1>
            <p>Failed to generate detailed report: {str(e)}</p>
            <h2>Raw Data:</h2>
            <pre>{json.dumps(result, indent=2, default=str)}</pre>
        </body>
        </html>
        """

def main():
    """Main function to run the GUI"""
    print("🌐 Starting Penetration Testing GUI...")
    print("=" * 50)
    print("🚀 Starting Flask server...")
    print("📱 GUI will be available at: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop the server")
    print("=" * 50)
    
    # Create templates directory if it doesn't exist
    templates_dir = Path(__file__).parent / 'templates'
    templates_dir.mkdir(exist_ok=True)
    
    # Run Flask app
    try:
        app.run(
            host='127.0.0.1',
            port=5000,
            debug=False,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == "__main__":
    main()
