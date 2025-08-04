# Web GUI Documentation

## Overview
The Intelligent Terminal AI Tool now includes a modern web-based GUI that runs on localhost, providing an intuitive interface for penetration testing operations.

## Features

### 🌐 **Web Interface**
- **Modern responsive design** that works on desktop and mobile
- **Real-time scan monitoring** with live status updates
- **AI provider status** display with configuration detection
- **Interactive results viewer** with detailed vulnerability analysis
- **Export functionality** for JSON and HTML reports

### 🚀 **Easy Launch**
```bash
# Launch the GUI
python run.py --gui

# Then open your browser to:
http://localhost:5000
```

### ✨ **Key Capabilities**
- ✅ **Start new scans** with customizable options
- ✅ **Monitor active scans** in real-time
- ✅ **View detailed results** with vulnerability breakdown
- ✅ **Export reports** in multiple formats
- ✅ **AI provider management** with automatic detection
- ✅ **Scan history** with persistent storage

## Installation

### Prerequisites
```bash
# Install GUI dependencies
pip install flask>=2.3.0

# Or install all requirements
pip install -r requirements.txt
```

### Verify Installation
```bash
# Test GUI functionality
python test_gui.py
```

## Usage Guide

### 1. Launch the GUI
```bash
python run.py --gui
```

The server will start and display:
```
🌐 Starting Penetration Testing GUI...
📱 GUI will be available at: http://localhost:5000
🛑 Press Ctrl+C to stop the server
```

### 2. Access the Interface
Open your web browser and navigate to:
- **Local access**: `http://localhost:5000`
- **Network access**: `http://127.0.0.1:5000`

### 3. Configure AI Providers
The GUI automatically detects available AI providers based on environment variables:

```bash
# Set up AI provider keys
export GROQ_API_KEY="your-groq-key"
export OPENAI_API_KEY="your-openai-key" 
export ANTHROPIC_API_KEY="your-anthropic-key"
export GOOGLE_API_KEY="your-google-key"
```

### 4. Start a Scan
1. **Enter target URL** (e.g., `https://testphp.vulnweb.com`)
2. **Select scan depth**:
   - Level 1: WordPress Focus
   - Level 2: Balanced Security Testing (recommended)
   - Level 3: Deep Security Analysis
3. **Configure AI settings**:
   - Toggle AI analysis on/off
   - Select AI provider (Groq recommended)
4. **Click "Start Penetration Test"**

### 5. Monitor Progress
- **Real-time updates** every 5 seconds
- **Status indicators**: Running, Completed, Failed
- **Scan history** with timestamps and configurations

### 6. View Results
- **Click "View Results"** on completed scans
- **Interactive vulnerability viewer** with expandable details
- **Risk-based color coding** (Critical, High, Medium, Low)
- **Export options** for reports

## API Endpoints

The GUI provides a REST API for programmatic access:

### Scan Management
```bash
# Start new scan
POST /api/start_scan
{
  "target_url": "https://example.com",
  "scan_depth": "2",
  "use_ai": true,
  "ai_provider": "groq"
}

# Get scan status
GET /api/scan_status/<scan_id>

# Get scan results
GET /api/scan_results/<scan_id>

# List all scans
GET /api/active_scans
```

### System Status
```bash
# Check AI provider status
GET /api/ai_status

# Export results
GET /api/export_results/<scan_id>/json
GET /api/export_results/<scan_id>/html
```

## Configuration Options

### Server Configuration
The GUI runs with these default settings:
- **Host**: `127.0.0.1` (localhost only)
- **Port**: `5000`
- **Debug**: `False` (production mode)
- **Threading**: `True` (multi-threaded)

### Customization
To customize the server configuration, modify `gui_app.py`:

```python
app.run(
    host='0.0.0.0',  # Allow external access
    port=8080,       # Custom port
    debug=True,      # Enable debug mode
    threaded=True
)
```

## Security Considerations

### Local Access Only
By default, the GUI binds to `127.0.0.1` (localhost) for security:
- **Prevents external access** to your penetration testing tool
- **Protects sensitive scan results** from network exposure
- **Reduces attack surface** of the application

### Production Deployment
If you need to deploy in a production environment:

```python
# Add authentication middleware
from flask_login import LoginManager

# Configure HTTPS
app.run(ssl_context='adhoc')

# Set security headers
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```

## Troubleshooting

### Common Issues

**Q: GUI won't start - "ImportError: No module named 'flask'"**
```bash
# Install Flask
pip install flask

# Or install all requirements
pip install -r requirements.txt
```

**Q: "Address already in use" error**
```bash
# Check what's using port 5000
netstat -an | grep 5000

# Kill the process or use a different port
# Modify gui_app.py to use port 8080
```

**Q: AI providers show as "unavailable"**
```bash
# Set up environment variables
export GROQ_API_KEY="your-api-key"

# Restart the GUI
python run.py --gui
```

**Q: Scans fail to start**
- Verify target URL is accessible
- Check AI provider configuration
- Review console logs for detailed errors

### Debug Mode
Enable debug mode for development:

```python
# In gui_app.py
app.run(debug=True)
```

This provides:
- **Detailed error pages** with stack traces
- **Auto-reload** on file changes
- **Enhanced logging** for troubleshooting

## Advanced Usage

### Programmatic API Access
```python
import requests

# Start a scan programmatically
response = requests.post('http://localhost:5000/api/start_scan', json={
    'target_url': 'https://example.com',
    'scan_depth': '2',
    'use_ai': True,
    'ai_provider': 'groq'
})

scan_id = response.json()['scan_id']

# Monitor scan progress
status_response = requests.get(f'http://localhost:5000/api/scan_status/{scan_id}')
print(status_response.json())
```

### Custom Extensions
The GUI is built with a modular architecture:

```python
# Add custom endpoints
@app.route('/api/custom_analysis', methods=['POST'])
def custom_analysis():
    # Your custom analysis logic
    return jsonify({'success': True})

# Add custom templates
# Create: templates/custom_page.html
@app.route('/custom')
def custom_page():
    return render_template('custom_page.html')
```

## Performance Optimization

### Background Processing
Scans run in separate threads to prevent blocking:
- **Non-blocking UI** during scan execution
- **Multiple concurrent scans** supported
- **Real-time progress updates** via polling

### Memory Management
- **Automatic cleanup** of completed scans
- **Configurable result retention** period
- **Efficient data structures** for scan storage

### Network Optimization
- **Compressed responses** for large results
- **Efficient polling** with exponential backoff
- **Client-side caching** of static resources

## Integration Examples

### CI/CD Pipeline
```yaml
# GitHub Actions example
- name: Run Security Scan
  run: |
    python run.py --gui &
    GUI_PID=$!
    
    # Wait for GUI to start
    sleep 5
    
    # Trigger scan via API
    curl -X POST http://localhost:5000/api/start_scan \
      -H "Content-Type: application/json" \
      -d '{"target_url": "${{ env.TARGET_URL }}", "use_ai": false}'
    
    # Kill GUI
    kill $GUI_PID
```

### Automated Reporting
```python
# Generate daily reports
import schedule
import time

def daily_scan():
    # Start scan via API
    # Wait for completion
    # Export and email results
    pass

schedule.every().day.at("02:00").do(daily_scan)

while True:
    schedule.run_pending()
    time.sleep(1)
```

The web GUI provides a comprehensive, user-friendly interface for all penetration testing operations while maintaining the full power and flexibility of the command-line tool.
