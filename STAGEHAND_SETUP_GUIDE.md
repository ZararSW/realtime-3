# Stagehand Integration Setup Guide

This guide will help you set up Stagehand AI browser automation with the Advanced Intelligent Web Crawler.

## What is Stagehand?

Stagehand is an AI-powered browser automation framework that can:
- Intelligently navigate web pages using natural language commands
- Automatically discover and interact with forms, buttons, and links
- Understand page context and make smart decisions about what to test
- Generate screenshots and detailed interaction logs
- Provide more realistic user behavior simulation

## Installation Options

### Option 1: Full Stagehand Installation (Recommended for AI Mode)

1. **Install Node.js** (required for Stagehand):
   ```bash
   # Windows (using Chocolatey)
   choco install nodejs
   
   # Or download from https://nodejs.org/
   ```

2. **Install Stagehand**:
   ```bash
   npm install -g @browserbase/stagehand
   ```

3. **Install Python wrapper** (if available):
   ```bash
   pip install stagehand-python
   ```

4. **Verify installation**:
   ```bash
   node -e "console.log('Node.js:', process.version)"
   npm list -g @browserbase/stagehand
   ```

### Option 2: No-AI Mode (Selenium Only)

If you prefer to run without Stagehand, the tool will automatically fall back to Selenium:

1. **Run with --no-ai flag**:
   ```bash
   python run.py --no-ai https://example.com
   ```

2. **Comment out AI dependencies** in requirements.txt:
   ```bash
   # openai>=1.3.0
   # anthropic>=0.7.0
   # google-generativeai>=0.3.0
   # groq>=0.4.0
   ```

## Configuration

### Environment Variables

Create a `.env` file with your AI provider API keys (only needed for AI mode):

```env
# Choose your preferred AI provider
GROQ_API_KEY=your_groq_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
GOOGLE_API_KEY=your_google_api_key_here
```

### Stagehand Configuration

The tool automatically configures Stagehand with these settings:
- **Browser**: Chromium (for compatibility)
- **Headless**: True (for performance)
- **Screenshots**: Enabled (saved to screenshots/ directory)
- **Debug**: Enabled in non-headless mode

## Usage Examples

### With Stagehand AI (Full Power)
```bash
# AI-enhanced testing with Stagehand
python run.py --ai https://testphp.vulnweb.com/

# Generates comprehensive AI analysis + Stagehand automation
```

### Without Stagehand (Standard Mode)
```bash
# Rule-based testing without AI
python run.py --no-ai https://testphp.vulnweb.com/

# Uses heuristic detection + Selenium automation
```

### Mixed Mode (AI Analysis + Selenium)
```bash
# AI analysis but no Stagehand (if Stagehand fails to install)
python run.py --ai https://testphp.vulnweb.com/

# Tool will automatically fall back to Selenium if Stagehand unavailable
```

## Features Enhanced by Stagehand

When Stagehand is available and AI mode is enabled:

### 🤖 Intelligent Navigation
- AI understands page context and navigation flow
- Smart waiting for page loads and dynamic content
- Natural language form interaction

### 📝 Advanced Form Testing
- AI identifies form purpose and appropriate test vectors
- Context-aware payload selection
- Intelligent field filling strategies

### 🔗 Smart Link Discovery
- AI categorizes links by importance and functionality
- Focuses on security-relevant navigation paths
- Avoids noise (social media, external links)

### 📸 Visual Documentation
- Automatic screenshots at key testing points
- Before/after form submission captures
- Visual evidence of vulnerabilities

### 🎯 Reduced False Positives
- AI understands application context
- More accurate vulnerability detection
- Better confidence scoring

## Troubleshooting

### Stagehand Installation Issues

1. **Node.js not found**:
   ```bash
   # Verify Node.js installation
   node --version
   npm --version
   ```

2. **Permission errors**:
   ```bash
   # Use npm global prefix (Linux/Mac)
   npm config set prefix ~/.npm-global
   export PATH=~/.npm-global/bin:$PATH
   
   # Or use sudo (not recommended)
   sudo npm install -g @browserbase/stagehand
   ```

3. **Python wrapper issues**:
   ```bash
   # If stagehand-python is not available, tool will fall back to direct integration
   # This is normal and expected
   ```

### Runtime Issues

1. **Stagehand fails to initialize**:
   - Tool automatically falls back to Selenium
   - Check console output for specific error messages
   - Verify Node.js and npm installation

2. **AI API errors**:
   - Check your API key configuration
   - Verify network connectivity
   - Tool falls back to rule-based analysis

3. **Browser automation issues**:
   - Ensure Chrome/Chromium is installed
   - Check for adequate system resources
   - Review firewall and antivirus settings

## Performance Comparison

| Mode | Speed | Accuracy | Features | Requirements |
|------|-------|----------|----------|--------------|
| Stagehand + AI | Medium | Highest | Full | Node.js + API Key |
| Selenium + AI | Fast | High | Analysis Only | API Key |
| Selenium Only | Fastest | Good | Basic | None |

## Security Considerations

### API Key Security
- Store API keys in `.env` file, not in code
- Use environment variables in production
- Rotate keys regularly

### Network Security
- Stagehand makes external API calls for AI analysis
- In air-gapped environments, use --no-ai mode
- Review AI provider data handling policies

### Browser Security
- Stagehand runs with reduced browser security for testing
- Only use against authorized test targets
- Use isolated testing environments

## Integration Examples

### CI/CD Pipeline
```yaml
# GitHub Actions example
name: Security Scan
on: [push]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup Node.js
      uses: actions/setup-node@v2
      with:
        node-version: '18'
    - name: Install Stagehand
      run: npm install -g @browserbase/stagehand
    - name: Run Security Scan
      env:
        GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
      run: python run.py --ai https://staging.example.com
```

### Docker Integration
```dockerfile
FROM python:3.11

# Install Node.js for Stagehand
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
RUN apt-get install -y nodejs

# Install Stagehand
RUN npm install -g @browserbase/stagehand

# Install Python dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application
COPY . /app
WORKDIR /app

CMD ["python", "run.py", "--ai", "https://target.com"]
```

## Support and Resources

- **Stagehand Documentation**: https://docs.stagehand.dev/
- **Node.js Downloads**: https://nodejs.org/
- **AI Provider Documentation**:
  - OpenAI: https://platform.openai.com/docs
  - Anthropic: https://docs.anthropic.com/
  - Groq: https://groq.com/docs/
  - Google AI: https://ai.google.dev/docs

For issues specific to this integration, check the console output for detailed error messages and fallback behavior.
