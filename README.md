# Advanced Intelligent Web Crawler & AI Penetration Tester

🚀 **Next-generation autonomous security testing with AI-powered browser automation**

## Overview
A production-grade, modular, AI-powered web crawler and penetration testing framework featuring Stagehand AI browser automation, real-time vulnerability detection, and comprehensive security analysis.

## 🌟 Key Features

### 🤖 AI-Powered Analysis
- **Multiple AI Providers**: OpenAI GPT-4, Anthropic Claude, Google Gemini, Groq
- **Smart Payload Generation**: Context-aware vulnerability testing
- **Intelligent Risk Assessment**: AI-powered confidence scoring
- **No-AI Fallback**: Rule-based heuristics when AI is unavailable

### ✨ Stagehand AI Browser Automation
- **Natural Language Navigation**: AI understands page context and user flows
- **Intelligent Form Discovery**: Automatically identifies and categorizes forms
- **Smart Interaction**: Context-aware form filling and testing
- **Visual Documentation**: Automatic screenshots at key testing points
- **Fallback Support**: Graceful degradation to Selenium when unavailable

### 🔍 Advanced Security Testing
- **Comprehensive Vulnerability Detection**: XSS, SQL Injection, SSRF, IDOR, CSRF
- **WordPress-Specific Testing**: Plugin enumeration, version detection, security checks
- **Real-time Monitoring**: DOM changes, console logs, network traffic
- **Stealth Automation**: Anti-detection browser configuration

### 📊 Professional Reporting
- **Multiple Output Formats**: Console, HTML, JSON, text reports
- **Visual Evidence**: Screenshots and interaction logs
- **Risk Scoring**: Confidence-based vulnerability assessment
- **Actionable Recommendations**: Specific remediation guidance

## 🚀 Quick Start

### Installation Options

#### Option 1: Full Installation (AI + Stagehand)
```bash
# Install Node.js for Stagehand
# Windows: Download from https://nodejs.org/
# Linux: sudo apt install nodejs npm
# macOS: brew install node

# Install Stagehand
npm install -g @browserbase/stagehand

# Install Python dependencies
pip install -r requirements.txt

# Set up API keys (optional but recommended)
cp .env.example .env
# Edit .env with your AI provider API keys
```

#### Option 2: No-AI Installation (Fastest)
```bash
# Install only core dependencies
pip install requests selenium beautifulsoup4 rich pyyaml python-dotenv

# Comment out AI dependencies in requirements.txt
# No API keys needed
```

### Basic Usage

#### AI-Enhanced Testing (Recommended)
```bash
# Full AI + Stagehand automation
python run.py --ai https://example.com

# Generate HTML report
python run.py --ai --output report.html https://example.com
```

#### No-AI Mode (Fast & Reliable)
```bash
# Rule-based testing without external dependencies
python run.py --no-ai https://example.com

# Generate JSON report
python run.py --no-ai --output results.json https://example.com
```

#### Testing Options
```bash
# Test vulnerable application
python run.py --ai https://testphp.vulnweb.com/

# WordPress-specific testing
python run.py --ai https://wordpress-site.com

# Quick vulnerability scan
python run.py --no-ai --output scan.txt https://target.com
```

## 🛠️ Configuration

### Environment Variables (.env)
```env
# Choose your preferred AI provider
GROQ_API_KEY=your_groq_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
GOOGLE_API_KEY=your_google_api_key_here
```

### Command Line Options
- `--ai`: Enable AI-powered analysis
- `--no-ai`: Disable AI analysis (rule-based only)
- `--output FILE`: Save report to file (supports .html, .json, .txt)
- `--gui`: Launch web interface on localhost:5000

## 🎯 Testing Modes Comparison

| Feature | AI + Stagehand | AI + Selenium | No-AI Mode |
|---------|----------------|---------------|------------|
| Speed | Medium | Fast | Fastest |
| Accuracy | Highest | High | Good |
| Setup Complexity | Complex | Medium | Simple |
| Dependencies | Node.js + API Key | API Key | None |
| Form Testing | Intelligent | Smart | Rule-based |
| Vulnerability Detection | Context-aware | AI-powered | Heuristic |
| False Positives | Lowest | Low | Medium |

## 📦 Install as a package (optional)

```bash
# Core + dev tooling, with a `webscan` console command
pip install -e ".[dev]"

# Add AI providers
pip install -e ".[ai]"

# Then run from anywhere:
webscan https://testphp.vulnweb.com/ --no-ai
```

## 🧪 Running the Tests

The project ships a pytest suite covering the URL validation, risk/CVSS
scoring, report transforms, and the rule-based AI-policy fallback.

```bash
pip install -e ".[dev]"   # or: pip install pytest pytest-asyncio
pytest -q

# Quick smoke test against a safe, intentionally-vulnerable target
python run.py --no-ai https://testphp.vulnweb.com/
```

CI runs the same suite on Python 3.9 and 3.11 (see `.github/workflows/ci.yml`).

## 📁 Project Structure

```
run.py                       # thin shim -> scanner.cli:main (keeps `python run.py <url>`)
scanner/                     # the application package
  cli.py                     # CLI entry point (also the `webscan` console command)
  crawler.py                 # main crawler + vulnerability-testing engine
  ai_policy.py               # AI / rule-based payload + response-analysis policy
  stagehand_integration.py   # optional Stagehand AI browser automation
  report_generator.py        # report generation helpers
  gui_app.py                 # Flask web UI (python run.py --gui)
  logging_config.py          # structured logging + secret-redacting SecurityFilter
  error_handler.py           # retry/recovery decorators and error utilities
  config_loader.py / config_validator.py / constants.py
intelligent_terminal_ai/     # AI analyzer, config, logging, models package
tests/                       # pytest suite
pyproject.toml               # packaging, dependencies, console script, pytest config
```

## Extending
- Add new payloads / detection logic in `scanner/crawler.py` or `scanner/ai_policy.py`
- Plug in new AI providers in `intelligent_terminal_ai/core/ai_analyzer.py`
- Customize reporting in `scanner/report_generator.py`
- Add tests under `tests/` (they import from the `scanner` package directly)

## Security & Privacy
- All logs are sanitized for sensitive data
- API keys and secrets are loaded from environment/config (never commit `.env`)
- Reports and logs are privacy-aware by default

## License
MIT
