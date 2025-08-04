# 🤖 AI Provider Usage Guide

Your penetration testing tool now supports multiple AI providers! Here's how to use them:

## 🚀 Quick Start

### Using Groq (Default - Already Configured)
```bash
# Use default Groq configuration
venv\Scripts\python.exe run.py http://testphp.vulnweb.com/ --output groq_report.html

# Specify Groq explicitly  
venv\Scripts\python.exe run.py http://testphp.vulnweb.com/ --ai-provider groq --output report.html

# Use different Groq model
venv\Scripts\python.exe run.py http://testphp.vulnweb.com/ --ai-provider groq --ai-model llama3-8b-8192
```

### Using Gemini
```bash
# Switch to Gemini (requires GOOGLE_API_KEY environment variable)
venv\Scripts\python.exe run.py http://testphp.vulnweb.com/ --ai-provider gemini --output gemini_report.html

# Use specific Gemini model
venv\Scripts\python.exe run.py http://testphp.vulnweb.com/ --ai-provider gemini --ai-model gemini-2.0-flash-exp
```

### Using OpenAI
```bash
# Switch to OpenAI (requires OPENAI_API_KEY environment variable)
venv\Scripts\python.exe run.py http://testphp.vulnweb.com/ --ai-provider openai --output openai_report.html
```

### Using Anthropic Claude
```bash
# Switch to Claude (requires ANTHROPIC_API_KEY environment variable)
venv\Scripts\python.exe run.py http://testphp.vulnweb.com/ --ai-provider anthropic --output claude_report.html
```

## 🔧 Configuration Management

### Show Current Configuration
```bash
venv\Scripts\python.exe ai_provider_config.py --show
```

### Switch Providers Permanently
```bash
# Switch to Groq
venv\Scripts\python.exe ai_provider_config.py --switch groq

# Switch to Gemini  
venv\Scripts\python.exe ai_provider_config.py --switch gemini

# Switch to OpenAI
venv\Scripts\python.exe ai_provider_config.py --switch openai

# Switch to Claude
venv\Scripts\python.exe ai_provider_config.py --switch anthropic
```

### Test Provider Connection
```bash
# Test current provider
venv\Scripts\python.exe ai_provider_config.py --test

# Test specific provider
venv\Scripts\python.exe ai_provider_config.py --test groq
venv\Scripts\python.exe ai_provider_config.py --test gemini
```

### Interactive Configuration
```bash
# Launch interactive configuration menu
venv\Scripts\python.exe ai_provider_config.py
```

## 🗂️ Current API Keys

### ✅ Groq (Ready to Use)
- **API Key**: `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`
- **Models**: `llama-3.1-8b-instant`, `llama3-8b-8192`, `gemma-7b-it`

### ⚠️ Gemini (Requires Setup)
- **Environment Variable**: Set `GOOGLE_API_KEY`
- **Models**: `gemini-2.0-flash-exp`, `gemini-1.5-pro`

### ⚠️ OpenAI (Requires Setup)  
- **Environment Variable**: Set `OPENAI_API_KEY`
- **Models**: `gpt-4`, `gpt-3.5-turbo`

### ⚠️ Anthropic (Requires Setup)
- **Environment Variable**: Set `ANTHROPIC_API_KEY`  
- **Models**: `claude-3-sonnet-20240229`, `claude-3-haiku-20240307`

## 🎯 Comparison

| Provider | Speed | Cost | Security Focus | Best For |
|----------|-------|------|----------------|----------|
| **Groq** | ⚡⚡⚡ Very Fast | 💰 Low | 🛡️ Good | Real-time analysis |
| **Gemini** | ⚡⚡ Fast | 💰💰 Medium | 🛡️🛡️ Very Good | Comprehensive analysis |  
| **OpenAI** | ⚡ Medium | 💰💰💰 High | 🛡️🛡️🛡️ Excellent | Advanced reasoning |
| **Claude** | ⚡ Medium | 💰💰💰 High | 🛡️🛡️🛡️ Excellent | Detailed reports |

## 🔄 Switching Examples

### Compare Multiple Providers on Same Target
```bash
# Test with Groq
venv\Scripts\python.exe run.py http://testphp.vulnweb.com/ --ai-provider groq --output groq_analysis.html

# Test with Gemini (if configured)
venv\Scripts\python.exe run.py http://testphp.vulnweb.com/ --ai-provider gemini --output gemini_analysis.html

# Compare results!
```

## 🛠️ Advanced Usage

### Environment Variables Setup
```bash
# Windows PowerShell
$env:GOOGLE_API_KEY="your_gemini_api_key_here"
$env:OPENAI_API_KEY="your_openai_api_key_here" 
$env:ANTHROPIC_API_KEY="your_claude_api_key_here"

# Windows Command Prompt
set GOOGLE_API_KEY=your_gemini_api_key_here
set OPENAI_API_KEY=your_openai_api_key_here
set ANTHROPIC_API_KEY=your_claude_api_key_here
```

### Configuration File (config.yaml)
The tool automatically reads from `config.yaml`. You can edit it directly:

```yaml
ai:
  provider: "groq"  # Change this to switch default provider
  
  groq:
    model: "llama-3.1-8b-instant"
    api_key: "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"
    
  gemini:
    model: "gemini-2.0-flash-exp"
    api_key_env: "GOOGLE_API_KEY"
```

## ✨ Features by Provider

### 🦙 Groq Advantages
- **Lightning Fast**: Sub-second response times
- **Cost Effective**: Free tier available
- **Multiple Models**: Llama, Mixtral, Gemma options
- **Real-time Streaming**: See analysis as it happens

### 🧬 Gemini Advantages  
- **Multimodal**: Can analyze images and code
- **Large Context**: Handle big vulnerability reports
- **Google Integration**: Latest security intelligence
- **Advanced Reasoning**: Complex attack chain analysis

### 🤖 OpenAI Advantages
- **GPT-4 Power**: Most advanced reasoning
- **Security Expertise**: Trained on cybersecurity data
- **Consistent Output**: Reliable JSON formatting
- **Plugin Ecosystem**: Extensible capabilities

### 🎭 Claude Advantages
- **Safety First**: Built-in security awareness
- **Long Context**: Analyze entire codebases
- **Detailed Reports**: Comprehensive explanations
- **Ethical AI**: Responsible vulnerability disclosure

Choose the provider that best fits your needs! 🚀
