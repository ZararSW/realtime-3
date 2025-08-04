# AI Toggle Feature Documentation

## Overview
The Intelligent Terminal AI Tool now supports enabling or disabling AI analysis, giving you full control over when to use AI-powered analysis versus fallback rule-based analysis.

## Features

### ✅ Command Line Control
Use the `--no-ai` flag to disable AI analysis completely:
```bash
# Run without AI analysis
python run.py https://example.com --no-ai

# Run with AI analysis (default behavior)
python run.py https://example.com

# Specify AI provider and disable AI (contradictory but handled gracefully)
python run.py https://example.com --ai-provider groq --no-ai
```

### ✅ Programmatic Control
Control AI usage when creating `AIAnalyzer` instances:

```python
from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer

# Disable AI from initialization
analyzer = AIAnalyzer(enable_ai=False)

# Enable AI with specific provider
analyzer = AIAnalyzer(
    model="groq",
    api_key="your-api-key",
    enable_ai=True
)

# Runtime toggle
analyzer.set_ai_enabled(False)  # Disable AI
analyzer.set_ai_enabled(True)   # Re-enable AI

# Check current status
if analyzer.is_ai_enabled():
    print("AI is currently enabled")
```

### ✅ Graceful Fallback
When AI is disabled, the tool automatically uses:
- **Rule-based analysis** for command execution results
- **Basic vulnerability detection** using pattern matching
- **Standard security testing** without AI enhancement
- **Comprehensive fallback logic** for all analysis types

## Method Behavior

### Core Analysis Methods
| Method | AI Enabled | AI Disabled |
|--------|------------|-------------|
| `analyze_execution()` | Uses AI provider for analysis | Uses rule-based fallback |
| `analyze_api_response()` | AI-powered API analysis | Basic HTTP status analysis |
| `analyze_text_prompt()` | Full AI processing | Returns error with fallback message |

### Specialized Vulnerability Analysis
| Method | AI Enabled | AI Disabled |
|--------|------------|-------------|
| `analyze_sqli_vulnerability()` | Advanced AI-generated payloads | Returns error with `fallback_used: true` |
| `analyze_xss_vulnerability()` | Context-aware XSS payloads | Returns error with `fallback_used: true` |
| `analyze_logical_flaws()` | Intelligent IDOR/Path traversal analysis | Returns error with `fallback_used: true` |

## Use Cases

### 🔸 When to Disable AI
- **No API key available**: Avoid API call failures
- **Privacy concerns**: Keep all analysis local
- **Speed requirements**: Faster analysis without API calls
- **Offline environments**: No internet connectivity
- **Cost control**: Avoid AI service charges
- **Testing fallback logic**: Verify non-AI functionality

### 🔸 When to Enable AI
- **Advanced vulnerability analysis**: Sophisticated payload generation
- **Context-aware testing**: AI understands target technology
- **Complex error analysis**: Better interpretation of results
- **Adaptive testing**: AI learns from responses
- **Comprehensive reporting**: Detailed analysis and recommendations

## Configuration Examples

### Environment-Based Configuration
```python
import os

# Disable AI if no API key is available
enable_ai = bool(os.getenv("GROQ_API_KEY"))
analyzer = AIAnalyzer(
    model="groq",
    api_key=os.getenv("GROQ_API_KEY"),
    enable_ai=enable_ai
)
```

### Conditional AI Usage
```python
# Enable AI for production targets, disable for internal testing
target_url = "https://example.com"
use_ai = not target_url.startswith("http://localhost")

analyzer = AIAnalyzer(enable_ai=use_ai)
```

### Runtime Configuration
```python
analyzer = AIAnalyzer(enable_ai=True)

# Disable AI for specific operations
analyzer.set_ai_enabled(False)
basic_result = await analyzer.analyze_execution(command_result)

# Re-enable for advanced analysis
analyzer.set_ai_enabled(True)
advanced_result = await analyzer.analyze_sqli_vulnerability(...)
```

## Output Differences

### With AI Enabled
```json
{
  "success": true,
  "message": "AI-powered analysis of SQL injection vulnerability",
  "sqli_analysis": [
    {
      "technique": "Error-Based",
      "payload": "' OR 1=1 -- ",
      "rationale": "Classic error-based test for MySQL...",
      "confidence_score": 8
    }
  ],
  "provider": "groq"
}
```

### With AI Disabled
```json
{
  "success": false,
  "error": "AI analysis is disabled",
  "sqli_analysis": [],
  "fallback_used": true
}
```

## Error Handling

The AI toggle feature includes comprehensive error handling:

- **Graceful degradation**: Falls back to rule-based analysis
- **Clear messaging**: Indicates when AI is disabled
- **Consistent interface**: Same method signatures regardless of AI status
- **Fallback indicators**: `fallback_used` flag in responses

## Best Practices

### ✅ Recommended Practices
1. **Check AI status** before advanced analysis:
   ```python
   if analyzer.is_ai_enabled():
       result = await analyzer.analyze_sqli_vulnerability(...)
   else:
       print("Advanced analysis requires AI - using basic detection")
   ```

2. **Handle fallback gracefully**:
   ```python
   result = await analyzer.analyze_sqli_vulnerability(...)
   if result.get("fallback_used"):
       print("Using basic vulnerability detection")
   ```

3. **Use environment variables** for API keys:
   ```python
   analyzer = AIAnalyzer(
       model="groq",
       api_key=os.getenv("GROQ_API_KEY"),
       enable_ai=bool(os.getenv("GROQ_API_KEY"))
   )
   ```

### ❌ Things to Avoid
1. Don't assume AI is always available
2. Don't ignore the `fallback_used` flag
3. Don't mix AI providers without checking compatibility
4. Don't forget to handle API key errors

## Migration Guide

### From Previous Versions
If you're upgrading from a version without AI toggle:

```python
# Old code
analyzer = AIAnalyzer(model="groq", api_key="key")

# New code (same behavior)
analyzer = AIAnalyzer(model="groq", api_key="key", enable_ai=True)

# Or disable AI
analyzer = AIAnalyzer(model="groq", api_key="key", enable_ai=False)
```

### Command Line Changes
```bash
# Old command (AI always attempted)
python run.py https://example.com

# New options
python run.py https://example.com           # AI enabled (if configured)
python run.py https://example.com --no-ai   # AI disabled
```

## Troubleshooting

### Common Issues

**Q: AI is disabled even with `enable_ai=True`**
A: Check if the AI provider is available and API key is valid

**Q: Getting "fallback_used: true" unexpectedly**
A: Verify AI is enabled with `analyzer.is_ai_enabled()`

**Q: Performance is slow with AI disabled**
A: This is expected - the tool should be faster without AI calls

**Q: Missing vulnerability analysis**
A: Some advanced analysis requires AI - check the `fallback_used` flag

### Debug Commands
```python
# Check AI status
print(f"AI Enabled: {analyzer.is_ai_enabled()}")
print(f"Provider: {analyzer.provider}")

# Test AI functionality
result = await analyzer.analyze_text_prompt("Test prompt")
print(f"AI Working: {result.success}")
```

## Example Implementation

See the complete example in `examples/ai_toggle_example.py` and test your setup with `test_ai_toggle.py`.

This feature gives you complete control over AI usage while maintaining full functionality through intelligent fallback mechanisms.
