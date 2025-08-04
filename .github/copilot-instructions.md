<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# Intelligent Terminal AI Tool - Copilot Instructions

This is an AI-powered terminal assistant that can execute commands, analyze responses, automate browser testing, and self-correct errors using artificial intelligence.

## Project Overview

The tool combines several key technologies:
- **Async Python**: All operations are asynchronous for better performance
- **AI Integration**: OpenAI GPT-4 and Anthropic Claude for intelligent analysis
- **Browser Automation**: Selenium with Chrome/Chromium for visual testing
- **Terminal Execution**: Cross-platform command execution with error capture
- **Response Analysis**: Deep inspection of HTTP responses and web content

## Code Style Guidelines

1. **Use async/await** for all I/O operations
2. **Type hints** are required for all function parameters and return values
3. **Pydantic models** for data validation and serialization
4. **Rich logging** with structured output
5. **Error handling** with detailed context and suggestions
6. **Cross-platform compatibility** (Windows, macOS, Linux)

## Key Patterns

### Error Handling
```python
try:
    result = await some_operation()
    if not result.success:
        self.logger.warning(f"Operation failed: {result.message}")
    return result
except Exception as e:
    self.logger.error(f"Unexpected error: {e}")
    return fallback_result()
```

### AI Integration
```python
# Always provide fallback when AI services are unavailable
if self.client is None:
    return await self._fallback_analysis(data)

try:
    ai_result = await self._analyze_with_ai(prompt)
    return ai_result
except Exception as e:
    self.logger.error(f"AI analysis failed: {e}")
    return await self._fallback_analysis(data)
```

### Configuration Management
```python
# Use configuration system for all settings
timeout = config.get("terminal", "timeout", 30)
headless = config.get("browser", "headless", False)
```

## Architecture Components

1. **IntelligentTerminalAI** (main.py): Main orchestrator
2. **TerminalExecutor**: Command execution with error capture
3. **BrowserAutomator**: Selenium-based browser testing
4. **AIAnalyzer**: AI-powered analysis and suggestions
5. **ResponseInspector**: HTTP/web content analysis

## Common Scenarios

### Adding New AI Providers
- Extend the `AIAnalyzer` class
- Add provider-specific client initialization
- Implement analysis methods following existing patterns
- Always include fallback analysis

### Adding New Command Patterns
- Update `TerminalExecutor` for platform-specific handling
- Add error pattern recognition in `AIAnalyzer`
- Include common error solutions in fallback analysis

### Browser Automation Extensions
- Use Selenium WebDriver patterns
- Handle timeouts and exceptions gracefully
- Always take screenshots for debugging
- Support both headless and headed modes

## Dependencies and Imports

- Use relative imports within the package: `from ..models.command_result import CommandResult`
- External dependencies should be optional with fallbacks
- Check availability before importing: `try: import openai` pattern

## Testing Considerations

When writing test-related code:
- Mock external services (AI APIs, browsers)
- Test both success and failure scenarios
- Include cross-platform command variations
- Test with and without AI services available
