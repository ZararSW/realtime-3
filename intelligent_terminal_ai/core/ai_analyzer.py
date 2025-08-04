"""
AI-powered analyzer for command results and error correction
"""

import asyncio
import json
from typing import Dict, Any, Optional, List
from datetime import datetime

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import google.generativeai as genai
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

from ..models.command_result import CommandResult, BrowserResult, AnalysisResult
from ..utils.logger import setup_logger


class AIAnalyzer:
    """
    Uses AI models to analyze command results and suggest improvements
    """
    
    def __init__(self, model: str = "gpt-4", api_key: Optional[str] = None, enable_ai: bool = True):
        """
        Initialize the AI analyzer
        
        Args:
            model: AI model to use ("gpt-4", "gpt-3.5-turbo", "claude-3", etc.)
            api_key: API key for the AI service
            enable_ai: Whether to enable AI analysis (if False, will use fallback analysis)
        """
        self.model = model
        self.enable_ai = enable_ai
        self.logger = setup_logger(__name__)
        
        # Initialize AI client only if AI is enabled
        if not enable_ai:
            self.logger.info("AI analysis disabled - using fallback analysis only")
            self.client = None
            self.provider = "fallback"
        elif model.startswith("gpt") and OPENAI_AVAILABLE:
            self.client = openai.OpenAI(api_key=api_key)
            self.provider = "openai"
        elif model.startswith("claude") and ANTHROPIC_AVAILABLE:
            self.client = anthropic.Anthropic(api_key=api_key)
            self.provider = "anthropic"
        elif model.startswith("gemini") and GOOGLE_AVAILABLE:
            genai.configure(api_key=api_key)
            self.client = genai.GenerativeModel(model)
            self.provider = "google"
        elif model.startswith("groq") and GROQ_AVAILABLE:
            self.client = Groq(api_key=api_key)
            self.provider = "groq"
        else:
            self.logger.warning("No AI provider available - using fallback analysis")
            self.client = None
            self.provider = "fallback"
    
    def set_ai_enabled(self, enabled: bool) -> None:
        """
        Enable or disable AI analysis at runtime
        
        Args:
            enabled: Whether to enable AI analysis
        """
        old_state = self.enable_ai
        self.enable_ai = enabled
        
        if enabled != old_state:
            if enabled:
                self.logger.info("AI analysis enabled")
            else:
                self.logger.info("AI analysis disabled - switching to fallback analysis")
    
    def is_ai_enabled(self) -> bool:
        """
        Check if AI analysis is currently enabled
        
        Returns:
            True if AI analysis is enabled, False otherwise
        """
        return self.enable_ai and self.client is not None
    
    async def analyze_execution(self, 
                              command_result: CommandResult,
                              browser_result: Optional[BrowserResult] = None,
                              context: Optional[Dict[str, Any]] = None,
                              history: Optional[List[Dict[str, Any]]] = None) -> AnalysisResult:
        """
        Analyze command execution results and provide suggestions
        
        Args:
            command_result: Result of command execution
            browser_result: Optional browser test result
            context: Additional context information
            history: Previous execution history
            
        Returns:
            AnalysisResult with analysis and suggestions
        """
        self.logger.info(f"Analyzing execution of: {command_result.command}")
        
        if not self.enable_ai or self.client is None:
            return await self._fallback_analysis(command_result, browser_result)
        
        # Prepare analysis prompt
        prompt = self._build_analysis_prompt(
            command_result, browser_result, context, history
        )
        
        try:
            if self.provider == "openai":
                response = await self._analyze_with_openai(prompt)
            elif self.provider == "anthropic":
                response = await self._analyze_with_anthropic(prompt)
            elif self.provider == "google":
                response = await self._analyze_with_google(prompt)
            elif self.provider == "groq":
                response = await self._analyze_with_groq(prompt)
            else:
                response = await self._fallback_analysis(command_result, browser_result)
            
            self.logger.info("AI analysis completed")
            return response
            
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return await self._fallback_analysis(command_result, browser_result)
    
    async def analyze_api_response(self, 
                                 api_result: CommandResult,
                                 browser_result: Optional[BrowserResult] = None) -> AnalysisResult:
        """
        Analyze API response and provide insights
        
        Args:
            api_result: API request result
            browser_result: Optional browser test result
            
        Returns:
            AnalysisResult with API analysis
        """
        self.logger.info(f"Analyzing API response for: {api_result.command}")
        
        if not self.enable_ai or self.client is None:
            return await self._fallback_api_analysis(api_result, browser_result)
        
        prompt = self._build_api_analysis_prompt(api_result, browser_result)
        
        try:
            if self.provider == "openai":
                response = await self._analyze_with_openai(prompt)
            elif self.provider == "anthropic":
                response = await self._analyze_with_anthropic(prompt)
            elif self.provider == "google":
                response = await self._analyze_with_google(prompt)
            elif self.provider == "groq":
                response = await self._analyze_with_groq(prompt)
            else:
                response = await self._fallback_api_analysis(api_result, browser_result)
            
            self.logger.info("API analysis completed")
            return response
            
        except Exception as e:
            self.logger.error(f"API analysis failed: {e}")
            return await self._fallback_api_analysis(api_result, browser_result)
    
    async def analyze_text_prompt(self, prompt: str) -> AnalysisResult:
        """
        Analyze a text prompt using the configured AI provider
        
        Args:
            prompt: Text prompt to analyze
            
        Returns:
            AnalysisResult with AI analysis
        """
        if not self.enable_ai or self.client is None:
            return AnalysisResult(
                success=False,
                message="AI analysis disabled or no AI provider available",
                analysis="Fallback analysis: AI analysis is disabled or no provider configured"
            )
        
        try:
            if self.provider == "openai":
                response = await self._analyze_with_openai(prompt)
            elif self.provider == "anthropic":
                response = await self._analyze_with_anthropic(prompt)
            elif self.provider == "google":
                response = await self._analyze_with_google(prompt)
            elif self.provider == "groq":
                response = await self._analyze_with_groq(prompt)
            else:
                return AnalysisResult(
                    success=False,
                    message="Unknown AI provider",
                    analysis="No valid AI provider configured"
                )
            
            return response
            
        except Exception as e:
            self.logger.error(f"Text prompt analysis failed: {e}")
            return AnalysisResult(
                success=False,
                message=f"AI analysis error: {str(e)}",
                analysis="Error occurred during AI analysis"
            )
    
    async def analyze_with_prompt(self, prompt: str) -> Dict[str, Any]:
        """
        Analyze using a custom prompt and return raw response
        
        Args:
            prompt: Custom prompt to send to AI provider
            
        Returns:
            Dict containing the AI response
        """
        if not self.enable_ai or self.client is None:
            return {
                "success": False,
                "response": "AI analysis disabled or no AI provider available",
                "analysis": "Fallback analysis: AI analysis is disabled or no provider configured"
            }
        
        try:
            if self.provider == "openai":
                response = await asyncio.to_thread(
                    self.client.chat.completions.create,
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are an expert cybersecurity analyst and penetration tester."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    max_tokens=2000
                )
                return {
                    "success": True,
                    "response": response.choices[0].message.content,
                    "provider": self.provider
                }
                
            elif self.provider == "anthropic":
                response = await asyncio.to_thread(
                    self.client.messages.create,
                    model=self.model,
                    max_tokens=2000,
                    temperature=0.1,
                    messages=[{"role": "user", "content": prompt}]
                )
                return {
                    "success": True,
                    "response": response.content[0].text,
                    "provider": self.provider
                }
                
            elif self.provider == "google":
                response = await asyncio.to_thread(
                    self.client.generate_content,
                    prompt
                )
                return {
                    "success": True,
                    "response": response.text,
                    "provider": self.provider
                }
                
            elif self.provider == "groq":
                completion = await asyncio.to_thread(
                    self.client.chat.completions.create,
                    model="llama-3.1-8b-instant",
                    messages=[
                        {"role": "system", "content": "You are an expert cybersecurity analyst and penetration tester specializing in web application vulnerabilities."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                    max_completion_tokens=2000,
                    top_p=1,
                    stream=False,
                    stop=None
                )
                return {
                    "success": True,
                    "response": completion.choices[0].message.content,
                    "provider": self.provider
                }
                
            else:
                return {
                    "success": False,
                    "response": "Unknown AI provider",
                    "provider": self.provider
                }
            
        except Exception as e:
            self.logger.error(f"Custom prompt analysis failed: {e}")
            return {
                "success": False,
                "response": f"AI analysis error: {str(e)}",
                "error": str(e)
            }
    
    async def analyze_sqli_vulnerability(self, 
                                       url: str,
                                       parameter_name: str,
                                       http_method: str,
                                       technology_stack: str,
                                       html_snippet: str) -> Dict[str, Any]:
        """
        Specialized SQL injection vulnerability analysis
        
        Args:
            url: Target URL
            parameter_name: Vulnerable parameter name
            http_method: HTTP method (GET, POST, etc.)
            technology_stack: Known technology stack (e.g., PHP, MySQL, WordPress)
            html_snippet: HTML snippet around the parameter
            
        Returns:
            Dict containing SQL injection analysis with targeted payloads
        """
        sqli_prompt = f"""You are an elite cybersecurity analyst and penetration tester specializing in web application vulnerabilities for a top-tier bug bounty platform. Your analysis is meticulous, practical, and tailored to the specific context of the target. You do not provide generic advice. Your goal is to find verifiable flaws.

**## Target Context**
* **URL:** `{url}`
* **Vulnerable Parameter:** `{parameter_name}`
* **HTTP Method:** `{http_method}`
* **Known Technology Stack:** `{technology_stack}` (e.g., PHP, Nginx, MySQL, WordPress)
* **Surrounding HTML Snippet:** ```html
    {html_snippet}
    ```

**## Analysis Task**
Based *only* on the context provided, perform a deep analysis for potential SQL Injection vulnerabilities. Generate a series of diverse and targeted payloads to test for this flaw.

**## Required Output Format**
Respond with a single, valid JSON object. Do not include any text or formatting outside of the JSON. The JSON object must contain a single key, "sqli_analysis", which is an array of payload objects.

Each payload object in the array must have the following structure:
* `technique`: (String) The specific SQLi technique used (e.g., "Error-Based", "UNION-Based", "Time-Based Blind", "Boolean-Based Blind").
* `payload`: (String) The raw payload string to be sent in the parameter.
* `rationale`: (String) A brief, technical explanation of why this specific payload is likely to work against the `{technology_stack}` and what the expected outcome is (e.g., "This payload closes the query with a single quote and uses the '-- ' comment syntax for MySQL to bypass the rest of the query, likely causing a database error if vulnerable.").
* `confidence_score`: (Integer) Your confidence level from 1 to 10 that this payload will reveal a vulnerability.

**## Example JSON Structure**
```json
{{
  "sqli_analysis": [
    {{
      "technique": "Error-Based",
      "payload": "' OR 1=1 -- ",
      "rationale": "Classic error-based test for MySQL. The unbalanced quote and comment should trigger a verbose SQL error message on the page.",
      "confidence_score": 8
    }}
  ]
}}
```"""
        
        try:
            # Check if AI is enabled
            if not self.enable_ai:
                return {
                    "success": False,
                    "error": "AI analysis is disabled",
                    "sqli_analysis": [],
                    "fallback_used": True
                }
            
            # Use the custom prompt analyzer
            response = await self.analyze_with_prompt(sqli_prompt)
            
            if response.get("success", False):
                response_text = response.get("response", "")
                
                # Try to parse JSON response
                try:
                    sqli_data = json.loads(response_text)
                    return {
                        "success": True,
                        "sqli_analysis": sqli_data.get("sqli_analysis", []),
                        "provider": response.get("provider", self.provider),
                        "raw_response": response_text
                    }
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse SQL injection analysis JSON: {e}")
                    # Try to extract JSON from response if it's wrapped in other text
                    import re
                    json_match = re.search(r'\{.*"sqli_analysis".*\}', response_text, re.DOTALL)
                    if json_match:
                        try:
                            sqli_data = json.loads(json_match.group())
                            return {
                                "success": True,
                                "sqli_analysis": sqli_data.get("sqli_analysis", []),
                                "provider": response.get("provider", self.provider),
                                "raw_response": response_text
                            }
                        except json.JSONDecodeError:
                            pass
                    
                    # Fallback to text parsing
                    return {
                        "success": False,
                        "error": "Failed to parse JSON response",
                        "raw_response": response_text,
                        "sqli_analysis": []
                    }
            else:
                return {
                    "success": False,
                    "error": response.get("response", "Unknown error"),
                    "sqli_analysis": []
                }
                
        except Exception as e:
            self.logger.error(f"SQL injection analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "sqli_analysis": []
            }
    
    async def analyze_xss_vulnerability(self, 
                                      url: str,
                                      parameter_name: str,
                                      technology_hints: str,
                                      full_page_html: str) -> Dict[str, Any]:
        """
        Specialized Cross-Site Scripting (XSS) vulnerability analysis
        
        Args:
            url: Target URL
            parameter_name: Vulnerable parameter name
            technology_hints: Known technology stack (e.g., React, PHP, jQuery)
            full_page_html: Full HTML response where input is reflected
            
        Returns:
            Dict containing XSS analysis with targeted payloads
        """
        xss_prompt = f"""You are a JavaScript security expert and front-end vulnerability specialist. You have deep knowledge of browser rendering engines, DOM Clobbering, and modern XSS bypass techniques. Your objective is to craft payloads that execute despite common sanitization and WAF rules.

**## Target Context**
* **URL:** `{url}`
* **Vulnerable Parameter:** `{parameter_name}`
* **Technology Hints:** `{technology_hints}` (e.g., React, PHP, jQuery 1.8)
* **Full HTML Response Where Input is Reflected:**
    ```html
    {full_page_html}
    ```

**## Analysis Task**
Analyze the provided HTML to understand how the `{parameter_name}` parameter is being reflected in the DOM. Identify the surrounding tags, any potential encoding (like `&gt;` for `>`), and attribute context. Based on this deep analysis, generate a list of clever XSS payloads designed to bypass potential filters and achieve execution.

**## Required Output Format**
Respond with a single, valid JSON object containing one key, "xss_analysis". This key will hold an array of payload objects.

Each payload object must have the following structure:
* `payload_type`: (String) The type of XSS (e.g., "Reflected", "DOM-Based Suggestion").
* `payload`: (String) The raw payload string. Use various event handlers, tags, and encoding.
* `bypass_technique`: (String) The specific technique used (e.g., "SVG Onload", "Image OnError with Null Byte", "Case Obfuscation", "Event Handler in Unquoted Attribute").
* `rationale`: (String) A brief explanation of why this payload might bypass filters in the given HTML context. (e.g., "The reflection is within an unquoted `href` attribute. This payload uses `javascript:alert(1)` which might execute directly. Many filters focus on `<script>` tags and miss protocol-based attacks.").
* `confidence_score`: (Integer) Your confidence level from 1 to 10.

**## Example JSON Structure**
```json
{{
  "xss_analysis": [
    {{
      "payload_type": "Reflected",
      "payload": "\\"><img src=x onerror=alert(document.domain)>",
      "bypass_technique": "Image OnError",
      "rationale": "This payload breaks out of the current HTML attribute and injects an `<img>` tag. The `onerror` event is less commonly filtered than `<script>` tags and will execute if the `src` is invalid.",
      "confidence_score": 9
    }}
  ]
}}
```"""
        
        try:
            # Check if AI is enabled
            if not self.enable_ai:
                return {
                    "success": False,
                    "error": "AI analysis is disabled",
                    "xss_analysis": [],
                    "fallback_used": True
                }
            
            # Use the custom prompt analyzer
            response = await self.analyze_with_prompt(xss_prompt)
            
            if response.get("success", False):
                response_text = response.get("response", "")
                
                # Try to parse JSON response
                try:
                    xss_data = json.loads(response_text)
                    return {
                        "success": True,
                        "xss_analysis": xss_data.get("xss_analysis", []),
                        "provider": response.get("provider", self.provider),
                        "raw_response": response_text
                    }
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse XSS analysis JSON: {e}")
                    # Try to extract JSON from response if it's wrapped in other text
                    import re
                    json_match = re.search(r'\{.*"xss_analysis".*\}', response_text, re.DOTALL)
                    if json_match:
                        try:
                            xss_data = json.loads(json_match.group())
                            return {
                                "success": True,
                                "xss_analysis": xss_data.get("xss_analysis", []),
                                "provider": response.get("provider", self.provider),
                                "raw_response": response_text
                            }
                        except json.JSONDecodeError:
                            pass
                    
                    # Fallback to text parsing
                    return {
                        "success": False,
                        "error": "Failed to parse JSON response",
                        "raw_response": response_text,
                        "xss_analysis": []
                    }
            else:
                return {
                    "success": False,
                    "error": response.get("response", "Unknown error"),
                    "xss_analysis": []
                }
                
        except Exception as e:
            self.logger.error(f"XSS analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "xss_analysis": []
            }
    
    async def analyze_logical_flaws(self, 
                                  full_url_with_params: str,
                                  discovered_directories: List[str],
                                  server_software: str) -> Dict[str, Any]:
        """
        Specialized Path Traversal & IDOR vulnerability analysis
        
        Args:
            full_url_with_params: Complete URL with parameters (e.g., "https://example.com/profile?user_id=5402")
            discovered_directories: List of discovered server directories (e.g., ["/images", "/js", "/admin"])
            server_software: Server technology stack (e.g., "Apache", "IIS", "Nginx")
            
        Returns:
            Dict containing logical flaw analysis with testing methods
        """
        logical_flaw_prompt = f"""You are an application security analyst with a specialization in identifying business logic flaws, access control issues (IDOR), and file inclusion vulnerabilities. You think like an attacker trying to access resources they are not authorized for.

**## Target Context**
* **URL with Parameter(s):** `{full_url_with_params}` (e.g., `https://example.com/profile?user_id=5402` or `.../download.php?file=report.pdf`)
* **Discovered Server Directories:** `{discovered_directories}` (e.g., `["/images", "/js", "/css", "/includes", "/admin"]`)
* **Server Technology:** `{server_software}` (e.g., Apache, IIS, Nginx)

**## Analysis Task**
Based on the URL structure, parameter names, and server context, identify potential Insecure Direct Object Reference (IDOR) or Path Traversal vulnerabilities. Do not guess. Base your analysis on the patterns observed. For each potential vulnerability, describe the precise method for testing it.

**## Required Output Format**
Respond with a single, valid JSON object with one key, "logical_flaw_analysis". This key will hold an array of analysis objects.

Each object must have the following structure:
* `vulnerability_type`: (String) The suspected vulnerability ("IDOR", "Path Traversal").
* `parameter_to_test`: (String) The name of the parameter that is likely vulnerable.
* `testing_method`: (String) A clear, step-by-step description of how to test for the flaw. This will be used to guide the next phase of testing.
* `rationale`: (String) Explain the reasoning. Why does this pattern suggest this specific vulnerability? (e.g., "The parameter `user_id` is a sequential integer, which is a classic pattern for IDOR. An attacker can likely enumerate other users' data by incrementing this value.").
* `confidence_score`: (Integer) Your confidence level from 1 to 10.

**## Example JSON Structure**
```json
{{
  "logical_flaw_analysis": [
    {{
      "vulnerability_type": "IDOR",
      "parameter_to_test": "user_id",
      "testing_method": "1. Capture a request with your own `user_id`. 2. Increment or decrement the integer value of the `user_id` parameter (e.g., from 5402 to 5403). 3. Send the modified request and observe if the response contains data belonging to another user.",
      "rationale": "The endpoint uses a predictable, numeric identifier for a sensitive object (user profile). This lacks authorization checks at the object level, making it highly susceptible to IDOR.",
      "confidence_score": 9
    }},
    {{
      "vulnerability_type": "Path Traversal",
      "parameter_to_test": "file",
      "testing_method": "Replace 'report.pdf' with payloads like `../../../../etc/passwd` (for Linux/Apache) or `../../../../boot.ini` (for Windows/IIS).",
      "rationale": "The `file` parameter explicitly requests a file resource. If the application does not properly sanitize this input, it may be possible to traverse the file system and access sensitive system files.",
      "confidence_score": 7
    }}
  ]
}}
```"""
        
        try:
            # Check if AI is enabled
            if not self.enable_ai:
                return {
                    "success": False,
                    "error": "AI analysis is disabled",
                    "logical_flaw_analysis": [],
                    "fallback_used": True
                }
            
            # Use the custom prompt analyzer
            response = await self.analyze_with_prompt(logical_flaw_prompt)
            
            if response.get("success", False):
                response_text = response.get("response", "")
                
                # Try to parse JSON response
                try:
                    flaw_data = json.loads(response_text)
                    return {
                        "success": True,
                        "logical_flaw_analysis": flaw_data.get("logical_flaw_analysis", []),
                        "provider": response.get("provider", self.provider),
                        "raw_response": response_text
                    }
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse logical flaw analysis JSON: {e}")
                    # Try to extract JSON from response if it's wrapped in other text
                    import re
                    json_match = re.search(r'\{.*"logical_flaw_analysis".*\}', response_text, re.DOTALL)
                    if json_match:
                        try:
                            flaw_data = json.loads(json_match.group())
                            return {
                                "success": True,
                                "logical_flaw_analysis": flaw_data.get("logical_flaw_analysis", []),
                                "provider": response.get("provider", self.provider),
                                "raw_response": response_text
                            }
                        except json.JSONDecodeError:
                            pass
                    
                    # Fallback to text parsing
                    return {
                        "success": False,
                        "error": "Failed to parse JSON response",
                        "raw_response": response_text,
                        "logical_flaw_analysis": []
                    }
            else:
                return {
                    "success": False,
                    "error": response.get("response", "Unknown error"),
                    "logical_flaw_analysis": []
                }
                
        except Exception as e:
            self.logger.error(f"Logical flaw analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "logical_flaw_analysis": []
            }
    
    def _build_analysis_prompt(self, 
                             command_result: CommandResult,
                             browser_result: Optional[BrowserResult] = None,
                             context: Optional[Dict[str, Any]] = None,
                             history: Optional[List[Dict[str, Any]]] = None) -> str:
        """Build the analysis prompt for AI"""
        
        prompt = f"""
You are an expert system administrator and developer. Analyze the following command execution and provide insights.

COMMAND EXECUTED: {command_result.command}
SUCCESS: {command_result.success}
RETURN CODE: {command_result.return_code}
EXECUTION TIME: {command_result.execution_time:.2f}s

STDOUT:
{command_result.stdout[:2000]}

STDERR:
{command_result.stderr[:1000]}
"""
        
        if browser_result:
            prompt += f"""
BROWSER TEST RESULT:
URL: {browser_result.url}
Success: {browser_result.success}
Title: {browser_result.title}
Load Time: {browser_result.load_time:.2f}s
Errors: {browser_result.errors}
"""
        
        if history:
            prompt += f"""
PREVIOUS ATTEMPTS:
{json.dumps(history, indent=2)[:1000]}
"""
        
        prompt += """
Please analyze this execution and provide:

1. SUCCESS: true/false - whether the overall execution was successful
2. MESSAGE: A clear summary of what happened
3. SUGGESTIONS: List of specific actionable suggestions for improvement
4. SUGGESTED_COMMAND: If there's an error, provide a corrected command
5. ANALYSIS: Detailed technical analysis of any issues

Respond in this JSON format:
{
    "success": boolean,
    "message": "string",
    "suggestions": ["string", ...],
    "suggested_command": "string or null",
    "analysis": "string"
}
"""
        
        return prompt
    
    def _build_api_analysis_prompt(self, 
                                 api_result: CommandResult,
                                 browser_result: Optional[BrowserResult] = None) -> str:
        """Build API analysis prompt"""
        
        prompt = f"""
You are an API testing expert. Analyze the following API request and response.

API REQUEST: {api_result.command}
STATUS CODE: {api_result.return_code}
SUCCESS: {api_result.success}
RESPONSE TIME: {api_result.execution_time:.2f}s

RESPONSE BODY:
{api_result.stdout[:2000]}

ERROR (if any):
{api_result.stderr}
"""
        
        if browser_result:
            prompt += f"""
BROWSER VERIFICATION:
URL: {browser_result.url}
Page Title: {browser_result.title}
Load Success: {browser_result.success}
Visual Errors: {browser_result.errors}
"""
        
        prompt += """
Analyze this API interaction and provide:

1. SUCCESS: Whether the API call was successful
2. MESSAGE: Summary of the API response
3. SUGGESTIONS: Recommendations for improvement or testing
4. ANALYSIS: Technical analysis of the response

Respond in JSON format:
{
    "success": boolean,
    "message": "string", 
    "suggestions": ["string", ...],
    "analysis": "string"
}
"""
        
        return prompt
    
    async def _analyze_with_openai(self, prompt: str) -> AnalysisResult:
        """Analyze using OpenAI GPT models"""
        
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert system administrator and developer assistant."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=1000
            )
            
            content = response.choices[0].message.content
            
            # Try to parse JSON response
            try:
                result_data = json.loads(content)
                return AnalysisResult(
                    success=result_data.get("success", False),
                    message=result_data.get("message", "AI analysis completed"),
                    suggestions=result_data.get("suggestions", []),
                    suggested_command=result_data.get("suggested_command"),
                    analysis=result_data.get("analysis", "")
                )
            except json.JSONDecodeError:
                # Fallback to text parsing
                return self._parse_text_response(content)
                
        except Exception as e:
            self.logger.error(f"OpenAI analysis error: {e}")
            raise
    
    async def _analyze_with_anthropic(self, prompt: str) -> AnalysisResult:
        """Analyze using Anthropic Claude models"""
        
        try:
            response = await asyncio.to_thread(
                self.client.messages.create,
                model=self.model,
                max_tokens=1000,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )
            
            content = response.content[0].text
            
            # Try to parse JSON response
            try:
                result_data = json.loads(content)
                return AnalysisResult(
                    success=result_data.get("success", False),
                    message=result_data.get("message", "AI analysis completed"),
                    suggestions=result_data.get("suggestions", []),
                    suggested_command=result_data.get("suggested_command"),
                    analysis=result_data.get("analysis", "")
                )
            except json.JSONDecodeError:
                return self._parse_text_response(content)
                
        except Exception as e:
            self.logger.error(f"Anthropic analysis error: {e}")
            raise
    
    async def _analyze_with_google(self, prompt: str) -> AnalysisResult:
        """Analyze using Google Gemini models"""
        
        try:
            response = await asyncio.to_thread(
                self.client.generate_content,
                prompt
            )
            
            content = response.text
            
            # Try to parse JSON response
            try:
                result_data = json.loads(content)
                return AnalysisResult(
                    success=result_data.get("success", False),
                    message=result_data.get("message", "AI analysis completed"),
                    suggestions=result_data.get("suggestions", []),
                    suggested_command=result_data.get("suggested_command"),
                    analysis=result_data.get("analysis", "")
                )
            except json.JSONDecodeError:
                return self._parse_text_response(content)
                
        except Exception as e:
            self.logger.error(f"Google Gemini analysis error: {e}")
            raise
    
    async def _analyze_with_groq(self, prompt: str) -> AnalysisResult:
        """Analyze using Groq models"""
        
        try:
            # Use currently available Groq models
            completion = await asyncio.to_thread(
                self.client.chat.completions.create,
                model="llama-3.1-8b-instant",  # Try this available model first
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing penetration testing results. Provide detailed analysis and actionable recommendations in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_completion_tokens=1024,
                top_p=1,
                stream=False,
                stop=None
            )
            
            content = completion.choices[0].message.content
            
            # Try to parse JSON response
            try:
                result_data = json.loads(content)
                return AnalysisResult(
                    success=result_data.get("success", True),
                    message=result_data.get("message", "Groq AI analysis completed"),
                    suggestions=result_data.get("suggestions", []),
                    suggested_command=result_data.get("suggested_command"),
                    analysis=result_data.get("analysis", content)
                )
            except json.JSONDecodeError:
                return self._parse_text_response(content)
                
        except Exception as e:
            self.logger.error(f"Groq analysis error: {e}")
            # Try fallback with different models
            for fallback_model in ["llama3-8b-8192", "gemma-7b-it", "llama3-groq-8b-8192-tool-use-preview"]:
                try:
                    completion = await asyncio.to_thread(
                        self.client.chat.completions.create,
                        model=fallback_model,
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity expert analyzing penetration testing results. Provide detailed analysis and actionable recommendations in JSON format."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.3,
                        max_completion_tokens=1024,
                        top_p=1,
                        stream=False,
                        stop=None
                    )
                    
                    content = completion.choices[0].message.content
                    
                    try:
                        result_data = json.loads(content)
                        return AnalysisResult(
                            success=result_data.get("success", True),
                            message=result_data.get("message", f"Groq AI analysis completed (model: {fallback_model})"),
                            suggestions=result_data.get("suggestions", []),
                            suggested_command=result_data.get("suggested_command"),
                            analysis=result_data.get("analysis", content)
                        )
                    except json.JSONDecodeError:
                        return self._parse_text_response(content)
                        
                except Exception as e2:
                    self.logger.warning(f"Groq fallback model {fallback_model} failed: {e2}")
                    continue
            
            # If all models fail, raise the original error
            raise e
    
    async def _analyze_with_groq_streaming(self, prompt: str) -> AnalysisResult:
        """Analyze using Groq models with streaming output"""
        
        try:
            completion = await asyncio.to_thread(
                self.client.chat.completions.create,
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing penetration testing results. Provide detailed analysis and actionable recommendations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_completion_tokens=1024,
                top_p=1,
                stream=True,
                stop=None
            )
            
            # Collect streaming response
            full_response = ""
            for chunk in completion:
                if chunk.choices[0].delta.content:
                    content = chunk.choices[0].delta.content
                    full_response += content
                    print(content, end="")  # Real-time output
            
            print()  # New line after streaming
            
            # Try to parse JSON response
            try:
                result_data = json.loads(full_response)
                return AnalysisResult(
                    success=result_data.get("success", True),
                    message=result_data.get("message", "Groq streaming analysis completed"),
                    suggestions=result_data.get("suggestions", []),
                    suggested_command=result_data.get("suggested_command"),
                    analysis=result_data.get("analysis", full_response)
                )
            except json.JSONDecodeError:
                return self._parse_text_response(full_response)
                
        except Exception as e:
            self.logger.error(f"Groq streaming analysis error: {e}")
            # Try with fallback models
            for fallback_model in ["llama3-8b-8192", "gemma-7b-it"]:
                try:
                    completion = await asyncio.to_thread(
                        self.client.chat.completions.create,
                        model=fallback_model,
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity expert analyzing penetration testing results. Provide detailed analysis and actionable recommendations."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.3,
                        max_completion_tokens=1024,
                        top_p=1,
                        stream=True,
                        stop=None
                    )
                    
                    full_response = ""
                    for chunk in completion:
                        if chunk.choices[0].delta.content:
                            content = chunk.choices[0].delta.content
                            full_response += content
                            print(content, end="")
                    
                    print()
                    
                    try:
                        result_data = json.loads(full_response)
                        return AnalysisResult(
                            success=result_data.get("success", True),
                            message=result_data.get("message", f"Groq streaming analysis completed ({fallback_model})"),
                            suggestions=result_data.get("suggestions", []),
                            suggested_command=result_data.get("suggested_command"),
                            analysis=result_data.get("analysis", full_response)
                        )
                    except json.JSONDecodeError:
                        return self._parse_text_response(full_response)
                        
                except Exception as e2:
                    self.logger.warning(f"Groq streaming fallback {fallback_model} failed: {e2}")
                    continue
            
            raise e
    
    def _parse_text_response(self, content: str) -> AnalysisResult:
        """Parse text response when JSON parsing fails"""
        
        # Basic text parsing fallback
        success = "success" in content.lower() and "true" in content.lower()
        
        return AnalysisResult(
            success=success,
            message="AI analysis completed (text format)",
            suggestions=["Review the command output manually"],
            analysis=content[:500]
        )
    
    async def _fallback_analysis(self, 
                                command_result: CommandResult,
                                browser_result: Optional[BrowserResult] = None) -> AnalysisResult:
        """Fallback analysis when AI is not available"""
        
        # Basic rule-based analysis
        success = command_result.success
        suggestions = []
        
        if not success:
            # Common error patterns and suggestions
            stderr_lower = command_result.stderr.lower()
            
            if "command not found" in stderr_lower or "not recognized" in stderr_lower:
                suggestions.append("Check if the command is installed and in PATH")
                suggestions.append("Verify command spelling and syntax")
            elif "permission denied" in stderr_lower:
                suggestions.append("Check file/directory permissions")
                suggestions.append("Try running with elevated privileges")
            elif "no such file" in stderr_lower:
                suggestions.append("Verify the file path exists")
                suggestions.append("Check current working directory")
            elif "connection" in stderr_lower or "network" in stderr_lower:
                suggestions.append("Check network connectivity")
                suggestions.append("Verify URL or hostname is correct")
            else:
                suggestions.append("Review the error message for specific details")
                suggestions.append("Check command syntax and parameters")
        
        if browser_result and not browser_result.success:
            suggestions.extend([
                "Check if the website is accessible",
                "Verify the URL format is correct",
                "Test with a different browser or network"
            ])
        
        return AnalysisResult(
            success=success,
            message="Command executed successfully" if success else "Command execution failed",
            suggestions=suggestions,
            analysis=f"Basic analysis: {command_result.stderr[:200] if command_result.stderr else 'No detailed analysis available'}"
        )
    
    async def _fallback_api_analysis(self, 
                                   api_result: CommandResult,
                                   browser_result: Optional[BrowserResult] = None) -> AnalysisResult:
        """Fallback API analysis when AI is not available"""
        
        status_code = api_result.return_code
        success = 200 <= status_code < 400
        
        suggestions = []
        
        if status_code == 404:
            suggestions.extend([
                "Verify the API endpoint URL is correct",
                "Check if the resource exists",
                "Review API documentation for correct paths"
            ])
        elif status_code == 401:
            suggestions.extend([
                "Check authentication credentials",
                "Verify API key or token is valid",
                "Ensure proper authorization headers"
            ])
        elif status_code == 403:
            suggestions.extend([
                "Check user permissions for this resource",
                "Verify API access rights",
                "Review rate limiting policies"
            ])
        elif status_code >= 500:
            suggestions.extend([
                "Server error - try again later",
                "Check API service status",
                "Verify request format and parameters"
            ])
        
        return AnalysisResult(
            success=success,
            message=f"API request completed with status {status_code}",
            suggestions=suggestions,
            analysis=f"HTTP status: {status_code}, Response time: {api_result.execution_time:.2f}s"
        )
