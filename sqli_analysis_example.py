#!/usr/bin/env python3
"""
SQL Injection Analysis Integration Example
Shows how the prompt template integrates with the AI Provider system
"""

import json
from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer
from intelligent_terminal_ai.utils.config import config

class SQLInjectionAnalyzer:
    def __init__(self):
        # Initialize AI analyzer using current configuration
        provider = config.get("ai", "provider", "groq")
        provider_config = config.get("ai", provider, {})
        
        if provider == "groq":
            model = f"groq-{provider_config.get('model', 'llama-3.1-8b-instant')}"
            api_key = provider_config.get("api_key")
        # Add other providers as needed...
        
        self.ai_analyzer = AIAnalyzer(model=model, api_key=api_key)
    
    async def analyze_sqli_vulnerability(self, url: str, parameter_name: str, 
                                       http_method: str, technology_stack: str, 
                                       html_snippet: str):
        """
        Analyze a parameter for SQL injection vulnerabilities using AI
        """
        
        # Your sophisticated prompt template
        prompt_template = """**SYSTEM PROMPT**

You are an elite cybersecurity analyst and penetration tester specializing in web application vulnerabilities for a top-tier bug bounty platform. Your analysis is meticulous, practical, and tailored to the specific context of the target. You do not provide generic advice. Your goal is to find verifiable flaws.

**USER PROMPT**

**## Target Context**
* **URL:** `{URL}`
* **Vulnerable Parameter:** `{PARAMETER_NAME}`
* **HTTP Method:** `{HTTP_METHOD}`
* **Known Technology Stack:** `{TECHNOLOGY_STACK}` (e.g., PHP, Nginx, MySQL, WordPress)
* **Surrounding HTML Snippet:** ```html
    {HTML_SNIPPET_AROUND_PARAMETER}
    ```

**## Analysis Task**
Based *only* on the context provided, perform a deep analysis for potential SQL Injection vulnerabilities. Generate a series of diverse and targeted payloads to test for this flaw.

**## Required Output Format**
Respond with a single, valid JSON object. Do not include any text or formatting outside of the JSON. The JSON object must contain a single key, "sqli_analysis", which is an array of payload objects.

Each payload object in the array must have the following structure:
* `technique`: (String) The specific SQLi technique used (e.g., "Error-Based", "UNION-Based", "Time-Based Blind", "Boolean-Based Blind").
* `payload`: (String) The raw payload string to be sent in the parameter.
* `rationale`: (String) A brief, technical explanation of why this specific payload is likely to work against the `{TECHNOLOGY_STACK}` and what the expected outcome is (e.g., "This payload closes the query with a single quote and uses the '-- ' comment syntax for MySQL to bypass the rest of the query, likely causing a database error if vulnerable.").
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

        # Populate the template with actual values
        populated_prompt = prompt_template.format(
            URL=url,
            PARAMETER_NAME=parameter_name,
            HTTP_METHOD=http_method,
            TECHNOLOGY_STACK=technology_stack,
            HTML_SNIPPET_AROUND_PARAMETER=html_snippet
        )
        
        # Send to AI for analysis
        try:
            response = await self.ai_analyzer.analyze_with_prompt(populated_prompt)
            
            # Parse the JSON response
            if isinstance(response, dict):
                result_text = response.get('response', response.get('analysis', str(response)))
            else:
                result_text = str(response)
            
            # Extract JSON from response
            sqli_analysis = json.loads(result_text)
            return sqli_analysis
            
        except Exception as e:
            print(f"❌ SQL injection analysis failed: {e}")
            return {"sqli_analysis": []}

# Example usage
async def main():
    analyzer = SQLInjectionAnalyzer()
    
    # Example target analysis
    result = await analyzer.analyze_sqli_vulnerability(
        url="http://testphp.vulnweb.com/search.php",
        parameter_name="searchFor",
        http_method="GET",
        technology_stack="PHP, Apache, MySQL",
        html_snippet='<input type="text" name="searchFor" value="" maxlength="20">'
    )
    
    print("🎯 SQL Injection Analysis Results:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
