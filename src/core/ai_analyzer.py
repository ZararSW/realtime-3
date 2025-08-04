"""
Production-grade AI analyzer for Advanced Intelligent Web Crawler
Supports multiple AI models with robust error handling and retry logic
"""

import asyncio
import json
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import google.generativeai as genai
import openai
from anthropic import Anthropic
from .logger import Logger


@dataclass
class AIAnalysisResult:
    """Structured AI analysis result"""
    success: bool
    analysis: str
    risk_score: int
    recommendations: List[str]
    entities: List[str] = None
    vulnerabilities: List[str] = None
    confidence: float = 0.0
    model_used: str = None
    processing_time: float = 0.0
    error_message: str = None


class AIAnalyzer:
    """
    Production-grade AI analyzer with support for multiple models
    """
    
    def __init__(self, config, logger: Logger):
        """
        Initialize AI analyzer
        
        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.models = {}
        self.current_model = config.ai.model
        
        # Initialize AI models
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize supported AI models"""
        api_key = self.config.get_api_key()
        
        if not api_key:
            self.logger.warning("No API key found, AI analysis will be disabled")
            return
        
        try:
            # Initialize Google Gemini
            if self.current_model.startswith('gemini'):
                genai.configure(api_key=api_key)
                self.models['gemini'] = genai.GenerativeModel(self.current_model)
                self.logger.info(f"Initialized Gemini model: {self.current_model}")
            
            # Initialize OpenAI GPT
            elif self.current_model.startswith('gpt'):
                openai.api_key = api_key
                self.models['openai'] = openai
                self.logger.info(f"Initialized OpenAI model: {self.current_model}")
            
            # Initialize Anthropic Claude
            elif self.current_model.startswith('claude'):
                self.models['anthropic'] = Anthropic(api_key=api_key)
                self.logger.info(f"Initialized Anthropic model: {self.current_model}")
            
            else:
                self.logger.warning(f"Unsupported AI model: {self.current_model}")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize AI models: {e}")
    
    async def analyze_content(self, content: str, context: str = "general", 
                            target_url: str = None) -> AIAnalysisResult:
        """
        Analyze content using AI
        
        Args:
            content: Content to analyze
            context: Analysis context (e.g., 'security', 'dom', 'network')
            target_url: Target URL for context
            
        Returns:
            AIAnalysisResult with analysis
        """
        if not self.models:
            return AIAnalysisResult(
                success=False,
                analysis="AI analysis unavailable - no models initialized",
                risk_score=0,
                recommendations=["Enable AI analysis by providing API key"],
                error_message="No AI models available"
            )
        
        start_time = time.time()
        
        try:
            # Generate appropriate prompt based on context
            prompt = self._generate_prompt(content, context, target_url)
            
            # Get AI response with retry logic
            response = await self._get_ai_response(prompt)
            
            # Parse and structure the response
            result = self._parse_ai_response(response, context)
            
            processing_time = time.time() - start_time
            
            # Log the analysis
            self.logger.log_ai_event(
                f"AI analysis completed for {context}",
                self.current_model,
                {
                    'context': context,
                    'content_length': len(content),
                    'risk_score': result.risk_score,
                    'processing_time': processing_time
                },
                target_url
            )
            
            result.processing_time = processing_time
            result.model_used = self.current_model
            
            return result
            
        except Exception as e:
            processing_time = time.time() - start_time
            self.logger.error(f"AI analysis failed: {e}", 'ai_analysis', {'error': str(e)}, target_url)
            
            return AIAnalysisResult(
                success=False,
                analysis=f"AI analysis failed: {e}",
                risk_score=0,
                recommendations=["Retry analysis", "Check API key and model configuration"],
                error_message=str(e),
                processing_time=processing_time,
                model_used=self.current_model
            )
    
    def _generate_prompt(self, content: str, context: str, target_url: str = None) -> str:
        """Generate appropriate prompt based on context"""
        
        base_prompt = f"""
        Analyze the following content for security vulnerabilities and insights:
        
        Context: {context}
        Target URL: {target_url or 'Not specified'}
        Content: {content[:self.config.ai.context_window]}
        
        Please provide a comprehensive analysis including:
        1. Security vulnerabilities (XSS, SQL injection, etc.)
        2. Risk assessment (0-10 scale)
        3. Specific recommendations
        4. Identified entities (URLs, emails, etc.)
        5. Confidence level (0-1)
        
        Format your response as JSON with the following structure:
        {{
            "analysis": "Detailed analysis text",
            "risk_score": 5,
            "recommendations": ["rec1", "rec2"],
            "entities": ["entity1", "entity2"],
            "vulnerabilities": ["vuln1", "vuln2"],
            "confidence": 0.8
        }}
        """
        
        # Context-specific prompts
        if context == "security":
            base_prompt += """
            Focus on:
            - Input validation vulnerabilities
            - Output encoding issues
            - Authentication bypasses
            - Information disclosure
            - Business logic flaws
            """
        elif context == "dom":
            base_prompt += """
            Focus on:
            - DOM-based XSS
            - JavaScript injection
            - Event handler vulnerabilities
            - Dynamic content analysis
            """
        elif context == "network":
            base_prompt += """
            Focus on:
            - Suspicious network requests
            - API vulnerabilities
            - Data exfiltration attempts
            - Authentication tokens
            """
        
        return base_prompt
    
    async def _get_ai_response(self, prompt: str) -> str:
        """Get response from AI model with retry logic"""
        
        for attempt in range(self.config.ai.max_retries):
            try:
                if 'gemini' in self.models:
                    response = await asyncio.to_thread(
                        self.models['gemini'].generate_content, prompt
                    )
                    return response.text
                
                elif 'openai' in self.models:
                    response = await asyncio.to_thread(
                        openai.ChatCompletion.create,
                        model=self.current_model,
                        messages=[{"role": "user", "content": prompt}],
                        timeout=self.config.ai.timeout
                    )
                    return response.choices[0].message.content
                
                elif 'anthropic' in self.models:
                    response = await asyncio.to_thread(
                        self.models['anthropic'].messages.create,
                        model=self.current_model,
                        max_tokens=1000,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    return response.content[0].text
                
                else:
                    raise Exception("No supported AI model available")
                    
            except Exception as e:
                if attempt < self.config.ai.max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    self.logger.warning(f"AI request failed (attempt {attempt + 1}), retrying in {wait_time}s: {e}")
                    await asyncio.sleep(wait_time)
                else:
                    raise e
        
        raise Exception("All AI request attempts failed")
    
    def _parse_ai_response(self, response: str, context: str) -> AIAnalysisResult:
        """Parse AI response into structured format"""
        
        try:
            # Try to extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                parsed = json.loads(json_str)
                
                return AIAnalysisResult(
                    success=True,
                    analysis=parsed.get('analysis', response),
                    risk_score=parsed.get('risk_score', 5),
                    recommendations=parsed.get('recommendations', []),
                    entities=parsed.get('entities', []),
                    vulnerabilities=parsed.get('vulnerabilities', []),
                    confidence=parsed.get('confidence', 0.5)
                )
            else:
                # Fallback to parsing text response
                return self._parse_text_response(response, context)
                
        except json.JSONDecodeError:
            # Fallback to parsing text response
            return self._parse_text_response(response, context)
    
    def _parse_text_response(self, response: str, context: str) -> AIAnalysisResult:
        """Parse text response when JSON parsing fails"""
        
        # Extract risk score if mentioned
        risk_score = 5  # Default
        if "risk score" in response.lower():
            import re
            risk_match = re.search(r'risk score[:\s]*(\d+)', response.lower())
            if risk_match:
                risk_score = int(risk_match.group(1))
        
        # Extract recommendations
        recommendations = []
        lines = response.split('\n')
        for line in lines:
            if any(keyword in line.lower() for keyword in ['recommend', 'suggest', 'should', 'need to']):
                recommendations.append(line.strip())
        
        return AIAnalysisResult(
            success=True,
            analysis=response,
            risk_score=risk_score,
            recommendations=recommendations[:5],  # Limit to 5 recommendations
            confidence=0.6  # Lower confidence for text parsing
        )
    
    async def analyze_security_event(self, event_data: Dict[str, Any], 
                                   target_url: str = None) -> AIAnalysisResult:
        """Analyze security-specific event"""
        content = json.dumps(event_data, default=str)
        return await self.analyze_content(content, "security", target_url)
    
    async def analyze_network_traffic(self, network_data: Dict[str, Any], 
                                    target_url: str = None) -> AIAnalysisResult:
        """Analyze network traffic patterns"""
        content = json.dumps(network_data, default=str)
        return await self.analyze_content(content, "network", target_url)
    
    async def analyze_dom_changes(self, dom_content: str, 
                                target_url: str = None) -> AIAnalysisResult:
        """Analyze DOM changes for security issues"""
        return await self.analyze_content(dom_content, "dom", target_url)
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about available models"""
        return {
            'current_model': self.current_model,
            'available_models': list(self.models.keys()),
            'api_key_configured': bool(self.config.get_api_key()),
            'max_retries': self.config.ai.max_retries,
            'timeout': self.config.ai.timeout
        } 