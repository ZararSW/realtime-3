#!/usr/bin/env python3
"""
Stagehand Integration for Advanced Web Crawler
AI-powered browser automation for intelligent web interaction and testing
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from pathlib import Path
import json
import time

# Stagehand imports (with fallback for when not installed)
try:
    from stagehand import Stagehand, StagehandConfig
    from stagehand.types import BrowserType, LogLevel
    STAGEHAND_AVAILABLE = True
except ImportError:
    STAGEHAND_AVAILABLE = False
    # Create mock classes for development
    class Stagehand:
        def __init__(self, *args, **kwargs): pass
    class StagehandConfig:
        def __init__(self, *args, **kwargs): pass

from ai_policy import AIPolicy, ENABLE_AI

@dataclass
class NavigationResult:
    """Result of a navigation action"""
    success: bool
    url: str
    title: str
    forms_found: int
    links_found: int
    screenshots: List[str]
    errors: List[str]
    metadata: Dict[str, Any]

@dataclass
class FormInteractionResult:
    """Result of form interaction"""
    success: bool
    form_id: str
    fields_filled: Dict[str, str]
    submit_response: Optional[str]
    vulnerability_indicators: List[str]
    screenshots: List[str]
    errors: List[str]

class StagehandWebCrawler:
    """
    Advanced web crawler using Stagehand for AI-powered browser automation
    Integrates with the existing security testing framework
    """
    
    def __init__(self, 
                 ai_policy: Optional[AIPolicy] = None,
                 headless: bool = True,
                 browser_type: str = "chromium",
                 screenshots_dir: str = "screenshots",
                 enable_stagehand: bool = None):
        """
        Initialize Stagehand crawler
        
        Args:
            ai_policy: AI policy instance for AI/No-AI mode
            headless: Run browser in headless mode
            browser_type: Browser type (chromium, firefox, webkit)
            screenshots_dir: Directory to save screenshots
            enable_stagehand: Override to disable Stagehand (fallback to Selenium)
        """
        self.ai_policy = ai_policy or AIPolicy(enable_ai=ENABLE_AI)
        self.headless = headless
        self.browser_type = browser_type
        self.screenshots_dir = Path(screenshots_dir)
        self.screenshots_dir.mkdir(exist_ok=True)
        
        # Determine if we should use Stagehand
        self.use_stagehand = (
            STAGEHAND_AVAILABLE and 
            (enable_stagehand if enable_stagehand is not None else ENABLE_AI)
        )
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Stagehand instance
        self.stagehand: Optional[Stagehand] = None
        self.page = None
        
        # Fallback Selenium driver
        self.selenium_driver = None
        
        # Navigation history
        self.navigation_history: List[NavigationResult] = []
        self.form_interactions: List[FormInteractionResult] = []
        
        self.logger.info(f"StagehandWebCrawler initialized - Stagehand: {'ENABLED' if self.use_stagehand else 'DISABLED'}")
    
    async def initialize(self):
        """Initialize the browser automation framework"""
        if self.use_stagehand:
            await self._initialize_stagehand()
        else:
            await self._initialize_selenium_fallback()
    
    async def _initialize_stagehand(self):
        """Initialize Stagehand browser automation"""
        try:
            # Configure Stagehand
            config = StagehandConfig(
                browser=self.browser_type,
                headless=self.headless,
                logger=self.logger,
                enable_recording=True,  # Record interactions for debugging
                debug_dom=True if not self.headless else False
            )
            
            # Initialize Stagehand
            self.stagehand = Stagehand(config)
            await self.stagehand.init()
            
            # Get page instance
            self.page = await self.stagehand.page()
            
            self.logger.info("Stagehand initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Stagehand initialization failed: {e}")
            self.logger.info("Falling back to Selenium")
            self.use_stagehand = False
            await self._initialize_selenium_fallback()
    
    async def _initialize_selenium_fallback(self):
        """Initialize Selenium as fallback when Stagehand is not available"""
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        
        try:
            options = Options()
            if self.headless:
                options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920,1080")
            
            self.selenium_driver = webdriver.Chrome(options=options)
            self.logger.info("Selenium fallback initialized")
            
        except Exception as e:
            self.logger.error(f"Selenium fallback initialization failed: {e}")
            raise
    
    async def navigate_to(self, url: str, wait_for_load: bool = True) -> NavigationResult:
        """
        Navigate to a URL using AI-powered navigation
        
        Args:
            url: Target URL
            wait_for_load: Wait for page to fully load
            
        Returns:
            NavigationResult with navigation details
        """
        start_time = time.time()
        
        try:
            if self.use_stagehand and self.page:
                result = await self._stagehand_navigate(url, wait_for_load)
            else:
                result = await self._selenium_navigate(url, wait_for_load)
            
            # Record navigation
            self.navigation_history.append(result)
            
            # Take screenshot
            screenshot_path = await self._take_screenshot(f"navigation_{len(self.navigation_history)}")
            if screenshot_path:
                result.screenshots.append(screenshot_path)
            
            self.logger.info(f"Navigation to {url} completed in {time.time() - start_time:.2f}s")
            return result
            
        except Exception as e:
            self.logger.error(f"Navigation failed: {e}")
            return NavigationResult(
                success=False,
                url=url,
                title="",
                forms_found=0,
                links_found=0,
                screenshots=[],
                errors=[str(e)],
                metadata={}
            )
    
    async def _stagehand_navigate(self, url: str, wait_for_load: bool) -> NavigationResult:
        """Navigate using Stagehand AI"""
        await self.page.goto(url)
        
        if wait_for_load:
            # Use Stagehand's AI to wait for page to be ready
            await self.page.act("Wait for the page to fully load")
        
        # Get page information
        title = await self.page.title()
        
        # Use AI to count forms and links
        forms_count = await self._count_page_elements("forms")
        links_count = await self._count_page_elements("links")
        
        return NavigationResult(
            success=True,
            url=url,
            title=title,
            forms_found=forms_count,
            links_found=links_count,
            screenshots=[],
            errors=[],
            metadata={
                "load_time": time.time(),
                "method": "stagehand"
            }
        )
    
    async def _selenium_navigate(self, url: str, wait_for_load: bool) -> NavigationResult:
        """Navigate using Selenium fallback"""
        self.selenium_driver.get(url)
        
        if wait_for_load:
            # Wait for page load
            await asyncio.sleep(2)
        
        title = self.selenium_driver.title
        
        # Count forms and links
        forms = self.selenium_driver.find_elements("tag name", "form")
        links = self.selenium_driver.find_elements("tag name", "a")
        
        return NavigationResult(
            success=True,
            url=url,
            title=title,
            forms_found=len(forms),
            links_found=len(links),
            screenshots=[],
            errors=[],
            metadata={
                "load_time": time.time(),
                "method": "selenium"
            }
        )
    
    async def _count_page_elements(self, element_type: str) -> int:
        """Use AI to count page elements"""
        if not self.use_stagehand:
            return 0
            
        try:
            if element_type == "forms":
                # Use Stagehand's AI to find forms
                forms = await self.page.locate("Find all forms on this page")
                return len(forms) if forms else 0
            elif element_type == "links":
                # Use Stagehand's AI to find links
                links = await self.page.locate("Find all clickable links on this page")
                return len(links) if links else 0
        except Exception as e:
            self.logger.debug(f"AI element counting failed: {e}")
            return 0
        
        return 0
    
    async def intelligent_form_discovery(self) -> List[Dict[str, Any]]:
        """
        Use AI to discover and analyze forms on the page
        
        Returns:
            List of form information dictionaries
        """
        forms = []
        
        try:
            if self.use_stagehand and self.page:
                forms = await self._stagehand_form_discovery()
            else:
                forms = await self._selenium_form_discovery()
                
        except Exception as e:
            self.logger.error(f"Form discovery failed: {e}")
        
        return forms
    
    async def _stagehand_form_discovery(self) -> List[Dict[str, Any]]:
        """Use Stagehand AI to discover forms"""
        forms = []
        
        try:
            # Use AI to find all forms
            form_elements = await self.page.locate("Find all forms on this page that can be filled out")
            
            for i, form_element in enumerate(form_elements or []):
                # Use AI to analyze each form
                form_analysis = await self.page.extract(
                    "Analyze this form and return information about its fields, action, method, and purpose",
                    form_element
                )
                
                # Use AI to find input fields
                input_fields = await self.page.locate(
                    "Find all input fields, text areas, and select elements in this form",
                    form_element
                )
                
                fields = []
                for field in input_fields or []:
                    field_info = await self.page.extract(
                        "Get the name, type, placeholder, and required attributes of this field",
                        field
                    )
                    fields.append(field_info)
                
                forms.append({
                    'id': f'stagehand_form_{i}',
                    'element': form_element,
                    'analysis': form_analysis,
                    'fields': fields,
                    'method': 'stagehand_ai'
                })
                
        except Exception as e:
            self.logger.error(f"Stagehand form discovery failed: {e}")
        
        return forms
    
    async def _selenium_form_discovery(self) -> List[Dict[str, Any]]:
        """Use Selenium to discover forms (fallback)"""
        forms = []
        
        if not self.selenium_driver:
            return forms
        
        try:
            form_elements = self.selenium_driver.find_elements("tag name", "form")
            
            for i, form_element in enumerate(form_elements):
                action = form_element.get_attribute("action") or ""
                method = form_element.get_attribute("method") or "GET"
                
                # Find input fields
                input_fields = form_element.find_elements("tag name", "input")
                textarea_fields = form_element.find_elements("tag name", "textarea")
                select_fields = form_element.find_elements("tag name", "select")
                
                fields = []
                for field in input_fields + textarea_fields + select_fields:
                    fields.append({
                        'name': field.get_attribute("name") or "",
                        'type': field.get_attribute("type") or "text",
                        'placeholder': field.get_attribute("placeholder") or "",
                        'required': field.get_attribute("required") is not None
                    })
                
                forms.append({
                    'id': f'selenium_form_{i}',
                    'element': form_element,
                    'action': action,
                    'method': method.upper(),
                    'fields': fields,
                    'method': 'selenium'
                })
                
        except Exception as e:
            self.logger.error(f"Selenium form discovery failed: {e}")
        
        return forms
    
    async def intelligent_form_testing(self, form_info: Dict[str, Any]) -> FormInteractionResult:
        """
        Intelligently test a form with AI-generated or rule-based payloads
        
        Args:
            form_info: Form information from discovery
            
        Returns:
            FormInteractionResult with testing details
        """
        form_id = form_info.get('id', 'unknown')
        start_time = time.time()
        
        try:
            # Get payloads from AI policy
            form_metadata = {
                'fields': form_info.get('fields', []),
                'action': form_info.get('action', ''),
                'method': form_info.get('method', 'GET')
            }
            
            payloads = self.ai_policy.get_payloads(form_metadata)
            
            if self.use_stagehand and self.page:
                result = await self._stagehand_form_testing(form_info, payloads)
            else:
                result = await self._selenium_form_testing(form_info, payloads)
            
            # Record interaction
            self.form_interactions.append(result)
            
            self.logger.info(f"Form testing completed for {form_id} in {time.time() - start_time:.2f}s")
            return result
            
        except Exception as e:
            self.logger.error(f"Form testing failed: {e}")
            return FormInteractionResult(
                success=False,
                form_id=form_id,
                fields_filled={},
                submit_response=None,
                vulnerability_indicators=[],
                screenshots=[],
                errors=[str(e)]
            )
    
    async def _stagehand_form_testing(self, form_info: Dict[str, Any], payloads: List[str]) -> FormInteractionResult:
        """Test form using Stagehand AI"""
        form_element = form_info.get('element')
        fields = form_info.get('fields', [])
        fields_filled = {}
        vulnerability_indicators = []
        screenshots = []
        
        try:
            # Use AI to intelligently fill the form
            for i, payload in enumerate(payloads[:5]):  # Limit to 5 payloads per form
                # Take screenshot before filling
                screenshot_path = await self._take_screenshot(f"form_before_{form_info['id']}_{i}")
                if screenshot_path:
                    screenshots.append(screenshot_path)
                
                # Use AI to fill form fields with payload
                for field in fields:
                    field_name = field.get('name', '')
                    if field_name:
                        try:
                            await self.page.act(f"Fill the field named '{field_name}' with the value '{payload}'")
                            fields_filled[field_name] = payload
                        except Exception as e:
                            self.logger.debug(f"Failed to fill field {field_name}: {e}")
                
                # Submit the form using AI
                try:
                    await self.page.act("Submit this form by clicking the submit button")
                    
                    # Wait for response
                    await asyncio.sleep(2)
                    
                    # Take screenshot after submission
                    screenshot_path = await self._take_screenshot(f"form_after_{form_info['id']}_{i}")
                    if screenshot_path:
                        screenshots.append(screenshot_path)
                    
                    # Get page content for analysis
                    page_content = await self.page.content()
                    
                    # Analyze response for vulnerabilities
                    for attack_type in ['xss', 'sqli', 'command_injection']:
                        result = self.ai_policy.analyze_response(page_content, payload, attack_type)
                        if result.detected:
                            vulnerability_indicators.append({
                                'type': attack_type,
                                'confidence': result.confidence,
                                'evidence': result.evidence,
                                'payload': payload
                            })
                
                except Exception as e:
                    self.logger.debug(f"Form submission failed: {e}")
        
        except Exception as e:
            self.logger.error(f"Stagehand form testing failed: {e}")
        
        return FormInteractionResult(
            success=True,
            form_id=form_info['id'],
            fields_filled=fields_filled,
            submit_response="Stagehand AI submission",
            vulnerability_indicators=vulnerability_indicators,
            screenshots=screenshots,
            errors=[]
        )
    
    async def _selenium_form_testing(self, form_info: Dict[str, Any], payloads: List[str]) -> FormInteractionResult:
        """Test form using Selenium (fallback)"""
        form_element = form_info.get('element')
        fields = form_info.get('fields', [])
        fields_filled = {}
        vulnerability_indicators = []
        screenshots = []
        
        try:
            for i, payload in enumerate(payloads[:3]):  # Limit to 3 payloads for Selenium
                # Fill form fields
                for field in fields:
                    field_name = field.get('name', '')
                    if field_name:
                        try:
                            input_element = form_element.find_element("name", field_name)
                            input_element.clear()
                            input_element.send_keys(payload)
                            fields_filled[field_name] = payload
                        except Exception as e:
                            self.logger.debug(f"Failed to fill field {field_name}: {e}")
                
                # Submit form
                try:
                    submit_button = form_element.find_element("css selector", "input[type='submit'], button[type='submit'], button:not([type])")
                    submit_button.click()
                    
                    # Wait for response
                    await asyncio.sleep(2)
                    
                    # Get page source for analysis
                    page_source = self.selenium_driver.page_source
                    
                    # Analyze response
                    for attack_type in ['xss', 'sqli']:
                        result = self.ai_policy.analyze_response(page_source, payload, attack_type)
                        if result.detected:
                            vulnerability_indicators.append({
                                'type': attack_type,
                                'confidence': result.confidence,
                                'evidence': result.evidence,
                                'payload': payload
                            })
                
                except Exception as e:
                    self.logger.debug(f"Selenium form submission failed: {e}")
        
        except Exception as e:
            self.logger.error(f"Selenium form testing failed: {e}")
        
        return FormInteractionResult(
            success=True,
            form_id=form_info['id'],
            fields_filled=fields_filled,
            submit_response="Selenium submission",
            vulnerability_indicators=vulnerability_indicators,
            screenshots=screenshots,
            errors=[]
        )
    
    async def intelligent_link_discovery(self) -> List[Dict[str, Any]]:
        """
        Use AI to discover and categorize links on the page
        
        Returns:
            List of link information dictionaries
        """
        links = []
        
        try:
            if self.use_stagehand and self.page:
                links = await self._stagehand_link_discovery()
            else:
                links = await self._selenium_link_discovery()
                
        except Exception as e:
            self.logger.error(f"Link discovery failed: {e}")
        
        return links
    
    async def _stagehand_link_discovery(self) -> List[Dict[str, Any]]:
        """Use Stagehand AI to discover links"""
        links = []
        
        try:
            # Use AI to find important links
            link_elements = await self.page.locate(
                "Find all important navigation links, form links, and content links on this page. "
                "Ignore social media, external, and obviously non-functional links."
            )
            
            for i, link_element in enumerate(link_elements or []):
                # Use AI to analyze each link
                link_analysis = await self.page.extract(
                    "Get the URL, text content, and purpose of this link",
                    link_element
                )
                
                links.append({
                    'id': f'stagehand_link_{i}',
                    'element': link_element,
                    'analysis': link_analysis,
                    'method': 'stagehand_ai'
                })
                
        except Exception as e:
            self.logger.error(f"Stagehand link discovery failed: {e}")
        
        return links
    
    async def _selenium_link_discovery(self) -> List[Dict[str, Any]]:
        """Use Selenium to discover links (fallback)"""
        links = []
        
        if not self.selenium_driver:
            return links
        
        try:
            link_elements = self.selenium_driver.find_elements("tag name", "a")
            
            for i, link_element in enumerate(link_elements[:50]):  # Limit for performance
                href = link_element.get_attribute("href") or ""
                text = link_element.text.strip()
                
                if href and not href.startswith(('javascript:', 'mailto:', 'tel:')):
                    links.append({
                        'id': f'selenium_link_{i}',
                        'element': link_element,
                        'href': href,
                        'text': text,
                        'method': 'selenium'
                    })
                    
        except Exception as e:
            self.logger.error(f"Selenium link discovery failed: {e}")
        
        return links
    
    async def _take_screenshot(self, name: str) -> Optional[str]:
        """Take a screenshot for documentation"""
        try:
            timestamp = int(time.time())
            filename = f"{name}_{timestamp}.png"
            filepath = self.screenshots_dir / filename
            
            if self.use_stagehand and self.page:
                await self.page.screenshot(path=str(filepath))
            elif self.selenium_driver:
                self.selenium_driver.save_screenshot(str(filepath))
            else:
                return None
            
            return str(filepath)
            
        except Exception as e:
            self.logger.debug(f"Screenshot failed: {e}")
            return None
    
    async def close(self):
        """Clean up resources"""
        try:
            if self.stagehand:
                await self.stagehand.close()
            if self.selenium_driver:
                self.selenium_driver.quit()
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
    
    def get_navigation_summary(self) -> Dict[str, Any]:
        """Get summary of navigation history"""
        return {
            'total_navigations': len(self.navigation_history),
            'successful_navigations': sum(1 for nav in self.navigation_history if nav.success),
            'total_forms_found': sum(nav.forms_found for nav in self.navigation_history),
            'total_links_found': sum(nav.links_found for nav in self.navigation_history),
            'total_form_interactions': len(self.form_interactions),
            'vulnerabilities_found': sum(
                len(interaction.vulnerability_indicators) 
                for interaction in self.form_interactions
            )
        }


# Convenience functions for integration
async def create_stagehand_crawler(ai_policy: Optional[AIPolicy] = None, **kwargs) -> StagehandWebCrawler:
    """Create and initialize a Stagehand crawler"""
    crawler = StagehandWebCrawler(ai_policy=ai_policy, **kwargs)
    await crawler.initialize()
    return crawler
