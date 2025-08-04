"""
Browser automation for visual inspection and testing
"""

import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import base64
import json

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager

from ..models.command_result import BrowserResult
from ..utils.logger import setup_logger


class BrowserAutomator:
    """
    Automates browser interactions for visual inspection and testing
    """
    
    def __init__(self, headless: bool = False, timeout: int = 30):
        """
        Initialize the browser automator
        
        Args:
            headless: Whether to run browser in headless mode
            timeout: Default timeout for operations
        """
        self.headless = headless
        self.timeout = timeout
        self.driver: Optional[webdriver.Chrome] = None
        self.logger = setup_logger(__name__)
        
    async def __aenter__(self):
        """Async context manager entry"""
        await self.start_browser()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close_browser()
    
    async def start_browser(self):
        """Start the Chrome browser"""
        try:
            self.logger.info("Starting Chrome browser")
            
            # Chrome options
            chrome_options = Options()
            if self.headless:
                chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            
            # Install ChromeDriver if needed
            service = Service(ChromeDriverManager().install())
            
            # Create driver
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.implicitly_wait(10)
            
            self.logger.info("Browser started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start browser: {e}")
            raise
    
    async def close_browser(self):
        """Close the browser"""
        if self.driver:
            try:
                self.driver.quit()
                self.logger.info("Browser closed")
            except Exception as e:
                self.logger.error(f"Error closing browser: {e}")
            finally:
                self.driver = None
    
    async def test_url(self, url: str, 
                      check_elements: Optional[List[str]] = None) -> BrowserResult:
        """
        Test a URL by loading it in the browser and analyzing the result
        
        Args:
            url: URL to test
            check_elements: Optional list of CSS selectors to check for
            
        Returns:
            BrowserResult with test results
        """
        if not self.driver:
            await self.start_browser()
        
        self.logger.info(f"Testing URL: {url}")
        start_time = datetime.now()
        
        try:
            # Navigate to URL
            self.driver.get(url)
            
            # Wait for page to load
            WebDriverWait(self.driver, self.timeout).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            load_time = (datetime.now() - start_time).total_seconds()
            
            # Get page information
            title = self.driver.title
            current_url = self.driver.current_url
            page_source_length = len(self.driver.page_source)
            
            # Take screenshot
            screenshot = self.driver.get_screenshot_as_base64()
            
            # Check for common error indicators
            errors = []
            page_source = self.driver.page_source.lower()
            
            # Common error patterns
            error_patterns = [
                "404", "not found", "error", "exception", "failed", 
                "internal server error", "bad gateway", "service unavailable"
            ]
            
            for pattern in error_patterns:
                if pattern in page_source or pattern in title.lower():
                    errors.append(f"Found potential error indicator: {pattern}")
            
            # Check for specific elements if provided
            elements_found = {}
            if check_elements:
                for selector in check_elements:
                    try:
                        element = self.driver.find_element(By.CSS_SELECTOR, selector)
                        elements_found[selector] = {
                            "found": True,
                            "text": element.text[:100],  # First 100 chars
                            "visible": element.is_displayed()
                        }
                    except:
                        elements_found[selector] = {"found": False}
            
            # Analyze page performance
            performance_metrics = {}
            try:
                # Get performance metrics via JavaScript
                metrics = self.driver.execute_script("""
                    return {
                        loadEventEnd: performance.timing.loadEventEnd,
                        navigationStart: performance.timing.navigationStart,
                        domContentLoaded: performance.timing.domContentLoadedEventEnd,
                        firstPaint: performance.getEntriesByType('paint')[0]?.startTime || 0
                    };
                """)
                performance_metrics = metrics
            except:
                pass
            
            # Determine success
            success = (
                self.driver.current_url.startswith(('http://', 'https://')) and
                len(errors) == 0 and
                "error" not in title.lower()
            )
            
            result = BrowserResult(
                url=url,
                final_url=current_url,
                success=success,
                title=title,
                load_time=load_time,
                page_size=page_source_length,
                screenshot_base64=screenshot,
                errors=errors,
                elements_found=elements_found,
                performance_metrics=performance_metrics,
                timestamp=start_time.isoformat()
            )
            
            if success:
                self.logger.info(f"URL test successful: {title}")
            else:
                self.logger.warning(f"URL test found issues: {errors}")
            
            return result
            
        except TimeoutException:
            load_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Page load timeout after {self.timeout}s")
            
            return BrowserResult(
                url=url,
                final_url=url,
                success=False,
                title="",
                load_time=load_time,
                page_size=0,
                screenshot_base64="",
                errors=[f"Page load timeout after {self.timeout} seconds"],
                elements_found={},
                performance_metrics={},
                timestamp=start_time.isoformat()
            )
            
        except WebDriverException as e:
            load_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"WebDriver error: {e}")
            
            return BrowserResult(
                url=url,
                final_url=url,
                success=False,
                title="",
                load_time=load_time,
                page_size=0,
                screenshot_base64="",
                errors=[f"WebDriver error: {str(e)}"],
                elements_found={},
                performance_metrics={},
                timestamp=start_time.isoformat()
            )
        
        except Exception as e:
            load_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Unexpected error testing URL: {e}")
            
            return BrowserResult(
                url=url,
                final_url=url,
                success=False,
                title="",
                load_time=load_time,
                page_size=0,
                screenshot_base64="",
                errors=[f"Unexpected error: {str(e)}"],
                elements_found={},
                performance_metrics={},
                timestamp=start_time.isoformat()
            )
    
    async def extract_page_content(self, url: str) -> Dict[str, Any]:
        """
        Extract detailed content from a web page
        
        Args:
            url: URL to extract content from
            
        Returns:
            Dictionary with extracted content
        """
        if not self.driver:
            await self.start_browser()
        
        self.logger.info(f"Extracting content from: {url}")
        
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, self.timeout).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            # Extract various content types
            content = {
                "title": self.driver.title,
                "url": self.driver.current_url,
                "headers": [],
                "links": [],
                "forms": [],
                "images": [],
                "text_content": ""
            }
            
            # Extract headers
            for i in range(1, 7):
                headers = self.driver.find_elements(By.TAG_NAME, f"h{i}")
                content["headers"].extend([h.text for h in headers if h.text.strip()])
            
            # Extract links
            links = self.driver.find_elements(By.TAG_NAME, "a")
            content["links"] = [{"text": link.text, "href": link.get_attribute("href")} 
                              for link in links[:20] if link.get_attribute("href")]
            
            # Extract forms
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                form_data = {
                    "action": form.get_attribute("action"),
                    "method": form.get_attribute("method"),
                    "inputs": []
                }
                inputs = form.find_elements(By.TAG_NAME, "input")
                for inp in inputs:
                    form_data["inputs"].append({
                        "type": inp.get_attribute("type"),
                        "name": inp.get_attribute("name"),
                        "placeholder": inp.get_attribute("placeholder")
                    })
                content["forms"].append(form_data)
            
            # Extract images
            images = self.driver.find_elements(By.TAG_NAME, "img")
            content["images"] = [{"src": img.get_attribute("src"), 
                                "alt": img.get_attribute("alt")} 
                               for img in images[:10]]
            
            # Extract text content
            body = self.driver.find_element(By.TAG_NAME, "body")
            content["text_content"] = body.text[:1000]  # First 1000 chars
            
            return content
            
        except Exception as e:
            self.logger.error(f"Error extracting content: {e}")
            return {"error": str(e)}
    
    async def run_javascript(self, script: str) -> Any:
        """
        Execute JavaScript in the browser
        
        Args:
            script: JavaScript code to execute
            
        Returns:
            Result of the script execution
        """
        if not self.driver:
            await self.start_browser()
        
        try:
            return self.driver.execute_script(script)
        except Exception as e:
            self.logger.error(f"Error executing JavaScript: {e}")
            return None
