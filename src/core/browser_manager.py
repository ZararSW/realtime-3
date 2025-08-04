"""
Production-grade browser manager for Advanced Intelligent Web Crawler
Featured with Playwright for better reliability, speed, and modern web app support
"""

import asyncio
import time
from typing import Dict, Any, Optional, List
from pathlib import Path

# Playwright imports
try:
    from playwright.async_api import async_playwright, Browser, Page, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from .logger import Logger


class BrowserManager:
    """
    Production-grade browser manager with Playwright for better reliability and speed
    """
    
    def __init__(self, config, logger: Logger):
        """
        Initialize browser manager
        
        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.is_initialized = False
        self.start_time = None
        self.screenshots_dir = Path(getattr(config.output, 'screenshot_path', 'screenshots'))
        self.screenshots_dir.mkdir(exist_ok=True)
        
    async def initialize(self) -> bool:
        """
        Initialize browser with stealth capabilities
        
        Returns:
            bool: True if initialization successful
        """
        try:
            self.logger.info("Initializing browser with stealth capabilities")
            
            # Setup Chrome options
            chrome_options = self._setup_chrome_options()
            
            # Setup Chrome service
            self.service = Service(ChromeDriverManager().install())
            
            # Create driver
            self.driver = webdriver.Chrome(
                service=self.service,
                options=chrome_options
            )
            
            # Apply stealth settings
            await self._apply_stealth_settings()
            
            # Set timeouts
            self.driver.set_page_load_timeout(self.config.browser.page_load_timeout)
            self.driver.implicitly_wait(self.config.browser.implicit_wait)
            
            # Set window size
            if self.config.browser.window_size:
                width, height = self.config.browser.window_size.split('x')
                self.driver.set_window_size(int(width), int(height))
            
            self.is_initialized = True
            self.start_time = time.time()
            
            self.logger.info("Browser initialized successfully", 'browser_init', {
                'user_agent': self.config.browser.user_agent,
                'headless': self.config.browser.headless,
                'window_size': self.config.browser.window_size
            })
            
            return True
            
        except SessionNotCreatedException as e:
            self.logger.error(f"Failed to create browser session: {e}", 'browser_init')
            return False
        except WebDriverException as e:
            self.logger.error(f"WebDriver error during initialization: {e}", 'browser_init')
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during browser initialization: {e}", 'browser_init')
            return False
    
    def _setup_chrome_options(self) -> Options:
        """Setup Chrome options with stealth and security settings"""
        options = Options()
        
        # Basic options
        if self.config.browser.headless:
            options.add_argument("--headless")
        
        options.add_argument(f"--user-agent={self.config.browser.user_agent}")
        
        # Add configured Chrome options
        for option in self.config.browser.chrome_options:
            options.add_argument(option)
        
        # Additional stealth options
        if self.config.browser.stealth_mode:
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option('useAutomationExtension', False)
            options.add_argument("--disable-blink-features=AutomationControlled")
        
        # Performance options
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-plugins")
        
        # Security options
        options.add_argument("--disable-web-security")
        options.add_argument("--disable-features=VizDisplayCompositor")
        
        return options
    
    async def _apply_stealth_settings(self):
        """Apply additional stealth settings via JavaScript"""
        try:
            # Remove webdriver property
            self.driver.execute_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
            )
            
            # Fake plugins
            self.driver.execute_script(
                "Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]})"
            )
            
            # Fake languages
            self.driver.execute_script(
                "Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']})"
            )
            
            # Fake permissions
            self.driver.execute_script(
                "Object.defineProperty(navigator, 'permissions', {get: () => ({query: () => Promise.resolve({state: 'granted'})})})"
            )
            
            self.logger.debug("Stealth settings applied successfully", 'browser_stealth')
            
        except Exception as e:
            self.logger.warning(f"Failed to apply some stealth settings: {e}", 'browser_stealth')
    
    async def navigate_to(self, url: str, wait_for_load: bool = True) -> bool:
        """
        Navigate to URL with error handling
        
        Args:
            url: URL to navigate to
            wait_for_load: Whether to wait for page load
            
        Returns:
            bool: True if navigation successful
        """
        if not self.is_initialized:
            self.logger.error("Browser not initialized", 'browser_navigation')
            return False
        
        try:
            self.logger.info(f"Navigating to: {url}", 'browser_navigation')
            
            self.driver.get(url)
            
            if wait_for_load:
                # Wait for page to load
                WebDriverWait(self.driver, self.config.browser.page_load_timeout).until(
                    lambda driver: driver.execute_script("return document.readyState") == "complete"
                )
            
            self.logger.info(f"Successfully navigated to: {url}", 'browser_navigation')
            return True
            
        except TimeoutException:
            self.logger.error(f"Timeout navigating to: {url}", 'browser_navigation')
            return False
        except WebDriverException as e:
            self.logger.error(f"WebDriver error navigating to {url}: {e}", 'browser_navigation')
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error navigating to {url}: {e}", 'browser_navigation')
            return False
    
    async def get_page_source(self) -> Optional[str]:
        """Get current page source"""
        if not self.is_initialized:
            return None
        
        try:
            return self.driver.page_source
        except Exception as e:
            self.logger.error(f"Error getting page source: {e}", 'browser_operation')
            return None
    
    async def get_current_url(self) -> Optional[str]:
        """Get current URL"""
        if not self.is_initialized:
            return None
        
        try:
            return self.driver.current_url
        except Exception as e:
            self.logger.error(f"Error getting current URL: {e}", 'browser_operation')
            return None
    
    async def execute_script(self, script: str, *args) -> Any:
        """Execute JavaScript with error handling"""
        if not self.is_initialized:
            return None
        
        try:
            return self.driver.execute_script(script, *args)
        except Exception as e:
            self.logger.error(f"Error executing script: {e}", 'browser_operation')
            return None
    
    async def find_elements(self, by: By, value: str) -> List[Any]:
        """Find elements with error handling"""
        if not self.is_initialized:
            return []
        
        try:
            return self.driver.find_elements(by, value)
        except Exception as e:
            self.logger.error(f"Error finding elements {by}={value}: {e}", 'browser_operation')
            return []
    
    async def find_element(self, by: By, value: str) -> Optional[Any]:
        """Find single element with error handling"""
        if not self.is_initialized:
            return None
        
        try:
            return self.driver.find_element(by, value)
        except NoSuchElementException:
            return None
        except Exception as e:
            self.logger.error(f"Error finding element {by}={value}: {e}", 'browser_operation')
            return None
    
    async def wait_for_element(self, by: By, value: str, timeout: int = 10) -> Optional[Any]:
        """Wait for element to be present"""
        if not self.is_initialized:
            return None
        
        try:
            element = WebDriverWait(self.driver, timeout).until(
                EC.presence_of_element_located((by, value))
            )
            return element
        except TimeoutException:
            self.logger.warning(f"Timeout waiting for element {by}={value}", 'browser_operation')
            return None
        except Exception as e:
            self.logger.error(f"Error waiting for element {by}={value}: {e}", 'browser_operation')
            return None
    
    async def get_console_logs(self) -> List[Dict[str, Any]]:
        """Get browser console logs"""
        if not self.is_initialized:
            return []
        
        try:
            return self.driver.get_log('browser')
        except Exception as e:
            self.logger.warning(f"Error getting console logs: {e}", 'browser_operation')
            return []
    
    async def take_screenshot(self, filename: str = None) -> Optional[str]:
        """Take screenshot and save to file"""
        if not self.is_initialized:
            return None
        
        try:
            if not filename:
                timestamp = int(time.time())
                filename = f"screenshot_{timestamp}.png"
            
            filepath = f"{self.config.output.screenshot_path}/{filename}"
            self.driver.save_screenshot(filepath)
            
            self.logger.info(f"Screenshot saved: {filepath}", 'browser_screenshot')
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error taking screenshot: {e}", 'browser_screenshot')
            return None
    
    async def enable_network_monitoring(self) -> bool:
        """Enable network monitoring via CDP"""
        if not self.is_initialized:
            return False
        
        try:
            self.driver.execute_cdp_cmd('Network.enable', {})
            self.logger.info("Network monitoring enabled", 'browser_network')
            return True
        except Exception as e:
            self.logger.warning(f"Failed to enable network monitoring: {e}", 'browser_network')
            return False
    
    def get_browser_info(self) -> Dict[str, Any]:
        """Get browser information"""
        if not self.is_initialized:
            return {}
        
        try:
            return {
                'current_url': self.driver.current_url,
                'title': self.driver.title,
                'window_size': self.driver.get_window_size(),
                'user_agent': self.driver.execute_script("return navigator.userAgent"),
                'uptime': time.time() - self.start_time if self.start_time else 0
            }
        except Exception as e:
            self.logger.error(f"Error getting browser info: {e}", 'browser_operation')
            return {}
    
    async def close(self):
        """Close browser and cleanup resources"""
        if self.driver:
            try:
                self.driver.quit()
                self.logger.info("Browser closed successfully", 'browser_cleanup')
            except Exception as e:
                self.logger.error(f"Error closing browser: {e}", 'browser_cleanup')
            finally:
                self.driver = None
                self.is_initialized = False
        
        if self.service:
            try:
                self.service.stop()
            except Exception as e:
                self.logger.error(f"Error stopping service: {e}", 'browser_cleanup')
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close() 