#!/usr/bin/env python3
"""
🎭 PLAYWRIGHT STEALTH BROWSER MANAGER
Advanced browser automation with anti-detection and cross-browser support
"""

import asyncio
import json
import random
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import logging
from datetime import datetime
import platform
import os

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    Browser = None
    BrowserContext = None
    Page = None

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class StealthBrowserManager:
    """Advanced browser manager with stealth capabilities and anti-detection measures"""
    
    def __init__(self, 
                 headless: bool = True,
                 browser_type: str = "chromium",
                 stealth_mode: bool = True,
                 proxy: Optional[str] = None,
                 user_agent: Optional[str] = None,
                 viewport: Optional[Dict[str, int]] = None,
                 timeout: int = 30000):
        """
        Initialize stealth browser manager
        
        Args:
            headless: Run browser in headless mode
            browser_type: Browser type (chromium, firefox, webkit)
            stealth_mode: Enable stealth mode with anti-detection
            proxy: Proxy configuration
            user_agent: Custom user agent
            viewport: Viewport dimensions
            timeout: Page timeout in milliseconds
        """
        self.headless = headless
        self.browser_type = browser_type.lower()
        self.stealth_mode = stealth_mode
        self.proxy = proxy
        self.user_agent = user_agent
        self.viewport = viewport or {"width": 1920, "height": 1080}
        self.timeout = timeout
        
        # Browser instances
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        
        # Monitoring and analytics
        self.monitoring_data = {
            'requests': [],
            'responses': [],
            'errors': [],
            'performance': {},
            'detection_events': []
        }
        
        # Stealth configurations
        self.stealth_configs = self._load_stealth_configs()
        self.user_agents = self._load_user_agents()
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
    def _load_stealth_configs(self) -> Dict[str, Any]:
        """Load stealth configuration for different browsers"""
        return {
            'chromium': {
                'args': [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--disable-gpu',
                    '--disable-background-timer-throttling',
                    '--disable-backgrounding-occluded-windows',
                    '--disable-renderer-backgrounding',
                    '--disable-features=TranslateUI',
                    '--disable-ipc-flooding-protection',
                    '--disable-default-apps',
                    '--disable-extensions',
                    '--disable-plugins',
                    '--disable-images',
                    '--disable-javascript',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor',
                    '--disable-blink-features=AutomationControlled'
                ],
                'ignore_https_errors': True,
                'java_script_enabled': True,
                'has_touch': False,
                'is_mobile': False,
                'locale': 'en-US',
                'timezone_id': 'America/New_York'
            },
            'firefox': {
                'args': [
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-background-timer-throttling',
                    '--disable-backgrounding-occluded-windows',
                    '--disable-renderer-backgrounding'
                ],
                'ignore_https_errors': True,
                'java_script_enabled': True,
                'has_touch': False,
                'is_mobile': False,
                'locale': 'en-US',
                'timezone_id': 'America/New_York'
            },
            'webkit': {
                'args': [
                    '--no-sandbox',
                    '--disable-dev-shm-usage'
                ],
                'ignore_https_errors': True,
                'java_script_enabled': True,
                'has_touch': False,
                'is_mobile': False,
                'locale': 'en-US',
                'timezone_id': 'America/New_York'
            }
        }
    
    def _load_user_agents(self) -> List[str]:
        """Load realistic user agents for different browsers"""
        return [
            # Chrome
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            
            # Firefox
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            
            # Safari
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            
            # Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        ]
    
    async def initialize(self) -> bool:
        """Initialize browser with stealth configuration"""
        try:
            if not PLAYWRIGHT_AVAILABLE:
                self.logger.error("Playwright not available. Install with: pip install playwright")
                return False
            
            self.playwright = await async_playwright().start()
            
            # Get browser type
            browser_class = getattr(self.playwright, self.browser_type)
            
            # Configure browser launch options
            launch_options = {
                'headless': self.headless,
                'args': self.stealth_configs[self.browser_type]['args']
            }
            
            # Add proxy if specified
            if self.proxy:
                launch_options['proxy'] = {'server': self.proxy}
            
            # Launch browser
            self.browser = await browser_class.launch(**launch_options)
            
            # Create context with stealth settings
            context_options = {
                'ignore_https_errors': self.stealth_configs[self.browser_type]['ignore_https_errors'],
                'java_script_enabled': self.stealth_configs[self.browser_type]['java_script_enabled'],
                'has_touch': self.stealth_configs[self.browser_type]['has_touch'],
                'is_mobile': self.stealth_configs[self.browser_type]['is_mobile'],
                'locale': self.stealth_configs[self.browser_type]['locale'],
                'timezone_id': self.stealth_configs[self.browser_type]['timezone_id'],
                'viewport': self.viewport,
                'user_agent': self.user_agent or random.choice(self.user_agents)
            }
            
            self.context = await self.browser.new_context(**context_options)
            
            # Create page and apply stealth measures
            self.page = await self.context.new_page()
            await self.page.set_default_timeout(self.timeout)
            
            # Apply stealth measures
            if self.stealth_mode:
                await self._apply_stealth_measures()
            
            # Setup monitoring
            await self._setup_monitoring()
            
            self.logger.info(f"Browser initialized successfully: {self.browser_type}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize browser: {e}")
            return False
    
    async def _apply_stealth_measures(self):
        """Apply advanced stealth measures to avoid detection"""
        try:
            # Remove webdriver properties
            await self.page.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });
            """)
            
            # Override permissions
            await self.page.add_init_script("""
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                        Promise.resolve({ state: Notification.permission }) :
                        originalQuery(parameters)
                );
            """)
            
            # Override plugins
            await self.page.add_init_script("""
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                });
            """)
            
            # Override languages
            await self.page.add_init_script("""
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en'],
                });
            """)
            
            # Override chrome
            await self.page.add_init_script("""
                window.chrome = {
                    runtime: {},
                };
            """)
            
            # Override permissions
            await self.page.add_init_script("""
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                        Promise.resolve({ state: Notification.permission }) :
                        originalQuery(parameters)
                );
            """)
            
            # Override webgl
            await self.page.add_init_script("""
                const getParameter = WebGLRenderingContext.prototype.getParameter;
                WebGLRenderingContext.prototype.getParameter = function(parameter) {
                    if (parameter === 37445) {
                        return 'Intel Inc.';
                    }
                    if (parameter === 37446) {
                        return 'Intel(R) Iris(TM) Graphics 6100';
                    }
                    return getParameter.apply(this, arguments);
                };
            """)
            
            # Override canvas fingerprinting
            await self.page.add_init_script("""
                const originalGetContext = HTMLCanvasElement.prototype.getContext;
                HTMLCanvasElement.prototype.getContext = function(type, ...args) {
                    const context = originalGetContext.apply(this, [type, ...args]);
                    if (type === '2d') {
                        const originalFillText = context.fillText;
                        context.fillText = function(...args) {
                            args[0] = args[0] + ' ';
                            return originalFillText.apply(this, args);
                        };
                    }
                    return context;
                };
            """)
            
            self.logger.info("Stealth measures applied successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to apply stealth measures: {e}")
    
    async def _setup_monitoring(self):
        """Setup real-time monitoring for requests, responses, and errors"""
        try:
            # Monitor requests
            await self.page.on('request', self._on_request)
            
            # Monitor responses
            await self.page.on('response', self._on_response)
            
            # Monitor console messages
            await self.page.on('console', self._on_console)
            
            # Monitor page errors
            await self.page.on('pageerror', self._on_page_error)
            
            # Monitor frame errors
            await self.page.on('framecrashed', self._on_frame_crashed)
            
            self.logger.info("Monitoring setup completed")
            
        except Exception as e:
            self.logger.error(f"Failed to setup monitoring: {e}")
    
    async def _on_request(self, request):
        """Handle request monitoring"""
        self.monitoring_data['requests'].append({
            'url': request.url,
            'method': request.method,
            'headers': request.headers,
            'timestamp': datetime.now().isoformat()
        })
    
    async def _on_response(self, response):
        """Handle response monitoring"""
        self.monitoring_data['responses'].append({
            'url': response.url,
            'status': response.status,
            'headers': response.headers,
            'timestamp': datetime.now().isoformat()
        })
    
    async def _on_console(self, msg):
        """Handle console message monitoring"""
        if msg.type in ['error', 'warning']:
            self.monitoring_data['errors'].append({
                'type': msg.type,
                'text': msg.text,
                'timestamp': datetime.now().isoformat()
            })
    
    async def _on_page_error(self, error):
        """Handle page error monitoring"""
        self.monitoring_data['errors'].append({
            'type': 'page_error',
            'text': str(error),
            'timestamp': datetime.now().isoformat()
        })
    
    async def _on_frame_crashed(self, frame):
        """Handle frame crash monitoring"""
        self.monitoring_data['errors'].append({
            'type': 'frame_crashed',
            'text': f"Frame crashed: {frame.url}",
            'timestamp': datetime.now().isoformat()
        })
    
    async def navigate_to(self, url: str, wait_for_load: bool = True) -> bool:
        """Navigate to URL with stealth measures"""
        try:
            await self.page.goto(url, wait_until='networkidle' if wait_for_load else 'domcontentloaded')
            
            # Random delay to simulate human behavior
            if self.stealth_mode:
                await asyncio.sleep(random.uniform(1, 3))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to navigate to {url}: {e}")
            return False
    
    async def get_page_content(self) -> str:
        """Get current page content"""
        try:
            return await self.page.content()
        except Exception as e:
            self.logger.error(f"Failed to get page content: {e}")
            return ""
    
    async def execute_script(self, script: str) -> Any:
        """Execute JavaScript on the page"""
        try:
            return await self.page.evaluate(script)
        except Exception as e:
            self.logger.error(f"Failed to execute script: {e}")
            return None
    
    async def click_element(self, selector: str, wait_for: bool = True) -> bool:
        """Click element with stealth measures"""
        try:
            if wait_for:
                await self.page.wait_for_selector(selector)
            
            await self.page.click(selector)
            
            # Random delay
            if self.stealth_mode:
                await asyncio.sleep(random.uniform(0.5, 2))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to click element {selector}: {e}")
            return False
    
    async def fill_form(self, form_data: Dict[str, str]) -> bool:
        """Fill form with stealth measures"""
        try:
            for selector, value in form_data.items():
                await self.page.fill(selector, value)
                
                # Random delay between fields
                if self.stealth_mode:
                    await asyncio.sleep(random.uniform(0.1, 0.5))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to fill form: {e}")
            return False
    
    async def take_screenshot(self, path: str = None) -> str:
        """Take screenshot with timestamp"""
        try:
            if not path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = f"screenshots/screenshot_{timestamp}.png"
            
            # Ensure directory exists
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            
            await self.page.screenshot(path=path)
            return path
            
        except Exception as e:
            self.logger.error(f"Failed to take screenshot: {e}")
            return ""
    
    async def get_network_logs(self) -> List[Dict]:
        """Get network activity logs"""
        return self.monitoring_data['requests']
    
    async def get_performance_metrics(self) -> Dict:
        """Get page performance metrics"""
        try:
            metrics = await self.page.evaluate("""
                () => {
                    const perf = performance.getEntriesByType('navigation')[0];
                    return {
                        loadTime: perf.loadEventEnd - perf.loadEventStart,
                        domContentLoaded: perf.domContentLoadedEventEnd - perf.domContentLoadedEventStart,
                        firstPaint: performance.getEntriesByName('first-paint')[0]?.startTime || 0,
                        firstContentfulPaint: performance.getEntriesByName('first-contentful-paint')[0]?.startTime || 0
                    };
                }
            """)
            
            self.monitoring_data['performance'] = metrics
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to get performance metrics: {e}")
            return {}
    
    async def detect_automation(self) -> Dict[str, bool]:
        """Detect if automation is being detected"""
        try:
            detection_results = await self.page.evaluate("""
                () => {
                    const results = {};
                    
                    // Check for webdriver property
                    results.webdriver = navigator.webdriver === true;
                    
                    // Check for chrome automation
                    results.chrome_automation = window.chrome && window.chrome.runtime && window.chrome.runtime.onConnect;
                    
                    // Check for selenium
                    results.selenium = window.document.$cdc_asdjflasutopfhvcZLmcfl_ || window.document.$chrome_asyncScriptInfo;
                    
                    // Check for playwright
                    results.playwright = window.navigator.plugins.length === 0;
                    
                    // Check for headless
                    results.headless = !window.chrome || !window.chrome.app;
                    
                    return results;
                }
            """)
            
            return detection_results
            
        except Exception as e:
            self.logger.error(f"Failed to detect automation: {e}")
            return {}
    
    async def switch_browser(self, browser_type: str) -> bool:
        """Switch to different browser type"""
        try:
            await self.close()
            
            self.browser_type = browser_type.lower()
            return await self.initialize()
            
        except Exception as e:
            self.logger.error(f"Failed to switch browser: {e}")
            return False
    
    async def add_custom_headers(self, headers: Dict[str, str]):
        """Add custom headers to requests"""
        try:
            await self.context.set_extra_http_headers(headers)
            self.logger.info(f"Added custom headers: {headers}")
            
        except Exception as e:
            self.logger.error(f"Failed to add custom headers: {e}")
    
    async def set_cookies(self, cookies: List[Dict]):
        """Set cookies for the session"""
        try:
            await self.context.add_cookies(cookies)
            self.logger.info(f"Added {len(cookies)} cookies")
            
        except Exception as e:
            self.logger.error(f"Failed to set cookies: {e}")
    
    async def get_cookies(self) -> List[Dict]:
        """Get current cookies"""
        try:
            return await self.context.cookies()
        except Exception as e:
            self.logger.error(f"Failed to get cookies: {e}")
            return []
    
    async def close(self):
        """Close browser and cleanup"""
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
                
            self.logger.info("Browser closed successfully")
            
        except Exception as e:
            self.logger.error(f"Error closing browser: {e}")


class CrossBrowserManager:
    """Manager for cross-browser testing and automation"""
    
    def __init__(self):
        self.browsers = {}
        self.active_browser = None
    
    async def create_browser(self, browser_type: str, **kwargs) -> StealthBrowserManager:
        """Create browser instance for specified type"""
        browser = StealthBrowserManager(browser_type=browser_type, **kwargs)
        await browser.initialize()
        
        self.browsers[browser_type] = browser
        if not self.active_browser:
            self.active_browser = browser_type
            
        return browser
    
    async def switch_active_browser(self, browser_type: str) -> bool:
        """Switch active browser"""
        if browser_type in self.browsers:
            self.active_browser = browser_type
            return True
        return False
    
    async def get_active_browser(self) -> Optional[StealthBrowserManager]:
        """Get currently active browser"""
        return self.browsers.get(self.active_browser)
    
    async def run_cross_browser_test(self, test_func, browsers: List[str] = None) -> Dict[str, Any]:
        """Run test across multiple browsers"""
        if not browsers:
            browsers = ['chromium', 'firefox', 'webkit']
        
        results = {}
        
        for browser_type in browsers:
            try:
                browser = await self.create_browser(browser_type)
                result = await test_func(browser)
                results[browser_type] = result
                
            except Exception as e:
                results[browser_type] = {'error': str(e)}
            
            finally:
                await browser.close()
        
        return results
    
    async def close_all(self):
        """Close all browser instances"""
        for browser in self.browsers.values():
            await browser.close()
        self.browsers.clear()


# Example usage and testing
async def main():
    """Example usage of the stealth browser manager"""
    
    # Create browser manager
    browser_manager = StealthBrowserManager(
        headless=True,
        browser_type="chromium",
        stealth_mode=True
    )
    
    # Initialize browser
    if await browser_manager.initialize():
        console.print("✅ Browser initialized successfully", style="green")
        
        # Navigate to test page
        await browser_manager.navigate_to("http://testphp.vulnweb.com")
        
        # Get page content
        content = await browser_manager.get_page_content()
        console.print(f"📄 Page content length: {len(content)}", style="blue")
        
        # Check for automation detection
        detection = await browser_manager.detect_automation()
        console.print(f"🔍 Automation detection: {detection}", style="yellow")
        
        # Get performance metrics
        metrics = await browser_manager.get_performance_metrics()
        console.print(f"⚡ Performance metrics: {metrics}", style="cyan")
        
        # Take screenshot
        screenshot_path = await browser_manager.take_screenshot()
        console.print(f"📸 Screenshot saved: {screenshot_path}", style="green")
        
        # Close browser
        await browser_manager.close()
        console.print("🔒 Browser closed", style="red")


if __name__ == "__main__":
    asyncio.run(main())