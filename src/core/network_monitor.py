"""
Production-grade network monitor for Advanced Intelligent Web Crawler
Captures HTTP/HTTPS traffic, errors, and integrates with logger and AI analyzer
"""

from typing import Dict, Any, List, Optional
from selenium.webdriver.remote.webdriver import WebDriver
from .logger import Logger
from .ai_analyzer import AIAnalyzer
import asyncio

class NetworkMonitor:
    """
    Real-time network monitor using Selenium CDP
    """
    def __init__(self, driver: WebDriver, logger: Logger, ai_analyzer: AIAnalyzer, config):
        self.driver = driver
        self.logger = logger
        self.ai_analyzer = ai_analyzer
        self.config = config
        self.enabled = False
        self.seen_requests = set()
        self.seen_responses = set()

    async def enable(self):
        """Enable network monitoring via CDP"""
        if not self.enabled:
            try:
                self.driver.execute_cdp_cmd('Network.enable', {})
                self.enabled = True
                self.logger.info("Network monitoring enabled", 'network_monitor')
            except Exception as e:
                self.logger.warning(f"Failed to enable network monitoring: {e}", 'network_monitor')

    async def capture_traffic(self, interval: int = 2):
        """Capture network traffic in real time"""
        if not self.enabled:
            await self.enable()
        try:
            while True:
                # Capture requests
                try:
                    requests = self.driver.execute_cdp_cmd('Network.getRequestPostData', {})
                except Exception:
                    requests = []
                # Capture responses
                try:
                    responses = self.driver.execute_cdp_cmd('Network.getResponseBody', {})
                except Exception:
                    responses = []
                # Log and analyze new requests
                for req in requests if isinstance(requests, list) else []:
                    req_id = req.get('requestId')
                    if req_id and req_id not in self.seen_requests:
                        self.seen_requests.add(req_id)
                        self.logger.log_network_event('request', req.get('url'), req.get('method'), data=req)
                        if self.config.advanced.enable_ai_analysis:
                            ai_result = await self.ai_analyzer.analyze_network_traffic(req, req.get('url'))
                            self.logger.log_ai_event("AI network request analysis", self.ai_analyzer.current_model, ai_result.__dict__, req.get('url'))
                # Log and analyze new responses
                for resp in responses if isinstance(responses, list) else []:
                    resp_id = resp.get('requestId')
                    if resp_id and resp_id not in self.seen_responses:
                        self.seen_responses.add(resp_id)
                        self.logger.log_network_event('response', resp.get('url'), data=resp)
                        if self.config.advanced.enable_ai_analysis:
                            ai_result = await self.ai_analyzer.analyze_network_traffic(resp, resp.get('url'))
                            self.logger.log_ai_event("AI network response analysis", self.ai_analyzer.current_model, ai_result.__dict__, resp.get('url'))
                await asyncio.sleep(interval)
        except Exception as e:
            self.logger.error(f"Error in network traffic capture: {e}", 'network_monitor') 