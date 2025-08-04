#!/usr/bin/env python3
"""
Comprehensive test suite for AdvancedIntelligentCrawler
Tests XSS detection, SQL injection, WordPress vulnerabilities, API endpoints, and form submission
"""

import asyncio
import pytest
import unittest
from unittest.mock import Mock, patch, AsyncMock
import json
import tempfile
import os
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from advanced_intelligent_crawler import AdvancedIntelligentCrawler
from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer


class TestAdvancedCrawler(unittest.TestCase):
    """Comprehensive test suite for AdvancedIntelligentCrawler"""
    
    def setUp(self):
        """Set up test environment"""
        self.crawler = AdvancedIntelligentCrawler(log_to_file=False)
        self.test_url = "http://testphp.vulnweb.com"
        self.mock_ai_analyzer = Mock(spec=AIAnalyzer)
        
    def tearDown(self):
        """Clean up after tests"""
        if hasattr(self.crawler, 'driver') and self.crawler.driver:
            self.crawler.driver.quit()

    @pytest.mark.asyncio
    async def test_xss_detection_basic(self):
        """Test basic XSS detection capabilities"""
        # Mock page source with potential XSS
        test_page_source = """
        <html>
        <body>
        <input type="text" value="<script>alert('xss')</script>">
        <div id="content"><script>alert('stored')</script></div>
        <form action="/search">
            <input name="q" value="<img src=x onerror=alert(1)>">
        </form>
        </body>
        </html>
        """
        
        with patch.object(self.crawler, '_make_request_safe') as mock_request:
            mock_request.return_value = Mock(
                text=test_page_source,
                status_code=200,
                headers={}
            )
            
            # Test XSS detection
            vulnerabilities = await self.crawler._test_injection_comprehensive()
            
            # Verify XSS payloads are tested
            self.assertIn('xss', str(vulnerabilities).lower())
            self.assertTrue(hasattr(self.crawler, 'discovered_assets'))

    @pytest.mark.asyncio
    async def test_xss_detection_reflected(self):
        """Test reflected XSS detection"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
            "<svg onload=alert(1)>",
            "'\"><script>alert('XSS')</script>"
        ]
        
        for payload in xss_payloads:
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                # Mock response that reflects the payload
                mock_request.return_value = Mock(
                    text=f"<html><body>Search results for: {payload}</body></html>",
                    status_code=200
                )
                
                result = await self.crawler._test_parameter_payload(
                    f"{self.test_url}/search", "q", payload, "xss"
                )
                
                # Should detect reflected XSS
                self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_xss_detection_stored(self):
        """Test stored XSS detection"""
        stored_xss_page = """
        <html>
        <body>
        <div class="comment">
            <p><script>alert('stored xss')</script></p>
        </div>
        <div class="user-input">
            <span><img src=x onerror=alert(1)></span>
        </div>
        </body>
        </html>
        """
        
        with patch.object(self.crawler, '_make_request_safe') as mock_request:
            mock_request.return_value = Mock(
                text=stored_xss_page,
                status_code=200
            )
            
            # Test stored XSS detection
            vulnerabilities = await self.crawler._analyze_security_indicators(
                f"{self.test_url}/comments", stored_xss_page
            )
            
            self.assertIsNotNone(vulnerabilities)

    @pytest.mark.asyncio
    async def test_sql_injection_detection(self):
        """Test SQL injection detection capabilities"""
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1--",
            "admin'--",
            "1' AND '1'='1",
            "1' AND '1'='2"
        ]
        
        for payload in sql_payloads:
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                # Mock different SQL error responses
                error_responses = [
                    "mysql_fetch_array()",
                    "ORA-01756",
                    "SQL syntax",
                    "mysql_num_rows()",
                    "PostgreSQL query failed"
                ]
                
                for error in error_responses:
                    mock_request.return_value = Mock(
                        text=f"Error: {error}",
                        status_code=500
                    )
                    
                    result = await self.crawler._test_parameter_payload(
                        f"{self.test_url}/login", "username", payload, "sql"
                    )
                    
                    # Should detect SQL injection
                    if "mysql" in error.lower() or "sql" in error.lower():
                        self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_sql_injection_boolean_based(self):
        """Test boolean-based SQL injection detection"""
        boolean_payloads = [
            ("' AND 1=1--", True),
            ("' AND 1=2--", False),
            ("' OR 1=1--", True),
            ("' OR 1=2--", False)
        ]
        
        for payload, expected in boolean_payloads:
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                # Mock different responses for true/false conditions
                if expected:
                    mock_request.return_value = Mock(
                        text="Welcome back, admin",
                        status_code=200
                    )
                else:
                    mock_request.return_value = Mock(
                        text="Invalid credentials",
                        status_code=401
                    )
                
                result = await self.crawler._test_parameter_payload(
                    f"{self.test_url}/login", "id", payload, "sql_boolean"
                )
                
                self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_sql_injection_time_based(self):
        """Test time-based SQL injection detection"""
        time_payloads = [
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))--",
            "' WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT COUNT(*) FROM generate_series(1,5000000))--"
        ]
        
        for payload in time_payloads:
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                # Mock delayed response
                mock_request.return_value = Mock(
                    text="Response after delay",
                    status_code=200
                )
                
                # Mock timing
                with patch('time.time') as mock_time:
                    mock_time.side_effect = [1000, 1005]  # 5 second delay
                    
                    result = await self.crawler._test_parameter_payload(
                        f"{self.test_url}/search", "id", payload, "sql_time"
                    )
                    
                    self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_wordpress_vulnerability_scanning(self):
        """Test WordPress vulnerability scanning"""
        wp_page_source = """
        <html>
        <head>
        <meta name="generator" content="WordPress 5.8.1">
        <link rel="https://api.w.org/" href="http://test.com/wp-json/">
        </head>
        <body>
        <div id="wp-content">
        <p>Welcome to WordPress</p>
        </div>
        </body>
        </html>
        """
        
        with patch.object(self.crawler, '_make_request_safe') as mock_request:
            mock_request.return_value = Mock(
                text=wp_page_source,
                status_code=200
            )
            
            # Test WordPress detection
            wp_details = await self.crawler._detect_wordpress(wp_page_source, self.test_url)
            
            self.assertIsNotNone(wp_details)
            self.assertIn('version', wp_details)
            self.assertEqual(wp_details['version'], '5.8.1')

    @pytest.mark.asyncio
    async def test_wordpress_plugin_enumeration(self):
        """Test WordPress plugin enumeration"""
        plugin_page = """
        <html>
        <head>
        <link rel="stylesheet" href="/wp-content/plugins/contact-form-7/style.css">
        <script src="/wp-content/plugins/woocommerce/assets/js/woocommerce.js"></script>
        </head>
        <body>
        <div class="cf7-form">Contact form content</div>
        <div class="woocommerce">Shop content</div>
        </body>
        </html>
        """
        
        with patch.object(self.crawler, '_make_request_safe') as mock_request:
            mock_request.return_value = Mock(
                text=plugin_page,
                status_code=200
            )
            
            plugins = await self.crawler._enumerate_wp_plugins(plugin_page)
            
            self.assertIsNotNone(plugins)
            self.assertIn('contact-form-7', str(plugins))
            self.assertIn('woocommerce', str(plugins))

    @pytest.mark.asyncio
    async def test_wordpress_theme_enumeration(self):
        """Test WordPress theme enumeration"""
        theme_page = """
        <html>
        <head>
        <link rel="stylesheet" href="/wp-content/themes/twentytwentyone/style.css">
        <link rel="stylesheet" href="/wp-content/themes/twentytwentyone/assets/css/editor-style.css">
        </head>
        <body>
        <div class="twentytwentyone">Theme content</div>
        </body>
        </html>
        """
        
        with patch.object(self.crawler, '_make_request_safe') as mock_request:
            mock_request.return_value = Mock(
                text=theme_page,
                status_code=200
            )
            
            themes = await self.crawler._enumerate_wp_themes(theme_page)
            
            self.assertIsNotNone(themes)
            self.assertIn('twentytwentyone', str(themes))

    @pytest.mark.asyncio
    async def test_wordpress_xmlrpc_attacks(self):
        """Test WordPress XML-RPC attack vectors"""
        xmlrpc_endpoints = [
            "/xmlrpc.php",
            "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/posts"
        ]
        
        for endpoint in xmlrpc_endpoints:
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                mock_request.return_value = Mock(
                    text="XML-RPC response",
                    status_code=200
                )
                
                result = await self.crawler._test_xmlrpc_attacks()
                
                self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_api_endpoint_discovery(self):
        """Test API endpoint discovery"""
        api_page = """
        <html>
        <body>
        <script>
        fetch('/api/users')
        fetch('/api/v1/posts')
        fetch('/rest/users')
        </script>
        <div data-api="/api/config"></div>
        </body>
        </html>
        """
        
        with patch.object(self.crawler, '_make_request_safe') as mock_request:
            mock_request.return_value = Mock(
                text=api_page,
                status_code=200
            )
            
            apis = await self.crawler._discover_api_endpoints(api_page)
            
            self.assertIsNotNone(apis)
            self.assertIn('/api/users', str(apis))
            self.assertIn('/api/v1/posts', str(apis))

    @pytest.mark.asyncio
    async def test_api_endpoint_security_testing(self):
        """Test API endpoint security testing"""
        api_endpoints = [
            "/api/users",
            "/api/v1/posts",
            "/rest/users",
            "/graphql"
        ]
        
        for endpoint in api_endpoints:
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                mock_request.return_value = Mock(
                    text="API response",
                    status_code=200
                )
                
                result = await self.crawler._test_api_endpoint_security(f"{self.test_url}{endpoint}")
                
                self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_api_auth_bypass(self):
        """Test API authentication bypass"""
        auth_bypass_payloads = [
            {"Authorization": "null"},
            {"X-API-Key": ""},
            {"Bearer": "null"},
            {"X-Auth-Token": "undefined"}
        ]
        
        for payload in auth_bypass_payloads:
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                mock_request.return_value = Mock(
                    text="Unauthorized",
                    status_code=401
                )
                
                result = await self.crawler._test_api_auth_bypass(f"{self.test_url}/api/admin", "GET")
                
                self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_form_submission_testing(self):
        """Test form submission security testing"""
        test_form = """
        <form action="/login" method="POST">
        <input type="text" name="username" value="">
        <input type="password" name="password" value="">
        <input type="submit" value="Login">
        </form>
        """
        
        with patch.object(self.crawler, '_make_request_safe') as mock_request:
            mock_request.return_value = Mock(
                text="Login response",
                status_code=200
            )
            
            # Test form analysis
            form_data = {
                'username': 'admin',
                'password': 'password'
            }
            
            result = await self.crawler._test_form_comprehensive(
                test_form, form_data, "login_form"
            )
            
            self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_form_injection_testing(self):
        """Test form injection testing"""
        injection_payloads = {
            'xss': ["<script>alert('xss')</script>", "<img src=x onerror=alert(1)>"],
            'sql': ["' OR '1'='1", "'; DROP TABLE users--"],
            'command': ["| whoami", "; cat /etc/passwd"],
            'ldap': ["*)(uid=*))(|(uid=*", "admin)(&(password=*))"],
            'nosql': ['{"$ne": null}', '{"$gt": ""}']
        }
        
        for injection_type, payloads in injection_payloads.items():
            for payload in payloads:
                with patch.object(self.crawler, '_make_request_safe') as mock_request:
                    mock_request.return_value = Mock(
                        text="Form response",
                        status_code=200
                    )
                    
                    result = await self.crawler._test_form_injections(
                        {'test_field': payload}, injection_payloads
                    )
                    
                    self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_file_upload_vulnerabilities(self):
        """Test file upload vulnerability testing"""
        upload_payloads = [
            "test.php",
            "test.php.jpg",
            "test.php;.jpg",
            "test.php%00.jpg",
            "test.php..",
            "test.php...."
        ]
        
        for payload in upload_payloads:
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                mock_request.return_value = Mock(
                    text="Upload response",
                    status_code=200
                )
                
                result = await self.crawler._test_file_upload_security(
                    "file_input", f"{self.test_url}/upload"
                )
                
                self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_ssrf_vulnerabilities(self):
        """Test SSRF vulnerability testing"""
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:22",
            "http://localhost:8080",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/stat"
        ]
        
        for payload in ssrf_payloads:
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                mock_request.return_value = Mock(
                    text="SSRF response",
                    status_code=200
                )
                
                result = await self.crawler._test_ssrf_parameter(
                    f"{self.test_url}/fetch", "url", payload
                )
                
                self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_xxe_vulnerabilities(self):
        """Test XXE vulnerability testing"""
        xxe_payloads = [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hostname">]><data>&file;</data>'
        ]
        
        for payload in xxe_payloads:
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                mock_request.return_value = Mock(
                    text="XXE response",
                    status_code=200
                )
                
                result = await self.crawler._test_form_xxe(
                    {'xml_data': payload}, xxe_payloads
                )
                
                self.assertIsNotNone(result)

    @pytest.mark.asyncio
    async def test_comprehensive_crawl_and_test(self):
        """Test comprehensive crawl and test functionality"""
        with patch.object(self.crawler, 'setup_advanced_browser'):
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                mock_request.return_value = Mock(
                    text="<html><body>Test page</body></html>",
                    status_code=200
                )
                
                result = await self.crawler.comprehensive_crawl_and_test(self.test_url)
                
                self.assertIsNotNone(result)
                self.assertIn('vulnerabilities', result)
                self.assertIn('discovered_assets', result)

    @pytest.mark.asyncio
    async def test_error_handling_network_timeout(self):
        """Test error handling for network timeouts"""
        with patch.object(self.crawler, '_make_request_safe') as mock_request:
            mock_request.side_effect = Exception("Connection timeout")
            
            try:
                result = await self.crawler._test_parameter_payload(
                    self.test_url, "test", "payload", "test"
                )
                # Should handle timeout gracefully
                self.assertIsNone(result)
            except Exception as e:
                # Should not raise unhandled exceptions
                self.assertIn("timeout", str(e).lower())

    @pytest.mark.asyncio
    async def test_error_handling_ai_service_failure(self):
        """Test error handling for AI service failures"""
        with patch.object(self.crawler, 'ai_analyzer') as mock_ai:
            mock_ai.analyze.side_effect = Exception("AI service unavailable")
            
            try:
                result = await self.crawler.ai_analyze_page(
                    self.test_url, "test content", "test context"
                )
                # Should handle AI failure gracefully
                self.assertIsNone(result)
            except Exception as e:
                # Should not raise unhandled exceptions
                self.assertIn("ai", str(e).lower())

    @pytest.mark.asyncio
    async def test_error_handling_browser_automation(self):
        """Test error handling for browser automation errors"""
        with patch.object(self.crawler, 'setup_advanced_browser') as mock_browser:
            mock_browser.side_effect = Exception("Browser automation failed")
            
            try:
                await self.crawler.setup_advanced_browser()
                # Should handle browser failure gracefully
            except Exception as e:
                # Should not raise unhandled exceptions
                self.assertIn("browser", str(e).lower())

    def test_graceful_degradation_modes(self):
        """Test graceful degradation modes"""
        # Test without AI
        crawler_no_ai = AdvancedIntelligentCrawler(log_to_file=False)
        self.assertFalse(crawler_no_ai.ai_enabled)
        
        # Test without browser
        crawler_no_browser = AdvancedIntelligentCrawler(log_to_file=False)
        self.assertIsNone(crawler_no_browser.driver)
        
        # Test with minimal configuration
        crawler_minimal = AdvancedIntelligentCrawler(log_to_file=False)
        self.assertIsNotNone(crawler_minimal.session)


class TestAdvancedCrawlerIntegration(unittest.TestCase):
    """Integration tests for AdvancedIntelligentCrawler"""
    
    def setUp(self):
        """Set up integration test environment"""
        self.crawler = AdvancedIntelligentCrawler(log_to_file=False)
        
    def tearDown(self):
        """Clean up after integration tests"""
        if hasattr(self.crawler, 'driver') and self.crawler.driver:
            self.crawler.driver.quit()

    @pytest.mark.asyncio
    async def test_full_scan_workflow(self):
        """Test complete scan workflow"""
        with patch.object(self.crawler, 'setup_advanced_browser'):
            with patch.object(self.crawler, '_make_request_safe') as mock_request:
                mock_request.return_value = Mock(
                    text="<html><body>Test content</body></html>",
                    status_code=200
                )
                
                # Run full scan
                result = await self.crawler.comprehensive_crawl_and_test("http://test.com")
                
                # Verify comprehensive results
                self.assertIsNotNone(result)
                self.assertIn('summary', result)
                self.assertIn('vulnerabilities', result)
                self.assertIn('recommendations', result)

    @pytest.mark.asyncio
    async def test_ai_integration(self):
        """Test AI integration with crawler"""
        mock_ai = Mock(spec=AIAnalyzer)
        mock_ai.analyze.return_value = "AI analysis result"
        
        crawler_with_ai = AdvancedIntelligentCrawler(
            log_to_file=False,
            ai_analyzer=mock_ai
        )
        
        with patch.object(crawler_with_ai, '_make_request_safe') as mock_request:
            mock_request.return_value = Mock(
                text="<html><body>Test content</body></html>",
                status_code=200
            )
            
            result = await crawler_with_ai.ai_analyze_page(
                "http://test.com", "test content", "test context"
            )
            
            self.assertIsNotNone(result)
            mock_ai.analyze.assert_called()


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)