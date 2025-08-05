#!/usr/bin/env python3
"""
🐛 ADVANCED BUG BOUNTY HUNTER
Real-time endpoint discovery, JavaScript analysis, and browser-based testing
Mimics techniques used by successful bug bounty hunters
"""

import asyncio
import argparse
import sys
import os
import re
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import hashlib

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from advanced_intelligent_crawler import AdvancedIntelligentCrawler

@dataclass
class HunterFinding:
    """Advanced finding with hunter techniques"""
    url: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    technique: str
    confidence: str
    browser_confirmed: bool = False
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class BugBountyHunter:
    """Advanced bug bounty hunter with real-time techniques"""
    
    def __init__(self, target_url: str, headless: bool = False):
        self.target_url = target_url
        self.headless = headless
        
        # Core components
        self.crawler = None
        self.browser = None
        self.findings: List[HunterFinding] = []
        self.discovered_endpoints: Set[str] = set()
        self.js_endpoints: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.tested_endpoints: Set[str] = set()
        
        # Hunter techniques tracking
        self.techniques_used = []
        self.js_files_analyzed = 0
        self.endpoints_extracted = 0
        
        # Setup logging
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging for bug bounty hunter"""
        import logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('bug_bounty_hunter.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize the bug bounty hunter"""
        self.logger.info("Initializing bug bounty hunter...")
        print("🐛 Initializing Advanced Bug Bounty Hunter...")
        
        # Initialize crawler
        self.crawler = AdvancedIntelligentCrawler(log_to_file=True)
        
        # Initialize browser for real-time testing
        await self.initialize_browser()
        
        print("✅ Bug bounty hunter ready for action!")
    
    async def initialize_browser(self):
        """Initialize browser for real-time testing"""
        try:
            from playwright.async_api import async_playwright
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=self.headless)
            self.context = await self.browser.new_context()
            self.page = await self.context.new_page()
            print("🌐 Browser initialized for real-time testing")
        except Exception as e:
            self.logger.warning(f"Browser initialization failed: {e}")
            self.browser = None
            print("⚠️ Browser not available, using network-only testing")
    
    async def start_hunter_scan(self):
        """Start the advanced bug bounty hunter scan"""
        self.logger.info(f"Starting bug bounty hunter scan on {self.target_url}")
        print(f"🎯 Target: {self.target_url}")
        print("🚀 Starting advanced bug bounty techniques...")
        
        try:
            # Phase 1: JavaScript endpoint extraction
            await self.extract_js_endpoints()
            
            # Phase 2: API endpoint discovery
            await self.discover_api_endpoints()
            
            # Phase 3: Real-time browser testing
            await self.realtime_browser_testing()
            
            # Phase 4: Advanced vulnerability testing
            await self.advanced_vulnerability_testing()
            
            # Phase 5: Generate hunter report
            await self.generate_hunter_report()
            
        except Exception as e:
            self.logger.error(f"Error in hunter scan: {e}")
            print(f"❌ Error: {e}")
    
    async def extract_js_endpoints(self):
        """Extract endpoints from JavaScript files"""
        print("🔍 Phase 1: Extracting endpoints from JavaScript files...")
        
        # Common JavaScript file patterns
        js_patterns = [
            '/js/', '/javascript/', '/assets/js/', '/static/js/',
            '/scripts/', '/app.js', '/main.js', '/bundle.js',
            '/vendor/', '/lib/', '/dist/', '/build/'
        ]
        
        js_files = []
        
        # Find JavaScript files
        for pattern in js_patterns:
            js_url = urljoin(self.target_url, pattern)
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.get(js_url, timeout=10) as response:
                        if response.status == 200:
                            content = await response.text()
                            js_files.append((js_url, content))
                            print(f"  📄 Found JS file: {js_url}")
            except:
                continue
        
        # Extract endpoints from JavaScript content
        for js_url, content in js_files:
            endpoints = self.extract_endpoints_from_js(content, js_url)
            self.js_endpoints.update(endpoints)
            self.js_files_analyzed += 1
        
        print(f"📊 Extracted {len(self.js_endpoints)} endpoints from {self.js_files_analyzed} JS files")
        self.techniques_used.append("JavaScript Endpoint Extraction")
    
    def extract_endpoints_from_js(self, js_content: str, js_url: str) -> Set[str]:
        """Extract endpoints from JavaScript content using hunter techniques"""
        endpoints = set()
        
        # Advanced regex patterns used by bug bounty hunters
        patterns = [
            # API endpoints
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            
            # Common endpoints
            r'["\'](/admin[^"\']*)["\']',
            r'["\'](/login[^"\']*)["\']',
            r'["\'](/user[^"\']*)["\']',
            r'["\'](/profile[^"\']*)["\']',
            r'["\'](/settings[^"\']*)["\']',
            r'["\'](/config[^"\']*)["\']',
            r'["\'](/test[^"\']*)["\']',
            r'["\'](/debug[^"\']*)["\']',
            
            # File operations
            r'["\'](/upload[^"\']*)["\']',
            r'["\'](/download[^"\']*)["\']',
            r'["\'](/file[^"\']*)["\']',
            
            # Search and listing
            r'["\'](/search[^"\']*)["\']',
            r'["\'](/list[^"\']*)["\']',
            r'["\'](/view[^"\']*)["\']',
            r'["\'](/edit[^"\']*)["\']',
            r'["\'](/delete[^"\']*)["\']',
            
            # AJAX calls
            r'\.ajax\(["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
            
            # URL patterns
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
            r'path:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    endpoint = match[1] if len(match) > 1 else match[0]
                else:
                    endpoint = match
                
                if endpoint and not endpoint.startswith('http'):
                    # Normalize endpoint
                    if not endpoint.startswith('/'):
                        endpoint = '/' + endpoint
                    
                    # Build full URL
                    full_url = urljoin(self.target_url, endpoint)
                    endpoints.add(full_url)
        
        return endpoints
    
    async def discover_api_endpoints(self):
        """Discover API endpoints using hunter techniques"""
        print("🔍 Phase 2: Discovering API endpoints...")
        
        # Common API patterns
        api_patterns = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/graphql', '/graphql/v1',
            '/swagger', '/swagger-ui', '/swagger.json',
            '/openapi', '/openapi.json',
            '/docs', '/documentation',
            '/health', '/status', '/ping',
            '/metrics', '/prometheus',
            '/actuator', '/actuator/health',
            '/.well-known', '/.well-known/security.txt'
        ]
        
        for pattern in api_patterns:
            api_url = urljoin(self.target_url, pattern)
            if await self.test_endpoint_exists(api_url):
                self.api_endpoints.add(api_url)
                print(f"  🔗 Found API: {api_url}")
        
        print(f"📊 Discovered {len(self.api_endpoints)} API endpoints")
        self.techniques_used.append("API Endpoint Discovery")
    
    async def test_endpoint_exists(self, url: str) -> bool:
        """Test if an endpoint exists"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    return response.status < 500
        except:
            return False
    
    async def realtime_browser_testing(self):
        """Real-time browser testing of discovered endpoints"""
        if not self.browser:
            print("⚠️ Skipping browser testing - browser not available")
            return
        
        print("🌐 Phase 3: Real-time browser testing...")
        
        all_endpoints = self.js_endpoints.union(self.api_endpoints)
        
        for i, endpoint in enumerate(all_endpoints, 1):
            if endpoint in self.tested_endpoints:
                continue
            
            print(f"  🌐 Testing {i}/{len(all_endpoints)}: {endpoint}")
            
            try:
                # Navigate to endpoint
                await self.page.goto(endpoint, wait_until='domcontentloaded', timeout=10000)
                
                # Check for common vulnerabilities
                findings = await self.browser_vulnerability_check(endpoint)
                
                if findings:
                    self.findings.extend(findings)
                    for finding in findings:
                        print(f"    ⚠️  Found {finding.vulnerability_type} ({finding.severity})")
                
                self.tested_endpoints.add(endpoint)
                
            except Exception as e:
                self.logger.debug(f"Error testing {endpoint}: {e}")
        
        print(f"📊 Browser tested {len(self.tested_endpoints)} endpoints")
        self.techniques_used.append("Real-time Browser Testing")
    
    async def browser_vulnerability_check(self, url: str) -> List[HunterFinding]:
        """Check for vulnerabilities using browser automation"""
        findings = []
        
        try:
            # Get page content
            content = await self.page.content()
            
            # Check for sensitive information
            sensitive_patterns = [
                'password', 'secret', 'key', 'token', 'api_key',
                'database', 'config', 'admin', 'debug', 'error'
            ]
            
            for pattern in sensitive_patterns:
                if pattern in content.lower():
                    finding = HunterFinding(
                        url=url,
                        vulnerability_type="Information Disclosure",
                        severity="Medium",
                        description=f"Sensitive information '{pattern}' found in response",
                        evidence=f"Found '{pattern}' in page content",
                        technique="Browser Content Analysis",
                        confidence="High"
                    )
                    findings.append(finding)
            
            # Check for error messages
            error_patterns = [
                'sql', 'mysql', 'oracle', 'postgresql', 'database error',
                'stack trace', 'exception', 'error occurred'
            ]
            
            for pattern in error_patterns:
                if pattern in content.lower():
                    finding = HunterFinding(
                        url=url,
                        vulnerability_type="Error Information Disclosure",
                        severity="Low",
                        description=f"Error information '{pattern}' found in response",
                        evidence=f"Found '{pattern}' in page content",
                        technique="Error Message Analysis",
                        confidence="Medium"
                    )
                    findings.append(finding)
            
            # Check for XSS reflection
            xss_payload = "<script>alert('XSS')</script>"
            if xss_payload in content:
                finding = HunterFinding(
                    url=url,
                    vulnerability_type="Reflected XSS",
                    severity="High",
                    description="XSS payload reflected in response",
                    evidence=f"Found XSS payload in page content",
                    technique="XSS Payload Testing",
                    confidence="High"
                )
                finding.browser_confirmed = True
                findings.append(finding)
        
        except Exception as e:
            self.logger.debug(f"Error in browser vulnerability check: {e}")
        
        return findings
    
    async def advanced_vulnerability_testing(self):
        """Advanced vulnerability testing using hunter techniques"""
        print("🛡️ Phase 4: Advanced vulnerability testing...")
        
        all_endpoints = self.js_endpoints.union(self.api_endpoints)
        
        for endpoint in all_endpoints:
            if endpoint in self.tested_endpoints:
                continue
            
            # Advanced payload testing
            findings = await self.advanced_payload_testing(endpoint)
            
            if findings:
                self.findings.extend(findings)
                for finding in findings:
                    print(f"  ⚠️  Found {finding.vulnerability_type} ({finding.severity})")
        
        self.techniques_used.append("Advanced Payload Testing")
    
    async def advanced_payload_testing(self, url: str) -> List[HunterFinding]:
        """Advanced payload testing using hunter techniques"""
        findings = []
        
        # Advanced SQL injection payloads
        sql_payloads = [
            "' OR '1'='1'--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin'#",
            "admin'/*"
        ]
        
        # Advanced XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        # Test SQL injection
        for payload in sql_payloads:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    test_url = f"{url}?id={payload}"
                    async with session.get(test_url, timeout=5) as response:
                        content = await response.text()
                        if any(error in content.lower() for error in ['sql', 'mysql', 'oracle', 'postgresql']):
                            finding = HunterFinding(
                                url=url,
                                vulnerability_type="SQL Injection",
                                severity="High",
                                description=f"SQL injection vulnerability detected with payload: {payload}",
                                evidence=f"SQL error found in response",
                                technique="Advanced SQL Injection Testing",
                                confidence="High"
                            )
                            findings.append(finding)
                            break
            except:
                continue
        
        # Test XSS
        for payload in xss_payloads:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    test_url = f"{url}?q={payload}"
                    async with session.get(test_url, timeout=5) as response:
                        content = await response.text()
                        if payload in content:
                            finding = HunterFinding(
                                url=url,
                                vulnerability_type="Reflected XSS",
                                severity="High",
                                description=f"XSS vulnerability detected with payload: {payload}",
                                evidence=f"XSS payload reflected in response",
                                technique="Advanced XSS Testing",
                                confidence="High"
                            )
                            findings.append(finding)
                            break
            except:
                continue
        
        return findings
    
    async def generate_hunter_report(self):
        """Generate advanced bug bounty hunter report"""
        print("📝 Phase 5: Generating hunter report...")
        
        # Calculate statistics
        total_findings = len(self.findings)
        high_severity = len([f for f in self.findings if f.severity == 'High'])
        medium_severity = len([f for f in self.findings if f.severity == 'Medium'])
        low_severity = len([f for f in self.findings if f.severity == 'Low'])
        browser_confirmed = len([f for f in self.findings if f.browser_confirmed])
        
        # Generate report
        report = {
            'target_url': self.target_url,
            'scan_timestamp': datetime.now().isoformat(),
            'scan_duration': 'Advanced Bug Bounty Hunter Scan',
            'hunter_techniques': self.techniques_used,
            'statistics': {
                'js_files_analyzed': self.js_files_analyzed,
                'endpoints_extracted': len(self.js_endpoints),
                'api_endpoints_discovered': len(self.api_endpoints),
                'endpoints_browser_tested': len(self.tested_endpoints),
                'total_findings': total_findings,
                'browser_confirmed': browser_confirmed,
                'high_severity': high_severity,
                'medium_severity': medium_severity,
                'low_severity': low_severity
            },
            'findings': [
                {
                    'url': f.url,
                    'vulnerability_type': f.vulnerability_type,
                    'severity': f.severity,
                    'description': f.description,
                    'evidence': f.evidence,
                    'technique': f.technique,
                    'confidence': f.confidence,
                    'browser_confirmed': f.browser_confirmed,
                    'timestamp': f.timestamp.isoformat()
                }
                for f in self.findings
            ],
            'discovered_endpoints': list(self.js_endpoints.union(self.api_endpoints)),
            'js_endpoints': list(self.js_endpoints),
            'api_endpoints': list(self.api_endpoints)
        }
        
        # Save report
        await self.save_hunter_report(report)
        
        # Display summary
        self.display_hunter_summary(report)
        
        print("✅ Bug bounty hunter scan completed!")
    
    async def save_hunter_report(self, report: dict):
        """Save the hunter report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"bug_bounty_hunter_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Hunter report saved to {filename}")
        print(f"📄 Hunter report saved to {filename}")
    
    def display_hunter_summary(self, report: dict):
        """Display hunter summary"""
        stats = report['statistics']
        techniques = report['hunter_techniques']
        
        print("\n" + "="*80)
        print("🐛 BUG BOUNTY HUNTER REPORT")
        print("="*80)
        print(f"Target: {report['target_url']}")
        print(f"Techniques Used: {', '.join(techniques)}")
        print(f"JS Files Analyzed: {stats['js_files_analyzed']}")
        print(f"Endpoints Extracted: {stats['endpoints_extracted']}")
        print(f"API Endpoints Discovered: {stats['api_endpoints_discovered']}")
        print(f"Endpoints Browser Tested: {stats['endpoints_browser_tested']}")
        print(f"Total Findings: {stats['total_findings']}")
        print(f"Browser Confirmed: {stats['browser_confirmed']}")
        print(f"High Severity: {stats['high_severity']}")
        print(f"Medium Severity: {stats['medium_severity']}")
        print(f"Low Severity: {stats['low_severity']}")
        print("="*80)
        
        if self.findings:
            print("\n🔍 VULNERABILITIES FOUND:")
            for finding in self.findings:
                confirmed = "✅" if finding.browser_confirmed else "❌"
                print(f"  • {finding.vulnerability_type} ({finding.severity}) - {finding.url}")
                print(f"    Technique: {finding.technique} | Confidence: {finding.confidence} | Confirmed: {confirmed}")
        else:
            print("\n✅ No vulnerabilities found")
    
    async def stop(self):
        """Stop the bug bounty hunter"""
        if self.browser:
            try:
                await self.browser.close()
                await self.playwright.stop()
            except:
                pass

async def main():
    """Main entry point for bug bounty hunter"""
    parser = argparse.ArgumentParser(description="🐛 Advanced Bug Bounty Hunter - Real-time endpoint discovery and testing")
    parser.add_argument("url", help="Target URL to test")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    
    args = parser.parse_args()
    
    # Create bug bounty hunter
    hunter = BugBountyHunter(
        target_url=args.url,
        headless=args.headless
    )
    
    try:
        # Initialize
        await hunter.initialize()
        
        # Start hunter scan
        await hunter.start_hunter_scan()
        
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        await hunter.stop()

if __name__ == "__main__":
    asyncio.run(main())