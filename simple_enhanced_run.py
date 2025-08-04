#!/usr/bin/env python3
"""
Simple Enhanced Pentester - Real-time crawling and auditing without complex UI
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from advanced_intelligent_crawler import AdvancedIntelligentCrawler

@dataclass
class SimpleFinding:
    """Simple finding without browser confirmation"""
    url: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class SimpleEnhancedPentester:
    """Simple enhanced pentester without complex UI"""
    
    def __init__(self, target_url: str, headless: bool = False, ai_enabled: bool = True):
        self.target_url = target_url
        self.headless = headless
        self.ai_enabled = ai_enabled
        
        # Core components
        self.crawler = None
        self.findings: List[SimpleFinding] = []
        self.discovered_endpoints: List[str] = []
        self.audited_endpoints: List[str] = []
        
        # Simple progress tracking
        self.current_stage = "initializing"
        self.stage_message = "Initializing..."
        
        # Setup logging
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging for simple pentester"""
        import logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('simple_pentest.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize the simple pentester"""
        self.logger.info("Initializing simple enhanced pentester...")
        
        # Initialize crawler
        self.crawler = AdvancedIntelligentCrawler(log_to_file=True)
        
        self.current_stage = "ready"
        self.stage_message = "Simple pentester ready"
        print("✅ Simple enhanced pentester initialized")
    
    async def start_simple_scan(self):
        """Start the simple scanning process"""
        self.logger.info(f"Starting simple pentest on {self.target_url}")
        print(f"🎯 Starting pentest on: {self.target_url}")
        
        try:
            # Phase 1: Discover endpoints
            await self.discover_endpoints()
            
            # Phase 2: Audit endpoints
            await self.audit_endpoints()
            
            # Phase 3: Generate report
            await self.generate_simple_report()
            
        except Exception as e:
            self.logger.error(f"Error in simple scan: {e}")
            print(f"❌ Error: {e}")
    
    async def discover_endpoints(self):
        """Discover endpoints from the target"""
        self.current_stage = "discovering"
        self.stage_message = "Discovering endpoints..."
        print("🔍 Discovering endpoints...")
        
        # Common endpoint patterns
        common_patterns = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/admin', '/login', '/register', '/user', '/users',
            '/profile', '/settings', '/config', '/test', '/debug',
            '/status', '/health', '/metrics', '/docs', '/swagger',
            '/openapi', '/search', '/list', '/view', '/edit',
            '/delete', '/upload', '/download'
        ]
        
        # Test common endpoints
        for pattern in common_patterns:
            endpoint = f"{self.target_url.rstrip('/')}{pattern}"
            if await self.test_endpoint_exists(endpoint):
                self.discovered_endpoints.append(endpoint)
                print(f"  ✅ Found: {endpoint}")
        
        print(f"📊 Discovered {len(self.discovered_endpoints)} endpoints")
    
    async def test_endpoint_exists(self, url: str) -> bool:
        """Test if an endpoint exists"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    return response.status < 500
        except:
            return False
    
    async def audit_endpoints(self):
        """Audit discovered endpoints"""
        self.current_stage = "auditing"
        self.stage_message = "Auditing endpoints..."
        print("🛡️ Auditing endpoints...")
        
        for i, endpoint in enumerate(self.discovered_endpoints, 1):
            print(f"  🔍 Testing {i}/{len(self.discovered_endpoints)}: {endpoint}")
            
            # Quick audit
            findings = await self.quick_audit_endpoint(endpoint)
            
            if findings:
                self.findings.extend(findings)
                for finding in findings:
                    print(f"    ⚠️  Found {finding.vulnerability_type} ({finding.severity})")
            
            self.audited_endpoints.append(endpoint)
        
        print(f"📊 Audit completed. Found {len(self.findings)} vulnerabilities")
    
    async def quick_audit_endpoint(self, url: str) -> List[SimpleFinding]:
        """Quick audit of an endpoint"""
        findings = []
        
        # Test for common vulnerabilities
        vulnerability_tests = [
            ('XSS', self.test_xss),
            ('SQL Injection', self.test_sql_injection),
            ('Open Redirect', self.test_open_redirect),
            ('Information Disclosure', self.test_info_disclosure),
            ('Authentication Bypass', self.test_auth_bypass)
        ]
        
        for vuln_type, test_func in vulnerability_tests:
            try:
                if await test_func(url):
                    finding = SimpleFinding(
                        url=url,
                        vulnerability_type=vuln_type,
                        severity=self.determine_severity(vuln_type),
                        description=f"Potential {vuln_type} vulnerability detected",
                        evidence=f"Detected during {vuln_type} testing"
                    )
                    findings.append(finding)
            except Exception as e:
                self.logger.debug(f"Error testing {vuln_type} on {url}: {e}")
        
        return findings
    
    async def test_xss(self, url: str) -> bool:
        """Test for XSS vulnerability"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')"
        ]
        
        for payload in xss_payloads:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    test_url = f"{url}?q={payload}"
                    async with session.get(test_url, timeout=5) as response:
                        content = await response.text()
                        if payload in content:
                            return True
            except:
                continue
        
        return False
    
    async def test_sql_injection(self, url: str) -> bool:
        """Test for SQL injection vulnerability"""
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--"
        ]
        
        for payload in sql_payloads:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    test_url = f"{url}?id={payload}"
                    async with session.get(test_url, timeout=5) as response:
                        content = await response.text()
                        if any(error in content.lower() for error in ['sql', 'mysql', 'oracle', 'postgresql']):
                            return True
            except:
                continue
        
        return False
    
    async def test_open_redirect(self, url: str) -> bool:
        """Test for open redirect vulnerability"""
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "javascript:alert('redirect')"
        ]
        
        for payload in redirect_payloads:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    test_url = f"{url}?redirect={payload}"
                    async with session.get(test_url, timeout=5, allow_redirects=False) as response:
                        if response.status in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if payload in location:
                                return True
            except:
                continue
        
        return False
    
    async def test_info_disclosure(self, url: str) -> bool:
        """Test for information disclosure"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    content = await response.text()
                    
                    sensitive_patterns = [
                        'password', 'secret', 'key', 'token', 'api_key',
                        'database', 'config', 'admin', 'debug'
                    ]
                    
                    for pattern in sensitive_patterns:
                        if pattern in content.lower():
                            return True
        except:
            pass
        
        return False
    
    async def test_auth_bypass(self, url: str) -> bool:
        """Test for authentication bypass"""
        bypass_payloads = [
            {'Authorization': 'null'},
            {'X-API-Key': ''},
            {'Bearer': 'null'}
        ]
        
        for headers in bypass_payloads:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=5) as response:
                        if response.status == 200:
                            return True
            except:
                continue
        
        return False
    
    def determine_severity(self, vuln_type: str) -> str:
        """Determine severity based on vulnerability type"""
        severity_map = {
            'SQL Injection': 'High',
            'XSS': 'Medium',
            'Authentication Bypass': 'High',
            'Open Redirect': 'Medium',
            'Information Disclosure': 'Low'
        }
        return severity_map.get(vuln_type, 'Medium')
    
    async def generate_simple_report(self):
        """Generate simple report"""
        self.current_stage = "reporting"
        self.stage_message = "Generating report..."
        print("📝 Generating report...")
        
        # Calculate statistics
        total_findings = len(self.findings)
        high_severity = len([f for f in self.findings if f.severity == 'High'])
        medium_severity = len([f for f in self.findings if f.severity == 'Medium'])
        low_severity = len([f for f in self.findings if f.severity == 'Low'])
        
        # Generate report
        report = {
            'target_url': self.target_url,
            'scan_timestamp': datetime.now().isoformat(),
            'scan_duration': 'Simple scan',
            'statistics': {
                'total_endpoints_discovered': len(self.discovered_endpoints),
                'total_endpoints_audited': len(self.audited_endpoints),
                'total_findings': total_findings,
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
                    'timestamp': f.timestamp.isoformat()
                }
                for f in self.findings
            ],
            'discovered_endpoints': self.discovered_endpoints,
            'audited_endpoints': self.audited_endpoints
        }
        
        # Save report
        await self.save_simple_report(report)
        
        # Display summary
        self.display_simple_summary(report)
        
        self.current_stage = "completed"
        self.stage_message = "Simple pentest completed"
        print("✅ Simple pentest completed")
    
    async def save_simple_report(self, report: dict):
        """Save the simple report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"simple_pentest_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Report saved to {filename}")
        print(f"📄 Report saved to {filename}")
    
    def display_simple_summary(self, report: dict):
        """Display simple summary"""
        stats = report['statistics']
        
        print("\n" + "="*60)
        print("📊 SIMPLE PENTEST SUMMARY")
        print("="*60)
        print(f"Target: {report['target_url']}")
        print(f"Endpoints Discovered: {stats['total_endpoints_discovered']}")
        print(f"Endpoints Audited: {stats['total_endpoints_audited']}")
        print(f"Total Findings: {stats['total_findings']}")
        print(f"High Severity: {stats['high_severity']}")
        print(f"Medium Severity: {stats['medium_severity']}")
        print(f"Low Severity: {stats['low_severity']}")
        print("="*60)
        
        if self.findings:
            print("\n🔍 VULNERABILITIES FOUND:")
            for finding in self.findings:
                print(f"  • {finding.vulnerability_type} ({finding.severity}) - {finding.url}")
        else:
            print("\n✅ No vulnerabilities found")

async def main():
    """Main entry point for simple enhanced pentester"""
    parser = argparse.ArgumentParser(description="Simple Enhanced Pentester - Real-time crawling and auditing")
    parser.add_argument("url", help="Target URL to test")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    
    args = parser.parse_args()
    
    # Create simple enhanced pentester
    pentester = SimpleEnhancedPentester(
        target_url=args.url,
        headless=args.headless,
        ai_enabled=not args.no_ai
    )
    
    try:
        # Initialize
        await pentester.initialize()
        
        # Start simple scan
        await pentester.start_simple_scan()
        
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())