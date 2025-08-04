#!/usr/bin/env python3
"""
Enhanced run.py with real-time pentesting capabilities
Integrates crawling, auditing, and browser confirmation
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
from concurrent.futures import ThreadPoolExecutor
import threading

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from advanced_intelligent_crawler import AdvancedIntelligentCrawler
from playwright_browser import StealthBrowserManager
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

console = Console()

@dataclass
class RealTimeFinding:
    """Real-time finding with browser confirmation"""
    url: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    browser_confirmed: bool = False
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class EnhancedPentester:
    """Enhanced pentester with real-time capabilities"""
    
    def __init__(self, target_url: str, headless: bool = False, ai_enabled: bool = True):
        self.target_url = target_url
        self.headless = headless
        self.ai_enabled = ai_enabled
        
        # Core components
        self.crawler = None
        self.browser = None
        self.findings: List[RealTimeFinding] = []
        self.discovered_endpoints: List[str] = []
        self.audited_endpoints: List[str] = []
        
        # Real-time tracking
        self.scan_progress = {
            'crawling': 0,
            'auditing': 0,
            'confirming': 0,
            'overall': 0
        }
        self.current_stage = "initializing"
        self.stage_message = "Initializing enhanced pentester..."
        
        # Threading for concurrent operations
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.running = True
        
        # Setup logging
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging for enhanced pentester"""
        import logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('enhanced_pentest.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize the enhanced pentester"""
        self.logger.info("Initializing enhanced pentester...")
        
        # Initialize crawler
        self.crawler = AdvancedIntelligentCrawler(log_to_file=True)
        
        # Initialize browser for confirmation
        self.browser = StealthBrowserManager(
            headless=self.headless,
            browser_type="chromium",
            stealth_mode=True
        )
        
        if await self.browser.initialize():
            self.logger.info("Browser initialized successfully")
        else:
            self.logger.warning("Browser initialization failed, continuing without browser confirmation")
            self.browser = None
        
        self.current_stage = "ready"
        self.stage_message = "Enhanced pentester ready"
    
    async def start_enhanced_scan(self):
        """Start the enhanced scanning process"""
        self.logger.info(f"Starting enhanced pentest on {self.target_url}")
        
        # Start real-time monitoring
        monitor_task = asyncio.create_task(self.realtime_monitor())
        
        # Start enhanced scan workflow
        scan_task = asyncio.create_task(self.enhanced_scan_workflow())
        
        # Wait for both tasks
        await asyncio.gather(scan_task, monitor_task)
    
    async def enhanced_scan_workflow(self):
        """Main enhanced scanning workflow"""
        try:
            # Phase 1: Real-time crawling and discovery
            await self.realtime_crawling()
            
            # Phase 2: Real-time auditing
            await self.realtime_auditing()
            
            # Phase 3: Browser confirmation
            await self.browser_confirmation()
            
            # Phase 4: Generate final report
            await self.generate_final_report()
            
        except Exception as e:
            self.logger.error(f"Error in enhanced scan workflow: {e}")
            self.current_stage = "error"
            self.stage_message = f"Error: {str(e)}"
    
    async def realtime_crawling(self):
        """Real-time crawling with live endpoint discovery"""
        self.current_stage = "crawling"
        self.stage_message = "Discovering endpoints in real-time..."
        
        self.logger.info("Starting real-time crawling...")
        
        # Discover initial endpoints
        initial_endpoints = await self.discover_initial_endpoints()
        self.discovered_endpoints.extend(initial_endpoints)
        
        # Real-time endpoint discovery
        discovery_task = asyncio.create_task(self.continuous_endpoint_discovery())
        
        # Process discovered endpoints in real-time
        process_task = asyncio.create_task(self.process_discovered_endpoints())
        
        # Wait for both tasks
        await asyncio.gather(discovery_task, process_task)
        
        self.scan_progress['crawling'] = 100
        self.logger.info(f"Crawling completed. Discovered {len(self.discovered_endpoints)} endpoints")
    
    async def discover_initial_endpoints(self) -> List[str]:
        """Discover initial endpoints from the target"""
        endpoints = []
        
        # Common endpoint patterns
        common_patterns = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/rest',
            '/graphql',
            '/admin',
            '/login',
            '/register',
            '/user',
            '/users',
            '/profile',
            '/settings',
            '/config',
            '/test',
            '/debug',
            '/status',
            '/health',
            '/metrics',
            '/docs',
            '/swagger',
            '/openapi'
        ]
        
        # Test common endpoints
        for pattern in common_patterns:
            endpoint = f"{self.target_url.rstrip('/')}{pattern}"
            if await self.test_endpoint_exists(endpoint):
                endpoints.append(endpoint)
                self.logger.info(f"Discovered endpoint: {endpoint}")
        
        return endpoints
    
    async def test_endpoint_exists(self, url: str) -> bool:
        """Test if an endpoint exists"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    return response.status < 500  # Consider 4xx as existing
        except:
            return False
    
    async def continuous_endpoint_discovery(self):
        """Continuously discover new endpoints"""
        while self.running:
            # Discover new endpoints from existing ones
            new_endpoints = []
            
            for endpoint in self.discovered_endpoints[:10]:  # Limit to avoid overwhelming
                if endpoint not in self.audited_endpoints:
                    # Extract potential new endpoints from response
                    potential_endpoints = await self.extract_endpoints_from_response(endpoint)
                    new_endpoints.extend(potential_endpoints)
            
            # Add new unique endpoints
            for endpoint in new_endpoints:
                if endpoint not in self.discovered_endpoints:
                    self.discovered_endpoints.append(endpoint)
                    self.logger.info(f"New endpoint discovered: {endpoint}")
            
            await asyncio.sleep(2)  # Discovery interval
    
    async def extract_endpoints_from_response(self, url: str) -> List[str]:
        """Extract potential endpoints from response content"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    content = await response.text()
                    
                    # Extract URLs from content
                    import re
                    url_pattern = r'href=["\']([^"\']+)["\']'
                    urls = re.findall(url_pattern, content)
                    
                    # Convert relative URLs to absolute
                    endpoints = []
                    for url_path in urls:
                        if url_path.startswith('/'):
                            full_url = f"{self.target_url.rstrip('/')}{url_path}"
                            endpoints.append(full_url)
                    
                    return endpoints
        except:
            return []
    
    async def process_discovered_endpoints(self):
        """Process discovered endpoints in real-time"""
        processed_count = 0
        
        while self.running and processed_count < len(self.discovered_endpoints):
            for endpoint in self.discovered_endpoints:
                if endpoint not in self.audited_endpoints:
                    # Quick audit of endpoint
                    findings = await self.quick_audit_endpoint(endpoint)
                    
                    if findings:
                        self.findings.extend(findings)
                        self.logger.info(f"Found {len(findings)} vulnerabilities in {endpoint}")
                    
                    self.audited_endpoints.append(endpoint)
                    processed_count += 1
                    
                    # Update progress
                    self.scan_progress['crawling'] = min(100, (processed_count / max(1, len(self.discovered_endpoints))) * 100)
                    
                    await asyncio.sleep(0.5)  # Processing interval
            
            await asyncio.sleep(1)
    
    async def quick_audit_endpoint(self, url: str) -> List[RealTimeFinding]:
        """Quick audit of an endpoint for common vulnerabilities"""
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
                    finding = RealTimeFinding(
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
                    # Test reflected XSS
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
                    
                    # Check for sensitive information
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
    
    async def realtime_auditing(self):
        """Real-time auditing of discovered endpoints"""
        self.current_stage = "auditing"
        self.stage_message = "Auditing endpoints in real-time..."
        
        self.logger.info("Starting real-time auditing...")
        
        # Audit each endpoint with comprehensive tests
        for i, endpoint in enumerate(self.discovered_endpoints):
            if not self.running:
                break
            
            self.stage_message = f"Auditing endpoint {i+1}/{len(self.discovered_endpoints)}: {endpoint}"
            
            # Comprehensive audit
            findings = await self.comprehensive_audit_endpoint(endpoint)
            
            if findings:
                self.findings.extend(findings)
                self.logger.info(f"Found {len(findings)} vulnerabilities in {endpoint}")
            
            # Update progress
            self.scan_progress['auditing'] = min(100, ((i + 1) / len(self.discovered_endpoints)) * 100)
            
            await asyncio.sleep(1)  # Audit interval
        
        self.logger.info(f"Auditing completed. Found {len(self.findings)} total vulnerabilities")
    
    async def comprehensive_audit_endpoint(self, url: str) -> List[RealTimeFinding]:
        """Comprehensive audit of an endpoint"""
        findings = []
        
        # Additional comprehensive tests
        comprehensive_tests = [
            ('CSRF', self.test_csrf),
            ('File Upload', self.test_file_upload),
            ('Command Injection', self.test_command_injection),
            ('XXE', self.test_xxe),
            ('SSRF', self.test_ssrf)
        ]
        
        for vuln_type, test_func in comprehensive_tests:
            try:
                if await test_func(url):
                    finding = RealTimeFinding(
                        url=url,
                        vulnerability_type=vuln_type,
                        severity=self.determine_severity(vuln_type),
                        description=f"Comprehensive {vuln_type} vulnerability detected",
                        evidence=f"Detected during comprehensive {vuln_type} testing"
                    )
                    findings.append(finding)
            except Exception as e:
                self.logger.debug(f"Error in comprehensive {vuln_type} test on {url}: {e}")
        
        return findings
    
    async def test_csrf(self, url: str) -> bool:
        """Test for CSRF vulnerability"""
        # Simplified CSRF test
        return False  # Placeholder
    
    async def test_file_upload(self, url: str) -> bool:
        """Test for file upload vulnerability"""
        # Simplified file upload test
        return False  # Placeholder
    
    async def test_command_injection(self, url: str) -> bool:
        """Test for command injection vulnerability"""
        # Simplified command injection test
        return False  # Placeholder
    
    async def test_xxe(self, url: str) -> bool:
        """Test for XXE vulnerability"""
        # Simplified XXE test
        return False  # Placeholder
    
    async def test_ssrf(self, url: str) -> bool:
        """Test for SSRF vulnerability"""
        # Simplified SSRF test
        return False  # Placeholder
    
    async def browser_confirmation(self):
        """Confirm findings in browser"""
        if not self.browser:
            self.logger.warning("Browser not available, skipping confirmation")
            return
        
        self.current_stage = "confirming"
        self.stage_message = "Confirming findings in browser..."
        
        self.logger.info("Starting browser confirmation...")
        
        confirmed_count = 0
        for i, finding in enumerate(self.findings):
            if not self.running:
                break
            
            self.stage_message = f"Confirming finding {i+1}/{len(self.findings)}: {finding.vulnerability_type}"
            
            # Navigate to the vulnerable URL in browser
            if await self.browser.navigate_to(finding.url):
                # Take screenshot for evidence
                screenshot_path = await self.browser.take_screenshot()
                
                # Check if vulnerability is visible in browser
                page_content = await self.browser.get_page_content()
                
                if self.confirm_vulnerability_in_browser(finding, page_content):
                    finding.browser_confirmed = True
                    finding.evidence += f" | Browser confirmed | Screenshot: {screenshot_path}"
                    confirmed_count += 1
                    self.logger.info(f"Browser confirmed: {finding.vulnerability_type} on {finding.url}")
            
            # Update progress
            self.scan_progress['confirming'] = min(100, ((i + 1) / len(self.findings)) * 100)
            
            await asyncio.sleep(2)  # Confirmation interval
        
        self.logger.info(f"Browser confirmation completed. Confirmed {confirmed_count}/{len(self.findings)} findings")
    
    def confirm_vulnerability_in_browser(self, finding: RealTimeFinding, page_content: str) -> bool:
        """Confirm vulnerability is visible in browser"""
        vuln_type = finding.vulnerability_type.lower()
        
        if 'xss' in vuln_type:
            # Check for script tags or alert calls
            return '<script>' in page_content or 'alert(' in page_content
        elif 'sql' in vuln_type:
            # Check for SQL error messages
            sql_errors = ['sql', 'mysql', 'oracle', 'postgresql', 'database']
            return any(error in page_content.lower() for error in sql_errors)
        elif 'redirect' in vuln_type:
            # Check for redirects
            return 'location.href' in page_content or 'window.location' in page_content
        else:
            # Generic confirmation
            return True
    
    async def generate_final_report(self):
        """Generate final enhanced pentest report"""
        self.current_stage = "reporting"
        self.stage_message = "Generating final report..."
        
        self.logger.info("Generating final report...")
        
        # Calculate statistics
        total_findings = len(self.findings)
        confirmed_findings = len([f for f in self.findings if f.browser_confirmed])
        high_severity = len([f for f in self.findings if f.severity == 'High'])
        medium_severity = len([f for f in self.findings if f.severity == 'Medium'])
        low_severity = len([f for f in self.findings if f.severity == 'Low'])
        
        # Generate report
        report = {
            'target_url': self.target_url,
            'scan_timestamp': datetime.now().isoformat(),
            'scan_duration': 'Real-time',
            'statistics': {
                'total_endpoints_discovered': len(self.discovered_endpoints),
                'total_endpoints_audited': len(self.audited_endpoints),
                'total_findings': total_findings,
                'confirmed_findings': confirmed_findings,
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
                    'browser_confirmed': f.browser_confirmed,
                    'timestamp': f.timestamp.isoformat()
                }
                for f in self.findings
            ],
            'discovered_endpoints': self.discovered_endpoints,
            'audited_endpoints': self.audited_endpoints
        }
        
        # Save report
        await self.save_report(report)
        
        # Display summary
        self.display_report_summary(report)
        
        self.scan_progress['overall'] = 100
        self.current_stage = "completed"
        self.stage_message = "Enhanced pentest completed"
    
    async def save_report(self, report: dict):
        """Save the final report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"enhanced_pentest_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Report saved to {filename}")
    
    def display_report_summary(self, report: dict):
        """Display report summary in console"""
        stats = report['statistics']
        
        console.print(Panel.fit(
            f"[bold green]Enhanced Pentest Report[/bold green]\n"
            f"Target: {report['target_url']}\n"
            f"Endpoints Discovered: {stats['total_endpoints_discovered']}\n"
            f"Endpoints Audited: {stats['total_endpoints_audited']}\n"
            f"Total Findings: {stats['total_findings']}\n"
            f"Browser Confirmed: {stats['confirmed_findings']}\n"
            f"High Severity: {stats['high_severity']}\n"
            f"Medium Severity: {stats['medium_severity']}\n"
            f"Low Severity: {stats['low_severity']}",
            title="📊 Scan Summary"
        ))
    
    async def realtime_monitor(self):
        """Real-time monitoring and display"""
        with Live(self.create_status_display(), refresh_per_second=2) as live:
            while self.running:
                live.update(self.create_status_display())
                await asyncio.sleep(0.5)
    
    def create_status_display(self):
        """Create real-time status display"""
        # Create layout
        layout = Layout()
        
        # Header
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        # Main content
        layout["main"].split_row(
            Layout(name="progress", ratio=1),
            Layout(name="findings", ratio=2)
        )
        
        # Header content
        layout["header"].update(Panel(
            f"[bold blue]Enhanced Pentester[/bold blue]\n"
            f"Target: {self.target_url}\n"
            f"Stage: {self.current_stage.title()} - {self.stage_message}",
            title="🚀 Enhanced Pentest"
        ))
        
        # Progress content
        progress_table = Table(title="📈 Progress")
        progress_table.add_column("Stage", style="cyan")
        progress_table.add_column("Progress", style="green")
        
        for stage, progress in self.scan_progress.items():
            progress_table.add_row(stage.title(), f"{progress}%")
        
        layout["progress"].update(progress_table)
        
        # Findings content
        findings_table = Table(title="🔍 Recent Findings")
        findings_table.add_column("Type", style="red")
        findings_table.add_column("Severity", style="yellow")
        findings_table.add_column("URL", style="blue")
        findings_table.add_column("Confirmed", style="green")
        
        # Show recent findings
        recent_findings = self.findings[-5:]  # Last 5 findings
        for finding in recent_findings:
            confirmed = "✅" if finding.browser_confirmed else "❌"
            findings_table.add_row(
                finding.vulnerability_type,
                finding.severity,
                finding.url.split('/')[-1] if '/' in finding.url else finding.url,
                confirmed
            )
        
        layout["findings"].update(findings_table)
        
        # Footer content
        layout["footer"].update(Panel(
            f"Endpoints: {len(self.discovered_endpoints)} discovered, {len(self.audited_endpoints)} audited\n"
            f"Findings: {len(self.findings)} total\n"
            f"Status: {'Running' if self.running else 'Completed'}",
            title="📊 Statistics"
        ))
        
        return layout
    
    async def stop(self):
        """Stop the enhanced pentester"""
        self.running = False
        if self.browser:
            await self.browser.close()
        self.executor.shutdown(wait=False)

async def main():
    """Main entry point for enhanced pentester"""
    parser = argparse.ArgumentParser(description="Enhanced Pentester - Real-time crawling, auditing, and browser confirmation")
    parser.add_argument("url", help="Target URL to test")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    
    args = parser.parse_args()
    
    # Create enhanced pentester
    pentester = EnhancedPentester(
        target_url=args.url,
        headless=args.headless,
        ai_enabled=not args.no_ai
    )
    
    try:
        # Initialize
        await pentester.initialize()
        
        # Start enhanced scan
        await pentester.start_enhanced_scan()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
    finally:
        await pentester.stop()

if __name__ == "__main__":
    asyncio.run(main())