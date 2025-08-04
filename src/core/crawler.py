"""
Main orchestrator for Advanced Intelligent Web Crawler
Integrates all modules and manages the full workflow
"""

import asyncio
from typing import Optional, Dict, Any, List
from .config import Config
from .logger import Logger
from .ai_analyzer import AIAnalyzer
from .browser_manager import BrowserManager
from .network_monitor import NetworkMonitor
from .security_tester import SecurityTester
from .report_generator import ReportGenerator

class AdvancedIntelligentCrawler:
    """
    Main orchestrator for production-grade crawling, analysis, and reporting
    """
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.logger = Logger(self.config)
        self.ai_analyzer = AIAnalyzer(self.config, self.logger)
        self.browser_manager = BrowserManager(self.config, self.logger)
        self.security_tester = SecurityTester(self.config, self.logger, self.ai_analyzer)
        self.report_generator = ReportGenerator(self.config, self.logger, self.ai_analyzer)
        self.network_monitor = None  # Will be initialized after browser
        self.findings: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.ai_summaries: List[Dict[str, Any]] = []

    async def run(self, target_url: str):
        self.logger.info(f"Starting crawl for {target_url}", 'crawler')
        await self.browser_manager.initialize()
        self.network_monitor = NetworkMonitor(
            self.browser_manager.driver, self.logger, self.ai_analyzer, self.config
        )
        await self.network_monitor.enable()
        # Start network monitoring in background
        network_task = asyncio.create_task(self.network_monitor.capture_traffic(self.config.monitoring.interval))
        # --- Advanced workflow ---
        await self.advanced_discovery(target_url)
        await self.discover_advanced_forms()
        await self.analyze_javascript()
        await self.analyze_cookies_sessions()
        await self.discover_hidden_parameters()
        await self.intelligent_exploration()
        await self.advanced_vulnerability_testing()
        # Generate AI summary
        ai_summary = await self.report_generator.generate_ai_summary(self.findings, self.vulnerabilities, target_url)
        self.ai_summaries.append(ai_summary)
        # Generate and save report
        report = self.report_generator.generate_report(target_url, self.findings, self.vulnerabilities, self.ai_summaries)
        self.report_generator.save_report(report)
        # Cleanup
        await self.browser_manager.close()
        self.logger.info(f"Crawl completed for {target_url}", 'crawler')

    async def advanced_discovery(self, url):
        """Phase 1: Advanced intelligent feature discovery with AI analysis"""
        self.logger.info("Phase 1: Advanced Intelligent Discovery...", 'discovery')
        self.logger.info(f"Deep analysis of: {url}", 'discovery')
        try:
            await self.browser_manager.navigate_to(url)
            await asyncio.sleep(3)
            # Basic page info
            page_title = self.browser_manager.driver.title
            page_source = await self.browser_manager.get_page_source()
            current_url = await self.browser_manager.get_current_url()
            self.logger.info(f"Page: {page_title}", 'discovery')
            self.logger.info(f"Final URL: {current_url}", 'discovery')
            # AI analysis of the page
            ai_analysis = await self.ai_analyzer.analyze_content(page_source, context="discovery", target_url=url)
            risk_score = ai_analysis.risk_score if hasattr(ai_analysis, 'risk_score') else 0
            self.logger.info(f"AI Risk Score: {risk_score}/10", 'discovery')
            # Technology detection
            detected_techs = self.detect_technologies(page_source)
            self.logger.info(f"Technologies detected: {', '.join(detected_techs) if detected_techs else 'None'}", 'discovery')
            # Advanced link discovery
            categorized_links = await self.discover_advanced_links()
            self.logger.info(f"Discovered {sum(len(v) for v in categorized_links.values())} links", 'discovery')
            # Store findings
            self.findings.append({
                'url': url,
                'title': page_title,
                'ai_analysis': ai_analysis.__dict__ if hasattr(ai_analysis, '__dict__') else ai_analysis,
                'technologies': list(detected_techs),
                'links': categorized_links,
                'timestamp': asyncio.get_event_loop().time()
            })
        except Exception as e:
            self.logger.error(f"Error in advanced discovery: {e}", 'discovery')

    async def discover_hidden_parameters(self):
        """Discover hidden parameters through various techniques"""
        self.logger.info("Hidden Parameter Discovery...", 'param_discovery')
        common_params = [
            'debug', 'test', 'admin', 'user', 'id', 'action', 'cmd', 'exec',
            'file', 'path', 'dir', 'page', 'include', 'cat', 'detail',
            'source', 'data', 'input', 'query', 'search', 'filter'
        ]
        current_url = await self.browser_manager.get_current_url()
        base_url = current_url.split('?')[0]
        discovered_params = []
        for param in common_params[:10]:
            test_url = f"{base_url}?{param}=test"
            try:
                response = await asyncio.to_thread(
                    self.browser_manager.driver.request, 'GET', test_url, timeout=5
                )
                if response.status_code == 200:
                    original_length = len(await self.browser_manager.get_page_source())
                    await self.browser_manager.navigate_to(test_url)
                    await asyncio.sleep(1)
                    new_length = len(await self.browser_manager.get_page_source())
                    if abs(new_length - original_length) > 50:
                        discovered_params.append(param)
                        self.logger.info(f"Potential parameter: {param}", 'param_discovery')
            except Exception:
                continue
        self.findings.append({'hidden_parameters': discovered_params})
        await self.browser_manager.navigate_to(current_url)

    async def intelligent_exploration(self):
        """Phase 2: Intelligent exploration of discovered assets"""
        self.logger.info("Phase 2: Intelligent Asset Exploration...", 'exploration')
        # Explore internal links intelligently
        internal_links = []
        suspicious_links = []
        admin_links = []
        for finding in self.findings:
            if 'links' in finding:
                internal_links.extend(finding['links'].get('internal', []))
                suspicious_links.extend(finding['links'].get('suspicious', []))
                admin_links.extend(finding['links'].get('admin', []))
        priority_links = admin_links + suspicious_links + internal_links[:5]
        visited = set()
        for i, url in enumerate(priority_links[:8]):
            if url in visited:
                continue
            self.logger.info(f"Exploring {i+1}: {url}", 'exploration')
            try:
                await self.browser_manager.navigate_to(url)
                await asyncio.sleep(2)
                page_content = await self.browser_manager.get_page_source()
                ai_analysis = await self.ai_analyzer.analyze_content(page_content, context="exploration", target_url=url)
                self.logger.info(f"AI Risk Assessment: {ai_analysis.risk_score if hasattr(ai_analysis, 'risk_score') else 0}/10", 'exploration')
                visited.add(url)
            except Exception as e:
                self.logger.warning(f"Error exploring {url}: {str(e)[:50]}", 'exploration')

    async def advanced_vulnerability_testing(self):
        """Phase 3: Advanced vulnerability testing with AI guidance"""
        self.logger.info("Phase 3: Advanced Vulnerability Testing...", 'vuln_testing')
        # Test forms with comprehensive payloads
        await self.security_tester.run_all_tests(self.browser_manager, await self.browser_manager.get_current_url())
        # Additional advanced tests (URL params, headers, auth, business logic) can be added here

    async def discover_advanced_forms(self):
        """Advanced form discovery with input analysis"""
        self.logger.info("Advanced Form Analysis...", 'form_discovery')
        forms = await self.browser_manager.find_elements('tag name', 'form')
        for i, form in enumerate(forms):
            try:
                action = form.get_attribute("action") or await self.browser_manager.get_current_url()
                method = form.get_attribute("method") or "GET"
                form_id = form.get_attribute("id") or f"form_{i}"
                self.logger.info(f"Form {i+1}: {method.upper()} → {action}", 'form_discovery')
                # Analyze inputs
                inputs = form.find_elements_by_tag_name("input")
                textareas = form.find_elements_by_tag_name("textarea")
                selects = form.find_elements_by_tag_name("select")
                form_data = {
                    'action': action,
                    'method': method,
                    'inputs': [],
                    'vulnerability_score': 0
                }
                all_inputs = inputs + textareas + selects
                for inp in all_inputs:
                    input_type = inp.get_attribute("type") or "text"
                    name = inp.get_attribute("name") or "unnamed"
                    placeholder = inp.get_attribute("placeholder") or ""
                    value = inp.get_attribute("value") or ""
                    input_data = {
                        'type': input_type,
                        'name': name,
                        'placeholder': placeholder,
                        'value': value,
                        'vulnerable_to': []
                    }
                    if input_type in ['text', 'search', 'url', 'email']:
                        input_data['vulnerable_to'].extend(['xss', 'sqli', 'lfi'])
                        form_data['vulnerability_score'] += 3
                    elif input_type == 'password':
                        input_data['vulnerable_to'].extend(['sqli', 'timing_attack'])
                        form_data['vulnerability_score'] += 2
                    elif input_type == 'file':
                        input_data['vulnerable_to'].extend(['file_upload', 'path_traversal'])
                        form_data['vulnerability_score'] += 4
                    form_data['inputs'].append(input_data)
                    self.logger.info(f"Input: {input_type} {name} (Risk: {len(input_data['vulnerable_to'])})", 'form_discovery')
                self.findings.append({'form_id': form_id, 'form_data': form_data})
            except Exception as e:
                self.logger.warning(f"Error analyzing form: {e}", 'form_discovery')

    async def analyze_javascript(self):
        """Analyze JavaScript for potential vulnerabilities"""
        self.logger.info("JavaScript Analysis...", 'js_analysis')
        try:
            scripts = await self.browser_manager.find_elements('tag name', 'script')
            js_content = ""
            for script in scripts:
                content = script.get_attribute("innerHTML")
                if content:
                    js_content += content + "\n"
            sensitive_patterns = {
                'API Keys': r'api[_-]?key[\'\"]\s*[:=]\s*[\'\"]\w+',
                'Passwords': r'password[\'\"]\s*[:=]\s*[\'\"]\w+',
                'Tokens': r'token[\'\"]\s*[:=]\s*[\'\"]\w+',
                'URLs': r'https?://[^\s\'\"]+',
                'AJAX Endpoints': r'ajax|xhr|fetch\([\'\"](/[^\'\"]+)',
                'DOM Manipulation': r'innerHTML|document\.write|eval\(',
                'Local Storage': r'localStorage|sessionStorage'
            }
            import re
            js_findings = {}
            for pattern_name, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                if matches:
                    js_findings[pattern_name] = matches[:5]
                    self.logger.info(f"{pattern_name}: {len(matches)} occurrences", 'js_analysis')
            self.findings.append({'javascript': js_findings})
        except Exception as e:
            self.logger.error(f"JavaScript analysis failed: {e}", 'js_analysis')

    async def analyze_cookies_sessions(self):
        """Analyze cookies and session management"""
        self.logger.info("Cookie & Session Analysis...", 'cookie_analysis')
        try:
            cookies = self.browser_manager.driver.get_cookies()
            for cookie in cookies:
                name = cookie.get('name', 'unknown')
                value = cookie.get('value', '')
                secure = cookie.get('secure', False)
                httponly = cookie.get('httpOnly', False)
                security_score = 0
                issues = []
                if not secure:
                    issues.append("Not Secure")
                    security_score += 1
                if not httponly:
                    issues.append("Not HttpOnly")
                    security_score += 1
                if len(value) > 50:
                    issues.append("Long Value")
                    security_score += 1
                self.logger.info(f"Cookie: {name} (Issues: {len(issues)})", 'cookie_analysis')
                self.findings.append({'cookie': name, 'issues': issues, 'security_score': security_score})
        except Exception as e:
            self.logger.error(f"Cookie analysis failed: {e}", 'cookie_analysis')

    def detect_technologies(self, page_source):
        """Detect technologies and frameworks"""
        tech_patterns = {
            'PHP': r'\.php|<\?php|PHP/',
            'ASP.NET': r'\.aspx|__VIEWSTATE|asp\.net',
            'JSP': r'\.jsp|<%=|<%@',
            'Node.js': r'Express|node\.js',
            'WordPress': r'wp-content|wp-includes|wordpress',
            'Drupal': r'drupal|/sites/default/',
            'Joomla': r'joomla|/components/',
            'React': r'react|ReactDOM',
            'Angular': r'angular|ng-app',
            'jQuery': r'jquery|jQuery',
            'Bootstrap': r'bootstrap',
            'MySQL': r'mysql|phpmyadmin',
            'PostgreSQL': r'postgresql|postgres',
            'MongoDB': r'mongodb|mongo',
            'Apache': r'apache|httpd',
            'Nginx': r'nginx',
            'IIS': r'iis|microsoft-iis'
        }
        detected = set()
        import re
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, page_source, re.IGNORECASE):
                detected.add(tech)
        return detected

    async def discover_advanced_links(self):
        """Advanced link discovery with categorization"""
        self.logger.info("Advanced Link Discovery...", 'discovery')
        links = await self.browser_manager.find_elements('tag name', 'a')
        categorized_links = {
            'internal': [],
            'external': [],
            'suspicious': [],
            'admin': [],
        }
        from urllib.parse import urlparse, urljoin
        base_domain = urlparse(await self.browser_manager.get_current_url()).netloc
        for link in links:
            try:
                href = link.get_attribute('href')
                if not href:
                    continue
                parsed = urlparse(href)
                if base_domain in parsed.netloc:
                    categorized_links['internal'].append(href)
                elif any(x in href.lower() for x in ['admin', 'login', 'manage']):
                    categorized_links['admin'].append(href)
                elif parsed.scheme in ['http', 'https']:
                    categorized_links['external'].append(href)
                else:
                    categorized_links['suspicious'].append(href)
            except Exception:
                continue
        return categorized_links 