#!/usr/bin/env python3
"""
Entry point for the Intelligent Terminal AI Tool
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path
import json
import html  # for HTML-escaping JSON outputs
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Add improved error handling for WebDriver issues
import time
from selenium.common.exceptions import (
    StaleElementReferenceException, 
    WebDriverException, 
    TimeoutException,
    NoSuchElementException
)

def handle_webdriver_error(driver, error, retry_count=3):
    """Handle WebDriver errors with intelligent retry logic"""
    if retry_count <= 0:
        raise error
    
    if isinstance(error, StaleElementReferenceException):
        # Wait and refresh page for stale elements
        time.sleep(2)
        driver.refresh()
        return True
    elif isinstance(error, TimeoutException):
        # Increase timeout and retry
        driver.set_page_load_timeout(driver.get_page_load_timeout() + 10)
        return True
    elif isinstance(error, WebDriverException):
        # Try to restart browser session
        try:
            driver.quit()
            time.sleep(1)
            # Reinitialize driver here
            return True
        except:
            return False
    
    return False

from intelligent_terminal_ai.main import IntelligentTerminalAI
from intelligent_terminal_ai.utils.logger import setup_logger
from intelligent_terminal_ai.utils.config import config
from intelligent_terminal_ai.core.autonomous_pentester import AutonomousPenTester
from intelligent_terminal_ai.core.ai_analyzer import AIAnalyzer
from intelligent_terminal_ai.core.browser_automator import BrowserAutomator
from intelligent_terminal_ai.core.terminal_executor import TerminalExecutor

# Import the working visual pentest demo
from visual_pentest_demo import VisualPenTest
from intelligent_crawler import IntelligentWebCrawler
from advanced_intelligent_crawler import AdvancedIntelligentCrawler

# Import the professional report generator
from report_generator import ReportGenerator

# Import AI Policy Layer for AI/No-AI mode switching
import ai_policy


# ... (existing code) ...


def get_risk_level(score: float) -> str:
    """Convert risk score to risk level with enhanced categorization"""
    if score <= 2:
        return "LOW RISK"
    elif score <= 4:
        return "MEDIUM RISK"
    elif score <= 7:
        return "HIGH RISK"
    elif score <= 9:
        return "CRITICAL RISK"
    else:
        return "SEVERE RISK"

def calculate_cvss_score(vulnerability_type: str, severity: str, context: dict = None) -> float:
    """Calculate CVSS score based on vulnerability type and context"""
    base_scores = {
        'xss': 6.1,
        'sqli': 8.8,
        'command_injection': 9.8,
        'auth_bypass': 8.1,
        'csrf': 6.5,
        'directory_listing': 4.3,
        'access_control': 7.5,
        'lfi': 7.5,
        'rfi': 8.5,
        'xxe': 7.5,
        'ssrf': 7.5,
        'idor': 6.5
    }
    
    vuln_lower = vulnerability_type.lower()
    for key, score in base_scores.items():
        if key in vuln_lower:
            base_score = score
            break
    else:
        base_score = 5.0
    
    # Adjust based on severity
    severity_multipliers = {
        'critical': 1.2,
        'high': 1.0,
        'medium': 0.8,
        'low': 0.6,
        'info': 0.4
    }
    
    multiplier = severity_multipliers.get(severity.lower(), 1.0)
    return min(10.0, base_score * multiplier)


def generate_pentest_recommendations(vulnerabilities: dict, scan_depth: str) -> list[str]:
    """Generate security recommendations based on findings"""
    recommendations = []
    
    # WordPress-specific recommendations
    if 'xmlrpc_enabled' in vulnerabilities:
        recommendations.append("🔧 Disable XML-RPC interface if not needed to prevent brute-force and DDoS attacks.")
    
    if 'user_enumeration' in vulnerabilities:
        recommendations.append("🛡️ Implement user enumeration protection (e.g., disable REST API user endpoints, use plugins).")
    
    if 'directory_listing' in vulnerabilities:
        recommendations.append("📁 Disable directory listings on your web server to prevent information leakage.")

    # Enhanced vulnerability recommendations
    vuln_types = set(vuln.get('type', 'general') for vuln in vulnerabilities.values())
    if 'xss' in vuln_types:
        recommendations.append("🚫 Implement a strict Content Security Policy (CSP) and use context-aware output encoding to prevent XSS.")
    if 'sqli' in vuln_types:
        recommendations.append("💾 Use parameterized queries (prepared statements) for all database interactions to prevent SQL Injection.")
    if 'command_injection' in vuln_types:
        recommendations.append("⚡ Sanitize and validate all user-supplied input that is passed to system shells or interpreters.")
    if 'csrf' in vuln_types:
        recommendations.append("🔄 Implement CSRF tokens and validate request origins to prevent Cross-Site Request Forgery.")
    if 'auth_bypass' in vuln_types:
        recommendations.append("🔐 Implement proper authentication mechanisms and avoid relying on client-side controls.")
    if 'directory_listing' in vuln_types:
        recommendations.append("📂 Disable directory listing in web server configuration to prevent information disclosure.")
    if 'access_control' in vuln_types:
        recommendations.append("🚪 Implement proper access controls and authorization checks for all sensitive resources.")
    
    # General recommendations
    base_recommendations = [
        "🔄 Keep all software (CMS, frameworks, libraries) up to date.",
        "🔐 Implement strong password policies and enable multi-factor authentication.",
        "🔒 Use SSL/TLS (HTTPS) for all data transmission.",
        "📋 Perform regular, automated security backups and test the restoration process.",
        "🚨 Install and properly configure a Web Application Firewall (WAF).",
        "🔍 Implement comprehensive logging and monitoring for security events.",
        "🧪 Conduct regular penetration testing and security assessments."
    ]
    
    if scan_depth == '3': # Deep Security
        base_recommendations.extend([
            "🧪 Commission regular, in-depth penetration testing from third-party experts.",
            "📡 Implement security headers like HSTS, X-Frame-Options, and X-Content-Type-Options.",
            "🔐 Harden file permissions on the web server.",
            "📊 Aggregate security logs and monitor them for suspicious activity.",
            "🔒 Implement API security best practices including rate limiting and input validation.",
            "🛡️ Use security scanning tools and integrate them into your CI/CD pipeline."
        ])
    
    # Combine and deduplicate
    all_recommendations = recommendations + base_recommendations
    return list(dict.fromkeys(all_recommendations))


async def generate_pentest_report(crawler: AdvancedIntelligentCrawler, target_site: dict, scan_depth: str):
    """Generate comprehensive security report from crawler findings"""
    
    vulnerabilities = crawler.discovered_assets.get('vulnerabilities', {})
    pages_count = len(crawler.discovered_assets.get('pages', {}))
    forms_count = len(crawler.discovered_assets.get('forms', {}))
    
    print("\n" + "="*75)
    print("📋 COMPREHENSIVE SECURITY ASSESSMENT")
    print("=" * 75)
    
    print(f"🎯 Target: {target_site['name']}")
    print(f"🌐 URL: {target_site['url']}")
    scan_type_map = {'1': 'WordPress Focus', '2': 'Balanced Scan', '3': 'Deep Security'}
    print(f"📈 Scan Type: {scan_type_map.get(scan_depth, 'Unknown')}")
    
    print("\n📊 SCAN STATISTICS:")
    print(f"  • Pages analyzed: {pages_count}")
    print(f"  • Forms discovered: {forms_count}")
    print(f"  • Potential vulnerabilities found: {len(vulnerabilities)}")
    
    # Vulnerability analysis
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    
    print("\n🚨 SECURITY VULNERABILITIES DETECTED:")
    if not vulnerabilities:
        print("  ✅ No direct vulnerabilities found by the automated scanner.")
    else:
        # Group by severity
        severity_groups = {'critical': [], 'high': [], 'medium': [], 'low': [], 'informational': []}
        for name, details in vulnerabilities.items():
            severity = details.get('severity', 'low').lower()
            details['name'] = name
            severity_groups.get(severity, severity_groups['low']).append(details)

        for severity, issues in severity_groups.items():
            if issues:
                print(f"    📊 {severity.upper()} ({len(issues)} issues):")
                for issue in issues:
                    print(f"      • {issue.get('name', 'Unknown').replace('_', ' ').title()}")
                    print(f"        └─ Description: {issue.get('description', 'N/A')}")
                    if issue.get('url'):
                        print(f"           └─ URL: {issue['url']}")
                    if issue.get('parameter'):
                        print(f"           └─ Parameter: {issue['parameter']}")

                # Update totals
                if severity == 'critical':
                    total_critical += len(issues)
                elif severity == 'high':
                    total_high += len(issues)
                elif severity == 'medium':
                    total_medium += len(issues)
                else:
                    total_low += len(issues)

    # Overall risk assessment
    risk_score = min(10, 1 + total_critical * 3 + total_high * 2 + total_medium * 1 + total_low * 0.5)
    risk_level = get_risk_level(risk_score)
    
    print("\n🎯 OVERALL SECURITY ASSESSMENT:")
    print(f"  📊 Risk Score: {risk_score:.1f}/10 ({risk_level})")
    print(f"  🔴 Critical Issues: {total_critical}")
    print(f"  🟠 High Issues: {total_high}")
    print(f"  🟡 Medium Issues: {total_medium}")
    print(f"  🟢 Low/Info Issues: {total_low}")
    
    # Security recommendations
    print("\n💡 SECURITY RECOMMENDATIONS:")
    recommendations = generate_pentest_recommendations(vulnerabilities, scan_depth)
    
    for i, rec in enumerate(recommendations[:10], 1):
        print(f"  {i}. {rec}")
    
    # Summary
    if total_critical > 0:
        print(f"\n🚨 URGENT: {total_critical} critical issue(s) require immediate attention!")
    elif total_high > 0:
        print(f"\n⚠️ WARNING: {total_high} high-risk issue(s) should be addressed promptly.")
    elif not vulnerabilities:
        print(f"\n✅ GOOD: No obvious security issues detected in this automated scan. Manual review is still recommended.")
    else:
        print(f"\n📋 INFO: Review the {len(vulnerabilities)} issues found and address them based on your risk assessment.")
    
    print("=" * 75)
    print("✅ Security assessment completed!")


async def interactive_pentest(logger):
    """Run an interactive penetration testing session with enhanced performance."""
    
    # Test sites (known WordPress installations)
    test_sites = [
        {
            'url': 'http://testphp.vulnweb.com/wordpress/',
            'name': 'Vulnerable WordPress Test Site',
            'description': 'Intentionally vulnerable WordPress for testing'
        },
        {
            'url': 'https://wpexploit-labs.com/',
            'name': 'WordPress Exploit Labs',
            'description': 'WordPress security testing environment'
        },
        {
            'url': 'https://sxi.io/common-wordpress-vulnerabilities/',
            'name': 'WordPress Vulnerability Info Site',
            'description': 'A blog post about WP vulnerabilities (good for crawling)'
        },
        {
            'url': 'https://wordpress.org/',
            'name': 'Official WordPress.org',
            'description': 'The official WordPress project site'
        }
    ]
    
    print("🎯 AUTONOMOUS PENTESTING TOOL")
    print("🛡️ An intelligent, human-like security scanner")
    print("="*75)
    
    # Let user choose a site
    print(f"\n🌐 Select a target site:")
    for i, site in enumerate(test_sites, 1):
        print(f"  {i}. {site['name']} ({site['url']})")
    
    print(f"  {len(test_sites) + 1}. Enter a custom URL")
    
    choice = input(f"Select an option (1-{len(test_sites) + 1}): ").strip()
    
    target_site = None
    try:
        choice_num = int(choice)
        if 1 <= choice_num <= len(test_sites):
            target_site = test_sites[choice_num - 1]
        elif choice_num == len(test_sites) + 1:
            custom_url = input("Enter the full URL to test: ").strip()
            if not custom_url.startswith(('http://', 'https://')):
                custom_url = f"https://{custom_url}"
            target_site = {'url': custom_url, 'name': 'Custom Site', 'description': 'User-provided target'}
    except ValueError:
        pass

    if not target_site:
        print("Invalid choice. Exiting.")
        return

    # Select scan depth with performance considerations
    print(f"\n📊 Select scan comprehensiveness:")
    print(f"  1. WordPress Focus (Fast check for WordPress-specific issues) - ~2-3 minutes")
    print(f"  2. Balanced Scan (Standard crawling and vulnerability testing) - ~5-7 minutes")
    print(f"  3. Deep Security (Comprehensive testing, slower) - ~10-15 minutes")
    
    scan_depth = input("Enter choice (1-3, default 2): ").strip() or "2"
    if scan_depth not in ['1', '2', '3']:
        scan_depth = '2'

    scan_type_map = {'1': 'WordPress Focus', '2': 'Balanced Scan', '3': 'Deep Security'}
    
    print(f"\n🎯 Selected Target: {target_site['name']}")
    print(f"🌐 URL: {target_site['url']}")
    print(f"📈 Scan Type: {scan_type_map.get(scan_depth, 'Unknown')}")
    print("="*75)
    
    # Performance monitoring
    start_time = time.time()
    crawler = None
    try:
        logger.info("Initializing advanced intelligent crawler...")
        # Pass the scan_depth to the crawler to control its behavior
        crawler = AdvancedIntelligentCrawler()
        await crawler.setup_advanced_browser()
        
        logger.info(f"Starting comprehensive scan for {target_site['url']}")
        await crawler.comprehensive_crawl_and_test(target_site['url'])
        
        # Generate the final report
        await generate_pentest_report(crawler, target_site, scan_depth)
        
        # Performance summary
        elapsed_time = time.time() - start_time
        print(f"\n⏱️ Scan completed in {elapsed_time:.1f} seconds")
        
    except KeyboardInterrupt:
        logger.warning("\n⚠️ Scan interrupted by user.")
    except Exception as e:
        logger.error(f"\n❌ A critical error occurred during the scan: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if crawler and crawler.driver:
            await crawler.close()
            logger.info("🔧 Browser and resources have been released.")


def save_report_as_html(data: dict, filename: str = 'report.html', ai_enabled: bool = True):
    """Save a dictionary as a professional HTML report using ReportGenerator."""
    try:
        # Convert the data to the format expected by ReportGenerator
        final_findings = []
        
        # Handle main data structure
        main_findings = convert_data_to_findings(data)
        final_findings.extend(main_findings)
        
        # Check for console analysis in the data
        if isinstance(data, dict) and 'console_analysis' in data:
            console_findings = parse_console_analysis_to_findings(str(data['console_analysis']))
            final_findings.extend(console_findings)
        
        # Check for AI analysis results in various formats
        if isinstance(data, dict):
            for key in ['ai_results', 'ai_analysis', 'ai_assessment']:
                if key in data:
                    ai_findings = convert_data_to_findings({key: data[key]})
                    final_findings.extend(ai_findings)
        
        # Extract target URL
        target_url = extract_target_url(data)
        
        # Find log file path
        log_file_path = find_log_file()
        
        # If no findings from structured data, try to parse log file
        if not final_findings and log_file_path:
            try:
                with open(log_file_path, 'r', encoding='utf-8') as f:
                    log_content = f.read()
                    log_findings = parse_console_analysis_to_findings(log_content)
                    final_findings.extend(log_findings)
            except Exception as e:
                print(f"⚠️ Could not analyze log file: {e}")
        
        # Remove duplicate findings
        unique_findings = []
        seen_vulns = set()
        for finding in final_findings:
            vuln_key = (finding.get('vulnerability_type', ''), finding.get('detailed_description', ''))
            if vuln_key not in seen_vulns:
                seen_vulns.add(vuln_key)
                unique_findings.append(finding)
        
        # Create ReportGenerator instance
        generator = ReportGenerator(log_file_path=log_file_path, ai_enabled=ai_enabled)
        
        # Generate the professional HTML report
        report_path = generator.generate_html_report(
            final_findings=unique_findings,
            target_url=target_url,
            output_filename=filename
        )
        
        print(f"✅ Professional HTML report saved to {report_path}")
        print(f"📊 Report contains {len(unique_findings)} vulnerability findings")
        
    except Exception as e:
        print(f"⚠️ Error generating professional report, falling back to basic HTML: {e}")
        # Fallback to basic HTML if professional report fails
        save_basic_html_report(data, filename, ai_enabled)


def save_basic_html_report(data: dict, filename: str = 'report.html', ai_enabled: bool = True):
    """Fallback basic HTML report generation."""
    # Make data JSON serializable by converting sets to lists
    serializable_data = make_json_serializable(data)
    escaped = html.escape(json.dumps(serializable_data, indent=2))
    content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{'AI-Enhanced ' if ai_enabled else ''}PenTest Report</title>
  <style>
    body {{ font-family: 'Courier New', monospace; background-color: #1e1e1e; color: #d4d4d4; margin: 20px; }}
    pre {{ background-color: #2d2d30; padding: 20px; border-radius: 8px; overflow-x: auto; line-height: 1.4; }}
    h1 {{ color: #569cd6; text-align: center; }}
  </style>
</head>
<body>
<h1>🛡️ {'AI-Enhanced ' if ai_enabled else ''}Penetration Testing Report</h1>
<p style="text-align: center; color: #9cdcfe;">Analysis Type: {'AI-Enhanced' if ai_enabled else 'Standard'} Security Scan</p>
<pre>{escaped}</pre>
</body>
</html>
"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✅ Basic HTML report saved to {filename}")


def convert_data_to_findings(data: dict) -> list:
    """Convert raw report data to findings format expected by ReportGenerator."""
    findings = []
    
    try:
        # Handle AI analysis results with detailed vulnerability structure
        if 'ai_analysis' in data:
            ai_data = data['ai_analysis']
            
            # Handle multiple AI analysis entries
            if isinstance(ai_data, list):
                for analysis in ai_data:
                    if isinstance(analysis, dict):
                        findings.extend(extract_vulnerabilities_from_ai_analysis(analysis))
            elif isinstance(ai_data, dict):
                findings.extend(extract_vulnerabilities_from_ai_analysis(ai_data))
        
        # Handle direct vulnerabilities array (from AI analysis JSON)
        if 'vulnerabilities' in data:
            vulns = data['vulnerabilities']
            if isinstance(vulns, list):
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        finding = {
                            'vulnerability_type': vuln.get('type', 'Unknown Vulnerability'),
                            'severity': determine_severity_from_vuln(vuln),
                            'cvss_score': vuln.get('cvss_score', extract_cvss_from_severity(vuln.get('severity', 'Medium'))),
                            'detailed_description': vuln.get('description', 'Vulnerability detected'),
                            'business_impact': generate_business_impact(vuln),
                            'remediation_steps': vuln.get('remediation', 'Apply security patches and controls'),
                            'payload_used': vuln.get('payload', vuln.get('location', 'N/A')),
                            'evidence': vuln.get('evidence', vuln.get('details', 'Automated detection confirmed'))
                        }
                        findings.append(finding)
            elif isinstance(vulns, dict):
                # Handle vulnerabilities from discovered_assets (dict with vulnerability IDs as keys)
                for vuln_id, vuln_data in vulns.items():
                    if isinstance(vuln_data, dict):
                        # Check if this is a discovered_assets vulnerability structure
                        if 'type' in vuln_data and 'severity' in vuln_data:
                            finding = {
                                'vulnerability_type': vuln_data.get('type', 'Unknown Vulnerability').replace('_', ' ').title(),
                                'severity': vuln_data.get('severity', 'Medium').title(),
                                'cvss_score': extract_cvss_from_severity(vuln_data.get('severity', 'Medium')),
                                'detailed_description': vuln_data.get('description', f"{vuln_data.get('type', 'vulnerability')} detected at {vuln_data.get('vulnerable_url', 'target location')}"),
                                'business_impact': generate_business_impact_from_type(vuln_data.get('type', '')),
                                'remediation_steps': get_remediation_for_vuln_type(vuln_data.get('type', '')),
                                'payload_used': vuln_data.get('payload', vuln_data.get('attack_vector', 'N/A')),
                                'evidence': f"Vulnerability ID: {vuln_id}, Attack vector: {vuln_data.get('attack_vector', 'Direct injection')}, URL: {vuln_data.get('vulnerable_url', 'N/A')}"
                            }
                            findings.append(finding)
                        # Handle legacy structure (boolean found flag)
                        elif vuln_data.get('found', False):
                            finding = {
                                'vulnerability_type': vuln_id.replace('_', ' ').title(),
                                'severity': determine_severity_from_type(vuln_id),
                                'detailed_description': vuln_data.get('description', f'{vuln_id} vulnerability detected'),
                                'business_impact': 'Security vulnerability that may compromise system integrity',
                                'remediation_steps': vuln_data.get('remediation', 'Implement proper security controls and input validation'),
                                'payload_used': vuln_data.get('payload', 'N/A'),
                                'evidence': vuln_data.get('evidence', 'Vulnerability confirmed through automated testing')
                            }
                            findings.append(finding)
        
        # Handle security test results
        if 'security_tests' in data:
            for test_name, test_result in data['security_tests'].items():
                if isinstance(test_result, dict) and test_result.get('vulnerable', False):
                    finding = {
                        'vulnerability_type': test_name.replace('_', ' ').title(),
                        'severity': 'High' if 'injection' in test_name.lower() else 'Medium',
                        'detailed_description': test_result.get('description', f'{test_name} vulnerability detected'),
                        'business_impact': 'Security vulnerability requiring immediate attention',
                        'remediation_steps': test_result.get('remediation', 'Implement proper input validation and security controls'),
                        'payload_used': test_result.get('payload', 'N/A'),
                        'evidence': test_result.get('evidence', 'Security test confirmed vulnerability')
                    }
                    findings.append(finding)
        
        # Handle recommendations as low-priority findings
        if 'recommendations' in data:
            recommendations = data['recommendations']
            if isinstance(recommendations, list):
                for rec in recommendations:
                    if isinstance(rec, dict):
                        finding = {
                            'vulnerability_type': f"Security Recommendation: {rec.get('area', 'General')}",
                            'severity': map_priority_to_severity(rec.get('priority', 'Medium')),
                            'detailed_description': rec.get('description', 'Security improvement recommendation'),
                            'business_impact': 'Proactive security measure to reduce risk exposure',
                            'remediation_steps': rec.get('description', 'Follow security best practices'),
                            'payload_used': 'N/A - Preventive Measure',
                            'evidence': 'Security assessment recommendation'
                        }
                        findings.append(finding)
    
    except Exception as e:
        print(f"⚠️ Error converting data to findings: {e}")
        # Create a generic finding if conversion fails
        findings.append({
            'vulnerability_type': 'Data Processing Error',
            'severity': 'Info',
            'detailed_description': f'Error processing scan results: {str(e)}',
            'business_impact': 'Unable to properly parse vulnerability data',
            'remediation_steps': 'Review scan configuration and data format',
            'payload_used': 'N/A',
            'evidence': 'Data conversion error encountered'
        })
    
    return findings


def extract_vulnerabilities_from_ai_analysis(analysis: dict) -> list:
    """Extract vulnerabilities from AI analysis structure."""
    findings = []
    
    # Handle vulnerabilities array within AI analysis
    vulnerabilities = analysis.get('vulnerabilities', [])
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                finding = {
                    'vulnerability_type': vuln.get('type', 'AI-Detected Vulnerability'),
                    'severity': determine_severity_from_vuln(vuln),
                    'cvss_score': vuln.get('cvss_score', extract_cvss_from_severity(vuln.get('severity', 'Medium'))),
                    'detailed_description': vuln.get('description', 'AI-powered vulnerability analysis'),
                    'business_impact': vuln.get('business_impact', generate_business_impact(vuln)),
                    'remediation_steps': vuln.get('remediation', extract_remediation_from_recommendations(analysis)),
                    'payload_used': vuln.get('payload', vuln.get('location', 'N/A')),
                    'evidence': vuln.get('evidence', vuln.get('details', 'AI-based vulnerability assessment'))
                }
                findings.append(finding)
    
    return findings


def determine_severity_from_vuln(vuln: dict) -> str:
    """Determine severity from vulnerability data."""
    # Check explicit severity
    if 'severity' in vuln:
        severity = vuln['severity'].title()
        if severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            return severity
    
    # Check CVSS score
    if 'cvss_score' in vuln:
        score = vuln['cvss_score']
        if isinstance(score, (int, float)):
            if score >= 9.0:
                return 'Critical'
            elif score >= 7.0:
                return 'High'
            elif score >= 4.0:
                return 'Medium'
            elif score >= 0.1:
                return 'Low'
    
    # Check vulnerability type
    vuln_type = vuln.get('type', '').lower()
    if any(term in vuln_type for term in ['critical', 'rce', 'command injection', 'sql injection']):
        return 'Critical'
    elif any(term in vuln_type for term in ['xss', 'csrf', 'auth', 'high']):
        return 'High'
    elif any(term in vuln_type for term in ['disclosure', 'exposure', 'medium']):
        return 'Medium'
    elif any(term in vuln_type for term in ['low', 'info']):
        return 'Low'
    
    return 'Medium'


def extract_cvss_from_severity(severity: str) -> float:
    """Convert severity to approximate CVSS score."""
    severity_map = {
        'Critical': 9.5,
        'High': 7.5,
        'Medium': 5.0,
        'Low': 3.0,
        'Info': 1.0
    }
    return severity_map.get(severity, 5.0)


def generate_business_impact(vuln: dict) -> str:
    """Generate business impact based on vulnerability type and severity."""
    vuln_type = vuln.get('type', '').lower()
    severity = vuln.get('severity', 'medium').lower()
    
    if 'xss' in vuln_type:
        return 'Potential for session hijacking, data theft, and website defacement. Could damage user trust and brand reputation.'
    elif 'injection' in vuln_type:
        return 'Complete database compromise possible. Risk of data breach, financial loss, and regulatory violations.'
    elif 'csp' in vuln_type or 'bypass' in vuln_type:
        return 'Security controls can be circumvented, potentially leading to successful attacks and compliance violations.'
    elif 'clickjacking' in vuln_type:
        return 'Users may be tricked into performing unintended actions, potentially leading to unauthorized transactions or data disclosure.'
    elif 'disclosure' in vuln_type:
        return 'Sensitive information exposure could aid attackers in reconnaissance and targeted attacks.'
    elif severity == 'critical':
        return 'Critical security flaw with potential for complete system compromise and significant business disruption.'
    elif severity == 'high':
        return 'High-risk vulnerability that could lead to data breach, financial loss, and reputational damage.'
    else:
        return 'Security vulnerability that may compromise system integrity and user safety.'


def extract_remediation_from_recommendations(analysis: dict) -> str:
    """Extract remediation steps from analysis recommendations."""
    recommendations = analysis.get('recommendations', [])
    if isinstance(recommendations, list) and recommendations:
        # Return the first recommendation as primary remediation
        first_rec = recommendations[0]
        if isinstance(first_rec, dict):
            return first_rec.get('action', first_rec.get('recommendation', 'Follow security best practices'))
        elif isinstance(first_rec, str):
            return first_rec
    
    return 'Implement proper security controls and follow industry best practices'


def parse_console_analysis_to_findings(console_analysis_text: str) -> list:
    """Parse console analysis text and extract vulnerability findings."""
    findings = []
    
    try:
        # Look for JSON blocks in the console analysis
        import re
        json_pattern = r'```json\s*(\{.*?\})\s*```'
        json_matches = re.findall(json_pattern, console_analysis_text, re.DOTALL)
        
        for json_str in json_matches:
            try:
                data = json.loads(json_str)
                if 'vulnerabilities' in data:
                    findings.extend(convert_data_to_findings(data))
            except json.JSONDecodeError:
                continue
        
        # If no JSON found, look for structured vulnerability descriptions
        if not findings:
            vulnerability_sections = re.split(r'\[AI\].*?Console Analysis:', console_analysis_text)
            for section in vulnerability_sections[1:]:  # Skip first empty section
                findings.extend(extract_findings_from_text_section(section))
    
    except Exception as e:
        print(f"⚠️ Error parsing console analysis: {e}")
    
    return findings


def extract_findings_from_text_section(text: str) -> list:
    """Extract findings from a text section using pattern matching."""
    findings = []
    
    try:
        # Look for common vulnerability indicators in text
        lines = text.split('\n')
        current_vuln = {}
        
        for line in lines:
            line = line.strip()
            
            # Look for vulnerability type indicators
            if any(term in line.lower() for term in ['xss', 'injection', 'csp', 'clickjacking', 'disclosure']):
                if current_vuln:
                    findings.append(finalize_text_vulnerability(current_vuln))
                current_vuln = {
                    'vulnerability_type': extract_vuln_type_from_line(line),
                    'description_lines': [line]
                }
            elif current_vuln and line:
                current_vuln['description_lines'].append(line)
        
        # Add the last vulnerability if exists
        if current_vuln:
            findings.append(finalize_text_vulnerability(current_vuln))
    
    except Exception as e:
        print(f"⚠️ Error extracting findings from text: {e}")
    
    return findings


def extract_vuln_type_from_line(line: str) -> str:
    """Extract vulnerability type from a line of text."""
    line_lower = line.lower()
    
    if 'xss' in line_lower:
        return 'Cross-Site Scripting (XSS)'
    elif 'sql injection' in line_lower or 'sqli' in line_lower:
        return 'SQL Injection'
    elif 'csp' in line_lower:
        return 'Content Security Policy Bypass'
    elif 'clickjacking' in line_lower:
        return 'Clickjacking Vulnerability'
    elif 'disclosure' in line_lower:
        return 'Information Disclosure'
    elif 'third-party' in line_lower:
        return 'Third-Party Dependency Risk'
    else:
        return 'Security Vulnerability'


def finalize_text_vulnerability(vuln_data: dict) -> dict:
    """Convert text-based vulnerability data to finding format."""
    description = ' '.join(vuln_data.get('description_lines', []))
    vuln_type = vuln_data.get('vulnerability_type', 'Security Issue')
    
    return {
        'vulnerability_type': vuln_type,
        'severity': determine_severity_from_type(vuln_type.lower()),
        'detailed_description': description,
        'business_impact': generate_business_impact({'type': vuln_type, 'severity': 'medium'}),
        'remediation_steps': get_default_remediation(vuln_type),
        'payload_used': 'See console analysis for details',
        'evidence': 'AI-powered console analysis detected potential vulnerability'
    }


def get_default_remediation(vuln_type: str) -> str:
    """Get default remediation steps based on vulnerability type."""
    vuln_lower = vuln_type.lower()
    
    if 'xss' in vuln_lower:
        return 'Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers.'
    elif 'injection' in vuln_lower:
        return 'Use parameterized queries and prepared statements. Implement proper input validation.'
    elif 'csp' in vuln_lower:
        return 'Review and tighten CSP directives. Remove unnecessary wildcards and domains.'
    elif 'clickjacking' in vuln_lower:
        return 'Implement X-Frame-Options or CSP frame-ancestors directive.'
    elif 'disclosure' in vuln_lower:
        return 'Review information exposure and implement proper access controls.'
    else:
        return 'Follow security best practices and implement appropriate controls.'


def map_priority_to_severity(priority: str) -> str:
    """Map recommendation priority to vulnerability severity."""
    priority_map = {
        'Critical': 'High',
        'High': 'Medium', 
        'Medium': 'Low',
        'Low': 'Info'
    }
    return priority_map.get(priority, 'Low')


def determine_severity_from_type(vuln_type: str) -> str:
    """Determine vulnerability severity based on type."""
    vuln_type_lower = vuln_type.lower()
    
    if any(term in vuln_type_lower for term in ['injection', 'rce', 'command', 'sqli']):
        return 'Critical'
    elif any(term in vuln_type_lower for term in ['xss', 'csrf', 'auth']):
        return 'High'
    elif any(term in vuln_type_lower for term in ['disclosure', 'exposure', 'leak']):
        return 'Medium'
    else:
        return 'Low'


def extract_target_url(data: dict) -> str:
    """Extract target URL from report data."""
    # Try various fields where URL might be stored
    for field in ['target_url', 'url', 'target', 'base_url', 'site']:
        if field in data:
            return str(data[field])
    return 'Unknown Target'


def generate_business_impact_from_type(vuln_type: str) -> str:
    """Generate business impact description based on vulnerability type."""
    vuln_type_lower = vuln_type.lower()
    
    if 'sqli' in vuln_type_lower or 'injection' in vuln_type_lower:
        return 'Critical security risk allowing potential data breach, unauthorized database access, and complete system compromise'
    elif 'xss' in vuln_type_lower:
        return 'High security risk enabling session hijacking, credential theft, and malicious script execution affecting user data'
    elif 'csrf' in vuln_type_lower:
        return 'Medium security risk allowing unauthorized actions on behalf of authenticated users'
    elif 'ssrf' in vuln_type_lower:
        return 'High security risk enabling internal network scanning and potential access to restricted resources'
    elif 'idor' in vuln_type_lower:
        return 'High security risk allowing unauthorized access to sensitive data through broken access controls'
    elif 'command' in vuln_type_lower:
        return 'Critical security risk enabling remote code execution and complete server compromise'
    else:
        return 'Security vulnerability that may compromise system integrity and user data confidentiality'


def get_remediation_for_vuln_type(vuln_type: str) -> str:
    """Get specific remediation steps based on vulnerability type."""
    vuln_type_lower = vuln_type.lower()
    
    if 'sqli' in vuln_type_lower or 'sql' in vuln_type_lower:
        return 'Implement parameterized queries/prepared statements, input validation, and principle of least privilege for database access'
    elif 'xss' in vuln_type_lower:
        return 'Implement proper input validation, output encoding, Content Security Policy (CSP), and sanitize user inputs'
    elif 'csrf' in vuln_type_lower:
        return 'Implement CSRF tokens, verify referrer headers, and use SameSite cookie attributes'
    elif 'ssrf' in vuln_type_lower:
        return 'Validate and whitelist allowed URLs, implement network segmentation, and restrict outbound connections'
    elif 'idor' in vuln_type_lower:
        return 'Implement proper access controls, user session validation, and indirect object references'
    elif 'command' in vuln_type_lower:
        return 'Avoid system calls with user input, implement strict input validation, and use safer alternatives to system commands'
    elif 'form' in vuln_type_lower:
        return 'Implement proper form validation, CSRF protection, and secure form processing'
    elif 'parameter' in vuln_type_lower:
        return 'Validate all URL parameters, implement input sanitization, and use whitelist validation'
    else:
        return 'Implement proper security controls, input validation, and follow secure coding practices'
        if field in data and data[field]:
            return str(data[field])
    
    # Try nested structures
    if 'config' in data and isinstance(data['config'], dict):
        for field in ['target_url', 'url', 'target']:
            if field in data['config'] and data['config'][field]:
                return str(data['config'][field])
    
    return 'Unknown Target'


def find_log_file() -> str:
    """Find the most recent log file."""
    try:
        log_dirs = ['logs', 'log', '.']
        log_files = []
        
        for log_dir in log_dirs:
            if os.path.exists(log_dir):
                for file in Path(log_dir).glob('*.log'):
                    log_files.append(file)
        
        if log_files:
            # Return the most recently modified log file
            latest_log = max(log_files, key=lambda f: f.stat().st_mtime)
            return str(latest_log)
    except Exception:
        pass
    
    return None


def make_json_serializable(obj):
    """Convert non-JSON serializable objects (like sets) to serializable ones."""
    if isinstance(obj, dict):
        return {key: make_json_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [make_json_serializable(item) for item in obj]
    elif isinstance(obj, set):
        return list(obj)
    else:
        # Handle other non-serializable types if needed
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)


def save_report_as_json(data: dict, filename: str = 'report.json'):
    """Save a dictionary as a JSON report."""
    # Make data JSON serializable by converting sets to lists
    serializable_data = make_json_serializable(data)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(serializable_data, f, indent=2, ensure_ascii=False)
    print(f"✅ JSON report saved to {filename}")


def save_report_as_text(data: dict, filename: str = 'report.txt'):
    """Save a dictionary as a formatted text report."""
    def format_dict(d, indent=0):
        lines = []
        if not isinstance(d, dict):
            return [str(d)]
            
        for key, value in d.items():
            prefix = "  " * indent
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                lines.extend(format_dict(value, indent + 1))
            elif isinstance(value, (list, set)):
                lines.append(f"{prefix}{key}:")
                for i, item in enumerate(list(value)):
                    if isinstance(item, dict):
                        lines.append(f"{prefix}  [{i}]:")
                        lines.extend(format_dict(item, indent + 2))
                    else:
                        lines.append(f"{prefix}  - {item}")
            else:
                lines.append(f"{prefix}{key}: {value}")
        return lines
    
    content = "🛡️ PENETRATION TESTING REPORT\n"
    content += "=" * 50 + "\n\n"
    
    if data:
        content += "\n".join(format_dict(data))
    else:
        content += "No data available in report.\n"
    
    content += "\n\n" + "=" * 50
    content += f"\nReport generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✅ Text report saved to {filename}")


def generate_crawler_report(crawler, target_url):
    """Generate a structured report from the Advanced Intelligent Crawler findings."""
    try:
        # Extract findings from crawler's discovered_assets
        discovered_assets = getattr(crawler, 'discovered_assets', {})
        
        report = {
            "scan_info": {
                "target_url": target_url,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "scanner": "Advanced Intelligent Crawler",
                "scan_type": "Comprehensive Security Assessment"
            },
            "summary": {
                "pages_analyzed": len(discovered_assets.get('pages', {})),
                "forms_discovered": len(discovered_assets.get('forms', {})),
                "technologies_detected": list(discovered_assets.get('technologies', set())),
                "vulnerabilities_found": len(discovered_assets.get('vulnerabilities', {})),
                "links_discovered": sum(len(links) for links in discovered_assets.get('links', {}).values())
            },
            "vulnerabilities": discovered_assets.get('vulnerabilities', {}),
            "technologies": list(discovered_assets.get('technologies', set())),
            "pages": discovered_assets.get('pages', {}),
            "forms": discovered_assets.get('forms', {}),
            "links": discovered_assets.get('links', {}),
            "wordpress": discovered_assets.get('wordpress', {}),
            "javascript": discovered_assets.get('javascript', {}),
            "cookies": discovered_assets.get('cookies', {}),
            "recommendations": [
                "🔄 Keep all software (CMS, frameworks, libraries) up to date",
                "🛡️ Implement proper input validation and output encoding",
                "💾 Use parameterized queries for database operations",
                "🔒 Enable security headers (CSP, HSTS, X-Frame-Options)",
                "📋 Regular security testing and code reviews",
                "🚨 Install and configure a Web Application Firewall (WAF)"
            ]
        }
        
        # Add risk assessment
        vuln_count = len(discovered_assets.get('vulnerabilities', {}))
        if vuln_count == 0:
            report["risk_level"] = "LOW"
            report["risk_score"] = 2
        elif vuln_count <= 2:
            report["risk_level"] = "MEDIUM"
            report["risk_score"] = 5
        elif vuln_count <= 5:
            report["risk_level"] = "HIGH"
            report["risk_score"] = 7
        else:
            report["risk_level"] = "CRITICAL"
            report["risk_score"] = 9
        
        # Add WordPress-specific recommendations if WordPress detected
        if 'WordPress' in discovered_assets.get('technologies', set()):
            wp_recommendations = [
                "🔧 Update WordPress core to the latest version",
                "🔌 Review and update all plugins and themes",
                "🔐 Implement strong password policies",
                "📋 Enable WordPress security plugins (Wordfence, Sucuri)",
                "🚫 Disable XML-RPC if not needed",
                "🛡️ Implement user enumeration protection"
            ]
            report["recommendations"].extend(wp_recommendations)
        
        return report
        
    except Exception as e:
        # Fallback report if something goes wrong
        return {
            "scan_info": {
                "target_url": target_url,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "scanner": "Advanced Intelligent Crawler",
                "scan_type": "Comprehensive Security Assessment",
                "error": f"Report generation error: {str(e)}"
            },
            "summary": {
                "pages_analyzed": 0,
                "forms_discovered": 0,
                "technologies_detected": [],
                "vulnerabilities_found": 0,
                "links_discovered": 0
            },
            "vulnerabilities": {},
            "recommendations": [
                "🔄 Manual security review recommended",
                "🛡️ Implement comprehensive security testing",
                "📋 Regular security audits advised"
            ],
            "risk_level": "UNKNOWN",
            "risk_score": 0
        }


def handle_output(report_data, output_format: str, output_file: str = None, ai_enabled: bool = True):
    """Handle different output formats for reports."""
    if output_format == "console":
        if report_data:
            print(json.dumps(report_data, indent=2))
        else:
            print("No report data generated")
    elif output_format == "html" and output_file:
        save_report_as_html(report_data or {}, output_file, ai_enabled)
    elif output_format == "json" and output_file:
        save_report_as_json(report_data or {}, output_file)
    elif output_format == "text" and output_file:
        save_report_as_text(report_data or {}, output_file)
    else:
        print(f"⚠️ Unknown output format: {output_format}")
        if report_data:
            print(json.dumps(report_data, indent=2))


async def main():
    """Main entry point with enhanced configuration management"""
    parser = argparse.ArgumentParser(
        description="Intelligent Terminal AI - Execute commands with AI analysis and self-correction"
    )
    
    parser.add_argument(
        "command",
        nargs="?",
        help="Command to execute (if not provided, starts interactive mode)"
    )
    
    parser.add_argument(
        "--url",
        help="URL to test/analyze"
    )
    
    parser.add_argument(
        "--model",
        default=config.get("ai", "model"),
        help="AI model to use (gpt-4, claude-3-sonnet, gemini-pro, etc.)"
    )
    
    parser.add_argument(
        "--headless",
        action="store_true",
        default=config.get("browser", "headless"),
        help="Run browser in headless mode"
    )
    
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=config.get("session", "max_iterations"),
        help="Maximum number of self-correction iterations"
    )
    
    parser.add_argument(
        "--log-level",
        default=config.get("logging", "level"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )
    
    parser.add_argument(
        "--api-test",
        action="store_true",
        help="Treat the URL as an API endpoint to test"
    )
    
    parser.add_argument(
        "--method",
        default="GET",
        help="HTTP method for API testing (default: GET)"
    )
    
    parser.add_argument(
        "--pentest",
        action="store_true",
        help="Perform autonomous penetration testing on the URL"
    )
    
    parser.add_argument(
        "--visual-pentest",
        action="store_true",
        help="Perform real-time visual penetration testing with browser feedback"
    )
    
    parser.add_argument(
        "--intelligent-crawl",
        action="store_true", 
        help="Perform intelligent web crawling and feature-based testing"
    )
    
    parser.add_argument(
        "--advanced-crawl",
        action="store_true",
        help="Perform advanced AI-powered intelligent crawling with comprehensive vulnerability testing"
    )
    
    parser.add_argument(
        "--depth",
        type=int,
        default=3,
        help="Penetration testing depth (default: 3)"
    )
    
    # Enhanced configuration options
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)"
    )
    
    parser.add_argument(
        "--concurrent",
        type=int,
        default=5,
        help="Number of concurrent requests (default: 5)"
    )
    
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        default=True,
        help="Retry failed requests (default: True)"
    )
    
    parser.add_argument(
        "--save-screenshots",
        action="store_true",
        help="Save screenshots during scanning"
    )
    
    parser.add_argument(
        "--output-format",
        choices=["html", "json", "text", "console"],
        default="console",
        help="Output format for reports (default: console)"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logger(__name__, args.log_level)
    
    # Load environment variables for configuration
    os.environ.setdefault('BROWSER_TIMEOUT', str(args.timeout))
    os.environ.setdefault('CONCURRENT_REQUESTS', str(args.concurrent))
    os.environ.setdefault('RETRY_FAILED', str(args.retry_failed))
    os.environ.setdefault('SAVE_SCREENSHOTS', str(args.save_screenshots))
    
    # Handle visual pentest separately (doesn't need the full AI tool)
    if args.url and args.visual_pentest:
        logger.info("Starting visual autonomous penetration testing")
        visual_pentester = VisualPenTest()
        await visual_pentester.visual_pentest(args.url)
        return
    
    # Handle intelligent crawling separately
    if args.url and args.intelligent_crawl:
        logger.info("Starting intelligent web crawling and testing")
        crawler = IntelligentWebCrawler()  
        await crawler.intelligent_crawl_and_test(args.url)
        return
    
    # Handle advanced intelligent crawling
    if args.url and args.advanced_crawl:
        logger.info("Starting advanced AI-powered intelligent crawling")
        advanced_crawler = AdvancedIntelligentCrawler()
        await advanced_crawler.comprehensive_crawl_and_test(args.url)
        return
    
    try:
        # Initialize the AI tool for other operations
        async with IntelligentTerminalAI(
            ai_model=args.model,
            headless_browser=args.headless,
            log_level=args.log_level
        ) as ai_tool:
            
            if args.command and args.url:
                # Execute command and test URL
                logger.info("Executing command with URL testing")
                result = await ai_tool.execute_intelligent_command(
                    args.command,
                    target_url=args.url,
                    max_iterations=args.max_iterations
                )
                print_result(result)
                
            elif args.command:
                # Execute command only
                logger.info("Executing command")
                result = await ai_tool.execute_intelligent_command(
                    args.command,
                    max_iterations=args.max_iterations
                )
                print_result(result)
                
            elif args.url:
                # Test URL/API or run pentest
                if args.pentest:
                    logger.info("Starting autonomous penetration testing")
                    result = await ai_tool.autonomous_pentest(
                        args.url,
                        depth=args.depth
                    )
                    print_pentest_result(result)
                elif args.api_test:
                    logger.info("Testing API endpoint")
                    result = await ai_tool.test_api_endpoint(
                        args.url,
                        method=args.method
                    )
                    print_result(result)
                else:
                    logger.info("Testing URL")
                    result = await ai_tool.test_api_endpoint(args.url)
                    print_result(result)
                
            else:
                # Interactive pentest mode is the default
                logger.info("Starting interactive pentest mode")
                await interactive_pentest(logger)
    
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


def print_result(result):
    """Print analysis result in a formatted way"""
    
    print("\n" + "="*60)
    print("INTELLIGENT TERMINAL AI - ANALYSIS RESULT")
    print("="*60)
    
    status = "✅ SUCCESS" if result.success else "❌ FAILED"
    print(f"Status: {status}")
    print(f"Message: {result.message}")
    
    if hasattr(result, 'iterations_used') and result.iterations_used:
        print(f"Iterations: {result.iterations_used}")
    
    if hasattr(result, 'final_command') and result.final_command:
        print(f"Final Command: {result.final_command}")
    
    if result.suggestions:
        print("\n💡 SUGGESTIONS:")
        for i, suggestion in enumerate(result.suggestions, 1):
            print(f"  {i}. {suggestion}")
    
    if hasattr(result, 'analysis') and result.analysis:
        print(f"\n🔍 DETAILED ANALYSIS:")
        print(f"  {result.analysis}")
    
    print("="*60)


def print_pentest_result(result):
    """Print pentest result in a formatted way"""
    
    print("\n" + "="*70)
    print("🛡️  AUTONOMOUS PENETRATION TEST REPORT")
    print("="*70)
    
    print(f"🎯 Target: {result.get('target', 'Unknown')}")
    print(f"📊 Risk Score: {result.get('risk_score', 0)}/10")
    
    # Show phases completed
    phases = result.get('phases', [])
    print(f"\n📋 Phases Completed: {len(phases)}")
    for i, phase in enumerate(phases, 1):
        tests = len(phase.get('tests', []))
        findings = len(phase.get('findings', []))
        print(f"  {i}. {phase.get('name', 'Unknown Phase')} - {tests} tests, {findings} findings")
    
    # Show summary
    summary = result.get('summary', '')
    if summary:
        print(f"\n🤖 AI ANALYSIS:")
        print(f"  {summary}")
    
    # Show recommendations
    recommendations = result.get('recommendations', [])
    if recommendations:
        print(f"\n💡 RECOMMENDATIONS:")
        for i, rec in enumerate(recommendations[:5], 1):
            print(f"  {i}. {rec}")
    
    # Show error if any
    if 'error' in result:
        print(f"\n❌ ERROR: {result['error']}")
    
    print("="*70)
    print("📝 Full report saved to session history")
    print("="*70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Security Scanner - Comprehensive vulnerability testing with tree-like exploration")
    parser.add_argument("url", help="Target URL to test")
    parser.add_argument("--output", default="console", help="Output format: 'console' for terminal display, 'filename.html' for HTML report, 'filename.txt' for text report, 'filename.json' for JSON report")
    parser.add_argument("--ai", action="store_true", help="Enable AI-powered analysis (requires API key)")
    parser.add_argument("--no-ai", action="store_true", help="Explicitly disable AI analysis (default if no API key)")
    parser.add_argument("--gui", action="store_true", help="Launch web GUI interface on localhost:5000")
    
    # Enhanced configuration options
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("--concurrent", type=int, default=5, help="Number of concurrent requests (default: 5)")
    parser.add_argument("--retry-failed", action="store_true", default=True, help="Retry failed requests (default: True)")
    parser.add_argument("--save-screenshots", action="store_true", help="Save screenshots during scanning")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--depth", type=int, default=3, help="Scan depth (1=quick, 2=balanced, 3=comprehensive)")
    
    args = parser.parse_args()
    
    # Handle conflicting AI flags
    if args.ai and args.no_ai:
        print("❌ Error: Cannot specify both --ai and --no-ai flags")
        sys.exit(1)

    # Override AI configuration if specified
    if args.ai:
        print("🤖 AI Analysis: ENABLED by --ai flag")
        ai_enabled = True
        ai_policy.ENABLE_AI = True
    elif args.no_ai:
        print("🚫 AI Analysis: DISABLED by --no-ai flag")
        ai_enabled = False
        ai_policy.ENABLE_AI = False
    else:
        # Auto-detect based on API key availability
        try:
            provider = config.get("ai", "provider", "groq")
            provider_config = config.get("ai", provider, {})
            
            # Check for API key based on provider
            if provider == "groq":
                api_key = provider_config.get("api_key") or os.getenv("GROQ_API_KEY")
            elif provider == "gemini":
                api_key = provider_config.get("api_key") or os.getenv(provider_config.get("api_key_env", "GOOGLE_API_KEY"))
            elif provider == "openai":
                api_key = provider_config.get("api_key") or os.getenv(provider_config.get("api_key_env", "OPENAI_API_KEY"))
            elif provider == "anthropic":
                api_key = provider_config.get("api_key") or os.getenv(provider_config.get("api_key_env", "ANTHROPIC_API_KEY"))
            else:
                api_key = None
                
            ai_enabled = bool(api_key)
            if ai_enabled:
                print(f"🤖 AI Analysis: AUTO-ENABLED (found {provider.upper()} API key)")
            else:
                print("🚫 AI Analysis: AUTO-DISABLED (no API key found)")
        except Exception:
            ai_enabled = False
            print("🚫 AI Analysis: AUTO-DISABLED (configuration error)")

    # Launch GUI if requested
    if args.gui:
        print("🌐 Launching Web GUI...")
        print("=" * 50)
        try:
            from gui_app import main as gui_main
            gui_main()
        except ImportError as e:
            print(f"❌ Error: GUI dependencies not available: {e}")
            print("💡 Please install Flask: pip install flask")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error launching GUI: {e}")
            sys.exit(1)
        sys.exit(0)  # Exit after GUI is closed

    # Apply enhanced configuration
    os.environ.setdefault('BROWSER_TIMEOUT', str(args.timeout))
    os.environ.setdefault('CONCURRENT_REQUESTS', str(args.concurrent))
    os.environ.setdefault('RETRY_FAILED', str(args.retry_failed))
    os.environ.setdefault('SAVE_SCREENSHOTS', str(args.save_screenshots))
    os.environ.setdefault('HEADLESS_MODE', str(args.headless))
    os.environ.setdefault('SCAN_DEPTH', str(args.depth))

    logger = setup_logger("run")

    print("🛡️ ADVANCED SECURITY SCANNER")
    if ai_enabled:
        print("🤖 AI-powered comprehensive vulnerability testing with tree-like exploration")
    else:
        print("🔧 Comprehensive vulnerability testing with tree-like exploration")
    print("="*80)

    # Determine output format from filename extension
    output_format = "console"
    output_file = None
    
    if args.output != "console":
        output_file = args.output
        if output_file.endswith('.html'):
            output_format = "html"
        elif output_file.endswith('.json'):
            output_format = "json"
        elif output_file.endswith('.txt'):
            output_format = "text"
        else:
            # Default to text if no extension provided
            output_format = "text"
            if not output_file.endswith('.txt'):
                output_file += '.txt'
        
        print(f"📄 Output will be saved to: {output_file} (format: {output_format})")

    # Always run the advanced crawler - it's the best mode
    print("🚀 Running ADVANCED CRAWLER - Most comprehensive security testing available!")
    if ai_enabled:
        print("✨ Features: AI-powered analysis, deep vulnerability detection, tree-like exploration, live logging")
    else:
        print("✨ Features: Deep vulnerability detection, tree-like exploration, live logging, external scanner integration")
    
    # Initialize the advanced crawler with optional AI
    try:
        if ai_enabled:
            # Get AI configuration
            provider = config.get("ai", "provider", "groq")
            provider_config = config.get("ai", provider, {})
            
            # Determine model and API key based on provider
            if provider == "groq":
                model = f"groq-{provider_config.get('model', 'llama-3.1-8b-instant')}"
                api_key = provider_config.get("api_key") or os.getenv("GROQ_API_KEY")
            elif provider == "gemini":
                model = f"gemini-{provider_config.get('model', 'gemini-2.0-flash-exp')}"
                api_key = provider_config.get("api_key") or os.getenv(provider_config.get("api_key_env", "GOOGLE_API_KEY"))
            elif provider == "openai":
                model = provider_config.get("model", "gpt-4")
                api_key = provider_config.get("api_key") or os.getenv(provider_config.get("api_key_env", "OPENAI_API_KEY"))
            elif provider == "anthropic":
                model = provider_config.get("model", "claude-3-sonnet-20240229")
                api_key = provider_config.get("api_key") or os.getenv(provider_config.get("api_key_env", "ANTHROPIC_API_KEY"))
            
            print(f"🤖 AI Provider: {provider.upper()}")
            print(f"🧠 AI Model: {model}")
            
            if api_key:
                ai = AIAnalyzer(model=model, api_key=api_key, enable_ai=True)
                print("✅ AI Analysis: Enabled")
                crawler = AdvancedIntelligentCrawler(log_to_file=True, ai_analyzer=ai)
            else:
                print("⚠️  AI Analysis: Failed (no API key)")
                ai_enabled = False
                crawler = AdvancedIntelligentCrawler(log_to_file=True)
        else:
            crawler = AdvancedIntelligentCrawler(log_to_file=True)
    except Exception as e:
        print(f"⚠️  AI initialization failed: {e}")
        print("🔄 Running without AI analysis")
        ai_enabled = False
        crawler = AdvancedIntelligentCrawler(log_to_file=True)
        
    # Run the comprehensive crawler
    report = asyncio.run(crawler.comprehensive_crawl_and_test(args.url))
    handle_output(report, output_format, output_file, ai_enabled=ai_enabled)
