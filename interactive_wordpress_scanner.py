#!/usr/bin/env python3
"""
Interactive WordPress Security Scanner
Enhanced version with custom target capability
"""

import asyncio
import sys
from advanced_intelligent_crawler import AdvancedIntelligentCrawler

async def interactive_wordpress_scanner():
    """Interactive WordPress security scanner"""
    print("🎯 INTERACTIVE WORDPRESS SECURITY SCANNER")
    print("🛡️ Professional-grade WordPress vulnerability assessment")
    print("="*65)
    
    # Get target from user
    target_url = input("\n🌐 Enter WordPress site URL to scan (or press Enter for demo): ").strip()
    
    if not target_url:
        target_url = "https://wordpress.com"
        print(f"🎮 Using demo target: {target_url}")
    elif not target_url.startswith(('http://', 'https://')):
        target_url = f"https://{target_url}"
        print(f"🔗 Auto-corrected URL: {target_url}")
    
    # Get scan depth
    print(f"\n📊 Select scan depth:")
    print(f"  1. Quick scan (Basic WordPress detection)")
    print(f"  2. Standard scan (Detection + vulnerability testing)")
    print(f"  3. Deep scan (Full security assessment)")
    
    depth_choice = input("Enter choice (1-3, default 2): ").strip() or "2"
    
    # Initialize crawler
    crawler = AdvancedIntelligentCrawler()
    
    try:
        print(f"\n🚀 Initializing advanced security scanner...")
        await crawler.setup_advanced_browser()
        
        print(f"🎯 Target: {target_url}")
        print(f"📈 Scan Depth: {'Quick' if depth_choice=='1' else 'Standard' if depth_choice=='2' else 'Deep'}")
        print("="*65)
        
        # Set target
        crawler.target_url = target_url
        from urllib.parse import urlparse
        crawler.target_domain = urlparse(target_url).netloc
        
        # Phase 1: Discovery (all scan types)
        print(f"\n🔍 PHASE 1: WordPress Detection & Discovery")
        await crawler.advanced_discovery(target_url)
        
        # Check if WordPress detected
        is_wordpress = 'WordPress' in crawler.discovered_assets.get('technologies', set())
        
        if not is_wordpress:
            print(f"\n❌ WordPress not detected on {target_url}")
            print(f"   Detected technologies: {', '.join(crawler.discovered_assets.get('technologies', ['None']))}")
            print(f"   This scanner is optimized for WordPress sites.")
            return
        
        # Display WordPress findings
        print(f"\n✅ WORDPRESS SITE CONFIRMED!")
        await display_wordpress_findings(crawler)
        
        # Phase 2: Vulnerability testing (Standard and Deep scans)
        if depth_choice in ['2', '3']:
            print(f"\n🧪 PHASE 2: WordPress Security Testing")
            await crawler._test_wordpress_vulnerabilities()
        
        # Phase 3: Additional security tests (Deep scan only)
        if depth_choice == '3':
            print(f"\n🔬 PHASE 3: Advanced Security Assessment")
            await crawler.intelligent_exploration()
            await crawler._test_forms_comprehensively()
        
        # Final report
        print(f"\n📋 FINAL SECURITY REPORT")
        await generate_security_report(crawler, depth_choice)
        
    except KeyboardInterrupt:
        print(f"\n⚠️ Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Scan error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if crawler.driver:
            crawler.driver.quit()
            print(f"🔧 Scanner closed")

async def display_wordpress_findings(crawler):
    """Display WordPress-specific findings"""
    wp_data = crawler.discovered_assets.get('wordpress', {})
    
    if wp_data.get('version'):
        print(f"  📋 Version: {wp_data['version']}")
    
    if wp_data.get('plugins'):
        print(f"  🔌 Plugins Found: {len(wp_data['plugins'])}")
        for plugin in wp_data['plugins'][:5]:  # Show first 5
            version = plugin.get('version', 'Unknown')
            print(f"     • {plugin['name']} ({version})")
    
    if wp_data.get('themes'):
        print(f"  🎨 Themes Found: {len(wp_data['themes'])}")
        for theme in wp_data['themes'][:3]:  # Show first 3
            version = theme.get('version', 'Unknown')
            print(f"     • {theme['name']} ({version})")
    
    if wp_data.get('interesting_files'):
        print(f"  📁 Interesting Files: {len(wp_data['interesting_files'])}")
        for file_info in wp_data['interesting_files'][:3]:
            print(f"     • {file_info['file']} ({file_info['status']})")

async def generate_security_report(crawler, scan_depth):
    """Generate comprehensive security report"""
    print("="*65)
    
    vulnerabilities = crawler.discovered_assets.get('vulnerabilities', {})
    pages_count = len(crawler.discovered_assets.get('pages', {}))
    forms_count = len(crawler.discovered_assets.get('forms', {}))
    
    # Risk calculation
    risk_score = calculate_risk_score(vulnerabilities)
    risk_level = get_risk_level(risk_score)
    
    print(f"🎯 SECURITY ASSESSMENT SUMMARY")
    print(f"  📊 Overall Risk Score: {risk_score}/10 ({risk_level})")
    print(f"  📄 Pages Analyzed: {pages_count}")
    print(f"  📝 Forms Discovered: {forms_count}")
    print(f"  🚨 Vulnerabilities: {len(vulnerabilities)}")
    
    if vulnerabilities:
        print(f"\n🚨 VULNERABILITIES DETECTED:")
        for vuln_type, vuln_data in vulnerabilities.items():
            severity = vuln_data.get('severity', 'unknown').upper()
            description = vuln_data.get('description', 'No description')
            print(f"  • {vuln_type.upper()}: {severity}")
            print(f"    {description}")
    
    print(f"\n💡 RECOMMENDATIONS:")
    recommendations = generate_recommendations(vulnerabilities, scan_depth)
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec}")
    
    print("="*65)

def calculate_risk_score(vulnerabilities):
    """Calculate overall risk score based on vulnerabilities"""
    if not vulnerabilities:
        return 2
    
    score = 3  # Base score
    severity_weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    
    for vuln_data in vulnerabilities.values():
        severity = vuln_data.get('severity', 'low')
        score += severity_weights.get(severity, 1)
    
    return min(score, 10)

def get_risk_level(score):
    """Convert risk score to risk level"""
    if score <= 3:
        return "LOW RISK"
    elif score <= 6:
        return "MEDIUM RISK"
    elif score <= 8:
        return "HIGH RISK"
    else:
        return "CRITICAL RISK"

def generate_recommendations(vulnerabilities, scan_depth):
    """Generate security recommendations based on findings"""
    recommendations = [
        "Update WordPress to the latest version",
        "Update all plugins and themes",
        "Implement strong password policies",
        "Enable two-factor authentication",
        "Install a security plugin (Wordfence, Sucuri)",
        "Regular security backups",
        "Use SSL/HTTPS for all connections"
    ]
    
    # Add specific recommendations based on vulnerabilities
    if 'xmlrpc_enabled' in vulnerabilities:
        recommendations.insert(0, "Disable XML-RPC interface if not needed")
    
    if 'user_enumeration' in vulnerabilities:
        recommendations.insert(0, "Implement user enumeration protection")
    
    if 'directory_listing' in vulnerabilities:
        recommendations.insert(0, "Disable directory listings")
    
    if scan_depth == '3':
        recommendations.extend([
            "Implement Web Application Firewall (WAF)",
            "Regular penetration testing",
            "Security headers implementation",
            "File permission hardening"
        ])
    
    return recommendations[:8]  # Return top 8 recommendations

def main():
    """Main entry point"""
    try:
        asyncio.run(interactive_wordpress_scanner())
    except KeyboardInterrupt:
        print(f"\n👋 Scanner terminated by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")

if __name__ == "__main__":
    main()
