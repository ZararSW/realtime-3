#!/usr/bin/env python3
"""
Simple demo script for the Advanced Intelligent Crawler with WordPress capabilities
"""

import asyncio
import sys
from advanced_intelligent_crawler import AdvancedIntelligentCrawler

async def demo_wordpress_scanner():
    """Demo the WordPress scanning capabilities"""
    print("🚀 ADVANCED INTELLIGENT CRAWLER - WORDPRESS SCANNER DEMO")
    print("="*65)
    
    # Initialize crawler
    crawler = AdvancedIntelligentCrawler()
    
    try:
        # Setup browser
        print("🌐 Initializing advanced browser...")
        await crawler.setup_advanced_browser()
        
        # Test on a WordPress demo site
        target_url = "https://wordpress.com"
        print(f"\n🎯 Testing WordPress detection on: {target_url}")
        print("="*65)
        
        # Set target URL and domain
        crawler.target_url = target_url
        from urllib.parse import urlparse
        crawler.target_domain = urlparse(target_url).netloc
        
        # Run discovery phase
        print("\n🔍 Phase 1: Advanced Discovery & WordPress Detection")
        await crawler.advanced_discovery(target_url)
        
        # Show discovered technologies
        if crawler.discovered_assets['technologies']:
            print(f"\n✅ Technologies Detected: {', '.join(crawler.discovered_assets['technologies'])}")
        
        # Show WordPress specific findings
        if 'wordpress' in crawler.discovered_assets:
            wp_data = crawler.discovered_assets['wordpress']
            print(f"\n🎯 WordPress Details:")
            if wp_data.get('version'):
                print(f"  📋 Version: {wp_data['version']}")
            if wp_data.get('plugins'):
                print(f"  🔌 Plugins: {len(wp_data['plugins'])} found")
            if wp_data.get('themes'):
                print(f"  🎨 Themes: {len(wp_data['themes'])} found")
        
        # Quick vulnerability testing if WordPress detected
        if 'WordPress' in crawler.discovered_assets.get('technologies', set()):
            print(f"\n🧪 Phase 2: WordPress-Specific Security Testing")
            await crawler._test_wordpress_vulnerabilities()
        
        print(f"\n✅ Demo completed! WordPress scanning capabilities demonstrated.")
        print(f"📊 Full analysis found:")
        print(f"  • {len(crawler.discovered_assets.get('pages', {}))} pages analyzed")
        print(f"  • {len(crawler.discovered_assets.get('forms', {}))} forms discovered")
        print(f"  • {len(crawler.discovered_assets.get('vulnerabilities', {}))} vulnerabilities detected")
        
    except KeyboardInterrupt:
        print("\n⚠️ Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if crawler.driver:
            crawler.driver.quit()
            print("🔧 Browser closed")

def main():
    """Main entry point"""
    asyncio.run(demo_wordpress_scanner())

if __name__ == "__main__":
    main()
