"""
CLI entry point for Advanced Intelligent Web Crawler
"""

import asyncio
import sys
from core.config import Config
from core.crawler import AdvancedIntelligentCrawler

def main():
    config, target_url = Config.from_cli_args()
    crawler = AdvancedIntelligentCrawler(config)
    asyncio.run(crawler.run(target_url))

if __name__ == "__main__":
    main() 