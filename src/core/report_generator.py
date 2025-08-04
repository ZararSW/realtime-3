"""
Production-grade report generator for Advanced Intelligent Web Crawler
Generates structured, AI-augmented, and privacy-aware reports
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from .logger import Logger
from .ai_analyzer import AIAnalyzer

class ReportGenerator:
    """
    Generates structured reports with optional AI summary and privacy filtering
    """
    def __init__(self, config, logger: Logger, ai_analyzer: AIAnalyzer):
        self.config = config
        self.logger = logger
        self.ai_analyzer = ai_analyzer

    def generate_report(self, target_url: str, findings: List[Dict[str, Any]],
                       vulnerabilities: List[Dict[str, Any]],
                       ai_summaries: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate a structured report dictionary"""
        report = {
            'target_url': target_url,
            'timestamp': datetime.utcnow().isoformat(),
            'findings': findings,
            'vulnerabilities': vulnerabilities,
            'ai_summaries': ai_summaries or [],
            'config': self.config.to_dict() if hasattr(self.config, 'to_dict') else {},
        }
        return report

    def save_report(self, report: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Save report to file in configured format"""
        if not filename:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{timestamp}.{self.config.output.report_format}"
        path = f"{self.config.output.report_path}/{filename}"
        try:
            with open(path, 'w', encoding='utf-8') as f:
                if self.config.output.report_format == 'json':
                    json.dump(report, f, indent=2)
                else:
                    f.write(str(report))
            self.logger.info(f"Report saved: {path}", 'report_generator')
            return path
        except Exception as e:
            self.logger.error(f"Failed to save report: {e}", 'report_generator')
            return ""

    async def generate_ai_summary(self, findings: List[Dict[str, Any]],
                                 vulnerabilities: List[Dict[str, Any]],
                                 target_url: str) -> Dict[str, Any]:
        """Generate an AI-powered summary for the report"""
        content = json.dumps({
            'findings': findings,
            'vulnerabilities': vulnerabilities,
            'target_url': target_url
        }, default=str)
        ai_result = await self.ai_analyzer.analyze_content(content, context="report", target_url=target_url)
        return ai_result.__dict__ 