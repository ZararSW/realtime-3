"""
Response inspector for detailed analysis of web and API responses
"""

import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs

from ..utils.logger import setup_logger


class ResponseInspector:
    """
    Inspects and analyzes HTTP responses, HTML content, and API data
    """
    
    def __init__(self):
        self.logger = setup_logger(__name__)
    
    def inspect_http_response(self, 
                            response_text: str,
                            headers: Dict[str, str],
                            status_code: int,
                            url: str) -> Dict[str, Any]:
        """
        Inspect an HTTP response for detailed analysis
        
        Args:
            response_text: Response body text
            headers: Response headers
            status_code: HTTP status code
            url: Request URL
            
        Returns:
            Dictionary with detailed inspection results
        """
        self.logger.info(f"Inspecting HTTP response for {url}")
        
        inspection = {
            "url": url,
            "status_code": status_code,
            "headers": headers,
            "content_analysis": {},
            "security_analysis": {},
            "performance_analysis": {},
            "issues": [],
            "recommendations": []
        }
        
        # Analyze content type and structure
        content_type = headers.get('content-type', '').lower()
        inspection["content_analysis"] = self._analyze_content(response_text, content_type)
        
        # Security analysis
        inspection["security_analysis"] = self._analyze_security_headers(headers)
        
        # Performance analysis
        inspection["performance_analysis"] = self._analyze_performance(headers, response_text)
        
        # Find issues and provide recommendations
        inspection["issues"] = self._find_issues(inspection)
        inspection["recommendations"] = self._generate_recommendations(inspection)
        
        return inspection
    
    def _analyze_content(self, content: str, content_type: str) -> Dict[str, Any]:
        """Analyze response content based on type"""
        
        analysis = {
            "type": content_type,
            "size": len(content),
            "structure": {},
            "validation": {}
        }
        
        if "json" in content_type:
            analysis["structure"] = self._analyze_json(content)
        elif "xml" in content_type:
            analysis["structure"] = self._analyze_xml(content)
        elif "html" in content_type:
            analysis["structure"] = self._analyze_html(content)
        else:
            analysis["structure"] = self._analyze_text(content)
        
        return analysis
    
    def _analyze_json(self, content: str) -> Dict[str, Any]:
        """Analyze JSON content"""
        
        try:
            data = json.loads(content)
            
            return {
                "valid": True,
                "type": type(data).__name__,
                "keys": list(data.keys()) if isinstance(data, dict) else None,
                "length": len(data) if isinstance(data, (list, dict)) else None,
                "nested_levels": self._count_json_depth(data),
                "has_errors": self._check_json_errors(data)
            }
        except json.JSONDecodeError as e:
            return {
                "valid": False,
                "error": str(e),
                "type": "invalid_json"
            }
    
    def _analyze_xml(self, content: str) -> Dict[str, Any]:
        """Analyze XML content"""
        
        try:
            root = ET.fromstring(content)
            
            return {
                "valid": True,
                "root_tag": root.tag,
                "children_count": len(root),
                "namespaces": list(root.nsmap.keys()) if hasattr(root, 'nsmap') else [],
                "depth": self._count_xml_depth(root)
            }
        except ET.ParseError as e:
            return {
                "valid": False,
                "error": str(e),
                "type": "invalid_xml"
            }
    
    def _analyze_html(self, content: str) -> Dict[str, Any]:
        """Analyze HTML content"""
        
        # Basic HTML analysis using regex (for simplicity)
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else ""
        
        # Count elements
        links = len(re.findall(r'<a\s+[^>]*href', content, re.IGNORECASE))
        images = len(re.findall(r'<img\s+[^>]*src', content, re.IGNORECASE))
        forms = len(re.findall(r'<form\s+[^>]*>', content, re.IGNORECASE))
        scripts = len(re.findall(r'<script\s+[^>]*>', content, re.IGNORECASE))
        
        # Check for common issues
        has_doctype = content.strip().lower().startswith('<!doctype')
        has_meta_charset = 'charset=' in content.lower()
        has_viewport = 'viewport' in content.lower()
        
        return {
            "valid": True,
            "title": title,
            "elements": {
                "links": links,
                "images": images,
                "forms": forms,
                "scripts": scripts
            },
            "meta_info": {
                "has_doctype": has_doctype,
                "has_charset": has_meta_charset,
                "has_viewport": has_viewport
            }
        }
    
    def _analyze_text(self, content: str) -> Dict[str, Any]:
        """Analyze plain text content"""
        
        lines = content.split('\n')
        words = content.split()
        
        return {
            "valid": True,
            "lines": len(lines),
            "words": len(words),
            "characters": len(content),
            "encoding": "utf-8",  # Assumed
            "empty_lines": sum(1 for line in lines if not line.strip())
        }
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security-related headers"""
        
        security_headers = {
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-frame-options': 'Clickjacking protection',
            'x-content-type-options': 'MIME sniffing protection',
            'x-xss-protection': 'XSS protection',
            'referrer-policy': 'Referrer policy'
        }
        
        analysis = {
            "present_headers": [],
            "missing_headers": [],
            "security_score": 0
        }
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, description in security_headers.items():
            if header in headers_lower:
                analysis["present_headers"].append({
                    "header": header,
                    "value": headers_lower[header],
                    "description": description
                })
                analysis["security_score"] += 1
            else:
                analysis["missing_headers"].append({
                    "header": header,
                    "description": description
                })
        
        analysis["security_score"] = analysis["security_score"] / len(security_headers) * 100
        
        return analysis
    
    def _analyze_performance(self, headers: Dict[str, str], content: str) -> Dict[str, Any]:
        """Analyze performance-related aspects"""
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        analysis = {
            "content_size": len(content),
            "compression": {},
            "caching": {},
            "recommendations": []
        }
        
        # Check compression
        encoding = headers_lower.get('content-encoding', '')
        analysis["compression"] = {
            "enabled": bool(encoding),
            "type": encoding,
            "estimated_savings": self._estimate_compression_savings(content) if not encoding else 0
        }
        
        # Check caching headers
        cache_control = headers_lower.get('cache-control', '')
        etag = headers_lower.get('etag', '')
        expires = headers_lower.get('expires', '')
        
        analysis["caching"] = {
            "cache_control": cache_control,
            "etag": bool(etag),
            "expires": bool(expires),
            "cacheable": bool(cache_control or etag or expires)
        }
        
        # Performance recommendations
        if not encoding and len(content) > 1000:
            analysis["recommendations"].append("Enable compression (gzip/brotli)")
        
        if not analysis["caching"]["cacheable"]:
            analysis["recommendations"].append("Add caching headers for better performance")
        
        if len(content) > 100000:
            analysis["recommendations"].append("Consider reducing response size")
        
        return analysis
    
    def _find_issues(self, inspection: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find potential issues in the response"""
        
        issues = []
        
        # Status code issues
        status_code = inspection["status_code"]
        if status_code >= 400:
            issues.append({
                "type": "http_error",
                "severity": "high" if status_code >= 500 else "medium",
                "message": f"HTTP error status: {status_code}",
                "recommendation": "Check server logs and fix the underlying issue"
            })
        
        # Content issues
        content_analysis = inspection["content_analysis"]
        if not content_analysis.get("structure", {}).get("valid", True):
            issues.append({
                "type": "content_error",
                "severity": "high",
                "message": "Invalid content format",
                "recommendation": "Fix content syntax and structure"
            })
        
        # Security issues
        security_analysis = inspection["security_analysis"]
        if security_analysis["security_score"] < 50:
            issues.append({
                "type": "security",
                "severity": "medium",
                "message": f"Low security score: {security_analysis['security_score']:.1f}%",
                "recommendation": "Add missing security headers"
            })
        
        # Performance issues
        performance = inspection["performance_analysis"]
        if performance["content_size"] > 1000000:  # 1MB
            issues.append({
                "type": "performance",
                "severity": "medium",
                "message": "Large response size",
                "recommendation": "Consider pagination or data reduction"
            })
        
        return issues
    
    def _generate_recommendations(self, inspection: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on inspection results"""
        
        recommendations = []
        
        # Add specific recommendations from sub-analyses
        performance_recs = inspection["performance_analysis"].get("recommendations", [])
        recommendations.extend(performance_recs)
        
        # Add security recommendations
        missing_headers = inspection["security_analysis"]["missing_headers"]
        if missing_headers:
            recommendations.append(f"Add security headers: {', '.join([h['header'] for h in missing_headers[:3]])}")
        
        # Add content recommendations
        content_structure = inspection["content_analysis"].get("structure", {})
        if content_structure.get("has_errors"):
            recommendations.append("Review and fix data structure errors")
        
        return recommendations
    
    def _count_json_depth(self, obj, depth=0) -> int:
        """Count maximum depth of JSON object"""
        if isinstance(obj, dict):
            return max([self._count_json_depth(v, depth + 1) for v in obj.values()], default=depth)
        elif isinstance(obj, list):
            return max([self._count_json_depth(item, depth + 1) for item in obj], default=depth)
        else:
            return depth
    
    def _count_xml_depth(self, element, depth=0) -> int:
        """Count maximum depth of XML element"""
        if len(element) == 0:
            return depth
        return max([self._count_xml_depth(child, depth + 1) for child in element])
    
    def _check_json_errors(self, data) -> bool:
        """Check for common error indicators in JSON"""
        if isinstance(data, dict):
            error_keys = ['error', 'errors', 'message', 'exception', 'status']
            return any(key in data for key in error_keys)
        return False
    
    def _estimate_compression_savings(self, content: str) -> int:
        """Estimate potential compression savings"""
        # Simple estimation based on repeated patterns
        unique_chars = len(set(content))
        total_chars = len(content)
        
        if total_chars == 0:
            return 0
        
        # Rough estimation: more repetitive content compresses better
        repetition_ratio = 1 - (unique_chars / total_chars)
        estimated_savings = min(int(repetition_ratio * 70), 90)  # Max 90% savings
        
        return estimated_savings
