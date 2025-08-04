#!/usr/bin/env python3
"""
Test script to validate enhanced report generation with console analysis data
"""

import json
from report_generator import ReportGenerator
from run import convert_data_to_findings, parse_console_analysis_to_findings

def test_console_analysis_parsing():
    """Test parsing of the console analysis data provided by the user."""
    
    # Sample console analysis data from user's output
    console_analysis_sample = """
[AI] Console Analysis: ```json
{
  "risk_score": 6,
  "vulnerabilities": [
    {
      "type": "Content Security Policy (CSP) Bypass Potential",
      "description": "The CSP policy is extensive but not foolproof. The presence of numerous `*.domain.com` wildcards, particularly for services like Google, Yahoo, and Facebook, increases the attack surface. If any of these third-party services are compromised or allow user-generated content that can be controlled by an attacker (e.g., a vulnerable Yahoo subdomain allowing script injection), it could lead to XSS.",
      "severity": "Medium",
      "likelihood": "Low",
      "cvss_score": 6.5,
      "location": "CSP Header",
      "remediation": "Review and tighten CSP directives. Remove unnecessary wildcards and domains."
    },
    {
      "type": "Third-Party Dependency Risks",
      "description": "The site relies heavily on third-party JavaScript libraries and services (e.g., Intercom, Hotjar, Zendesk, Wistia, Google Analytics, etc.). Vulnerabilities in these libraries or services could be exploited to compromise the site. The version of these dependencies is unknown and may have security flaws.",
      "severity": "Medium",
      "likelihood": "Medium",
      "cvss_score": 5.8
    },
    {
      "type": "Information Disclosure (Potential)",
      "description": "The numerous AWS S3 buckets referenced in the CSP (e.g., `stable-production-v1-user-documents-bucket.s3.ap-southeast-1.amazonaws.com`) could potentially expose sensitive data if misconfigured with overly permissive access controls (e.g., publicly readable buckets).",       
      "severity": "Low",
      "likelihood": "Low",
      "cvss_score": 3.2
    }
  ],
  "recommendations": [
    {
      "area": "CSP Hardening",
      "recommendation": "Review and tighten the CSP policy. Avoid wildcard subdomains if possible, and explicitly list allowed origins.",
      "priority": "High"
    },
    {
      "area": "Third-Party Risk Management", 
      "recommendation": "Implement a robust third-party risk management program. Regularly audit third-party dependencies for known vulnerabilities.",
      "priority": "Medium"
    }
  ],
  "technologies": [
    "JavaScript",
    "AWS S3",
    "CDN (CloudFront)",
    "Twitter Ads",
    "Intercom",
    "Hotjar"
  ]
}
```
"""
    
    print("🧪 Testing Console Analysis Parsing...")
    
    # Test parsing console analysis
    findings = parse_console_analysis_to_findings(console_analysis_sample)
    
    print(f"✅ Extracted {len(findings)} findings from console analysis")
    
    for i, finding in enumerate(findings, 1):
        print(f"\n📋 Finding #{i}:")
        print(f"   Type: {finding['vulnerability_type']}")
        print(f"   Severity: {finding['severity']}")
        print(f"   Description: {finding['detailed_description'][:100]}...")
    
    return findings


def test_report_generation():
    """Test generating a professional report with the extracted findings."""
    
    print("\n🔧 Testing Professional Report Generation...")
    
    # Get findings from console analysis
    findings = test_console_analysis_parsing()
    
    # Create sample scan data
    scan_data = {
        "target_url": "https://www.syfe.com",
        "vulnerabilities": [
            {
                "type": "XSS (Low Probability)",
                "description": "The use of `swiper-bundle.min.js` raises a minor concern. While the library itself is generally safe, dynamically injecting content based on user input or external data, combined with the use of Swiper components, could potentially lead to XSS vulnerabilities if not handled carefully.",
                "location": "Potentially through dynamic content injection used by `swiper-bundle.min.js` components",
                "severity": "Low",
                "cvss_score": 3.5,
                "remediation": "Ensure all data passed to `swiper-bundle.min.js` and used for creating or modifying slides is properly sanitized and encoded."
            }
        ],
        "recommendations": [
            {
                "area": "Input Validation",
                "description": "Thoroughly validate and sanitize all user inputs, even those that appear to be indirectly used.",
                "priority": "High"
            }
        ]
    }
    
    # Convert to findings format
    additional_findings = convert_data_to_findings(scan_data)
    all_findings = findings + additional_findings
    
    # Create ReportGenerator and generate report
    try:
        generator = ReportGenerator(log_file_path="logs/crawler.log")
        
        report_path = generator.generate_html_report(
            final_findings=all_findings,
            target_url="https://www.syfe.com",
            output_filename="test_console_analysis_report.html"
        )
        
        print(f"\n✅ Professional report generated successfully!")
        print(f"📄 Report saved to: {report_path}")
        print(f"📊 Total findings included: {len(all_findings)}")
        
        # Show findings summary
        severity_count = {}
        for finding in all_findings:
            sev = finding.get('severity', 'Unknown')
            severity_count[sev] = severity_count.get(sev, 0) + 1
        
        print(f"\n📈 Findings Summary:")
        for severity, count in severity_count.items():
            print(f"   {severity}: {count}")
        
        return report_path
        
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        return None


def main():
    """Main test function."""
    print("🚀 Starting Console Analysis Report Generation Test")
    print("=" * 60)
    
    # Test parsing
    findings = test_console_analysis_parsing()
    
    if not findings:
        print("❌ No findings extracted from console analysis")
        return
    
    # Test report generation
    report_path = test_report_generation()
    
    if report_path:
        print(f"\n🎉 Test completed successfully!")
        print(f"🔗 Open the report: {report_path}")
    else:
        print(f"\n❌ Test failed during report generation")


if __name__ == "__main__":
    main()
