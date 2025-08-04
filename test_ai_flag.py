#!/usr/bin/env python3
"""
Test script to verify AI flag handling in reports
"""

from report_generator import ReportGenerator

def test_ai_flag():
    """Test that AI flag correctly changes report content."""
    
    # Sample findings
    sample_findings = [
        {
            'vulnerability_type': 'Cross-Site Scripting (XSS)',
            'severity': 'High',
            'detailed_description': 'XSS vulnerability found in search parameter',
            'business_impact': 'Could lead to session hijacking',
            'remediation_steps': 'Implement input validation',
            'payload_used': '<script>alert("xss")</script>',
            'evidence': 'Script executed successfully'
        }
    ]
    
    print("🧪 Testing AI-enabled report...")
    # Test with AI enabled
    generator_ai = ReportGenerator(ai_enabled=True)
    ai_report = generator_ai.generate_html_report(
        final_findings=sample_findings,
        target_url="https://example.com",
        output_filename="test_ai_enabled_report.html"
    )
    print(f"✅ AI-enabled report: {ai_report}")
    
    print("\n🧪 Testing AI-disabled report...")
    # Test with AI disabled
    generator_no_ai = ReportGenerator(ai_enabled=False)
    no_ai_report = generator_no_ai.generate_html_report(
        final_findings=sample_findings,
        target_url="https://example.com", 
        output_filename="test_ai_disabled_report.html"
    )
    print(f"✅ AI-disabled report: {no_ai_report}")
    
    print("\n📋 Check the generated reports:")
    print("- test_ai_enabled_report.html should show 'AI-Enhanced' and '🤖 AI Triage Analysis'")
    print("- test_ai_disabled_report.html should show 'Standard' and '🔍 Security Analysis'")

if __name__ == "__main__":
    test_ai_flag()
