#!/usr/bin/env python3
"""
Test the integration of ReportGenerator with the main application
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from run import save_report_as_html, convert_data_to_findings, extract_target_url

def test_report_generation():
    """Test the report generation with sample data"""
    print("🧪 Testing Professional Report Generation Integration")
    print("=" * 60)
    
    # Sample data that mimics what the scanners would produce
    sample_data = {
        'target_url': 'https://example.com',
        'vulnerabilities': {
            'xss_reflected': {
                'found': True,
                'description': 'Reflected XSS vulnerability in search parameter',
                'impact': 'Session hijacking and data theft possible',
                'remediation': 'Implement proper input validation and output encoding',
                'payload': '<script>alert("XSS")</script>',
                'evidence': 'JavaScript alert triggered successfully'
            },
            'sql_injection': {
                'found': True,
                'description': 'SQL injection in login form',
                'impact': 'Database compromise and data breach',
                'remediation': 'Use parameterized queries and input validation',
                'payload': "' OR '1'='1' --",
                'evidence': 'Database error messages revealed structure'
            }
        },
        'ai_analysis': {
            'risk_score': 8.5,
            'summary': 'Multiple high-severity vulnerabilities detected',
            'vulnerabilities': [
                {
                    'type': 'Authentication Bypass',
                    'severity': 'Critical',
                    'description': 'Weak authentication mechanism allows bypass',
                    'business_impact': 'Unauthorized access to sensitive data',
                    'remediation': 'Implement multi-factor authentication',
                    'evidence': 'Login bypass confirmed through testing'
                }
            ]
        },
        'security_tests': {
            'csrf_test': {
                'vulnerable': True,
                'description': 'CSRF vulnerability in form submission',
                'remediation': 'Implement CSRF tokens',
                'payload': 'Forged request submitted successfully',
                'evidence': 'State-changing request executed without token'
            }
        },
        'scan_info': {
            'start_time': '2025-07-31 10:00:00',
            'end_time': '2025-07-31 10:30:00',
            'pages_scanned': 15,
            'total_requests': 250
        }
    }
    
    # Test the conversion functions
    print("🔍 Testing data conversion...")
    findings = convert_data_to_findings(sample_data)
    print(f"   ✅ Converted {len(findings)} findings")
    
    target_url = extract_target_url(sample_data)
    print(f"   ✅ Extracted target URL: {target_url}")
    
    # Test report generation
    print("\n📊 Testing report generation...")
    output_file = "test_professional_report.html"
    
    try:
        save_report_as_html(sample_data, output_file)
        
        # Check if file was created
        if os.path.exists(output_file):
            file_size = os.path.getsize(output_file)
            print(f"   ✅ Report generated successfully!")
            print(f"   📄 File: {output_file}")
            print(f"   📏 Size: {file_size:,} bytes")
            
            # Show first few lines to verify it's HTML
            with open(output_file, 'r', encoding='utf-8') as f:
                first_lines = [f.readline().strip() for _ in range(3)]
                print(f"   🔍 Content preview: {first_lines[0]}")
        else:
            print("   ❌ Report file was not created")
            
    except Exception as e:
        print(f"   ❌ Error generating report: {e}")
    
    print("\n" + "=" * 60)
    print("🎯 Test completed! Check the generated HTML file.")
    print(f"   Open in browser: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    test_report_generation()
