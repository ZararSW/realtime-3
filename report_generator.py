#!/usr/bin/env python3
"""
Professional Report Generator for Autonomous Penetration Testing
Creates comprehensive HTML reports with data visualization and detailed analysis
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
import html


class ReportGenerator:
    """
    Professional HTML report generator for penetration testing results.
    
    Features:
    - Responsive design with Tailwind CSS
    - Interactive vulnerability severity charts
    - Detailed findings with AI triage analysis
    - Collapsible full scan logs
    - Professional styling and layout
    """
    
    def __init__(self, log_file_path: Optional[str] = None, ai_enabled: bool = True):
        """
        Initialize the ReportGenerator.
        
        Args:
            log_file_path (Optional[str]): Path to the log file to include in the report
            ai_enabled (bool): Whether AI analysis was used in the scan
        """
        self.log_file_path = log_file_path
        self.log_content = ""
        self.ai_enabled = ai_enabled
        
    def generate_html_report(self, final_findings: List[Dict], target_url: str, output_filename: str) -> str:
        """
        Generate a comprehensive HTML report from penetration test findings.
        
        Args:
            final_findings (List[Dict]): List of vulnerability findings with details
            target_url (str): Target URL that was tested
            output_filename (str): Path where the HTML report will be saved
            
        Returns:
            str: Path to the generated HTML report file
            
        Raises:
            IOError: If unable to write the report file
        """
        try:
            # Read log content if log file path is provided
            if self.log_file_path:
                self._read_logs()
            
            # Build the complete HTML report
            html_content = self._build_html(final_findings, target_url)
            
            # Ensure output directory exists
            output_path = Path(output_filename)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write the HTML file
            with open(output_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return output_filename
            
        except Exception as e:
            raise IOError(f"Failed to generate HTML report: {str(e)}")
    
    def _read_logs(self) -> None:
        """
        Read the entire content of the log file specified in the constructor.
        Handles FileNotFoundError gracefully.
        """
        try:
            if self.log_file_path and os.path.exists(self.log_file_path):
                with open(self.log_file_path, 'r', encoding='utf-8') as f:
                    self.log_content = f.read()
            else:
                self.log_content = "Log file not found or not specified."
        except FileNotFoundError:
            self.log_content = f"Log file not found: {self.log_file_path}"
        except Exception as e:
            self.log_content = f"Error reading log file: {str(e)}"
    
    def _build_html(self, final_findings: List[Dict], target_url: str) -> str:
        """
        Construct the complete HTML document as a string.
        
        Args:
            final_findings (List[Dict]): List of vulnerability findings
            target_url (str): Target URL that was tested
            
        Returns:
            str: Complete HTML document
        """
        # Generate vulnerability statistics
        severity_stats = self._generate_severity_stats(final_findings)
        total_vulns = len(final_findings)
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {html.escape(target_url)}</title>
    
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <style>
        body {{
            font-family: 'Inter', sans-serif;
        }}
        .severity-critical {{
            @apply bg-red-100 text-red-800 border-red-200;
        }}
        .severity-high {{
            @apply bg-orange-100 text-orange-800 border-orange-200;
        }}
        .severity-medium {{
            @apply bg-yellow-100 text-yellow-800 border-yellow-200;
        }}
        .severity-low {{
            @apply bg-green-100 text-green-800 border-green-200;
        }}
        .severity-info {{
            @apply bg-blue-100 text-blue-800 border-blue-200;
        }}
    </style>
</head>
<body class="bg-slate-50 min-h-screen">
    <!-- Header Section -->
    <header class="bg-gradient-to-r from-slate-900 to-slate-700 text-white shadow-lg">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div class="text-center">
                <h1 class="text-4xl font-bold mb-2">🛡️ Penetration Test Report</h1>
                <p class="text-xl text-slate-300 mb-4">{'AI-Powered ' if self.ai_enabled else ''}Security Assessment Results</p>
                <div class="bg-slate-800 rounded-lg p-4 inline-block">
                    <p class="text-lg"><span class="font-semibold">Target:</span> {html.escape(target_url)}</p>
                    <p class="text-sm text-slate-400">Generated: {timestamp}</p>
                    <p class="text-sm text-slate-400">Analysis Type: {'AI-Enhanced' if self.ai_enabled else 'Standard'} Security Scan</p>
                </div>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Executive Summary -->
        <section class="mb-12">
            <div class="bg-white rounded-xl shadow-lg p-8">
                <h2 class="text-3xl font-bold text-slate-900 mb-6 flex items-center">
                    📊 Executive Summary
                </h2>
                
                <div class="grid md:grid-cols-2 gap-8">
                    <!-- Key Metrics -->
                    <div>
                        <h3 class="text-xl font-semibold text-slate-800 mb-4">Key Metrics</h3>
                        <div class="space-y-4">
                            <div class="bg-slate-50 rounded-lg p-4">
                                <div class="flex justify-between items-center">
                                    <span class="text-slate-600">Total Vulnerabilities Found</span>
                                    <span class="text-2xl font-bold text-slate-900">{total_vulns}</span>
                                </div>
                            </div>
                            {self._generate_severity_metrics_html(severity_stats)}
                        </div>
                    </div>
                    
                    <!-- Vulnerability Distribution Chart -->
                    <div>
                        <h3 class="text-xl font-semibold text-slate-800 mb-4">Vulnerability Distribution</h3>
                        <div class="bg-slate-50 rounded-lg p-4">
                            <canvas id="severityChart" width="300" height="300"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Detailed Findings -->
        <section class="mb-12">
            <div class="bg-white rounded-xl shadow-lg p-8">
                <h2 class="text-3xl font-bold text-slate-900 mb-6 flex items-center">
                    🔍 Detailed Findings
                </h2>
                
                {self._generate_findings_html(final_findings)}
            </div>
        </section>

        <!-- Full Execution Logs -->
        <section class="mb-8">
            <div class="bg-white rounded-xl shadow-lg">
                <div class="p-8">
                    <h2 class="text-3xl font-bold text-slate-900 mb-6 flex items-center">
                        📋 Full Scan Logs
                    </h2>
                    
                    <!-- Collapsible Accordion -->
                    <div class="border border-slate-200 rounded-lg">
                        <button 
                            class="w-full px-6 py-4 text-left bg-slate-50 hover:bg-slate-100 rounded-t-lg focus:outline-none focus:ring-2 focus:ring-sky-500 transition-colors"
                            onclick="toggleLogs()"
                            id="logsToggle"
                        >
                            <div class="flex justify-between items-center">
                                <span class="text-lg font-semibold text-slate-800">Show Full Scan Logs</span>
                                <svg class="w-5 h-5 text-slate-600 transform transition-transform" id="logsIcon">
                                    <path stroke="currentColor" stroke-width="2" d="M19 9l-7 7-7-7"/>
                                </svg>
                            </div>
                        </button>
                        
                        <div id="logsContent" class="hidden border-t border-slate-200">
                            <div class="p-6">
                                <pre class="bg-slate-900 text-green-400 p-4 rounded-lg overflow-x-auto text-sm font-mono max-h-96 overflow-y-auto"><code>{html.escape(self.log_content)}</code></pre>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <!-- Footer -->
    <footer class="bg-slate-900 text-white py-6">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
            <p class="text-slate-400">Generated by {'AI-Enhanced ' if self.ai_enabled else ''}Autonomous Penetration Testing Tool</p>
        </div>
    </footer>

    <!-- JavaScript -->
    <script>
        // Severity Chart Configuration
        const ctx = document.getElementById('severityChart').getContext('2d');
        const severityData = {json.dumps(severity_stats)};
        
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: Object.keys(severityData),
                datasets: [{{
                    data: Object.values(severityData),
                    backgroundColor: [
                        '#DC2626', // Critical - Red
                        '#EA580C', // High - Orange
                        '#D97706', // Medium - Yellow
                        '#16A34A', // Low - Green
                        '#2563EB'  // Info - Blue
                    ],
                    borderWidth: 2,
                    borderColor: '#FFFFFF'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            padding: 20,
                            usePointStyle: true
                        }}
                    }},
                    tooltip: {{
                        callbacks: {{
                            label: function(context) {{
                                const label = context.label || '';
                                const value = context.parsed;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${{label}}: ${{value}} (${{percentage}}%)`;
                            }}
                        }}
                    }}
                }}
            }}
        }});

        // Logs Toggle Functionality
        function toggleLogs() {{
            const content = document.getElementById('logsContent');
            const icon = document.getElementById('logsIcon');
            const toggle = document.getElementById('logsToggle');
            
            if (content.classList.contains('hidden')) {{
                content.classList.remove('hidden');
                icon.style.transform = 'rotate(180deg)';
                toggle.querySelector('span').textContent = 'Hide Full Scan Logs';
            }} else {{
                content.classList.add('hidden');
                icon.style.transform = 'rotate(0deg)';
                toggle.querySelector('span').textContent = 'Show Full Scan Logs';
            }}
        }}
    </script>
</body>
</html>"""

        return html_content
    
    def _generate_severity_stats(self, findings: List[Dict]) -> Dict[str, int]:
        """
        Generate vulnerability statistics by severity level.
        
        Args:
            findings (List[Dict]): List of vulnerability findings
            
        Returns:
            Dict[str, int]: Count of vulnerabilities by severity
        """
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for finding in findings:
            # Extract severity from CVSS score or severity field
            severity = self._determine_severity(finding)
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Remove categories with zero count for cleaner chart
        return {k: v for k, v in severity_counts.items() if v > 0}
    
    def _determine_severity(self, finding: Dict) -> str:
        """
        Determine the severity level of a finding based on CVSS score or other indicators.
        
        Args:
            finding (Dict): Individual vulnerability finding
            
        Returns:
            str: Severity level (Critical, High, Medium, Low, Info)
        """
        # Check for explicit severity field
        if 'severity' in finding:
            return finding['severity'].title()
        
        # Check for CVSS score
        if 'cvss_score' in finding:
            score = finding['cvss_score']
            if isinstance(score, (int, float)):
                if score >= 9.0:
                    return 'Critical'
                elif score >= 7.0:
                    return 'High'
                elif score >= 4.0:
                    return 'Medium'
                elif score >= 0.1:
                    return 'Low'
        
        # Check vulnerability type for default severity
        vuln_type = finding.get('vulnerability_type', '').lower()
        if any(term in vuln_type for term in ['xss', 'injection', 'rce', 'command']):
            return 'High'
        elif any(term in vuln_type for term in ['disclosure', 'exposure']):
            return 'Medium'
        
        return 'Info'
    
    def _generate_severity_metrics_html(self, severity_stats: Dict[str, int]) -> str:
        """
        Generate HTML for severity metrics display.
        
        Args:
            severity_stats (Dict[str, int]): Vulnerability counts by severity
            
        Returns:
            str: HTML content for severity metrics
        """
        severity_colors = {
            'Critical': 'bg-red-100 text-red-800',
            'High': 'bg-orange-100 text-orange-800',
            'Medium': 'bg-yellow-100 text-yellow-800',
            'Low': 'bg-green-100 text-green-800',
            'Info': 'bg-blue-100 text-blue-800'
        }
        
        html_parts = []
        for severity, count in severity_stats.items():
            color_class = severity_colors.get(severity, 'bg-gray-100 text-gray-800')
            html_parts.append(f"""
            <div class="bg-slate-50 rounded-lg p-4">
                <div class="flex justify-between items-center">
                    <div class="flex items-center space-x-2">
                        <span class="px-2 py-1 rounded-full text-xs font-medium {color_class}">{severity}</span>
                    </div>
                    <span class="text-xl font-bold text-slate-900">{count}</span>
                </div>
            </div>
            """)
        
        return ''.join(html_parts)
    
    def _generate_findings_html(self, findings: List[Dict]) -> str:
        """
        Generate HTML content for detailed vulnerability findings.
        
        Args:
            findings (List[Dict]): List of vulnerability findings
            
        Returns:
            str: HTML content for findings section
        """
        if not findings:
            return """
            <div class="text-center py-12">
                <div class="text-6xl mb-4">🎉</div>
                <h3 class="text-xl font-semibold text-slate-800 mb-2">No Vulnerabilities Found</h3>
                <p class="text-slate-600">The security assessment completed successfully with no significant vulnerabilities detected.</p>
            </div>
            """
        
        # Sort findings by severity for better presentation
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(self._determine_severity(x), 5))
        
        findings_html = []
        for i, finding in enumerate(sorted_findings, 1):
            findings_html.append(self._generate_single_finding_html(finding, i))
        
        return ''.join(findings_html)
    
    def _generate_single_finding_html(self, finding: Dict, index: int) -> str:
        """
        Generate HTML for a single vulnerability finding card.
        
        Args:
            finding (Dict): Individual vulnerability finding
            index (int): Finding number/index
            
        Returns:
            str: HTML content for single finding card
        """
        # Extract finding details with safe defaults
        vuln_type = finding.get('vulnerability_type', 'Unknown Vulnerability')
        severity = self._determine_severity(finding)
        cvss_score = finding.get('cvss_score', 'N/A')
        
        # AI Triage Analysis
        detailed_description = finding.get('detailed_description', 'No detailed description available.')
        business_impact = finding.get('business_impact', 'Business impact assessment not available.')
        remediation_steps = finding.get('remediation_steps', 'Remediation steps not provided.')
        
        # Technical Details
        payload_used = finding.get('payload_used', 'No payload information available.')
        evidence = finding.get('evidence', 'No evidence details provided.')
        location = finding.get('location', finding.get('payload_used', 'N/A'))
        cwe_id = finding.get('cwe', 'N/A')
        likelihood = finding.get('likelihood', 'Unknown')
        
        # Severity badge styling
        severity_class = f"severity-{severity.lower()}"
        
        # Generate CVSS score display
        cvss_display = f" (CVSS: {cvss_score})" if cvss_score != 'N/A' else ""
        
        # Generate CWE badge if available
        cwe_badge = f"""
        <span class="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs font-mono">
            {cwe_id}
        </span>
        """ if cwe_id != 'N/A' else ""
        
        # Generate likelihood badge if available
        likelihood_badge = f"""
        <span class="px-2 py-1 bg-blue-100 text-blue-700 rounded text-xs">
            Likelihood: {likelihood}
        </span>
        """ if likelihood != 'Unknown' else ""
        
        return f"""
        <div class="mb-8 border border-slate-200 rounded-xl overflow-hidden">
            <!-- Finding Header -->
            <div class="bg-slate-50 px-6 py-4 border-b border-slate-200">
                <div class="flex justify-between items-start">
                    <div class="flex-1">
                        <h3 class="text-xl font-semibold text-slate-900 mb-2">
                            #{index}. {html.escape(vuln_type)}
                        </h3>
                        <div class="flex flex-wrap items-center gap-2">
                            <p class="text-slate-600">{'AI-Powered ' if self.ai_enabled else ''}Vulnerability Assessment Finding</p>
                            {cwe_badge}
                            {likelihood_badge}
                        </div>
                    </div>
                    <div class="text-right">
                        <span class="px-3 py-1 rounded-full text-sm font-medium border {severity_class}">
                            {severity}{cvss_display}
                        </span>
                        {f'<div class="text-xs text-slate-500 mt-1">Location: {html.escape(str(location))}</div>' if location != 'N/A' else ''}
                    </div>
                </div>
            </div>
            
            <!-- Finding Content -->
            <div class="p-6 space-y-6">
                <!-- Analysis Section -->
                <div>
                    <h4 class="text-lg font-semibold text-slate-800 mb-3 flex items-center">
                        {'🤖 AI Triage Analysis' if self.ai_enabled else '🔍 Security Analysis'}
                    </h4>
                    
                    <div class="space-y-4">
                        <div class="bg-blue-50 rounded-lg p-4">
                            <h5 class="font-medium text-blue-900 mb-2">{'AI-Generated ' if self.ai_enabled else ''}Description</h5>
                            <p class="text-blue-800 text-sm leading-relaxed">{html.escape(detailed_description)}</p>
                        </div>
                        
                        <div class="bg-red-50 rounded-lg p-4">
                            <h5 class="font-medium text-red-900 mb-2">Business Impact</h5>
                            <p class="text-red-800 text-sm leading-relaxed">{html.escape(business_impact)}</p>
                        </div>
                        
                        <div class="bg-green-50 rounded-lg p-4">
                            <h5 class="font-medium text-green-900 mb-2">Remediation Steps</h5>
                            <p class="text-green-800 text-sm leading-relaxed">{html.escape(remediation_steps)}</p>
                        </div>
                    </div>
                </div>
                
                <!-- Technical Evidence -->
                <div>
                    <h4 class="text-lg font-semibold text-slate-800 mb-3 flex items-center">
                        🔬 Technical Evidence
                    </h4>
                    
                    <div class="space-y-4">
                        {f'''
                        <div>
                            <h5 class="font-medium text-slate-700 mb-2">Payload/Location</h5>
                            <pre class="bg-slate-900 text-green-400 p-4 rounded-lg overflow-x-auto text-sm font-mono whitespace-pre-wrap"><code>{html.escape(str(payload_used))}</code></pre>
                        </div>
                        ''' if payload_used != 'No payload information available.' else ''}
                        
                        <div class="bg-yellow-50 rounded-lg p-4">
                            <h5 class="font-medium text-yellow-900 mb-2">Evidence</h5>
                            <p class="text-yellow-800 text-sm leading-relaxed">{html.escape(evidence)}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """


# Example usage and testing function
def main():
    """
    Example usage of the ReportGenerator class.
    This function demonstrates how to use the ReportGenerator.
    """
    # Sample findings data for testing
    sample_findings = [
        {
            'vulnerability_type': 'Reflected Cross-Site Scripting (XSS)',
            'severity': 'High',
            'cvss_score': 7.5,
            'detailed_description': 'A reflected XSS vulnerability was identified in the search parameter. User input is not properly sanitized before being reflected in the HTML response.',
            'business_impact': 'Attackers could steal user sessions, perform actions on behalf of users, or deface the website.',
            'remediation_steps': 'Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers.',
            'payload_used': '<script>alert("XSS")</script>',
            'evidence': 'JavaScript dialog was triggered, confirming script execution.'
        },
        {
            'vulnerability_type': 'SQL Injection',
            'severity': 'Critical',
            'cvss_score': 9.2,
            'detailed_description': 'SQL injection vulnerability in login form allows attackers to manipulate database queries.',
            'business_impact': 'Complete database compromise, data theft, and potential system takeover.',
            'remediation_steps': 'Use parameterized queries and prepared statements. Implement proper input validation.',
            'payload_used': "' OR '1'='1' --",
            'evidence': 'Database error messages revealed internal structure and successful bypass of authentication.'
        }
    ]
    
    # Create ReportGenerator instance (AI disabled for this example)
    generator = ReportGenerator(log_file_path="logs/scan.log", ai_enabled=False)
    
    # Generate report
    try:
        report_path = generator.generate_html_report(
            final_findings=sample_findings,
            target_url="https://example.com",
            output_filename="security_assessment_report.html"
        )
        print(f"✅ Report generated successfully: {report_path}")
    except Exception as e:
        print(f"❌ Failed to generate report: {e}")


if __name__ == "__main__":
    main()
