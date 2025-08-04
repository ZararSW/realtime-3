#!/usr/bin/env python3
"""
Comprehensive Test Suite for AI Policy and No-AI Mode
Tests rule-based payloads, heuristic detection, and integration
"""

import pytest
import asyncio
import subprocess
import time
import requests
from pathlib import Path
import sys
import os

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from ai_policy import AIPolicy, VulnerabilityResult, ENABLE_AI
import ai_policy

class TestVulnerableApp:
    """Test fixture manager for the vulnerable Flask application"""
    
    def __init__(self):
        self.process = None
        self.base_url = "http://localhost:5001"
    
    def start(self):
        """Start the vulnerable test application"""
        try:
            # Start the Flask app in background
            self.process = subprocess.Popen([
                sys.executable, "test_vulnerable_app.py"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for app to start
            for _ in range(30):  # Wait up to 30 seconds
                try:
                    response = requests.get(self.base_url, timeout=2)
                    if response.status_code == 200:
                        return True
                except requests.exceptions.RequestException:
                    time.sleep(1)
                    continue
            
            raise Exception("Failed to start test application")
        except Exception as e:
            if self.process:
                self.process.terminate()
            raise e
    
    def stop(self):
        """Stop the vulnerable test application"""
        if self.process:
            self.process.terminate()
            self.process.wait()
    
    def is_running(self):
        """Check if the application is running"""
        try:
            response = requests.get(self.base_url, timeout=2)
            return response.status_code == 200
        except:
            return False

@pytest.fixture(scope="session")
def vulnerable_app():
    """Session-scoped fixture for the vulnerable test application"""
    app = TestVulnerableApp()
    app.start()
    yield app
    app.stop()

class TestAIPolicyConfiguration:
    """Test AI Policy configuration and setup"""
    
    def test_ai_policy_initialization_no_ai(self):
        """Test AI Policy initialization with AI disabled"""
        policy = AIPolicy(enable_ai=False)
        assert policy.enable_ai is False
        assert policy.ai_client is None
        assert policy.payload_config is not None
    
    def test_ai_policy_initialization_with_ai(self):
        """Test AI Policy initialization with AI enabled"""
        policy = AIPolicy(enable_ai=True)
        assert policy.enable_ai is True
        assert policy.payload_config is not None
    
    def test_payload_config_loading(self):
        """Test payload configuration loading"""
        policy = AIPolicy(enable_ai=False)
        config = policy.payload_config
        
        # Check that all required payload types exist
        assert 'xss_payloads' in config
        assert 'sqli_payloads' in config
        assert 'ssrf_payloads' in config
        assert 'idor_payloads' in config
        assert 'csrf_tokens' in config
        assert 'command_injection' in config
        
        # Check payload structure
        assert 'basic' in config['xss_payloads']
        assert 'advanced' in config['xss_payloads']
        assert len(config['xss_payloads']['basic']) > 0

class TestRuleBasedPayloads:
    """Test rule-based payload generation"""
    
    def test_xss_payload_generation(self):
        """Test XSS payload generation for different form types"""
        policy = AIPolicy(enable_ai=False)
        
        # Test text input form
        form_metadata = {
            'fields': [
                {'name': 'search', 'type': 'text'},
                {'name': 'comment', 'type': 'textarea'}
            ],
            'action': '/search',
            'method': 'GET'
        }
        
        payloads = policy._rule_based_payloads(form_metadata)
        assert len(payloads) > 0
        
        # Check that XSS payloads are included
        xss_found = any('<script>' in payload for payload in payloads)
        assert xss_found, "XSS payloads should be generated for text inputs"
    
    def test_sqli_payload_generation(self):
        """Test SQL injection payload generation"""
        policy = AIPolicy(enable_ai=False)
        
        # Test login form
        form_metadata = {
            'fields': [
                {'name': 'username', 'type': 'text'},
                {'name': 'password', 'type': 'password'}
            ],
            'action': '/login',
            'method': 'POST'
        }
        
        payloads = policy._rule_based_payloads(form_metadata)
        
        # Check that SQL injection payloads are included
        sqli_found = any("' OR '" in payload for payload in payloads)
        assert sqli_found, "SQL injection payloads should be generated for login forms"
    
    def test_ssrf_payload_generation(self):
        """Test SSRF payload generation"""
        policy = AIPolicy(enable_ai=False)
        
        # Test URL input form
        form_metadata = {
            'fields': [
                {'name': 'url', 'type': 'url'}
            ],
            'action': '/fetch',
            'method': 'POST'
        }
        
        payloads = policy._rule_based_payloads(form_metadata)
        
        # Check that SSRF payloads are included
        ssrf_found = any('169.254.169.254' in payload for payload in payloads)
        assert ssrf_found, "SSRF payloads should be generated for URL inputs"
    
    def test_idor_payload_generation(self):
        """Test IDOR payload generation"""
        policy = AIPolicy(enable_ai=False)
        
        # Test form with ID parameter
        form_metadata = {
            'fields': [
                {'name': 'user_id', 'type': 'hidden'},
                {'name': 'action', 'type': 'text'}
            ],
            'action': '/profile',
            'method': 'POST'
        }
        
        payloads = policy._rule_based_payloads(form_metadata)
        
        # Check that IDOR payloads are included
        idor_found = any(payload.isdigit() for payload in payloads)
        assert idor_found, "IDOR payloads should be generated for ID fields"

class TestHeuristicDetection:
    """Test heuristic-based vulnerability detection"""
    
    def test_xss_detection_positive(self):
        """Test XSS detection with positive cases"""
        policy = AIPolicy(enable_ai=False)
        
        # Test reflected XSS
        response_text = '<div>You searched for: <script>alert("XSS")</script></div>'
        payload = '<script>alert("XSS")</script>'
        
        result = policy._simple_heuristic(response_text, payload, 'xss')
        
        assert result.detected is True
        assert result.confidence > 0.3
        assert 'Payload reflected in response' in result.evidence[0]
        assert result.heuristic_fired is not None
    
    def test_xss_detection_negative(self):
        """Test XSS detection with negative cases"""
        policy = AIPolicy(enable_ai=False)
        
        # Test clean response
        response_text = '<div>Search results for your query</div>'
        payload = '<script>alert("XSS")</script>'
        
        result = policy._simple_heuristic(response_text, payload, 'xss')
        
        assert result.detected is False
        assert result.confidence <= 0.3
    
    def test_sqli_detection_positive(self):
        """Test SQL injection detection with positive cases"""
        policy = AIPolicy(enable_ai=False)
        
        # Test MySQL error
        response_text = '''
        <h2>Database Error</h2>
        <p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p>
        '''
        payload = "' OR '1'='1"
        
        result = policy._simple_heuristic(response_text, payload, 'sqli')
        
        assert result.detected is True
        assert result.confidence > 0.5
        assert any('SQL error pattern' in evidence for evidence in result.evidence)
    
    def test_sqli_detection_negative(self):
        """Test SQL injection detection with negative cases"""
        policy = AIPolicy(enable_ai=False)
        
        # Test normal response
        response_text = '<div>Login successful! Welcome back.</div>'
        payload = "' OR '1'='1"
        
        result = policy._simple_heuristic(response_text, payload, 'sqli')
        
        assert result.detected is False
        assert result.confidence <= 0.5
    
    def test_ssrf_detection_positive(self):
        """Test SSRF detection with positive cases"""
        policy = AIPolicy(enable_ai=False)
        
        # Test AWS metadata response
        response_text = '''
        {
            "ami-id": "ami-1234567890abcdef0",
            "instance-id": "i-1234567890abcdef0",
            "instance-type": "t2.micro"
        }
        '''
        payload = "http://169.254.169.254/latest/meta-data/"
        
        result = policy._simple_heuristic(response_text, payload, 'ssrf')
        
        assert result.detected is True
        assert result.confidence > 0.5
        assert any('AWS metadata indicator' in evidence for evidence in result.evidence)
    
    def test_command_injection_detection_positive(self):
        """Test command injection detection with positive cases"""
        policy = AIPolicy(enable_ai=False)
        
        # Test command output
        response_text = '''
        uid=33(www-data) gid=33(www-data) groups=33(www-data)
        '''
        payload = "; id"
        
        result = policy._simple_heuristic(response_text, payload, 'command_injection')
        
        assert result.detected is True
        assert result.confidence > 0.5
        assert any('Command output pattern' in evidence for evidence in result.evidence)

class TestAIPolicyIntegration:
    """Test AI Policy integration with main scanner"""
    
    def test_global_ai_flag_setting(self):
        """Test that global AI flag is properly set"""
        # Test setting AI flag to False
        original_value = ai_policy.ENABLE_AI
        
        ai_policy.ENABLE_AI = False
        policy = AIPolicy(enable_ai=False)
        assert policy.enable_ai is False
        
        ai_policy.ENABLE_AI = True
        policy = AIPolicy(enable_ai=True)
        assert policy.enable_ai is True
        
        # Restore original value
        ai_policy.ENABLE_AI = original_value
    
    def test_payload_generation_api(self):
        """Test the convenience API for payload generation"""
        from ai_policy import get_payloads
        
        form_metadata = {
            'fields': [{'name': 'search', 'type': 'text'}],
            'action': '/search',
            'method': 'GET'
        }
        
        # Test with AI disabled
        payloads = get_payloads(form_metadata, enable_ai=False)
        assert len(payloads) > 0
        assert isinstance(payloads, list)
    
    def test_analysis_api(self):
        """Test the convenience API for response analysis"""
        from ai_policy import analyze_response
        
        response_text = '<script>alert("XSS")</script>'
        payload = '<script>alert("XSS")</script>'
        
        result = analyze_response(response_text, payload, 'xss', enable_ai=False)
        assert isinstance(result, VulnerabilityResult)
        assert result.attack_type == 'xss'

@pytest.mark.asyncio
@pytest.mark.integration
class TestEndToEndIntegration:
    """End-to-end integration tests with vulnerable application"""
    
    async def test_xss_detection_e2e(self, vulnerable_app):
        """End-to-end XSS detection test"""
        if not vulnerable_app.is_running():
            pytest.skip("Vulnerable app not running")
        
        # Test reflected XSS
        payload = '<script>alert("XSS")</script>'
        url = f"{vulnerable_app.base_url}/xss_reflect?q={payload}"
        
        response = requests.get(url)
        
        # Use AI Policy to analyze response
        policy = AIPolicy(enable_ai=False)
        result = policy.analyze_response(response.text, payload, 'xss')
        
        assert result.detected is True, f"XSS should be detected in response: {response.text[:200]}"
    
    async def test_sqli_detection_e2e(self, vulnerable_app):
        """End-to-end SQL injection detection test"""
        if not vulnerable_app.is_running():
            pytest.skip("Vulnerable app not running")
        
        # Test SQL injection in login
        payload = "admin' OR '1'='1"
        data = {'username': payload, 'password': 'anything'}
        
        response = requests.post(f"{vulnerable_app.base_url}/sqli_login", data=data)
        
        # Use AI Policy to analyze response
        policy = AIPolicy(enable_ai=False)
        result = policy.analyze_response(response.text, payload, 'sqli')
        
        # Should detect based on success message or error
        assert len(result.evidence) > 0, f"Should have evidence in response: {response.text[:200]}"
    
    async def test_ssrf_detection_e2e(self, vulnerable_app):
        """End-to-end SSRF detection test"""
        if not vulnerable_app.is_running():
            pytest.skip("Vulnerable app not running")
        
        # Test SSRF with local file
        payload = "file:///etc/passwd"
        url = f"{vulnerable_app.base_url}/ssrf?url={payload}"
        
        try:
            response = requests.get(url, timeout=5)
            
            # Use AI Policy to analyze response
            policy = AIPolicy(enable_ai=False)
            result = policy.analyze_response(response.text, payload, 'ssrf')
            
            # May or may not detect depending on system, but should not crash
            assert isinstance(result, VulnerabilityResult)
        except requests.exceptions.Timeout:
            # SSRF might cause timeout, which is also an indicator
            pass

class TestPerformanceAndScalability:
    """Test performance characteristics of rule-based approach"""
    
    def test_payload_generation_performance(self):
        """Test that payload generation is fast enough"""
        policy = AIPolicy(enable_ai=False)
        
        large_form = {
            'fields': [
                {'name': f'field_{i}', 'type': 'text'} for i in range(50)
            ],
            'action': '/large_form',
            'method': 'POST'
        }
        
        start_time = time.time()
        payloads = policy._rule_based_payloads(large_form)
        end_time = time.time()
        
        # Should complete in under 1 second
        assert (end_time - start_time) < 1.0
        assert len(payloads) > 0
    
    def test_heuristic_analysis_performance(self):
        """Test that heuristic analysis is fast"""
        policy = AIPolicy(enable_ai=False)
        
        # Large response text
        large_response = "A" * 100000  # 100KB response
        payload = '<script>alert("XSS")</script>'
        
        start_time = time.time()
        result = policy._simple_heuristic(large_response, payload, 'xss')
        end_time = time.time()
        
        # Should complete in under 1 second
        assert (end_time - start_time) < 1.0
        assert isinstance(result, VulnerabilityResult)

def run_tests():
    """Run all tests with proper setup"""
    print("🧪 Running Cybersecurity Tool Test Suite...")
    print("=" * 60)
    
    # Run pytest with verbose output
    pytest_args = [
        __file__,
        "-v",
        "-s",
        "--tb=short",
        "-m", "not integration"  # Skip integration tests by default
    ]
    
    return pytest.main(pytest_args)

def run_integration_tests():
    """Run integration tests (requires vulnerable app)"""
    print("🔧 Running Integration Tests...")
    print("⚠️  This will start a vulnerable web application on localhost:5001")
    print("=" * 60)
    
    pytest_args = [
        __file__,
        "-v",
        "-s",
        "--tb=short",
        "-m", "integration"
    ]
    
    return pytest.main(pytest_args)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run cybersecurity tool tests")
    parser.add_argument("--integration", action="store_true", help="Run integration tests")
    parser.add_argument("--all", action="store_true", help="Run all tests including integration")
    args = parser.parse_args()
    
    if args.integration:
        exit_code = run_integration_tests()
    elif args.all:
        print("Running unit tests...")
        exit_code1 = run_tests()
        print("\nRunning integration tests...")
        exit_code2 = run_integration_tests()
        exit_code = max(exit_code1, exit_code2)
    else:
        exit_code = run_tests()
    
    sys.exit(exit_code)
