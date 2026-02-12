#!/usr/bin/env python3
"""
Test Configuration and Utilities for PayGuard Simple Test Runner
Shared fixtures, utilities, and configuration for all test suites
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import json
import base64
from PIL import Image
import io
import time
import threading
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from run_simple_tests_optimized import SimpleTestRunner, TestResult, TestReport

# Test configuration
TEST_CONFIG = {
    "performance": {
        "max_text_analysis_time": 0.01,  # 10ms
        "max_url_analysis_time": 0.005,  # 5ms
        "max_html_analysis_time": 0.02,  # 20ms
        "max_image_analysis_time": 0.1,  # 100ms
        "min_operations_per_second": 100,
        "max_memory_growth_mb": 50,
    },
    "test_data": {
        "scam_texts": [
            "URGENT: Your computer is infected! Call 1-800-555-0199",
            "Your account has been suspended. Verify immediately.",
            "Microsoft Security Alert: Call +1-888-555-0123",
            "VIRUS DETECTED! Download antivirus now!",
            "Your payment failed. Update credit card information.",
            "Congratulations! You've won $1000. Send bank details.",
        ],
        "legitimate_texts": [
            "Welcome to our website. Please browse our products.",
            "Thank you for your purchase. Order ships in 2-3 days.",
            "Contact customer support at support@company.com",
            "Our business hours are Monday through Friday 9-5.",
            "Please review the attached document.",
            "Your appointment is scheduled for tomorrow at 2 PM.",
        ],
        "suspicious_urls": [
            "http://suspicious-site.tk",
            "https://phishing-example.com",
            "http://malware-test.ml",
            "https://192.168.1.1",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
        ],
        "legitimate_urls": [
            "https://google.com",
            "https://github.com",
            "https://stackoverflow.com",
            "https://wikipedia.org",
            "https://microsoft.com",
            "https://amazon.com",
        ],
    }
}

@dataclass
class TestScenario:
    """Test scenario configuration"""
    name: str
    description: str
    input_data: Any
    expected_result: Any
    test_type: str
    timeout: float = 30.0
    skip_reason: Optional[str] = None

class TestDataGenerator:
    """Generate test data for various scenarios"""
    
    @staticmethod
    def generate_scam_texts(count: int = 10) -> List[str]:
        """Generate scam text variations"""
        templates = [
            "URGENT: Your computer is infected with {malware}! Call {phone}",
            "Your {service} account has been {action}. {instruction}",
            "{company} Security Alert: {threat} detected. Call {phone}",
            "VIRUS DETECTED! {action} or your files will be {consequence}",
            "Your {payment_method} {status}. Update information at {url}",
        ]
        
        replacements = {
            'malware': ['virus', 'malware', 'trojan', 'spyware'],
            'phone': ['1-800-555-0199', '1-888-555-0123', '+1-900-555-1234'],
            'service': ['Amazon', 'PayPal', 'Netflix', 'Microsoft'],
            'action': ['suspended', 'blocked', 'expired', 'compromised'],
            'instruction': ['Verify immediately', 'Click here to restore', 'Update now'],
            'company': ['Microsoft', 'Apple', 'Google', 'Amazon'],
            'threat': ['Malware', 'Unauthorized access', 'Security breach'],
            'payment_method': ['credit card', 'payment method', 'subscription'],
            'status': ['has expired', 'was declined', 'needs verification'],
            'consequence': ['deleted', 'encrypted', 'corrupted'],
            'url': ['secure-update.com', 'verify-account.net', 'restore-access.org'],
        }
        
        import random
        texts = []
        for _ in range(count):
            template = random.choice(templates)
            text = template
            for key, values in replacements.items():
                if f'{{{key}}}' in text:
                    text = text.replace(f'{{{key}}}', random.choice(values))
            texts.append(text)
        
        return texts
    
    @staticmethod
    def generate_test_images(sizes: List[tuple] = None) -> Dict[str, tuple]:
        """Generate test images of various sizes and types"""
        if sizes is None:
            sizes = [(100, 100), (500, 500), (1000, 1000)]
        
        images = {}
        colors = ['white', 'red', 'blue', 'green', 'yellow']
        
        for i, (width, height) in enumerate(sizes):
            color = colors[i % len(colors)]
            img = Image.new('RGB', (width, height), color=color)
            
            # Add text for some images
            if i % 2 == 0:
                from PIL import ImageDraw
                draw = ImageDraw.Draw(img)
                draw.text((10, 10), f"Test {i}", fill='black')
            
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            
            images[f'{width}x{height}_{color}'] = (img, img_bytes.getvalue())
        
        return images
    
    @staticmethod
    def generate_html_samples() -> Dict[str, Dict[str, Any]]:
        """Generate HTML test samples"""
        samples = {
            'clean_website': {
                'html': '''
                <html>
                <head><title>Welcome</title></head>
                <body>
                    <h1>Welcome to Our Website</h1>
                    <p>We offer quality products and services.</p>
                    <p>Contact us at info@company.com</p>
                </body>
                </html>
                ''',
                'expected_level': 'LOW',
                'expected_patterns': []
            },
            'tech_support_scam': {
                'html': '''
                <html>
                <head><title>CRITICAL ERROR</title></head>
                <body style="background-color: red; color: white;">
                    <h1>⚠️ URGENT SECURITY ALERT ⚠️</h1>
                    <p>Your computer is infected with malware!</p>
                    <p>Call Microsoft Support: 1-800-555-0199</p>
                    <p>DO NOT CLOSE THIS WINDOW</p>
                </body>
                </html>
                ''',
                'expected_level': 'HIGH',
                'expected_patterns': ['urgency', 'virus_warning', 'phone_scam', 'brand_impersonation', 'visual_alarm']
            },
            'phishing_page': {
                'html': '''
                <html>
                <head><title>Amazon Security Notice</title></head>
                <body>
                    <h2>Account Verification Required</h2>
                    <p>Your account has been suspended due to suspicious activity.</p>
                    <p>Please verify your account information immediately.</p>
                    <button>Verify Account</button>
                </body>
                </html>
                ''',
                'expected_level': 'MEDIUM',
                'expected_patterns': ['account_threat', 'brand_impersonation']
            },
            'empty_page': {
                'html': '',
                'expected_level': 'LOW',
                'expected_patterns': []
            },
            'malformed_html': {
                'html': '<html><body><h1>Unclosed tag<p>Missing closing tags',
                'expected_level': 'LOW',
                'expected_patterns': []
            }
        }
        
        return samples

class MockManager:
    """Manage mocks for testing"""
    
    def __init__(self):
        self.active_mocks = []
    
    def mock_pil_unavailable(self):
        """Mock PIL as unavailable"""
        mock = patch('PIL.Image', side_effect=ImportError("PIL not available"))
        self.active_mocks.append(mock)
        return mock.start()
    
    def mock_file_system_error(self):
        """Mock file system errors"""
        mock = patch('tempfile.NamedTemporaryFile', side_effect=OSError("Disk full"))
        self.active_mocks.append(mock)
        return mock.start()
    
    def mock_network_timeout(self):
        """Mock network timeouts"""
        mock = patch('urllib.parse.urlparse', side_effect=TimeoutError("Network timeout"))
        self.active_mocks.append(mock)
        return mock.start()
    
    def cleanup(self):
        """Clean up all active mocks"""
        for mock in self.active_mocks:
            try:
                mock.stop()
            except:
                pass
        self.active_mocks.clear()

class PerformanceMonitor:
    """Monitor performance during tests"""
    
    def __init__(self):
        self.start_time = None
        self.measurements = []
    
    def start(self):
        """Start performance monitoring"""
        self.start_time = time.time()
    
    def measure(self, operation_name: str):
        """Measure an operation"""
        if self.start_time is None:
            self.start()
        
        current_time = time.time()
        duration = current_time - self.start_time
        
        self.measurements.append({
            'operation': operation_name,
            'duration': duration,
            'timestamp': current_time
        })
        
        self.start_time = current_time
        return duration
    
    def get_total_time(self) -> float:
        """Get total measured time"""
        return sum(m['duration'] for m in self.measurements)
    
    def get_slowest_operation(self) -> Dict[str, Any]:
        """Get the slowest operation"""
        if not self.measurements:
            return {}
        return max(self.measurements, key=lambda x: x['duration'])

class TestEnvironment:
    """Manage test environment setup and teardown"""
    
    def __init__(self):
        self.temp_dirs = []
        self.temp_files = []
        self.mock_manager = MockManager()
        self.performance_monitor = PerformanceMonitor()
    
    def create_temp_workspace(self) -> Path:
        """Create a temporary workspace"""
        temp_dir = Path(tempfile.mkdtemp(prefix="payguard_test_"))
        self.temp_dirs.append(temp_dir)
        return temp_dir
    
    def create_temp_file(self, content: str, suffix: str = '.txt') -> Path:
        """Create a temporary file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(content)
            temp_file = Path(f.name)
            self.temp_files.append(temp_file)
            return temp_file
    
    def cleanup(self):
        """Clean up test environment"""
        # Clean up temp files
        for temp_file in self.temp_files:
            try:
                if temp_file.exists():
                    temp_file.unlink()
            except:
                pass
        
        # Clean up temp directories
        for temp_dir in self.temp_dirs:
            try:
                if temp_dir.exists():
                    import shutil
                    shutil.rmtree(temp_dir)
            except:
                pass
        
        # Clean up mocks
        self.mock_manager.cleanup()
        
        self.temp_files.clear()
        self.temp_dirs.clear()

# Pytest fixtures
@pytest.fixture(scope="session")
def test_config():
    """Test configuration"""
    return TEST_CONFIG

@pytest.fixture
def test_runner():
    """Create a test runner instance"""
    return SimpleTestRunner()

@pytest.fixture
def test_data():
    """Generate test data"""
    return {
        'scam_texts': TestDataGenerator.generate_scam_texts(20),
        'legitimate_texts': TEST_CONFIG['test_data']['legitimate_texts'],
        'suspicious_urls': TEST_CONFIG['test_data']['suspicious_urls'],
        'legitimate_urls': TEST_CONFIG['test_data']['legitimate_urls'],
        'html_samples': TestDataGenerator.generate_html_samples(),
    }

@pytest.fixture
def test_images():
    """Generate test images"""
    return TestDataGenerator.generate_test_images()

@pytest.fixture
def mock_manager():
    """Mock manager for tests"""
    manager = MockManager()
    yield manager
    manager.cleanup()

@pytest.fixture
def performance_monitor():
    """Performance monitor for tests"""
    return PerformanceMonitor()

@pytest.fixture
def test_environment():
    """Test environment manager"""
    env = TestEnvironment()
    yield env
    env.cleanup()

@pytest.fixture(autouse=True)
def setup_test_logging():
    """Set up logging for tests"""
    import logging
    logging.basicConfig(level=logging.WARNING)  # Reduce noise during tests

# Custom pytest markers
def pytest_configure(config):
    """Configure pytest markers"""
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "performance: marks tests as performance tests")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "unit: marks tests as unit tests")
    config.addinivalue_line("markers", "property: marks tests as property-based tests")
    config.addinivalue_line("markers", "regression: marks tests as regression tests")

# Test utilities
class TestAssertions:
    """Custom assertions for PayGuard tests"""
    
    @staticmethod
    def assert_scam_result_valid(result):
        """Assert that a scam analysis result is valid"""
        from run_simple_tests_optimized import ScamAnalysisResult
        assert isinstance(result, ScamAnalysisResult)
        assert isinstance(result.is_scam, bool)
        assert isinstance(result.score, int)
        assert isinstance(result.patterns, list)
        assert isinstance(result.confidence, (int, float))
        assert 0 <= result.confidence <= 100
        assert result.score >= 0
    
    @staticmethod
    def assert_url_result_valid(result):
        """Assert that a URL analysis result is valid"""
        from run_simple_tests_optimized import UrlAnalysisResult
        assert isinstance(result, UrlAnalysisResult)
        assert isinstance(result.risk_score, int)
        assert result.risk_level in ['LOW', 'MEDIUM', 'HIGH', 'ERROR', 'INVALID']
        assert isinstance(result.is_valid, bool)
        assert 0 <= result.risk_score <= 100
    
    @staticmethod
    def assert_html_result_valid(result):
        """Assert that an HTML analysis result is valid"""
        assert isinstance(result, dict)
        assert 'risk_score' in result
        assert 'risk_level' in result
        assert 'detected_patterns' in result
        assert 'pattern_count' in result
        assert result['risk_level'] in ['LOW', 'MEDIUM', 'HIGH']
        assert isinstance(result['detected_patterns'], list)
        assert result['pattern_count'] == len(result['detected_patterns'])
    
    @staticmethod
    def assert_performance_acceptable(duration: float, max_duration: float, operation: str):
        """Assert that performance is acceptable"""
        assert duration < max_duration, f"{operation} too slow: {duration:.3f}s > {max_duration:.3f}s"

# Test data validation
def validate_test_data():
    """Validate test data integrity"""
    config = TEST_CONFIG
    
    # Validate scam texts
    scam_texts = config['test_data']['scam_texts']
    assert len(scam_texts) > 0, "No scam texts defined"
    
    # Validate legitimate texts
    legitimate_texts = config['test_data']['legitimate_texts']
    assert len(legitimate_texts) > 0, "No legitimate texts defined"
    
    # Validate URLs
    suspicious_urls = config['test_data']['suspicious_urls']
    legitimate_urls = config['test_data']['legitimate_urls']
    assert len(suspicious_urls) > 0, "No suspicious URLs defined"
    assert len(legitimate_urls) > 0, "No legitimate URLs defined"
    
    print("✅ Test data validation passed")

if __name__ == "__main__":
    validate_test_data()
    print("Test configuration loaded successfully")