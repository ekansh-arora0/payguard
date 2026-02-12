#!/usr/bin/env python3
"""
Integration Tests for PayGuard Simple Test Runner
End-to-end testing of complete workflows and system integration
"""

import pytest
import tempfile
import os
import sys
import time
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
import json
import base64
from PIL import Image
import io

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from run_simple_tests_optimized import SimpleTestRunner, TestResult

class TestSimpleRunnerIntegration:
    """Integration tests for the complete test runner system"""
    
    @pytest.fixture
    def runner(self):
        """Create a test runner instance"""
        return SimpleTestRunner()
    
    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            yield workspace
    
    def test_complete_scam_detection_workflow(self, runner):
        """Test complete scam detection workflow from text to result"""
        # Simulate a complete scam detection scenario
        scam_scenarios = [
            {
                'name': 'Tech Support Scam',
                'text': 'URGENT: Your computer is infected with malware! Call Microsoft at 1-800-555-0199 immediately!',
                'expected_patterns': ['urgency', 'virus_warning', 'phone_number', 'brand_impersonation'],
                'expected_scam': True
            },
            {
                'name': 'Phishing Email',
                'text': 'Your Amazon account has been suspended. Click here to verify your payment information.',
                'expected_patterns': ['account_threat', 'phishing'],
                'expected_scam': True
            },
            {
                'name': 'Fake Virus Warning',
                'text': 'VIRUS DETECTED! Your files will be deleted in 5 minutes. Download our antivirus now!',
                'expected_patterns': ['virus_warning', 'urgency', 'action_prompt'],
                'expected_scam': True
            },
            {
                'name': 'Legitimate Business Email',
                'text': 'Thank you for your recent purchase. Your order will be shipped within 2-3 business days.',
                'expected_patterns': [],
                'expected_scam': False
            }
        ]
        
        for scenario in scam_scenarios:
            result = runner.analyze_text_for_scam(scenario['text'])
            
            # Verify scam detection
            assert result.is_scam == scenario['expected_scam'], f"Failed for {scenario['name']}"
            
            # Verify expected patterns are detected
            for expected_pattern in scenario['expected_patterns']:
                assert expected_pattern in result.patterns, f"Missing pattern {expected_pattern} in {scenario['name']}"
            
            # Verify confidence scoring
            if scenario['expected_scam']:
                assert result.confidence > 50, f"Low confidence for scam: {scenario['name']}"
            else:
                assert result.confidence < 70, f"High confidence for legitimate: {scenario['name']}"
    
    def test_url_risk_assessment_workflow(self, runner):
        """Test complete URL risk assessment workflow"""
        url_scenarios = [
            {
                'name': 'Legitimate HTTPS Site',
                'url': 'https://github.com',
                'expected_level': 'LOW',
                'expected_valid': True
            },
            {
                'name': 'Suspicious TLD',
                'url': 'http://phishing-site.tk',
                'expected_level': 'HIGH',
                'expected_valid': True
            },
            {
                'name': 'JavaScript Injection',
                'url': "javascript:alert('xss')",
                'expected_level': 'HIGH',
                'expected_valid': False
            },
            {
                'name': 'IP Address',
                'url': 'https://192.168.1.1',
                'expected_level': 'MEDIUM',
                'expected_valid': True
            },
            {
                'name': 'Invalid URL',
                'url': 'not-a-valid-url',
                'expected_level': 'ERROR',
                'expected_valid': False
            }
        ]
        
        for scenario in url_scenarios:
            result = runner.analyze_url(scenario['url'])
            
            assert result.risk_level == scenario['expected_level'], f"Wrong risk level for {scenario['name']}"
            assert result.is_valid == scenario['expected_valid'], f"Wrong validity for {scenario['name']}"
            assert result.url == scenario['url'], f"URL mismatch for {scenario['name']}"
    
    def test_html_content_analysis_workflow(self, runner):
        """Test complete HTML content analysis workflow"""
        html_scenarios = [
            {
                'name': 'Clean Website',
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
            {
                'name': 'Tech Support Scam Page',
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
            {
                'name': 'Phishing Page',
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
            }
        ]
        
        for scenario in html_scenarios:
            result = runner.analyze_html_content(scenario['html'])
            
            assert result['risk_level'] == scenario['expected_level'], f"Wrong risk level for {scenario['name']}"
            
            for expected_pattern in scenario['expected_patterns']:
                assert expected_pattern in result['detected_patterns'], f"Missing pattern {expected_pattern} in {scenario['name']}"
    
    def test_image_processing_workflow(self, runner):
        """Test complete image processing workflow"""
        # Create test images with different characteristics
        test_images = []
        
        # Clean white image
        clean_img = Image.new('RGB', (800, 600), color='white')
        clean_bytes = io.BytesIO()
        clean_img.save(clean_bytes, format='PNG')
        test_images.append(('clean', clean_img, clean_bytes.getvalue()))
        
        # Red warning-style image
        warning_img = Image.new('RGB', (800, 600), color='red')
        from PIL import ImageDraw
        draw = ImageDraw.Draw(warning_img)
        draw.text((50, 50), "WARNING!", fill='white')
        warning_bytes = io.BytesIO()
        warning_img.save(warning_bytes, format='PNG')
        test_images.append(('warning', warning_img, warning_bytes.getvalue()))
        
        # Large image (potential size-based risk)
        large_img = Image.new('RGB', (3000, 2000), color='blue')
        large_bytes = io.BytesIO()
        large_img.save(large_bytes, format='JPEG', quality=95)  # High quality = larger size
        test_images.append(('large', large_img, large_bytes.getvalue()))
        
        for img_name, img, img_data in test_images:
            risk_score = runner._analyze_image_risk(img, img_data)
            
            # Verify risk scoring logic
            assert 0 <= risk_score <= 100, f"Risk score out of range for {img_name}"
            
            if img_name == 'clean':
                assert risk_score < 30, f"Clean image should have low risk: {risk_score}"
            elif img_name == 'warning':
                assert risk_score > 30, f"Warning image should have higher risk: {risk_score}"
            elif img_name == 'large' and len(img_data) > 5 * 1024 * 1024:
                assert risk_score >= 10, f"Large image should have size penalty: {risk_score}"
    
    def test_file_operations_workflow(self, runner, temp_workspace):
        """Test complete file operations workflow"""
        # Test various file operations
        test_files = [
            ('test.html', '<html><body>Test HTML content</body></html>'),
            ('test.txt', 'Test text content with phone 1-800-555-0199'),
            ('test.json', '{"test": "json content", "urgent": true}'),
            ('large.txt', 'Large content ' * 1000),
        ]
        
        created_files = []
        
        try:
            # Create and test files
            for filename, content in test_files:
                with runner._temp_file_manager(content, Path(filename).suffix) as temp_file:
                    created_files.append(temp_file)
                    
                    # Verify file creation
                    assert temp_file.exists()
                    assert temp_file.read_text() == content
                    
                    # Test content analysis based on file type
                    if filename.endswith('.html'):
                        html_result = runner.analyze_html_content(content)
                        assert 'risk_level' in html_result
                    elif filename.endswith('.txt'):
                        text_result = runner.analyze_text_for_scam(content)
                        assert hasattr(text_result, 'is_scam')
                
                # File should be auto-cleaned
                assert not temp_file.exists()
            
            # Verify all files were cleaned up
            assert len(runner._temp_files) == 0
            
        finally:
            # Ensure cleanup even if test fails
            runner.cleanup()
    
    def test_performance_benchmarking_workflow(self, runner):
        """Test performance benchmarking workflow"""
        # Test performance with various input sizes
        text_sizes = [10, 100, 1000, 5000]  # Different text lengths
        url_counts = [1, 10, 50, 100]  # Different URL batch sizes
        
        performance_results = {}
        
        # Text analysis performance
        for size in text_sizes:
            test_text = "URGENT: Your computer is infected! " * (size // 40 + 1)
            test_text = test_text[:size]  # Trim to exact size
            
            start_time = time.time()
            for _ in range(10):  # 10 iterations
                runner.analyze_text_for_scam(test_text)
            duration = (time.time() - start_time) / 10
            
            performance_results[f'text_{size}'] = duration
            
            # Performance should scale reasonably
            assert duration < 0.1, f"Text analysis too slow for size {size}: {duration:.3f}s"
        
        # URL analysis performance
        for count in url_counts:
            test_urls = [f"https://example{i}.com" for i in range(count)]
            
            start_time = time.time()
            for url in test_urls:
                runner.analyze_url(url)
            duration = time.time() - start_time
            
            performance_results[f'url_{count}'] = duration
            
            # Performance should be reasonable
            avg_per_url = duration / count
            assert avg_per_url < 0.01, f"URL analysis too slow: {avg_per_url:.3f}s per URL"
        
        # Log performance results for analysis
        print(f"\nPerformance Results: {performance_results}")
    
    def test_error_recovery_workflow(self, runner):
        """Test error recovery and graceful degradation"""
        # Test various error conditions
        error_scenarios = [
            {
                'name': 'PIL Import Error',
                'test_method': 'test_image_processing',
                'mock_target': 'PIL.Image',
                'mock_side_effect': ImportError("PIL not available"),
                'expected_result': True  # Should skip gracefully
            },
            {
                'name': 'File System Error',
                'test_method': 'test_file_operations',
                'mock_target': 'tempfile.NamedTemporaryFile',
                'mock_side_effect': OSError("Disk full"),
                'expected_result': False  # Should fail gracefully
            }
        ]
        
        for scenario in error_scenarios:
            with patch(scenario['mock_target'], side_effect=scenario['mock_side_effect']):
                test_method = getattr(runner, scenario['test_method'])
                result = test_method()
                
                # Should handle error gracefully
                assert isinstance(result, bool)
                if scenario['expected_result'] is not None:
                    assert result == scenario['expected_result'], f"Unexpected result for {scenario['name']}"
    
    def test_concurrent_execution_safety(self, runner):
        """Test thread safety and concurrent execution"""
        import threading
        import queue
        
        results_queue = queue.Queue()
        
        def worker_thread(thread_id):
            """Worker thread for concurrent testing"""
            try:
                # Each thread performs different operations
                text_result = runner.analyze_text_for_scam(f"URGENT: Thread {thread_id} test")
                url_result = runner.analyze_url(f"https://thread{thread_id}.example.com")
                html_result = runner.analyze_html_content(f"<html><body>Thread {thread_id}</body></html>")
                
                results_queue.put({
                    'thread_id': thread_id,
                    'text_result': text_result,
                    'url_result': url_result,
                    'html_result': html_result,
                    'success': True
                })
            except Exception as e:
                results_queue.put({
                    'thread_id': thread_id,
                    'error': str(e),
                    'success': False
                })
        
        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker_thread, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=10)  # 10 second timeout
        
        # Collect results
        results = []
        while not results_queue.empty():
            results.append(results_queue.get())
        
        # Verify all threads completed successfully
        assert len(results) == 5, f"Expected 5 results, got {len(results)}"
        
        for result in results:
            assert result['success'], f"Thread {result.get('thread_id', 'unknown')} failed: {result.get('error', 'unknown error')}"
    
    def test_memory_usage_workflow(self, runner):
        """Test memory usage patterns during extended operation"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Perform many operations to test for memory leaks
        for i in range(100):
            # Text analysis
            runner.analyze_text_for_scam(f"URGENT: Test iteration {i} with phone 1-800-555-{i:04d}")
            
            # URL analysis
            runner.analyze_url(f"https://test{i}.example.com")
            
            # HTML analysis
            runner.analyze_html_content(f"<html><body>Test {i}</body></html>")
            
            # File operations
            with runner._temp_file_manager(f"Test content {i}", '.txt') as temp_file:
                temp_file.read_text()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_growth = final_memory - initial_memory
        
        # Memory growth should be reasonable (less than 50MB for this test)
        assert memory_growth < 50, f"Excessive memory growth: {memory_growth:.2f}MB"
        
        # Cleanup should reduce memory usage
        runner.cleanup()
        
        cleanup_memory = process.memory_info().rss / 1024 / 1024  # MB
        assert cleanup_memory <= final_memory, "Memory usage increased after cleanup"
    
    def test_end_to_end_test_suite(self, runner):
        """Test complete end-to-end test suite execution"""
        # Mock external dependencies to ensure consistent results
        with patch('PIL.Image.new') as mock_image_new, \
             patch('PIL.ImageDraw.Draw') as mock_image_draw:
            
            # Configure mocks
            mock_img = MagicMock()
            mock_img.getcolors.return_value = [(1000, (255, 255, 255))]  # White image
            mock_image_new.return_value = mock_img
            
            mock_draw = MagicMock()
            mock_image_draw.return_value = mock_draw
            
            # Run complete test suite
            success = runner.run_all_tests()
            
            # Verify execution
            assert isinstance(success, bool)
            assert len(runner.results) > 0, "No test results generated"
            
            # Verify all tests were attempted
            test_names = [r.test_name for r in runner.results]
            expected_tests = [
                "Scam Text Detection",
                "URL Analysis", 
                "Image Processing",
                "HTML Analysis",
                "File Operations",
                "Performance Benchmarks"
            ]
            
            for expected_test in expected_tests:
                assert expected_test in test_names, f"Missing test: {expected_test}"
            
            # Verify results structure
            for result in runner.results:
                assert hasattr(result, 'test_name')
                assert hasattr(result, 'result')
                assert hasattr(result, 'duration')
                assert result.duration >= 0
                assert result.result in [TestResult.PASS, TestResult.FAIL, TestResult.ERROR, TestResult.SKIP]

class TestRealWorldScenarios:
    """Test real-world scenarios and use cases"""
    
    @pytest.fixture
    def runner(self):
        return SimpleTestRunner()
    
    def test_tech_support_scam_detection(self, runner):
        """Test detection of common tech support scams"""
        tech_support_scams = [
            "Your computer has been infected with a virus. Call Microsoft at 1-800-555-0199",
            "Windows Security Alert: Your PC is infected! Call +1-888-555-0123 immediately",
            "URGENT: Malware detected! Contact Apple Support at 1-800-555-0199",
            "Your computer will be disabled in 5 minutes. Call tech support now!",
        ]
        
        for scam_text in tech_support_scams:
            result = runner.analyze_text_for_scam(scam_text)
            assert result.is_scam, f"Failed to detect tech support scam: {scam_text}"
            assert result.confidence > 70, f"Low confidence for obvious scam: {result.confidence}"
    
    def test_phishing_email_detection(self, runner):
        """Test detection of phishing emails"""
        phishing_emails = [
            "Your Amazon account has been suspended. Click here to verify your payment method.",
            "PayPal Security Notice: Unusual activity detected. Confirm your account immediately.",
            "Your bank account will be closed. Update your information at secure-bank-update.com",
            "Netflix: Your subscription has expired. Renew now to avoid service interruption.",
        ]
        
        for email_text in phishing_emails:
            result = runner.analyze_text_for_scam(email_text)
            assert result.is_scam, f"Failed to detect phishing email: {email_text}"
    
    def test_legitimate_content_classification(self, runner):
        """Test that legitimate content is not flagged as scam"""
        legitimate_content = [
            "Thank you for your purchase. Your order will be shipped within 2-3 business days.",
            "Welcome to our newsletter. You can unsubscribe at any time.",
            "Your appointment is scheduled for tomorrow at 2 PM. Please arrive 15 minutes early.",
            "Our customer service team is available Monday through Friday, 9 AM to 5 PM.",
            "Please review the attached document and let us know if you have any questions.",
        ]
        
        for content in legitimate_content:
            result = runner.analyze_text_for_scam(content)
            assert not result.is_scam, f"False positive for legitimate content: {content}"
            assert result.confidence < 50, f"High confidence for legitimate content: {result.confidence}"
    
    def test_mixed_content_scenarios(self, runner):
        """Test scenarios with mixed legitimate and suspicious content"""
        mixed_scenarios = [
            {
                'text': "Thank you for contacting our support team. For urgent issues, call 1-800-555-0199.",
                'expected_scam': False,  # Legitimate business with phone number
                'note': 'Business phone number should not trigger scam detection'
            },
            {
                'text': "Your subscription expires soon. Renew now to continue enjoying our service.",
                'expected_scam': False,  # Legitimate renewal notice
                'note': 'Renewal notices should not be flagged as scams'
            },
            {
                'text': "URGENT: Your account shows suspicious activity. Verify immediately or face suspension.",
                'expected_scam': True,  # Combines urgency with account threats
                'note': 'Urgent account threats should be flagged'
            }
        ]
        
        for scenario in mixed_scenarios:
            result = runner.analyze_text_for_scam(scenario['text'])
            assert result.is_scam == scenario['expected_scam'], \
                f"Wrong classification for: {scenario['text']} - {scenario['note']}"

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])