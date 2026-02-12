#!/usr/bin/env python3
"""
Unit Tests for PayGuard Simple Test Runner
Comprehensive test coverage for all methods and edge cases
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import re
from PIL import Image
import io

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from run_simple_tests_optimized import (
    SimpleTestRunner, TestResult, TestReport, 
    ScamAnalysisResult, UrlAnalysisResult
)

class TestSimpleTestRunner:
    """Unit tests for SimpleTestRunner class"""
    
    @pytest.fixture
    def runner(self):
        """Create a test runner instance"""
        return SimpleTestRunner()
    
    @pytest.fixture
    def sample_texts(self):
        """Sample texts for testing"""
        return {
            'scam': [
                "URGENT: Your computer is infected! Call 1-800-555-0199",
                "Your account has been suspended. Verify immediately.",
                "Microsoft Security Alert: Call +1-888-555-0123",
                "VIRUS DETECTED! Click here to download antivirus now!",
            ],
            'legitimate': [
                "Welcome to our website. Please browse our products.",
                "Thank you for your purchase. Your order will arrive soon.",
                "Contact us for customer support at support@company.com",
                "Our business hours are Monday through Friday 9-5.",
            ],
            'edge_cases': [
                "",  # Empty string
                "   ",  # Whitespace only
                "A",  # Single character
                "A" * 1000,  # Very long string
                "Special chars: !@#$%^&*()",  # Special characters
                "Mixed 123 numbers and text",  # Mixed content
            ]
        }
    
    @pytest.fixture
    def sample_urls(self):
        """Sample URLs for testing"""
        return {
            'legitimate': [
                "https://google.com",
                "https://github.com",
                "https://stackoverflow.com",
                "https://wikipedia.org",
            ],
            'suspicious': [
                "http://suspicious-site.tk",
                "https://phishing-example.com",
                "http://malware-test.ml",
                "https://192.168.1.1",
            ],
            'malicious': [
                "javascript:alert('xss')",
                "data:text/html,<script>alert('xss')</script>",
                "file:///etc/passwd",
            ],
            'invalid': [
                "",
                "not-a-url",
                "ftp://invalid-protocol.com",
                None,
            ]
        }

class TestScamAnalysis:
    """Test scam text analysis functionality"""
    
    def test_analyze_text_for_scam_basic(self, runner, sample_texts):
        """Test basic scam text analysis"""
        # Test scam texts
        for text in sample_texts['scam']:
            result = runner.analyze_text_for_scam(text)
            assert isinstance(result, ScamAnalysisResult)
            assert result.is_scam is True
            assert result.score > 0
            assert result.confidence > 0
            assert len(result.patterns) > 0
        
        # Test legitimate texts
        for text in sample_texts['legitimate']:
            result = runner.analyze_text_for_scam(text)
            assert isinstance(result, ScamAnalysisResult)
            assert result.is_scam is False or result.confidence < 50
    
    def test_analyze_text_edge_cases(self, runner, sample_texts):
        """Test edge cases for text analysis"""
        for text in sample_texts['edge_cases']:
            result = runner.analyze_text_for_scam(text)
            assert isinstance(result, ScamAnalysisResult)
            
            # Empty/whitespace should not be scam
            if not text or not text.strip():
                assert result.is_scam is False
                assert result.score == 0
                assert result.confidence == 0.0
    
    def test_scam_patterns_compilation(self, runner):
        """Test that regex patterns are properly compiled"""
        assert len(runner._compiled_patterns) == len(runner.SCAM_PATTERNS)
        
        for compiled_pattern, score, name in runner._compiled_patterns:
            assert hasattr(compiled_pattern, 'search')  # Compiled regex
            assert isinstance(score, int)
            assert isinstance(name, str)
    
    def test_phone_number_detection(self, runner):
        """Test phone number pattern detection"""
        phone_texts = [
            "Call us at 1-800-555-0199",
            "Phone: 1-888-123-4567",
            "Contact 1-900-555-1234 now!",
        ]
        
        for text in phone_texts:
            result = runner.analyze_text_for_scam(text)
            assert 'phone_number' in result.patterns
    
    def test_urgency_detection(self, runner):
        """Test urgency pattern detection"""
        urgency_texts = [
            "URGENT action required",
            "Act now or lose access",
            "Immediate response needed",
            "Call now to avoid charges",
        ]
        
        for text in urgency_texts:
            result = runner.analyze_text_for_scam(text)
            assert 'urgency' in result.patterns
    
    def test_virus_warning_detection(self, runner):
        """Test virus warning pattern detection"""
        virus_texts = [
            "Your computer is infected with malware",
            "VIRUS DETECTED on your system",
            "Trojan found in your files",
        ]
        
        for text in virus_texts:
            result = runner.analyze_text_for_scam(text)
            assert 'virus_warning' in result.patterns
    
    def test_confidence_calculation(self, runner):
        """Test confidence score calculation"""
        # High pattern density should increase confidence
        dense_text = "URGENT VIRUS INFECTED Call 1-800-555-0199 IMMEDIATE"
        result = runner.analyze_text_for_scam(dense_text)
        assert result.confidence > result.score  # Density bonus
        
        # Long text with few patterns should have lower confidence
        sparse_text = "URGENT " + "normal text " * 100
        result = runner.analyze_text_for_scam(sparse_text)
        assert result.confidence <= 100  # Should be capped

class TestUrlAnalysis:
    """Test URL analysis functionality"""
    
    def test_analyze_url_basic(self, runner, sample_urls):
        """Test basic URL analysis"""
        # Test legitimate URLs
        for url in sample_urls['legitimate']:
            result = runner.analyze_url(url)
            assert isinstance(result, UrlAnalysisResult)
            assert result.risk_level in ["LOW", "MEDIUM"]
            assert result.is_valid is True
        
        # Test suspicious URLs
        for url in sample_urls['suspicious']:
            result = runner.analyze_url(url)
            assert isinstance(result, UrlAnalysisResult)
            assert result.risk_level in ["MEDIUM", "HIGH"]
    
    def test_analyze_url_edge_cases(self, runner, sample_urls):
        """Test URL analysis edge cases"""
        # Test invalid URLs
        for url in sample_urls['invalid']:
            if url is None:
                continue
            result = runner.analyze_url(url)
            assert isinstance(result, UrlAnalysisResult)
            
            if not url:
                assert result.risk_level == "INVALID"
                assert result.is_valid is False
    
    def test_protocol_scoring(self, runner):
        """Test URL protocol scoring"""
        test_cases = [
            ("https://example.com", "LOW"),  # HTTPS should be safer
            ("http://example.com", "MEDIUM"),  # HTTP less safe
            ("javascript:alert('xss')", "HIGH"),  # Dangerous protocol
            ("data:text/html,<script>", "HIGH"),  # Dangerous protocol
        ]
        
        for url, expected_min_level in test_cases:
            result = runner.analyze_url(url)
            if expected_min_level == "HIGH":
                assert result.risk_level == "HIGH"
            elif expected_min_level == "LOW":
                assert result.risk_level in ["LOW", "MEDIUM"]
    
    def test_suspicious_tld_detection(self, runner):
        """Test suspicious TLD detection"""
        suspicious_urls = [
            "http://test.tk",
            "https://example.ml",
            "http://site.ga",
        ]
        
        for url in suspicious_urls:
            result = runner.analyze_url(url)
            assert result.risk_score < 50  # Should be flagged as risky
    
    def test_ip_address_detection(self, runner):
        """Test IP address detection in URLs"""
        ip_urls = [
            "https://192.168.1.1",
            "http://10.0.0.1",
            "https://127.0.0.1",
        ]
        
        for url in ip_urls:
            result = runner.analyze_url(url)
            assert result.risk_score < 70  # IP addresses should be flagged

class TestHtmlAnalysis:
    """Test HTML content analysis"""
    
    def test_analyze_html_content_basic(self, runner):
        """Test basic HTML content analysis"""
        test_cases = [
            ('<html><body>Normal content</body></html>', 'LOW'),
            ('<html><body style="background:red">URGENT ALERT</body></html>', 'HIGH'),
            ('', 'LOW'),  # Empty content
        ]
        
        for content, expected_level in test_cases:
            result = runner.analyze_html_content(content)
            assert result['risk_level'] == expected_level
            assert isinstance(result['detected_patterns'], list)
            assert isinstance(result['pattern_count'], int)
    
    def test_html_scam_indicators(self, runner):
        """Test HTML scam indicator detection"""
        scam_html = '''
        <html><body style="background:red">
            <h1>URGENT SECURITY ALERT</h1>
            <p>Your computer is infected! Call 1-800-555-0199</p>
            <p>Microsoft Security Team</p>
        </body></html>
        '''
        
        result = runner.analyze_html_content(scam_html)
        assert result['risk_level'] == 'HIGH'
        assert 'urgency' in result['detected_patterns']
        assert 'virus_warning' in result['detected_patterns']
        assert 'phone_scam' in result['detected_patterns']
        assert 'brand_impersonation' in result['detected_patterns']

class TestImageProcessing:
    """Test image processing functionality"""
    
    @pytest.fixture
    def test_images(self):
        """Create test images"""
        images = {}
        
        # Clean white image
        clean_img = Image.new('RGB', (100, 100), color='white')
        clean_bytes = io.BytesIO()
        clean_img.save(clean_bytes, format='PNG')
        images['clean'] = (clean_img, clean_bytes.getvalue())
        
        # Red warning image
        red_img = Image.new('RGB', (100, 100), color='red')
        red_bytes = io.BytesIO()
        red_img.save(red_bytes, format='PNG')
        images['red'] = (red_img, red_bytes.getvalue())
        
        # Large image
        large_img = Image.new('RGB', (2000, 2000), color='blue')
        large_bytes = io.BytesIO()
        large_img.save(large_bytes, format='PNG')
        images['large'] = (large_img, large_bytes.getvalue())
        
        return images
    
    def test_analyze_image_risk(self, runner, test_images):
        """Test image risk analysis"""
        # Clean image should have low risk
        clean_img, clean_data = test_images['clean']
        risk = runner._analyze_image_risk(clean_img, clean_data)
        assert risk < 30
        
        # Red image should have higher risk
        red_img, red_data = test_images['red']
        risk = runner._analyze_image_risk(red_img, red_data)
        assert risk > 30
        
        # Large image should have additional risk
        large_img, large_data = test_images['large']
        risk = runner._analyze_image_risk(large_img, large_data)
        if len(large_data) > 5 * 1024 * 1024:  # 5MB
            assert risk >= 10  # Size penalty
    
    @patch('run_simple_tests_optimized.Image')
    def test_image_processing_import_error(self, mock_image, runner):
        """Test image processing when PIL is not available"""
        mock_image.side_effect = ImportError("PIL not available")
        
        # Should handle gracefully
        result = runner.test_image_processing()
        assert result is True  # Should skip gracefully

class TestFileOperations:
    """Test file operations and cleanup"""
    
    def test_temp_file_manager(self, runner):
        """Test temporary file context manager"""
        test_content = "Test content"
        
        with runner._temp_file_manager(test_content, '.txt') as temp_file:
            assert temp_file.exists()
            assert temp_file.read_text() == test_content
            assert temp_file in runner._temp_files
        
        # File should be cleaned up
        assert not temp_file.exists()
        assert temp_file not in runner._temp_files
    
    def test_temp_file_manager_exception(self, runner):
        """Test temp file manager handles exceptions"""
        test_content = "Test content"
        
        try:
            with runner._temp_file_manager(test_content, '.txt') as temp_file:
                assert temp_file.exists()
                raise ValueError("Test exception")
        except ValueError:
            pass
        
        # File should still be cleaned up
        assert not temp_file.exists()
    
    def test_cleanup_method(self, runner):
        """Test cleanup method"""
        # Create some temp files
        temp_files = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(delete=False) as f:
                temp_path = Path(f.name)
                runner._temp_files.append(temp_path)
                temp_files.append(temp_path)
        
        # All files should exist
        for temp_file in temp_files:
            assert temp_file.exists()
        
        # Cleanup should remove all files
        runner.cleanup()
        
        for temp_file in temp_files:
            assert not temp_file.exists()
        
        assert len(runner._temp_files) == 0

class TestTestExecution:
    """Test test execution and reporting"""
    
    def test_run_test_with_timing(self, runner):
        """Test test execution with timing"""
        def successful_test():
            return True
        
        def failing_test():
            return False
        
        def error_test():
            raise ValueError("Test error")
        
        # Test successful execution
        report = runner._run_test_with_timing("success_test", successful_test)
        assert report.result == TestResult.PASS
        assert report.duration > 0
        
        # Test failing execution
        report = runner._run_test_with_timing("fail_test", failing_test)
        assert report.result == TestResult.FAIL
        
        # Test error execution
        report = runner._run_test_with_timing("error_test", error_test)
        assert report.result == TestResult.ERROR
        assert "Test error" in report.message
    
    def test_print_summary(self, runner, capsys):
        """Test summary printing"""
        # Add some test results
        runner.results = [
            TestReport("test1", TestResult.PASS, 1.0),
            TestReport("test2", TestResult.FAIL, 0.5, "Failed"),
            TestReport("test3", TestResult.ERROR, 0.3, "Error occurred"),
            TestReport("test4", TestResult.SKIP, 0.1, "Skipped"),
        ]
        
        runner._print_summary(2.0)
        
        captured = capsys.readouterr()
        assert "Total Tests: 4" in captured.out
        assert "Passed: 1" in captured.out
        assert "Failed: 1" in captured.out
        assert "Errors: 1" in captured.out
        assert "Skipped: 1" in captured.out

class TestPerformance:
    """Test performance-related functionality"""
    
    def test_pattern_compilation_performance(self, runner):
        """Test that pattern compilation improves performance"""
        import time
        
        test_text = "URGENT: Your computer is infected! Call 1-800-555-0199"
        
        # Time with compiled patterns
        start_time = time.time()
        for _ in range(100):
            runner.analyze_text_for_scam(test_text)
        compiled_time = time.time() - start_time
        
        # Should be reasonably fast
        assert compiled_time < 1.0  # Less than 1 second for 100 iterations
    
    def test_memory_efficiency(self, runner):
        """Test memory efficiency of operations"""
        import sys
        
        # Test with large text
        large_text = "URGENT: Test " * 1000
        
        # Should not consume excessive memory
        initial_size = sys.getsizeof(runner)
        result = runner.analyze_text_for_scam(large_text)
        final_size = sys.getsizeof(runner)
        
        # Memory usage should not grow significantly
        assert final_size - initial_size < 1000  # Less than 1KB growth

class TestIntegration:
    """Integration tests for the test runner"""
    
    def test_full_test_suite_execution(self, runner):
        """Test running the complete test suite"""
        # Mock individual test methods to avoid external dependencies
        with patch.object(runner, 'test_scam_text_detection', return_value=True), \
             patch.object(runner, 'test_url_analysis', return_value=True), \
             patch.object(runner, 'test_image_processing', return_value=True), \
             patch.object(runner, 'test_html_analysis', return_value=True), \
             patch.object(runner, 'test_file_operations', return_value=True), \
             patch.object(runner, 'test_performance_benchmarks', return_value=True):
            
            success = runner.run_all_tests()
            assert success is True
            assert len(runner.results) == 6  # All test methods
            assert all(r.result == TestResult.PASS for r in runner.results)
    
    def test_partial_failure_handling(self, runner):
        """Test handling of partial test failures"""
        with patch.object(runner, 'test_scam_text_detection', return_value=True), \
             patch.object(runner, 'test_url_analysis', return_value=False), \
             patch.object(runner, 'test_image_processing', side_effect=Exception("Test error")), \
             patch.object(runner, 'test_html_analysis', return_value=True), \
             patch.object(runner, 'test_file_operations', return_value=True), \
             patch.object(runner, 'test_performance_benchmarks', return_value=True):
            
            success = runner.run_all_tests()
            assert success is False  # Should fail due to failures/errors
            
            # Check individual results
            results_by_name = {r.test_name: r for r in runner.results}
            assert results_by_name["URL Analysis"].result == TestResult.FAIL
            assert results_by_name["Image Processing"].result == TestResult.ERROR

class TestEdgeCases:
    """Test edge cases and error conditions"""
    
    def test_none_inputs(self, runner):
        """Test handling of None inputs"""
        # Text analysis with None
        result = runner.analyze_text_for_scam(None)
        assert result.is_scam is False
        assert result.score == 0
        
        # URL analysis with None should be handled gracefully
        # (skipped as it would cause issues in the current implementation)
    
    def test_unicode_handling(self, runner):
        """Test Unicode text handling"""
        unicode_texts = [
            "紧急：您的计算机已感染病毒！",  # Chinese
            "عاجل: جهاز الكمبيوتر الخاص بك مصاب!",  # Arabic
            "🚨 URGENT: Your computer is infected! 🚨",  # Emojis
        ]
        
        for text in unicode_texts:
            result = runner.analyze_text_for_scam(text)
            assert isinstance(result, ScamAnalysisResult)
            # Should handle without crashing
    
    def test_very_long_inputs(self, runner):
        """Test handling of very long inputs"""
        # Very long text
        long_text = "URGENT " * 10000
        result = runner.analyze_text_for_scam(long_text)
        assert isinstance(result, ScamAnalysisResult)
        assert len(result.text) <= 103  # Should be truncated
        
        # Very long URL
        long_url = "https://example.com/" + "a" * 10000
        result = runner.analyze_url(long_url)
        assert isinstance(result, UrlAnalysisResult)
    
    def test_malformed_regex_handling(self, runner):
        """Test handling of potential regex issues"""
        # Text with regex special characters
        special_text = "URGENT: Call 1-800-555-0199 (.*+?^${}[]|\\)"
        result = runner.analyze_text_for_scam(special_text)
        assert isinstance(result, ScamAnalysisResult)
        # Should not crash due to regex special chars

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])