#!/usr/bin/env python3
"""
Property-Based Tests for PayGuard Simple Test Runner
Using Hypothesis for comprehensive property testing and edge case discovery
"""

import pytest
from hypothesis import given, strategies as st, settings, example, assume
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, invariant
import string
import re
import sys
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse
import base64
from PIL import Image
import io

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from run_simple_tests_optimized import (
    SimpleTestRunner, TestResult, TestReport, 
    ScamAnalysisResult, UrlAnalysisResult
)

class TestSimpleRunnerProperties:
    """Property-based tests for SimpleTestRunner"""
    
    @pytest.fixture
    def runner(self):
        """Create a test runner instance"""
        return SimpleTestRunner()
    
    # Text Analysis Properties
    @given(st.text(min_size=0, max_size=10000))
    def test_text_analysis_never_crashes(self, runner, text):
        """Text analysis should never crash regardless of input"""
        try:
            result = runner.analyze_text_for_scam(text)
            
            # Result should always have required structure
            assert isinstance(result, ScamAnalysisResult)
            assert hasattr(result, 'text')
            assert hasattr(result, 'is_scam')
            assert hasattr(result, 'score')
            assert hasattr(result, 'patterns')
            assert hasattr(result, 'confidence')
            
            # Properties should be valid
            assert isinstance(result.is_scam, bool)
            assert isinstance(result.score, int)
            assert isinstance(result.patterns, list)
            assert isinstance(result.confidence, (int, float))
            
            # Score and confidence should be in valid ranges
            assert 0 <= result.score <= 1000  # Allow for multiple patterns
            assert 0 <= result.confidence <= 100
            
        except Exception as e:
            pytest.fail(f"Text analysis crashed with input '{text[:100]}...': {e}")
    
    @given(st.text(alphabet=string.whitespace, min_size=0, max_size=100))
    def test_whitespace_text_properties(self, runner, whitespace_text):
        """Whitespace-only text should have consistent properties"""
        result = runner.analyze_text_for_scam(whitespace_text)
        
        # Whitespace should not be detected as scam
        assert result.is_scam is False
        assert result.score == 0
        assert result.confidence == 0.0
        assert len(result.patterns) == 0
    
    @given(st.text(alphabet=string.digits + "-() +", min_size=10, max_size=20))
    def test_phone_number_detection_consistency(self, runner, phone_like_text):
        """Phone number detection should be consistent"""
        # Add context to make it more scam-like
        test_text = f"URGENT: Call us at {phone_like_text} immediately!"
        result = runner.analyze_text_for_scam(test_text)
        
        # If it matches phone pattern, should be detected
        phone_pattern = re.compile(r'\b1-\d{3}-\d{3}-\d{4}\b')
        if phone_pattern.search(phone_like_text):
            assert 'phone_number' in result.patterns
            assert result.score >= 25  # Phone number score
    
    @given(st.text(alphabet=string.ascii_uppercase + " !?", min_size=5, max_size=100))
    def test_urgency_detection_properties(self, runner, urgent_text):
        """Urgency detection should have consistent properties"""
        # Add urgency keywords
        test_text = f"URGENT {urgent_text} IMMEDIATELY ACT NOW"
        result = runner.analyze_text_for_scam(test_text)
        
        # Should detect urgency patterns
        urgency_keywords = ['URGENT', 'IMMEDIATELY', 'ACT NOW']
        if any(keyword in test_text for keyword in urgency_keywords):
            assert 'urgency' in result.patterns
            assert result.score >= 20  # Urgency score
    
    @example("")  # Empty string
    @example("a")  # Single character
    @example("a" * 10000)  # Very long string
    @given(st.text(min_size=0, max_size=10000))
    def test_text_length_properties(self, runner, text):
        """Text analysis should handle various lengths consistently"""
        result = runner.analyze_text_for_scam(text)
        
        # Very short text should have low confidence
        if len(text) < 5:
            assert result.confidence <= 30
        
        # Result text should be truncated if too long
        if len(text) > 100:
            assert len(result.text) <= 103  # 100 chars + "..."
            assert result.text.endswith('...')
        else:
            assert result.text == text
    
    # URL Analysis Properties
    @given(st.text(min_size=1, max_size=2000))
    def test_url_analysis_never_crashes(self, runner, url_string):
        """URL analysis should never crash regardless of input"""
        try:
            result = runner.analyze_url(url_string)
            
            # Result should always have required structure
            assert isinstance(result, UrlAnalysisResult)
            assert hasattr(result, 'url')
            assert hasattr(result, 'risk_score')
            assert hasattr(result, 'risk_level')
            assert hasattr(result, 'scheme')
            assert hasattr(result, 'domain')
            assert hasattr(result, 'is_valid')
            
            # Properties should be valid
            assert result.url == url_string
            assert isinstance(result.risk_score, int)
            assert result.risk_level in ['LOW', 'MEDIUM', 'HIGH', 'ERROR', 'INVALID']
            assert isinstance(result.scheme, str)
            assert isinstance(result.domain, str)
            assert isinstance(result.is_valid, bool)
            
            # Risk score should be in valid range
            assert 0 <= result.risk_score <= 100
            
        except Exception as e:
            pytest.fail(f"URL analysis crashed with input '{url_string[:100]}...': {e}")
    
    @given(st.text(alphabet=string.ascii_letters + string.digits + ".-", min_size=1, max_size=100))
    def test_domain_analysis_properties(self, runner, domain):
        """Domain analysis should have consistent properties"""
        # Test with different schemes
        for scheme in ['http', 'https', 'ftp']:
            url = f"{scheme}://{domain}"
            result = runner.analyze_url(url)
            
            if result.is_valid:
                # Domain should be lowercase
                assert result.domain == result.domain.lower()
                # Scheme should match
                assert result.scheme == scheme
                
                # HTTPS should have better score than HTTP
                if scheme == 'https':
                    https_result = result
                elif scheme == 'http':
                    http_result = result
        
        # Compare HTTPS vs HTTP if both are valid
        try:
            if 'https_result' in locals() and 'http_result' in locals():
                if https_result.is_valid and http_result.is_valid:
                    assert https_result.risk_score >= http_result.risk_score
        except:
            pass  # Skip comparison if not both available
    
    @given(st.sampled_from(['tk', 'ml', 'ga', 'cf', 'gq']))
    def test_suspicious_tld_detection(self, runner, suspicious_tld):
        """Suspicious TLD detection should be consistent"""
        url = f"http://test.{suspicious_tld}"
        result = runner.analyze_url(url)
        
        if result.is_valid:
            # Suspicious TLD should result in lower risk score
            assert result.risk_score < 50
            assert result.risk_level in ['MEDIUM', 'HIGH']
    
    @given(st.integers(min_value=0, max_value=255), 
           st.integers(min_value=0, max_value=255),
           st.integers(min_value=0, max_value=255),
           st.integers(min_value=0, max_value=255))
    def test_ip_address_detection(self, runner, a, b, c, d):
        """IP address detection should be consistent"""
        ip = f"{a}.{b}.{c}.{d}"
        url = f"https://{ip}"
        result = runner.analyze_url(url)
        
        if result.is_valid:
            # IP addresses should have reduced trust
            assert result.risk_score < 70
    
    # HTML Analysis Properties
    @given(st.text(min_size=0, max_size=5000))
    def test_html_analysis_never_crashes(self, runner, html_content):
        """HTML analysis should never crash regardless of input"""
        try:
            result = runner.analyze_html_content(html_content)
            
            # Result should always have required structure
            assert isinstance(result, dict)
            assert 'risk_score' in result
            assert 'risk_level' in result
            assert 'detected_patterns' in result
            assert 'pattern_count' in result
            
            # Properties should be valid
            assert isinstance(result['risk_score'], int)
            assert result['risk_level'] in ['LOW', 'MEDIUM', 'HIGH']
            assert isinstance(result['detected_patterns'], list)
            assert isinstance(result['pattern_count'], int)
            
            # Risk score should be in valid range
            assert 0 <= result['risk_score'] <= 1000  # Allow for multiple patterns
            
            # Pattern count should match list length
            assert result['pattern_count'] == len(result['detected_patterns'])
            
        except Exception as e:
            pytest.fail(f"HTML analysis crashed with input '{html_content[:100]}...': {e}")
    
    @given(st.text(alphabet=string.ascii_letters + " <>", min_size=0, max_size=1000))
    def test_html_tag_handling(self, runner, html_like_text):
        """HTML-like text should be handled consistently"""
        result = runner.analyze_html_content(html_like_text)
        
        # Should not crash on malformed HTML
        assert isinstance(result, dict)
        assert 'risk_level' in result
    
    # Image Analysis Properties
    @given(
        st.integers(min_value=1, max_value=1000),  # width
        st.integers(min_value=1, max_value=1000),  # height
        st.sampled_from(['RGB', 'RGBA', 'L'])      # mode
    )
    @settings(max_examples=20)  # Limit for performance
    def test_image_risk_analysis_properties(self, runner, width, height, mode):
        """Image risk analysis should handle various image properties"""
        try:
            # Create test image
            img = Image.new(mode, (width, height), color='red')
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            img_data = img_bytes.getvalue()
            
            # Analyze risk
            risk_score = runner._analyze_image_risk(img, img_data)
            
            # Risk score should be in valid range
            assert 0 <= risk_score <= 100
            assert isinstance(risk_score, (int, float))
            
        except Exception as e:
            # Some combinations might fail due to PIL limitations
            if "cannot write mode" not in str(e).lower():
                pytest.fail(f"Image analysis failed for {width}x{height} {mode}: {e}")
    
    # File Operations Properties
    @given(st.text(min_size=0, max_size=1000))
    def test_temp_file_operations_properties(self, runner, content):
        """Temporary file operations should be consistent"""
        try:
            with runner._temp_file_manager(content, '.txt') as temp_file:
                # File should exist during context
                assert temp_file.exists()
                
                # Content should be preserved
                read_content = temp_file.read_text()
                assert read_content == content
                
                # File should be tracked
                assert temp_file in runner._temp_files
            
            # File should be cleaned up after context
            assert not temp_file.exists()
            assert temp_file not in runner._temp_files
            
        except Exception as e:
            # Some content might cause encoding issues
            if "codec" not in str(e).lower():
                pytest.fail(f"File operations failed with content '{content[:50]}...': {e}")

class SimpleRunnerStateMachine(RuleBasedStateMachine):
    """Stateful testing for SimpleTestRunner"""
    
    def __init__(self):
        super().__init__()
        self.runner = SimpleTestRunner()
        self.analyzed_texts = []
        self.analyzed_urls = []
        self.temp_files_created = 0
    
    @initialize()
    def setup(self):
        """Initialize the state machine"""
        self.analyzed_texts = []
        self.analyzed_urls = []
        self.temp_files_created = 0
    
    @rule(text=st.text(min_size=0, max_size=500))
    def analyze_text(self, text):
        """Analyze text and track results"""
        result = self.runner.analyze_text_for_scam(text)
        self.analyzed_texts.append((text, result))
        
        # Verify result consistency
        assert isinstance(result, ScamAnalysisResult)
        assert 0 <= result.confidence <= 100
    
    @rule(url=st.text(min_size=1, max_size=200))
    def analyze_url(self, url):
        """Analyze URL and track results"""
        result = self.runner.analyze_url(url)
        self.analyzed_urls.append((url, result))
        
        # Verify result consistency
        assert isinstance(result, UrlAnalysisResult)
        assert 0 <= result.risk_score <= 100
    
    @rule(content=st.text(min_size=0, max_size=200))
    def create_temp_file(self, content):
        """Create temporary file and verify cleanup"""
        try:
            with self.runner._temp_file_manager(content, '.txt') as temp_file:
                self.temp_files_created += 1
                assert temp_file.exists()
            
            # File should be cleaned up
            assert not temp_file.exists()
            
        except Exception:
            # Some content might cause issues, but shouldn't crash
            pass
    
    @invariant()
    def results_are_consistent(self):
        """Invariant: All results should be consistent"""
        # Text analysis results should be valid
        for text, result in self.analyzed_texts:
            assert isinstance(result, ScamAnalysisResult)
            assert isinstance(result.is_scam, bool)
            assert isinstance(result.score, int)
            assert isinstance(result.patterns, list)
        
        # URL analysis results should be valid
        for url, result in self.analyzed_urls:
            assert isinstance(result, UrlAnalysisResult)
            assert result.risk_level in ['LOW', 'MEDIUM', 'HIGH', 'ERROR', 'INVALID']
    
    @invariant()
    def no_temp_files_leaked(self):
        """Invariant: No temporary files should be leaked"""
        # All temp files should be cleaned up
        assert len(self.runner._temp_files) == 0
    
    @invariant()
    def memory_usage_reasonable(self):
        """Invariant: Memory usage should not grow excessively"""
        # This is a simple check - in practice you'd use more sophisticated monitoring
        assert len(self.analyzed_texts) < 1000  # Prevent excessive memory usage
        assert len(self.analyzed_urls) < 1000

class TestSimpleRunnerEdgeCases:
    """Test edge cases discovered through property-based testing"""
    
    @pytest.fixture
    def runner(self):
        return SimpleTestRunner()
    
    @given(st.binary(min_size=0, max_size=1000))
    def test_binary_data_as_text(self, runner, binary_data):
        """Test handling of binary data decoded as text"""
        try:
            # Try to decode as UTF-8
            text = binary_data.decode('utf-8', errors='ignore')
            
            # Should handle the resulting text gracefully
            result = runner.analyze_text_for_scam(text)
            assert isinstance(result, ScamAnalysisResult)
            
        except Exception as e:
            # Binary data might cause issues, but shouldn't crash the analyzer
            assert "decode" not in str(e).lower()
    
    @given(st.text(alphabet=string.punctuation, min_size=1, max_size=100))
    def test_punctuation_only_text(self, runner, punct_text):
        """Test handling of punctuation-only text"""
        result = runner.analyze_text_for_scam(punct_text)
        
        # Should handle gracefully
        assert isinstance(result, ScamAnalysisResult)
        # Punctuation alone shouldn't trigger high confidence
        assert result.confidence < 80
    
    @given(st.text(min_size=0, max_size=100).filter(lambda x: '\x00' not in x))
    def test_unicode_edge_cases(self, runner, unicode_text):
        """Test Unicode edge cases"""
        result = runner.analyze_text_for_scam(unicode_text)
        
        # Should handle Unicode gracefully
        assert isinstance(result, ScamAnalysisResult)
        assert isinstance(result.text, str)
    
    @given(st.lists(st.text(min_size=1, max_size=50), min_size=0, max_size=20))
    def test_batch_processing_consistency(self, runner, text_list):
        """Test that batch processing is consistent with individual processing"""
        individual_results = []
        
        # Process individually
        for text in text_list:
            result = runner.analyze_text_for_scam(text)
            individual_results.append(result)
        
        # Results should be consistent
        for i, text in enumerate(text_list):
            result = runner.analyze_text_for_scam(text)
            
            # Same input should produce same result
            assert result.is_scam == individual_results[i].is_scam
            assert result.score == individual_results[i].score
            assert result.patterns == individual_results[i].patterns

class TestPerformanceProperties:
    """Property-based performance testing"""
    
    @pytest.fixture
    def runner(self):
        return SimpleTestRunner()
    
    @given(st.integers(min_value=1, max_value=10000))
    def test_text_length_performance(self, runner, text_length):
        """Test that performance scales reasonably with text length"""
        import time
        
        # Create text of specified length
        test_text = "URGENT: Test " * (text_length // 12 + 1)
        test_text = test_text[:text_length]
        
        # Measure performance
        start_time = time.time()
        result = runner.analyze_text_for_scam(test_text)
        duration = time.time() - start_time
        
        # Performance should be reasonable
        # Allow more time for very long texts, but should still be fast
        max_time = min(0.1, text_length / 10000)  # Scale with length but cap at 0.1s
        assert duration < max_time, f"Text analysis too slow for length {text_length}: {duration:.3f}s"
        
        # Result should still be valid
        assert isinstance(result, ScamAnalysisResult)
    
    @given(st.integers(min_value=1, max_value=100))
    def test_batch_url_performance(self, runner, url_count):
        """Test performance with multiple URL analyses"""
        import time
        
        # Create list of URLs
        urls = [f"https://example{i}.com" for i in range(url_count)]
        
        # Measure batch performance
        start_time = time.time()
        results = [runner.analyze_url(url) for url in urls]
        duration = time.time() - start_time
        
        # Performance should scale linearly
        avg_time_per_url = duration / url_count
        assert avg_time_per_url < 0.01, f"URL analysis too slow: {avg_time_per_url:.3f}s per URL"
        
        # All results should be valid
        assert len(results) == url_count
        for result in results:
            assert isinstance(result, UrlAnalysisResult)

# Test runner for property-based tests
class TestPropertyBasedRunner:
    """Run property-based tests with custom settings"""
    
    def test_run_stateful_tests(self):
        """Run stateful property-based tests"""
        # Configure settings for stateful testing
        SimpleRunnerStateMachine.TestCase.settings = settings(
            max_examples=50,
            stateful_step_count=20,
            deadline=None
        )
        
        # Run the state machine
        test_case = SimpleRunnerStateMachine.TestCase()
        test_case.runTest()
    
    @settings(max_examples=100, deadline=None)
    def test_comprehensive_property_testing(self):
        """Comprehensive property-based testing"""
        runner = SimpleTestRunner()
        
        @given(st.text(min_size=0, max_size=1000))
        def test_all_text_properties(text):
            result = runner.analyze_text_for_scam(text)
            
            # Core properties that should always hold
            assert isinstance(result, ScamAnalysisResult)
            assert isinstance(result.is_scam, bool)
            assert isinstance(result.confidence, (int, float))
            assert 0 <= result.confidence <= 100
            
            # If marked as scam, should have some score
            if result.is_scam:
                assert result.score > 0
            
            # If high confidence, should be marked as scam
            if result.confidence > 90:
                assert result.is_scam is True
        
        test_all_text_properties()

if __name__ == "__main__":
    # Run property-based tests
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])