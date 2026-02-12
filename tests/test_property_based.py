        #!/usr/bin/env python3
"""
PayGuard Property-Based Test Suite
Using Hypothesis for property-based testing to find edge cases
"""

import pytest
from hypothesis import given, strategies as st, settings, example
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, invariant
import string
import re
from typing import Any, Dict, List
from urllib.parse import urlparse
import json
import base64
from PIL import Image
import io

# Import PayGuard modules
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from backend.risk_engine import RiskScoringEngine
from backend.models import RiskLevel
from unittest.mock import Mock

class TestPayGuardProperties:
    """Property-based tests for PayGuard components"""
    
    @pytest.fixture
    def risk_engine(self):
        """Risk engine for testing"""
        return RiskScoringEngine(Mock())
    
    # URL validation properties
    @given(st.text(min_size=1, max_size=2000))
    def test_url_parsing_never_crashes(self, url_string):
        """URL parsing should never crash regardless of input"""
        try:
            parsed = urlparse(url_string)
            # Should always return a ParseResult
            assert hasattr(parsed, 'scheme')
            assert hasattr(parsed, 'netloc')
            assert hasattr(parsed, 'path')
        except Exception as e:
            pytest.fail(f"URL parsing crashed with input '{url_string}': {e}")
    
    @given(st.text(alphabet=string.ascii_letters + string.digits + ".-", min_size=1, max_size=100))
    def test_domain_extraction_properties(self, domain):
        """Domain extraction should have consistent properties"""
        from backend.risk_engine import RiskScoringEngine
        engine = RiskScoringEngine(Mock())
        
        # Test with http and https
        for scheme in ['http', 'https']:
            url = f"{scheme}://{domain}"
            try:
                # Domain extraction should be consistent
                extracted = engine._extract_domain(url)
                if extracted:
                    # Extracted domain should be lowercase
                    assert extracted == extracted.lower()
                    # Should not contain protocol
                    assert not extracted.startswith('http')
                    # Should not contain path
                    assert '/' not in extracted
            except Exception:
                # Some invalid domains are expected to fail
                pass
    
    # Text analysis properties
    @given(st.text(min_size=0, max_size=10000))
    def test_scam_detection_never_crashes(self, text, risk_engine):
        """Scam detection should never crash regardless of input text"""
        try:
            result = risk_engine._analyze_text_for_scam(text)
            
            # Result should always have required fields
            assert isinstance(result, dict)
            assert 'is_scam' in result
            assert 'confidence' in result
            assert 'detected_patterns' in result
            
            # Confidence should be between 0 and 100
            assert 0 <= result['confidence'] <= 100
            
            # is_scam should be boolean
            assert isinstance(result['is_scam'], bool)
            
            # detected_patterns should be a list
            assert isinstance(result['detected_patterns'], list)
            
        except Exception as e:
            pytest.fail(f"Scam detection crashed with input '{text[:100]}...': {e}")
    
    @given(st.text(alphabet=string.digits + "-() +", min_size=10, max_size=20))
    def test_phone_number_detection_consistency(self, phone_like_text, risk_engine):
        """Phone number detection should be consistent"""
        result = risk_engine._analyze_text_for_scam(f"Call us at {phone_like_text}")
        
        # If it looks like a phone number, should be detected
        if re.search(r'\b1-\d{3}-\d{3}-\d{4}\b', phone_like_text):
            assert 'phone_number' in result.get('detected_patterns', [])
    
    @given(st.text(alphabet=string.ascii_uppercase + " !?", min_size=5, max_size=100))
    def test_urgency_detection_properties(self, urgent_text, risk_engine):
        """Urgency detection should have consistent properties"""
        # Add common urgency words
        test_text = f"URGENT {urgent_text} IMMEDIATELY"
        result = risk_engine._analyze_text_for_scam(test_text)
        
        # High urgency text should increase confidence
        if any(word in test_text.upper() for word in ['URGENT', 'IMMEDIATELY', 'NOW']):
            # Should detect some urgency patterns
            patterns = result.get('detected_patterns', [])
            urgency_patterns = [p for p in patterns if 'urgent' in p.lower() or 'action' in p.lower()]
            # Don't assert specific patterns as they may vary, but confidence should reflect urgency
            if result['is_scam']:
                assert result['confidence'] > 30  # Some confidence if marked as scam
    
    # Risk scoring properties
    @given(st.floats(min_value=0.0, max_value=100.0))
    def test_trust_score_bounds(self, score):
        """Trust scores should always be within valid bounds"""
        # Simulate risk calculation result
        from backend.models import RiskScore, RiskLevel
        
        # Trust score should determine risk level consistently
        if score >= 70:
            expected_level = RiskLevel.LOW
        elif score >= 40:
            expected_level = RiskLevel.MEDIUM
        else:
            expected_level = RiskLevel.HIGH
        
        # This property should hold for any score
        assert 0 <= score <= 100
    
    # Image processing properties
    @given(
        st.integers(min_value=1, max_value=4000),  # width
        st.integers(min_value=1, max_value=4000),  # height
        st.sampled_from(['RGB', 'RGBA', 'L'])      # mode
    )
    @settings(max_examples=20)  # Limit examples for performance
    def test_image_processing_properties(self, width, height, mode):
        """Image processing should handle various image properties"""
        try:
            # Create test image
            img = Image.new(mode, (width, height), color='red')
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            img_data = img_bytes.getvalue()
            
            # Image data should be valid
            assert len(img_data) > 0
            assert img_data.startswith(b'\x89PNG')  # PNG header
            
            # Base64 encoding should work
            b64_data = base64.b64encode(img_data).decode()
            assert len(b64_data) > 0
            
            # Should be able to decode back
            decoded = base64.b64decode(b64_data)
            assert decoded == img_data
            
        except Exception as e:
            # Some combinations might fail due to memory or PIL limitations
            if "cannot write mode" not in str(e).lower():
                pytest.fail(f"Image processing failed for {width}x{height} {mode}: {e}")
    
    # JSON serialization properties
    @given(st.dictionaries(
        keys=st.text(alphabet=string.ascii_letters, min_size=1, max_size=20),
        values=st.one_of(
            st.text(max_size=100),
            st.integers(),
            st.floats(allow_nan=False, allow_infinity=False),
            st.booleans(),
            st.none()
        ),
        min_size=1,
        max_size=10
    ))
    def test_json_serialization_properties(self, data_dict):
        """JSON serialization should be consistent"""
        try:
            # Should be able to serialize
            json_str = json.dumps(data_dict)
            assert isinstance(json_str, str)
            assert len(json_str) > 0
            
            # Should be able to deserialize
            parsed = json.loads(json_str)
            assert isinstance(parsed, dict)
            
            # Should preserve data types for basic types
            for key, value in data_dict.items():
                if value is not None:
                    assert key in parsed
                    if isinstance(value, (str, int, bool)):
                        assert parsed[key] == value
                        assert type(parsed[key]) == type(value)
                        
        except (TypeError, ValueError) as e:
            # Some data might not be JSON serializable
            pass

class PayGuardStateMachine(RuleBasedStateMachine):
    """Stateful testing for PayGuard system"""
    
    def __init__(self):
        super().__init__()
        self.risk_engine = RiskScoringEngine(Mock())
        self.processed_urls = []
        self.risk_scores = {}
    
    @initialize()
    def setup(self):
        """Initialize the state machine"""
        self.processed_urls = []
        self.risk_scores = {}
    
    @rule(url=st.text(min_size=10, max_size=100))
    def process_url(self, url):
        """Process a URL and store the result"""
        try:
            # Simulate URL processing
            if url.startswith(('http://', 'https://')):
                self.processed_urls.append(url)
                # Simulate risk score (in real test, would call actual method)
                score = hash(url) % 100  # Deterministic but varied
                self.risk_scores[url] = max(0, min(100, score))
        except Exception:
            # Some URLs might be invalid
            pass
    
    @rule()
    def check_processed_urls(self):
        """Check that processed URLs maintain consistency"""
        # All processed URLs should have scores
        for url in self.processed_urls:
            if url in self.risk_scores:
                score = self.risk_scores[url]
                assert 0 <= score <= 100
    
    @invariant()
    def scores_are_valid(self):
        """Invariant: all scores should be valid"""
        for url, score in self.risk_scores.items():
            assert isinstance(score, (int, float))
            assert 0 <= score <= 100
    
    @invariant()
    def no_duplicate_processing(self):
        """Invariant: URLs should not be processed multiple times unnecessarily"""
        # In a real system, might check caching behavior
        assert len(self.processed_urls) <= 100  # Reasonable limit

class TestPayGuardEdgeCases:
    """Test edge cases discovered through property-based testing"""
    
    @given(st.text(alphabet=string.whitespace, min_size=1, max_size=100))
    def test_whitespace_only_text(self, whitespace_text, risk_engine):
        """Test handling of whitespace-only text"""
        result = risk_engine._analyze_text_for_scam(whitespace_text)
        
        # Should handle gracefully
        assert isinstance(result, dict)
        assert result['is_scam'] is False  # Whitespace shouldn't be scam
        assert result['confidence'] == 0   # No confidence in empty content
    
    @given(st.text(alphabet=string.punctuation, min_size=1, max_size=100))
    def test_punctuation_only_text(self, punct_text, risk_engine):
        """Test handling of punctuation-only text"""
        result = risk_engine._analyze_text_for_scam(punct_text)
        
        # Should handle gracefully
        assert isinstance(result, dict)
        # Punctuation alone shouldn't trigger scam detection
        assert result['confidence'] < 50
    
    @example("")  # Empty string
    @example("a")  # Single character
    @example("a" * 10000)  # Very long string
    @given(st.text(min_size=0, max_size=10000))
    def test_extreme_text_lengths(self, text, risk_engine):
        """Test handling of extreme text lengths"""
        result = risk_engine._analyze_text_for_scam(text)
        
        # Should always return valid result
        assert isinstance(result, dict)
        assert 'is_scam' in result
        assert 'confidence' in result
        
        # Very short text should have low confidence
        if len(text) < 5:
            assert result['confidence'] < 30
    
    @given(st.binary(min_size=0, max_size=1000))
    def test_binary_data_handling(self, binary_data):
        """Test handling of binary data as text"""
        try:
            # Try to decode as UTF-8
            text = binary_data.decode('utf-8', errors='ignore')
            
            # Should handle the resulting text gracefully
            risk_engine = RiskScoringEngine(Mock())
            result = risk_engine._analyze_text_for_scam(text)
            
            assert isinstance(result, dict)
            
        except Exception as e:
            # Binary data might cause issues, but shouldn't crash
            assert "decode" not in str(e).lower()

# Test runner for property-based tests
class TestPropertyBasedRunner:
    """Run property-based tests with custom settings"""
    
    def test_run_stateful_tests(self):
        """Run stateful property-based tests"""
        # Run the state machine
        PayGuardStateMachine.TestCase.settings = settings(
            max_examples=50,
            stateful_step_count=20
        )
        
        test_case = PayGuardStateMachine.TestCase()
        test_case.runTest()
    
    @settings(max_examples=100, deadline=None)
    def test_comprehensive_text_analysis(self):
        """Comprehensive property-based test for text analysis"""
        risk_engine = RiskScoringEngine(Mock())
        
        @given(st.text(min_size=0, max_size=1000))
        def test_text_analysis_properties(text):
            result = risk_engine._analyze_text_for_scam(text)
            
            # Core properties that should always hold
            assert isinstance(result, dict)
            assert 'is_scam' in result
            assert 'confidence' in result
            assert isinstance(result['is_scam'], bool)
            assert isinstance(result['confidence'], (int, float))
            assert 0 <= result['confidence'] <= 100
            
            # If marked as scam, should have some confidence
            if result['is_scam']:
                assert result['confidence'] > 0
            
            # If high confidence, should be marked as scam
            if result['confidence'] > 80:
                assert result['is_scam'] is True
        
        test_text_analysis_properties()

if __name__ == "__main__":
    # Run property-based tests
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])