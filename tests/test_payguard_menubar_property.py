#!/usr/bin/env python3
"""
Property-Based Tests for PayGuard Menu Bar
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
import time
import threading
from PIL import Image
import io

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from payguard_menubar_optimized import (
    PayGuardMenuBarOptimized, ScamDetector, NotificationManager,
    PerformanceMonitor, AlertType, ScamPattern, DetectionResult
)

class TestScamDetectorProperties:
    """Property-based tests for ScamDetector"""
    
    @pytest.fixture
    def detector(self):
        return ScamDetector()
    
    # Text Analysis Properties
    @given(st.text(min_size=0, max_size=10000))
    def test_text_analysis_never_crashes(self, detector, text):
        """Text analysis should never crash regardless of input"""
        try:
            result = detector.analyze_text(text)
            
            # Result should always have required structure
            assert isinstance(result, DetectionResult)
            assert hasattr(result, 'is_scam')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'patterns')
            assert hasattr(result, 'message')
            assert hasattr(result, 'advice')
            
            # Properties should be valid
            assert isinstance(result.is_scam, bool)
            assert isinstance(result.confidence, (int, float))
            assert isinstance(result.patterns, list)
            assert isinstance(result.message, str)
            assert isinstance(result.advice, str)
            
            # Confidence should be in valid range
            assert 0 <= result.confidence <= 100
            
        except Exception as e:
            pytest.fail(f"Text analysis crashed with input '{text[:100]}...': {e}")
    
    @given(st.text(alphabet=string.whitespace, min_size=0, max_size=100))
    def test_whitespace_text_properties(self, detector, whitespace_text):
        """Whitespace-only text should have consistent properties"""
        result = detector.analyze_text(whitespace_text)
        
        # Whitespace should not be detected as scam
        assert result.is_scam is False
        assert result.confidence == 0.0
        assert len(result.patterns) == 0
    
    @given(st.text(alphabet=string.digits + "-() +", min_size=10, max_size=20))
    def test_phone_number_detection_consistency(self, detector, phone_like_text):
        """Phone number detection should be consistent"""
        # Add context to make it more scam-like
        test_text = f"URGENT: Call us at {phone_like_text} immediately!"
        result = detector.analyze_text(test_text)
        
        # If it matches phone pattern, should be detected
        phone_pattern = re.compile(r'\b1-\d{3}-\d{3}-\d{4}\b')
        if phone_pattern.search(phone_like_text):
            assert 'phone_number' in result.patterns
            assert result.confidence >= 25  # Phone number weight
    
    @given(st.text(alphabet=string.ascii_uppercase + " !?", min_size=5, max_size=100))
    def test_urgency_detection_properties(self, detector, urgent_text):
        """Urgency detection should have consistent properties"""
        # Add urgency keywords
        test_text = f"URGENT {urgent_text} IMMEDIATELY ACT NOW"
        result = detector.analyze_text(test_text)
        
        # Should detect urgency patterns
        urgency_keywords = ['URGENT', 'IMMEDIATELY', 'ACT NOW']
        if any(keyword in test_text for keyword in urgency_keywords):
            assert 'urgency' in result.patterns
            assert result.confidence >= 20  # Urgency weight
    
    @example("")  # Empty string
    @example("a")  # Single character
    @example("a" * 10000)  # Very long string
    @given(st.text(min_size=0, max_size=10000))
    def test_text_length_properties(self, detector, text):
        """Text analysis should handle various lengths consistently"""
        result = detector.analyze_text(text)
        
        # Very short text should have low confidence
        if len(text) < 10:
            assert result.confidence <= 50
        
        # Result should always be valid
        assert isinstance(result, DetectionResult)
        assert 0 <= result.confidence <= 100
    
    @given(st.text(min_size=1, max_size=1000))
    def test_text_caching_consistency(self, detector, text):
        """Text caching should produce consistent results"""
        # First analysis
        result1 = detector.analyze_text(text)
        
        # Second analysis should be identical (cached)
        result2 = detector.analyze_text(text)
        
        assert result1.is_scam == result2.is_scam
        assert result1.confidence == result2.confidence
        assert result1.patterns == result2.patterns
        assert result1.message == result2.message
        assert result1.advice == result2.advice
    
    @given(st.lists(st.text(min_size=1, max_size=100), min_size=1, max_size=20))
    def test_batch_analysis_consistency(self, detector, text_list):
        """Batch analysis should be consistent with individual analysis"""
        individual_results = []
        
        # Analyze individually
        for text in text_list:
            result = detector.analyze_text(text)
            individual_results.append(result)
        
        # Analyze again and compare
        for i, text in enumerate(text_list):
            result = detector.analyze_text(text)
            
            # Should be identical due to caching
            assert result.is_scam == individual_results[i].is_scam
            assert result.confidence == individual_results[i].confidence
            assert result.patterns == individual_results[i].patterns
    
    # Image Analysis Properties
    @given(
        st.integers(min_value=1, max_value=1000),  # width
        st.integers(min_value=1, max_value=1000),  # height
        st.sampled_from(['RGB', 'RGBA', 'L'])      # mode
    )
    @settings(max_examples=20)  # Limit for performance
    def test_image_analysis_properties(self, detector, width, height, mode):
        """Image analysis should handle various image properties"""
        try:
            # Create test image
            img = Image.new(mode, (width, height), color='red')
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            img_data = img_bytes.getvalue()
            
            # Analyze image
            result = detector.analyze_image_colors(img_data)
            
            # Result should be valid
            assert isinstance(result, DetectionResult)
            assert isinstance(result.is_scam, bool)
            assert isinstance(result.confidence, (int, float))
            assert 0 <= result.confidence <= 100
            
        except Exception as e:
            # Some combinations might fail due to PIL limitations
            if "cannot write mode" not in str(e).lower():
                pytest.fail(f"Image analysis failed for {width}x{height} {mode}: {e}")
    
    @given(st.binary(min_size=0, max_size=1000))
    def test_image_analysis_invalid_data(self, detector, binary_data):
        """Image analysis should handle invalid image data gracefully"""
        result = detector.analyze_image_colors(binary_data)
        
        # Should not crash and return valid result
        assert isinstance(result, DetectionResult)
        assert isinstance(result.is_scam, bool)
        assert 0 <= result.confidence <= 100

class TestNotificationManagerProperties:
    """Property-based tests for NotificationManager"""
    
    @pytest.fixture
    def notification_manager(self):
        manager = NotificationManager(cooldown_seconds=0.1)
        yield manager
        manager.shutdown()
    
    @given(st.text(min_size=1, max_size=1000))
    def test_text_sanitization_properties(self, notification_manager, text):
        """Text sanitization should handle all input safely"""
        try:
            sanitized = notification_manager._sanitize_text(text)
            
            # Should be a string
            assert isinstance(sanitized, str)
            
            # Should not contain unescaped quotes or backslashes
            # (unless they were properly escaped)
            if '"' in text:
                assert '\\"' in sanitized or '"' not in sanitized
            if '\\' in text:
                assert '\\\\' in sanitized
                
        except Exception as e:
            pytest.fail(f"Text sanitization failed for '{text[:100]}...': {e}")
    
    @given(st.text(min_size=1, max_size=100), st.text(min_size=1, max_size=500))
    def test_notification_properties(self, notification_manager, title, message):
        """Notification handling should be consistent"""
        try:
            # Should not crash
            result = notification_manager.notify_user(title, message, critical=False)
            assert isinstance(result, bool)
            
        except Exception as e:
            pytest.fail(f"Notification failed for title='{title[:50]}...', message='{message[:50]}...': {e}")
    
    @given(st.lists(st.tuples(st.text(min_size=1, max_size=50), st.text(min_size=1, max_size=100)), 
                   min_size=1, max_size=10))
    def test_notification_throttling_properties(self, notification_manager, notifications):
        """Notification throttling should work consistently"""
        results = []
        
        for title, message in notifications:
            result = notification_manager.notify_user(title, message, critical=True)
            results.append(result)
            time.sleep(0.01)  # Small delay
        
        # First notification should succeed
        assert results[0] is True
        
        # Subsequent notifications should be throttled
        if len(results) > 1:
            # At least some should be throttled due to cooldown
            assert not all(results[1:])

class TestPerformanceMonitorProperties:
    """Property-based tests for PerformanceMonitor"""
    
    @pytest.fixture
    def monitor(self):
        return PerformanceMonitor(max_samples=10)
    
    @given(st.lists(st.floats(min_value=0.0, max_value=10.0), min_size=1, max_size=100))
    def test_performance_recording_properties(self, monitor, durations):
        """Performance recording should handle various inputs"""
        for duration in durations:
            if not (duration >= 0 and duration <= 10):  # Filter invalid floats
                continue
                
            monitor.record_screen_capture_time(duration)
        
        # Should not exceed max samples
        assert len(monitor.screen_capture_times) <= monitor.max_samples
        
        # All recorded times should be valid
        for recorded_time in monitor.screen_capture_times:
            assert recorded_time >= 0
            assert recorded_time <= 10
    
    @given(st.integers(min_value=1, max_value=1000))
    def test_max_samples_property(self, max_samples):
        """Max samples property should be respected"""
        monitor = PerformanceMonitor(max_samples=max_samples)
        
        # Add more samples than max
        for i in range(max_samples * 2):
            monitor.record_analysis_time(i * 0.001)
        
        # Should not exceed max samples
        assert len(monitor.analysis_times) <= max_samples
        
        # Should contain the most recent samples
        if max_samples > 0:
            expected_start = max(0, max_samples * 2 - max_samples)
            for i, recorded_time in enumerate(monitor.analysis_times):
                expected_time = (expected_start + i) * 0.001
                assert abs(recorded_time - expected_time) < 0.0001
    
    def test_stats_calculation_properties(self, monitor):
        """Stats calculation should be mathematically correct"""
        test_values = [0.1, 0.2, 0.3, 0.4, 0.5]
        
        for value in test_values:
            monitor.record_clipboard_time(value)
        
        stats = monitor.get_stats()
        clipboard_stats = stats["clipboard"]
        
        # Check mathematical properties
        assert clipboard_stats["min"] == min(test_values)
        assert clipboard_stats["max"] == max(test_values)
        assert abs(clipboard_stats["avg"] - sum(test_values) / len(test_values)) < 0.0001

class TestPayGuardProperties:
    """Property-based tests for PayGuardMenuBarOptimized"""
    
    @pytest.fixture
    def payguard(self):
        config = {
            "alert_cooldown": 0.1,
            "enable_performance_monitoring": True
        }
        guard = PayGuardMenuBarOptimized(config)
        yield guard
        guard.shutdown()
    
    @given(st.dictionaries(
        st.sampled_from(["alert_cooldown", "screen_check_interval", "clipboard_check_interval"]),
        st.floats(min_value=0.1, max_value=60.0),
        min_size=1, max_size=3
    ))
    def test_configuration_properties(self, config_dict):
        """Configuration should be handled consistently"""
        try:
            payguard = PayGuardMenuBarOptimized(config_dict)
            
            # Configuration should be applied
            for key, value in config_dict.items():
                assert payguard.config[key] == value
            
            # Should have default values for missing keys
            assert "enable_performance_monitoring" in payguard.config
            
            payguard.shutdown()
            
        except Exception as e:
            pytest.fail(f"Configuration failed for {config_dict}: {e}")
    
    @given(st.lists(st.text(min_size=1, max_size=100), min_size=1, max_size=20))
    def test_detection_handling_properties(self, payguard, text_list):
        """Detection handling should be consistent"""
        initial_count = payguard.scam_count
        scam_detections = 0
        
        for text in text_list:
            result = payguard.detector.analyze_text(text)
            
            # Mock notification to avoid actual system calls
            with pytest.MonkeyPatch().context() as m:
                m.setattr(payguard.notification_manager, 'notify_user', lambda *args, **kwargs: True)
                payguard.handle_detection(result, "property_test")
            
            if result.is_scam:
                scam_detections += 1
        
        # Scam count should match detected scams
        assert payguard.scam_count == initial_count + scam_detections

class PayGuardStateMachine(RuleBasedStateMachine):
    """Stateful testing for PayGuard system"""
    
    def __init__(self):
        super().__init__()
        self.payguard = PayGuardMenuBarOptimized({
            "alert_cooldown": 0.1,
            "enable_performance_monitoring": True
        })
        self.analyzed_texts = []
        self.notifications_sent = 0
        self.temp_files_created = 0
    
    @initialize()
    def setup(self):
        """Initialize the state machine"""
        self.analyzed_texts = []
        self.notifications_sent = 0
        self.temp_files_created = 0
    
    @rule(text=st.text(min_size=0, max_size=500))
    def analyze_text(self, text):
        """Analyze text and track results"""
        result = self.payguard.detector.analyze_text(text)
        self.analyzed_texts.append((text, result))
        
        # Verify result consistency
        assert isinstance(result, DetectionResult)
        assert 0 <= result.confidence <= 100
    
    @rule(detection_result=st.builds(
        DetectionResult,
        is_scam=st.booleans(),
        confidence=st.floats(min_value=0, max_value=100),
        message=st.text(min_size=0, max_size=100)
    ))
    def handle_detection(self, detection_result):
        """Handle detection and track notifications"""
        with pytest.MonkeyPatch().context() as m:
            def mock_notify(*args, **kwargs):
                self.notifications_sent += 1
                return True
            
            m.setattr(self.payguard.notification_manager, 'notify_user', mock_notify)
            self.payguard.handle_detection(detection_result, "state_test")
    
    @rule(content=st.text(min_size=0, max_size=200))
    def create_temp_file(self, content):
        """Create temporary file and verify cleanup"""
        try:
            with self.payguard._temp_file_manager('.txt') as temp_file:
                self.temp_files_created += 1
                assert temp_file.exists()
                temp_file.write_text(content)
                assert temp_file.read_text() == content
            
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
            assert isinstance(result, DetectionResult)
            assert isinstance(result.is_scam, bool)
            assert isinstance(result.confidence, (int, float))
            assert isinstance(result.patterns, list)
            assert 0 <= result.confidence <= 100
    
    @invariant()
    def no_temp_files_leaked(self):
        """Invariant: No temporary files should be leaked"""
        # All temp files should be cleaned up
        assert len(self.payguard.temp_files) == 0
    
    @invariant()
    def scam_count_consistency(self):
        """Invariant: Scam count should be consistent"""
        # Scam count should never be negative
        assert self.payguard.scam_count >= 0
        
        # Scam count should not exceed total detections handled
        assert self.payguard.scam_count <= len(self.analyzed_texts)
    
    def teardown(self):
        """Clean up after testing"""
        self.payguard.shutdown()

class TestEdgeCasesProperties:
    """Property-based tests for edge cases"""
    
    @pytest.fixture
    def detector(self):
        return ScamDetector()
    
    @given(st.binary(min_size=0, max_size=1000))
    def test_binary_data_as_text(self, detector, binary_data):
        """Test handling of binary data decoded as text"""
        try:
            # Try to decode as UTF-8
            text = binary_data.decode('utf-8', errors='ignore')
            
            # Should handle the resulting text gracefully
            result = detector.analyze_text(text)
            assert isinstance(result, DetectionResult)
            
        except Exception as e:
            # Binary data might cause issues, but shouldn't crash the analyzer
            assert "decode" not in str(e).lower()
    
    @given(st.text(alphabet=string.punctuation, min_size=1, max_size=100))
    def test_punctuation_only_text(self, detector, punct_text):
        """Test handling of punctuation-only text"""
        result = detector.analyze_text(punct_text)
        
        # Should handle gracefully
        assert isinstance(result, DetectionResult)
        # Punctuation alone shouldn't trigger high confidence
        assert result.confidence < 80
    
    @given(st.text(min_size=0, max_size=100).filter(lambda x: '\x00' not in x))
    def test_unicode_edge_cases(self, detector, unicode_text):
        """Test Unicode edge cases"""
        result = detector.analyze_text(unicode_text)
        
        # Should handle Unicode gracefully
        assert isinstance(result, DetectionResult)
        assert isinstance(result.message, str)
        assert isinstance(result.advice, str)
    
    @given(st.integers(min_value=1, max_value=10000))
    def test_text_length_performance_property(self, detector, text_length):
        """Test that performance scales reasonably with text length"""
        import time
        
        # Create text of specified length
        test_text = "URGENT: Test " * (text_length // 12 + 1)
        test_text = test_text[:text_length]
        
        # Measure performance
        start_time = time.time()
        result = detector.analyze_text(test_text)
        duration = time.time() - start_time
        
        # Performance should be reasonable
        # Allow more time for very long texts, but should still be fast
        max_time = min(0.1, text_length / 10000)  # Scale with length but cap at 0.1s
        assert duration < max_time, f"Text analysis too slow for length {text_length}: {duration:.3f}s"
        
        # Result should still be valid
        assert isinstance(result, DetectionResult)

class TestConcurrencyProperties:
    """Property-based tests for concurrency"""
    
    @pytest.fixture
    def payguard(self):
        config = {"enable_performance_monitoring": True}
        guard = PayGuardMenuBarOptimized(config)
        yield guard
        guard.shutdown()
    
    @given(st.lists(st.text(min_size=1, max_size=100), min_size=1, max_size=20))
    def test_concurrent_text_analysis_consistency(self, payguard, text_list):
        """Test that concurrent analysis produces consistent results"""
        import concurrent.futures
        
        # Analyze sequentially
        sequential_results = []
        for text in text_list:
            result = payguard.detector.analyze_text(text)
            sequential_results.append((text, result))
        
        # Analyze concurrently
        concurrent_results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_text = {
                executor.submit(payguard.detector.analyze_text, text): text 
                for text in text_list
            }
            
            for future in concurrent.futures.as_completed(future_to_text):
                text = future_to_text[future]
                result = future.result()
                concurrent_results[text] = result
        
        # Results should be consistent
        for text, seq_result in sequential_results:
            conc_result = concurrent_results[text]
            
            assert seq_result.is_scam == conc_result.is_scam
            assert seq_result.confidence == conc_result.confidence
            assert seq_result.patterns == conc_result.patterns

# Test runner for property-based tests
class TestPropertyBasedRunner:
    """Run property-based tests with custom settings"""
    
    def test_run_stateful_tests(self):
        """Run stateful property-based tests"""
        # Configure settings for stateful testing
        PayGuardStateMachine.TestCase.settings = settings(
            max_examples=50,
            stateful_step_count=20,
            deadline=None
        )
        
        # Run the state machine
        test_case = PayGuardStateMachine.TestCase()
        test_case.runTest()
    
    @settings(max_examples=100, deadline=None)
    def test_comprehensive_property_testing(self):
        """Comprehensive property-based testing"""
        detector = ScamDetector()
        
        @given(st.text(min_size=0, max_size=1000))
        def test_all_text_properties(text):
            result = detector.analyze_text(text)
            
            # Core properties that should always hold
            assert isinstance(result, DetectionResult)
            assert isinstance(result.is_scam, bool)
            assert isinstance(result.confidence, (int, float))
            assert 0 <= result.confidence <= 100
            
            # If marked as scam, should have some patterns or confidence
            if result.is_scam:
                assert result.confidence > 0 or len(result.patterns) > 0
            
            # If high confidence, should be marked as scam
            if result.confidence > 90:
                assert result.is_scam is True
        
        test_all_text_properties()

if __name__ == "__main__":
    # Run property-based tests
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])