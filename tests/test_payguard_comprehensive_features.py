#!/usr/bin/env python3
"""
Comprehensive Test Suite for PayGuard Feature Tester
Unit tests, integration tests, and property-based tests
"""

import pytest
import asyncio
import aiohttp
import json
import base64
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path
import tempfile
import time
from datetime import datetime
from typing import Dict, Any, List

# Import the modules to test
import sys
sys.path.append(str(Path(__file__).parent.parent))

from test_all_payguard_features_comprehensive_optimized import (
    PayGuardFeatureTesterOptimized, TestConfig, TestResult, TestStatus
)

class TestPayGuardFeatureTesterUnit:
    """Unit tests for PayGuardFeatureTesterOptimized"""
    
    @pytest.fixture
    def test_config(self):
        """Test configuration"""
        return TestConfig(
            backend_url="http://localhost:8002",
            timeout=10,
            max_concurrent=2,
            retry_attempts=2,
            retry_delay=0.1
        )
    
    @pytest.fixture
    def tester(self, test_config):
        """Tester instance"""
        return PayGuardFeatureTesterOptimized(test_config)
    
    def test_config_initialization(self, test_config):
        """Test configuration initialization"""
        assert test_config.backend_url == "http://localhost:8002"
        assert test_config.timeout == 10
        assert test_config.max_concurrent == 2
        assert test_config.retry_attempts == 2
        assert test_config.retry_delay == 0.1
    
    def test_tester_initialization(self, tester, test_config):
        """Test tester initialization"""
        assert tester.config == test_config
        assert tester.test_results == []
        assert tester.session is None
        assert tester._temp_files == []
    
    def test_log_result_pass(self, tester):
        """Test logging successful results"""
        tester._log_result(
            "Test Case", 
            TestStatus.PASS, 
            "Test passed", 
            1.5,
            metadata={"key": "value"}
        )
        
        assert len(tester.test_results) == 1
        result = tester.test_results[0]
        assert result.test_name == "Test Case"
        assert result.status == TestStatus.PASS
        assert result.details == "Test passed"
        assert result.duration == 1.5
        assert result.metadata == {"key": "value"}
        assert result.error_details is None
    
    def test_log_result_fail_with_error(self, tester):
        """Test logging failed results with error details"""
        tester._log_result(
            "Failed Test",
            TestStatus.FAIL,
            "Test failed",
            0.5,
            error_details="Connection timeout"
        )
        
        assert len(tester.test_results) == 1
        result = tester.test_results[0]
        assert result.status == TestStatus.FAIL
        assert result.error_details == "Connection timeout"
    
    def test_validate_risk_assessment_legitimate(self, tester):
        """Test risk assessment validation for legitimate sites"""
        assert tester._validate_risk_assessment("legitimate", "low", 80) is True
        assert tester._validate_risk_assessment("legitimate", "medium", 60) is True
        assert tester._validate_risk_assessment("legitimate", "high", 20) is False
    
    def test_validate_risk_assessment_suspicious(self, tester):
        """Test risk assessment validation for suspicious sites"""
        assert tester._validate_risk_assessment("suspicious", "medium", 50) is True
        assert tester._validate_risk_assessment("suspicious", "high", 30) is True
        assert tester._validate_risk_assessment("suspicious", "low", 90) is False
    
    def test_validate_risk_assessment_malicious(self, tester):
        """Test risk assessment validation for malicious sites"""
        assert tester._validate_risk_assessment("malicious", "high", 20) is True
        assert tester._validate_risk_assessment("malicious", "medium", 40) is False
        assert tester._validate_risk_assessment("malicious", "low", 80) is False
    
    def test_cleanup_temp_files(self, tester):
        """Test temporary file cleanup"""
        # Create mock temp files
        temp_file1 = Mock()
        temp_file1.exists.return_value = True
        temp_file2 = Mock()
        temp_file2.exists.return_value = False
        
        tester._temp_files = [temp_file1, temp_file2]
        tester._cleanup_temp_files()
        
        temp_file1.unlink.assert_called_once()
        temp_file2.unlink.assert_not_called()
        assert tester._temp_files == []
    
    @patch('test_all_payguard_features_comprehensive_optimized.subprocess.run')
    def test_check_agent_status_running(self, mock_run, tester):
        """Test agent status check when agent is running"""
        mock_run.return_value.returncode = 0
        assert tester.check_agent_status() is True
        mock_run.assert_called_once()
    
    @patch('test_all_payguard_features_comprehensive_optimized.subprocess.run')
    def test_check_agent_status_not_running(self, mock_run, tester):
        """Test agent status check when agent is not running"""
        mock_run.return_value.returncode = 1
        assert tester.check_agent_status() is False
    
    @patch('test_all_payguard_features_comprehensive_optimized.subprocess.run')
    def test_check_agent_status_exception(self, mock_run, tester):
        """Test agent status check with exception"""
        mock_run.side_effect = Exception("Process error")
        assert tester.check_agent_status() is False

class TestPayGuardFeatureTesterImageGeneration:
    """Test image generation functionality"""
    
    @pytest.fixture
    def tester(self):
        return PayGuardFeatureTesterOptimized()
    
    @patch('test_all_payguard_features_comprehensive_optimized.Image')
    @patch('test_all_payguard_features_comprehensive_optimized.ImageDraw')
    @patch('test_all_payguard_features_comprehensive_optimized.ImageFont')
    def test_generate_test_scam_image_success(self, mock_font, mock_draw, mock_image, tester):
        """Test successful scam image generation"""
        # Mock PIL components
        mock_img = Mock()
        mock_image.new.return_value = mock_img
        
        mock_draw_obj = Mock()
        mock_draw.Draw.return_value = mock_draw_obj
        
        mock_font.load_default.return_value = Mock()
        
        # Mock BytesIO
        with patch('test_all_payguard_features_comprehensive_optimized.io.BytesIO') as mock_bytesio:
            mock_bytes = Mock()
            mock_bytes.getvalue.return_value = b'fake_image_data'
            mock_bytesio.return_value = mock_bytes
            
            result = tester._generate_test_scam_image()
            
            assert result == b'fake_image_data'
            mock_image.new.assert_called_once_with('RGB', (800, 600), color='red')
            mock_draw.Draw.assert_called_once_with(mock_img)
            mock_img.save.assert_called_once()
    
    def test_generate_test_scam_image_no_pil(self, tester):
        """Test image generation when PIL is not available"""
        with patch('test_all_payguard_features_comprehensive_optimized.Image', side_effect=ImportError):
            result = tester._generate_test_scam_image()
            assert result is None
    
    @patch('test_all_payguard_features_comprehensive_optimized.Image')
    def test_generate_test_scam_image_exception(self, mock_image, tester):
        """Test image generation with exception"""
        mock_image.new.side_effect = Exception("Image creation failed")
        
        result = tester._generate_test_scam_image()
        assert result is None

class TestPayGuardFeatureTesterAsync:
    """Test async functionality"""
    
    @pytest.fixture
    def test_config(self):
        return TestConfig(timeout=5, max_concurrent=2, retry_attempts=1)
    
    @pytest.fixture
    async def tester(self, test_config):
        """Async tester fixture"""
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            yield tester
    
    @pytest.mark.asyncio
    async def test_context_manager(self, test_config):
        """Test async context manager"""
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            assert tester.session is not None
            assert isinstance(tester.session, aiohttp.ClientSession)
        
        # Session should be closed after context exit
        assert tester.session.closed
    
    @pytest.mark.asyncio
    async def test_make_request_with_retry_success(self, tester):
        """Test successful HTTP request"""
        # Mock the session request
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.content_type = 'application/json'
        mock_response.json = AsyncMock(return_value={"status": "ok"})
        
        tester.session.request = AsyncMock(return_value=mock_response)
        
        status, data = await tester._make_request_with_retry("GET", "http://test.com")
        
        assert status == 200
        assert data == {"status": "ok"}
    
    @pytest.mark.asyncio
    async def test_make_request_with_retry_timeout(self, tester):
        """Test request with timeout and retry"""
        # Mock timeout on first attempt, success on second
        tester.session.request = AsyncMock(side_effect=[
            asyncio.TimeoutError(),
            AsyncMock(status=200, content_type='application/json', 
                     json=AsyncMock(return_value={"status": "ok"}))
        ])
        
        with patch('asyncio.sleep'):  # Speed up test
            status, data = await tester._make_request_with_retry("GET", "http://test.com")
        
        assert status == 200
        assert data == {"status": "ok"}
        assert tester.session.request.call_count == 2
    
    @pytest.mark.asyncio
    async def test_make_request_with_retry_max_attempts(self, tester):
        """Test request exceeding max retry attempts"""
        tester.session.request = AsyncMock(side_effect=asyncio.TimeoutError())
        
        with patch('asyncio.sleep'):  # Speed up test
            with pytest.raises(Exception, match="Max retry attempts exceeded"):
                await tester._make_request_with_retry("GET", "http://test.com")
    
    @pytest.mark.asyncio
    async def test_check_backend_health_success(self, tester):
        """Test successful backend health check"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.content_type = 'application/json'
        mock_response.json = AsyncMock(return_value={
            "status": "healthy",
            "uptime": "1h 30m"
        })
        
        tester.session.request = AsyncMock(return_value=mock_response)
        
        result = await tester.check_backend_health()
        
        assert result is True
        assert len(tester.test_results) == 1
        assert tester.test_results[0].status == TestStatus.PASS
        assert "healthy" in tester.test_results[0].details
    
    @pytest.mark.asyncio
    async def test_check_backend_health_failure(self, tester):
        """Test failed backend health check"""
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.content_type = 'application/json'
        mock_response.json = AsyncMock(return_value={"error": "Internal server error"})
        
        tester.session.request = AsyncMock(return_value=mock_response)
        
        result = await tester.check_backend_health()
        
        assert result is False
        assert len(tester.test_results) == 1
        assert tester.test_results[0].status == TestStatus.FAIL
    
    @pytest.mark.asyncio
    async def test_check_backend_health_exception(self, tester):
        """Test backend health check with exception"""
        tester.session.request = AsyncMock(side_effect=Exception("Connection failed"))
        
        result = await tester.check_backend_health()
        
        assert result is False
        assert len(tester.test_results) == 1
        assert tester.test_results[0].status == TestStatus.ERROR
        assert "Connection failed" in tester.test_results[0].error_details

class TestPayGuardFeatureTesterIntegration:
    """Integration tests"""
    
    @pytest.fixture
    def test_config(self):
        return TestConfig(
            backend_url="http://localhost:8002",
            timeout=10,
            max_concurrent=2,
            retry_attempts=1
        )
    
    @pytest.mark.asyncio
    async def test_api_endpoints_batch_mock(self, test_config):
        """Test API endpoints batch with mocked responses"""
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            # Mock successful responses for all endpoints
            mock_responses = [
                (200, {"status": "healthy"}),  # health
                (200, {"stats": "data"}),      # stats
                (404, {"message": "not found"}),  # merchants (empty)
                (404, {"message": "not found"}),  # fraud-reports (empty)
                (200, {"message": "PayGuard API"}),  # root
            ]
            
            call_count = 0
            async def mock_request(*args, **kwargs):
                nonlocal call_count
                status, data = mock_responses[call_count % len(mock_responses)]
                call_count += 1
                return status, data
            
            tester._make_request_with_retry = mock_request
            
            await tester.test_api_endpoints_batch()
            
            # Should have results for all endpoints
            assert len(tester.test_results) == 5
            # All should pass (200 and 404 are acceptable)
            assert all(r.status == TestStatus.PASS for r in tester.test_results)
    
    @pytest.mark.asyncio
    async def test_url_risk_analysis_batch_mock(self, test_config):
        """Test URL risk analysis batch with mocked responses"""
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            # Mock risk analysis responses
            def mock_request(method, url, **kwargs):
                payload = kwargs.get('json', {})
                test_url = payload.get('url', '')
                
                if 'microsoft.com' in test_url or 'google.com' in test_url:
                    return asyncio.coroutine(lambda: (200, {
                        "risk_level": "low",
                        "trust_score": 85
                    }))()
                else:
                    return asyncio.coroutine(lambda: (200, {
                        "risk_level": "high", 
                        "trust_score": 25
                    }))()
            
            tester._make_request_with_retry = mock_request
            
            await tester.test_url_risk_analysis_batch()
            
            # Should have results for all test URLs
            assert len(tester.test_results) == 6  # 6 test URLs
    
    @pytest.mark.asyncio
    async def test_comprehensive_scam_patterns_mock(self, test_config):
        """Test comprehensive scam patterns with mocked responses"""
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            # Mock scam detection responses
            async def mock_request(method, url, **kwargs):
                return 200, {
                    "scam_alert": {
                        "is_scam": True,
                        "confidence": 85,
                        "detected_patterns": ["virus_warning", "phone_number", "urgency"]
                    }
                }
            
            tester._make_request_with_retry = mock_request
            
            await tester.test_comprehensive_scam_patterns()
            
            # Should have results for all scam patterns
            assert len(tester.test_results) == 4  # 4 scam patterns
            assert all(r.status == TestStatus.PASS for r in tester.test_results)
    
    @pytest.mark.asyncio
    async def test_performance_benchmarks_mock(self, test_config):
        """Test performance benchmarks with mocked responses"""
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            # Mock fast responses
            async def mock_request(method, url, **kwargs):
                await asyncio.sleep(0.01)  # Simulate fast response
                return 200, {"status": "ok"}
            
            tester._make_request_with_retry = mock_request
            
            await tester.test_performance_benchmarks()
            
            # Should have one performance result
            assert len(tester.test_results) == 1
            result = tester.test_results[0]
            assert result.test_name == "Performance Benchmark"
            assert "RPS:" in result.details

class TestPayGuardFeatureTesterEdgeCases:
    """Test edge cases and error conditions"""
    
    @pytest.fixture
    def tester(self):
        return PayGuardFeatureTesterOptimized()
    
    def test_validate_risk_assessment_unknown_category(self, tester):
        """Test risk assessment validation with unknown category"""
        # Unknown categories should always return True
        assert tester._validate_risk_assessment("unknown", "high", 10) is True
        assert tester._validate_risk_assessment("invalid", "low", 90) is True
    
    def test_log_result_with_none_values(self, tester):
        """Test logging results with None values"""
        tester._log_result("Test", TestStatus.PASS, None, None)
        
        result = tester.test_results[0]
        assert result.details is None
        assert result.duration is None
    
    def test_cleanup_temp_files_with_exception(self, tester):
        """Test temp file cleanup with exceptions"""
        temp_file = Mock()
        temp_file.exists.return_value = True
        temp_file.unlink.side_effect = OSError("Permission denied")
        
        tester._temp_files = [temp_file]
        
        # Should not raise exception
        tester._cleanup_temp_files()
        assert tester._temp_files == []
    
    @pytest.mark.asyncio
    async def test_ai_image_detection_no_pil(self):
        """Test AI image detection when PIL is not available"""
        config = TestConfig()
        async with PayGuardFeatureTesterOptimized(config) as tester:
            # Mock _generate_test_scam_image to return None (PIL not available)
            tester._generate_test_scam_image = Mock(return_value=None)
            
            await tester.test_ai_image_detection_optimized()
            
            assert len(tester.test_results) == 1
            assert tester.test_results[0].status == TestStatus.SKIP
            assert "PIL not available" in tester.test_results[0].details

class TestPayGuardFeatureTesterReporting:
    """Test reporting functionality"""
    
    @pytest.fixture
    def tester_with_results(self):
        """Tester with sample results"""
        tester = PayGuardFeatureTesterOptimized()
        
        # Add sample results
        tester.test_results = [
            TestResult("Test 1", TestStatus.PASS, "Success", 1.0, "2024-01-01T00:00:00"),
            TestResult("Test 2", TestStatus.FAIL, "Failed", 0.5, "2024-01-01T00:01:00"),
            TestResult("Test 3", TestStatus.ERROR, "Error", 0.2, "2024-01-01T00:02:00", "Connection failed"),
            TestResult("Test 4", TestStatus.SKIP, "Skipped", 0.0, "2024-01-01T00:03:00"),
        ]
        
        return tester
    
    def test_generate_final_report(self, tester_with_results):
        """Test final report generation"""
        with patch('builtins.open', create=True) as mock_open:
            with patch('json.dump') as mock_json_dump:
                result = tester_with_results._generate_final_report(10.0)
                
                # Should return False due to failed and error tests
                assert result is False
                
                # Should save report to file
                mock_open.assert_called_once()
                mock_json_dump.assert_called_once()
                
                # Check report structure
                report_data = mock_json_dump.call_args[0][0]
                assert "summary" in report_data
                assert "config" in report_data
                assert "results" in report_data
                assert "timestamp" in report_data
                
                summary = report_data["summary"]
                assert summary["total_tests"] == 4
                assert summary["passed"] == 1
                assert summary["failed"] == 1
                assert summary["errors"] == 1
                assert summary["skipped"] == 1
    
    def test_generate_final_report_all_pass(self):
        """Test final report with all passing tests"""
        tester = PayGuardFeatureTesterOptimized()
        tester.test_results = [
            TestResult("Test 1", TestStatus.PASS, "Success", 1.0, "2024-01-01T00:00:00"),
            TestResult("Test 2", TestStatus.PASS, "Success", 1.5, "2024-01-01T00:01:00"),
        ]
        
        with patch('builtins.open', create=True):
            with patch('json.dump'):
                result = tester._generate_final_report(5.0)
                
                # Should return True when all tests pass
                assert result is True

# Property-based tests using Hypothesis
try:
    from hypothesis import given, strategies as st
    
    class TestPayGuardFeatureTesterProperties:
        """Property-based tests"""
        
        @given(st.text(min_size=1, max_size=100))
        def test_log_result_test_name_property(self, test_name):
            """Test that any valid test name can be logged"""
            tester = PayGuardFeatureTesterOptimized()
            tester._log_result(test_name, TestStatus.PASS, "Test details")
            
            assert len(tester.test_results) == 1
            assert tester.test_results[0].test_name == test_name
        
        @given(st.floats(min_value=0.0, max_value=1000.0))
        def test_log_result_duration_property(self, duration):
            """Test that any valid duration can be logged"""
            tester = PayGuardFeatureTesterOptimized()
            tester._log_result("Test", TestStatus.PASS, "Details", duration)
            
            assert tester.test_results[0].duration == duration
        
        @given(st.integers(min_value=0, max_value=100))
        def test_validate_risk_assessment_trust_score_property(self, trust_score):
            """Test risk assessment validation with various trust scores"""
            tester = PayGuardFeatureTesterOptimized()
            
            # Should not raise exceptions for any valid trust score
            result = tester._validate_risk_assessment("legitimate", "low", trust_score)
            assert isinstance(result, bool)

except ImportError:
    # Hypothesis not available, skip property-based tests
    pass

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])