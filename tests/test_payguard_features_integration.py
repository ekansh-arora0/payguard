#!/usr/bin/env python3
"""
Integration Test Suite for PayGuard Feature Tester
End-to-end testing of complete workflows and system integration
"""

import pytest
import asyncio
import aiohttp
import json
import time
import tempfile
import subprocess
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any, List
import os

# Import test modules
import sys
sys.path.append(str(Path(__file__).parent.parent))

from test_all_payguard_features_comprehensive_optimized import (
    PayGuardFeatureTesterOptimized, TestConfig, TestStatus
)

class TestPayGuardFeatureTesterIntegration:
    """Integration tests for PayGuard feature tester"""
    
    @pytest.fixture
    def test_config(self):
        """Test configuration for integration tests"""
        return TestConfig(
            backend_url="http://localhost:8002",
            timeout=15,
            max_concurrent=3,
            retry_attempts=2,
            retry_delay=0.5
        )
    
    @pytest.fixture
    async def mock_backend_server(self):
        """Mock backend server for integration testing"""
        from aiohttp import web
        
        async def health_handler(request):
            return web.json_response({
                "status": "healthy",
                "uptime": "1h 30m",
                "version": "1.0.0"
            })
        
        async def stats_handler(request):
            return web.json_response({
                "total_checks": 1000,
                "scams_detected": 50,
                "uptime_hours": 24
            })
        
        async def risk_check_handler(request):
            data = await request.json()
            url = data.get("url", "")
            
            # Simulate risk assessment logic
            if any(suspicious in url.lower() for suspicious in ["phishing", "scam", "malware"]):
                risk_level = "high"
                trust_score = 20
            elif any(legit in url.lower() for legit in ["microsoft", "google", "amazon"]):
                risk_level = "low"
                trust_score = 85
            else:
                risk_level = "medium"
                trust_score = 60
            
            return web.json_response({
                "url": url,
                "risk_level": risk_level,
                "trust_score": trust_score,
                "checked_at": "2024-01-01T00:00:00Z"
            })
        
        async def content_risk_handler(request):
            data = await request.json()
            html = data.get("html", "")
            overlay = data.get("overlay_text", "")
            
            # Simulate scam detection
            scam_indicators = ["virus", "urgent", "call", "suspended", "verify"]
            detected_patterns = [indicator for indicator in scam_indicators 
                               if indicator in (html + overlay).lower()]
            
            is_scam = len(detected_patterns) >= 2
            confidence = min(len(detected_patterns) * 25, 95)
            
            scam_alert = None
            if is_scam:
                scam_alert = {
                    "is_scam": True,
                    "confidence": confidence,
                    "detected_patterns": detected_patterns,
                    "senior_message": "This appears to be a scam!",
                    "action_advice": "Close this window immediately."
                }
            
            return web.json_response({
                "url": data.get("url", "test://content"),
                "scam_alert": scam_alert
            })
        
        async def media_risk_handler(request):
            data = await request.json()
            content = data.get("content", "")
            
            # Simulate AI image analysis
            media_score = 75 if len(content) > 1000 else 25  # Larger images = higher risk
            media_color = "high" if media_score > 50 else "low"
            
            return web.json_response({
                "url": data.get("url", "test://media"),
                "media_score": media_score,
                "media_color": media_color,
                "reasons": ["AI analysis completed"]
            })
        
        # Create web application
        app = web.Application()
        app.router.add_get("/api/health", health_handler)
        app.router.add_get("/api/stats", stats_handler)
        app.router.add_get("/api/merchants", lambda r: web.json_response([]))
        app.router.add_get("/api/fraud-reports", lambda r: web.json_response([]))
        app.router.add_get("/api/", lambda r: web.json_response({"message": "PayGuard API"}))
        app.router.add_post("/api/risk-check", risk_check_handler)
        app.router.add_post("/api/content-risk", content_risk_handler)
        app.router.add_post("/api/media-risk/bytes", media_risk_handler)
        
        # Start server
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', 8003)  # Use different port
        await site.start()
        
        yield "http://localhost:8003"
        
        # Cleanup
        await runner.cleanup()
    
    @pytest.mark.asyncio
    async def test_complete_workflow_integration(self, mock_backend_server):
        """Test complete workflow from start to finish"""
        config = TestConfig(backend_url=mock_backend_server)
        
        async with PayGuardFeatureTesterOptimized(config) as tester:
            # Test health check
            health_ok = await tester.check_backend_health()
            assert health_ok is True
            
            # Test API endpoints
            await tester.test_api_endpoints_batch()
            
            # Test URL analysis
            await tester.test_url_risk_analysis_batch()
            
            # Test scam patterns
            await tester.test_comprehensive_scam_patterns()
            
            # Verify results
            assert len(tester.test_results) > 0
            
            # Should have successful health check
            health_results = [r for r in tester.test_results if "Health Check" in r.test_name]
            assert len(health_results) == 1
            assert health_results[0].status == TestStatus.PASS
            
            # Should have API endpoint results
            api_results = [r for r in tester.test_results if "API Endpoint" in r.test_name]
            assert len(api_results) >= 5  # At least 5 endpoints tested
            
            # Should have URL analysis results
            url_results = [r for r in tester.test_results if "URL Risk Analysis" in r.test_name]
            assert len(url_results) >= 6  # 6 test URLs
            
            # Should have scam pattern results
            scam_results = [r for r in tester.test_results if "Scam Pattern" in r.test_name]
            assert len(scam_results) >= 4  # 4 scam patterns
    
    @pytest.mark.asyncio
    async def test_error_recovery_integration(self, test_config):
        """Test error recovery and graceful degradation"""
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            # Mock network errors
            original_request = tester._make_request_with_retry
            
            call_count = 0
            async def failing_request(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                
                # Fail first few attempts, then succeed
                if call_count <= 2:
                    raise aiohttp.ClientError("Network error")
                else:
                    return 200, {"status": "recovered"}
            
            tester._make_request_with_retry = failing_request
            
            # Should recover from network errors
            health_ok = await tester.check_backend_health()
            
            # Should have attempted retries and eventually succeeded
            assert call_count > 1  # Multiple attempts made
            assert health_ok is True  # Eventually succeeded
    
    @pytest.mark.asyncio
    async def test_concurrent_operations_integration(self, mock_backend_server):
        """Test concurrent operations don't interfere with each other"""
        config = TestConfig(backend_url=mock_backend_server, max_concurrent=5)
        
        async with PayGuardFeatureTesterOptimized(config) as tester:
            # Run multiple test suites concurrently
            tasks = [
                tester.test_api_endpoints_batch(),
                tester.test_url_risk_analysis_batch(),
                tester.test_comprehensive_scam_patterns(),
            ]
            
            # All should complete successfully
            await asyncio.gather(*tasks)
            
            # Verify all results are present and valid
            assert len(tester.test_results) > 0
            
            # All results should have valid timestamps
            for result in tester.test_results:
                assert result.timestamp is not None
                assert isinstance(result.timestamp, str)
            
            # No results should have been corrupted by concurrent access
            for result in tester.test_results:
                assert result.test_name is not None
                assert result.status in [TestStatus.PASS, TestStatus.FAIL, TestStatus.ERROR, TestStatus.SKIP]
    
    @pytest.mark.asyncio
    async def test_performance_under_load_integration(self, mock_backend_server):
        """Test system performance under realistic load"""
        config = TestConfig(backend_url=mock_backend_server, max_concurrent=10)
        
        async with PayGuardFeatureTesterOptimized(config) as tester:
            start_time = time.time()
            
            # Run performance benchmark
            await tester.test_performance_benchmarks()
            
            total_duration = time.time() - start_time
            
            # Should complete within reasonable time
            assert total_duration < 30.0  # Less than 30 seconds
            
            # Should have performance results
            perf_results = [r for r in tester.test_results if "Performance" in r.test_name]
            assert len(perf_results) >= 1
            
            # Performance results should indicate good throughput
            for result in perf_results:
                assert result.status in [TestStatus.PASS, TestStatus.FAIL]  # Should not error
    
    @pytest.mark.asyncio
    async def test_image_processing_integration(self, mock_backend_server):
        """Test image processing integration"""
        config = TestConfig(backend_url=mock_backend_server)
        
        async with PayGuardFeatureTesterOptimized(config) as tester:
            # Test AI image detection
            await tester.test_ai_image_detection_optimized()
            
            # Should have image detection results
            image_results = [r for r in tester.test_results if "AI Image" in r.test_name]
            assert len(image_results) == 1
            
            result = image_results[0]
            # Should either pass (PIL available) or skip (PIL not available)
            assert result.status in [TestStatus.PASS, TestStatus.SKIP]
            
            if result.status == TestStatus.PASS:
                # Should have meaningful details
                assert "Score:" in result.details
                assert "Color:" in result.details
    
    @pytest.mark.asyncio
    async def test_configuration_validation_integration(self):
        """Test configuration validation in real scenarios"""
        # Test with various configuration combinations
        configs = [
            TestConfig(timeout=5, max_concurrent=1),
            TestConfig(timeout=30, max_concurrent=10),
            TestConfig(retry_attempts=1, retry_delay=0.1),
            TestConfig(retry_attempts=5, retry_delay=2.0),
        ]
        
        for config in configs:
            async with PayGuardFeatureTesterOptimized(config) as tester:
                # Should initialize successfully with any valid config
                assert tester.config == config
                assert tester.session is not None
                
                # Should be able to perform basic operations
                tester._log_result("Config Test", TestStatus.PASS, "Config validated")
                assert len(tester.test_results) == 1
    
    @pytest.mark.asyncio
    async def test_cleanup_integration(self, test_config):
        """Test proper cleanup of resources"""
        temp_files_created = []
        
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            # Simulate creating temporary files
            for i in range(3):
                temp_file = Path(f"/tmp/test_payguard_{i}.tmp")
                temp_file.touch()
                tester._temp_files.append(temp_file)
                temp_files_created.append(temp_file)
            
            # Files should exist during operation
            for temp_file in temp_files_created:
                assert temp_file.exists()
        
        # Files should be cleaned up after context exit
        for temp_file in temp_files_created:
            assert not temp_file.exists()
    
    def test_agent_status_integration(self):
        """Test agent status checking integration"""
        tester = PayGuardFeatureTesterOptimized()
        
        # Mock pgrep command
        with patch('subprocess.run') as mock_run:
            # Test agent running
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "12345\n"
            
            assert tester.check_agent_status() is True
            
            # Test agent not running
            mock_run.return_value.returncode = 1
            
            assert tester.check_agent_status() is False
            
            # Test command error
            mock_run.side_effect = Exception("Command failed")
            
            assert tester.check_agent_status() is False

class TestPayGuardRealWorldScenarios:
    """Test real-world scenarios and use cases"""
    
    @pytest.fixture
    def test_config(self):
        return TestConfig(backend_url="http://localhost:8002")
    
    @pytest.mark.asyncio
    async def test_tech_support_scam_scenario(self, test_config):
        """Test detection of tech support scam scenario"""
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            # Mock tech support scam response
            async def mock_scam_request(*args, **kwargs):
                return 200, {
                    "scam_alert": {
                        "is_scam": True,
                        "confidence": 95,
                        "detected_patterns": ["virus_warning", "phone_number", "urgency", "brand_impersonation"],
                        "senior_message": "STOP! This is a fake Microsoft warning.",
                        "action_advice": "Close this window immediately. Do NOT call the number."
                    }
                }
            
            tester._make_request_with_retry = mock_scam_request
            
            # Test comprehensive scam patterns (includes tech support scam)
            await tester.test_comprehensive_scam_patterns()
            
            # Should detect tech support scam
            scam_results = [r for r in tester.test_results if "Tech Support Scam" in r.test_name]
            assert len(scam_results) == 1
            assert scam_results[0].status == TestStatus.PASS
            
            # Should have high confidence detection
            metadata = scam_results[0].metadata
            if metadata:
                assert metadata.get("is_scam") is True
                assert metadata.get("confidence", 0) > 90
    
    @pytest.mark.asyncio
    async def test_phishing_email_scenario(self, test_config):
        """Test detection of phishing email scenario"""
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            # Mock phishing detection response
            async def mock_phishing_request(*args, **kwargs):
                return 200, {
                    "scam_alert": {
                        "is_scam": True,
                        "confidence": 85,
                        "detected_patterns": ["account_threat", "phishing", "brand_impersonation"],
                        "senior_message": "STOP! This is a fake security alert.",
                        "action_advice": "Do not enter any passwords or personal information."
                    }
                }
            
            tester._make_request_with_retry = mock_phishing_request
            
            await tester.test_comprehensive_scam_patterns()
            
            # Should detect phishing email
            phishing_results = [r for r in tester.test_results if "Phishing Email" in r.test_name]
            assert len(phishing_results) == 1
            assert phishing_results[0].status == TestStatus.PASS
    
    @pytest.mark.asyncio
    async def test_legitimate_content_scenario(self, test_config):
        """Test handling of legitimate content"""
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            # Mock legitimate content response
            async def mock_legitimate_request(*args, **kwargs):
                if "microsoft.com" in str(kwargs) or "google.com" in str(kwargs):
                    return 200, {
                        "risk_level": "low",
                        "trust_score": 90
                    }
                else:
                    return 200, {
                        "scam_alert": None  # No scam detected
                    }
            
            tester._make_request_with_retry = mock_legitimate_request
            
            await tester.test_url_risk_analysis_batch()
            
            # Should properly handle legitimate URLs
            url_results = [r for r in tester.test_results if "microsoft.com" in r.test_name or "google.com" in r.test_name]
            assert len(url_results) >= 2
            
            for result in url_results:
                assert result.status == TestStatus.PASS
    
    @pytest.mark.asyncio
    async def test_mixed_content_scenario(self, test_config):
        """Test scenario with mixed legitimate and suspicious content"""
        async with PayGuardFeatureTesterOptimized(test_config) as tester:
            request_count = 0
            
            async def mock_mixed_request(*args, **kwargs):
                nonlocal request_count
                request_count += 1
                
                # Alternate between legitimate and suspicious responses
                if request_count % 2 == 0:
                    return 200, {
                        "risk_level": "low",
                        "trust_score": 85,
                        "scam_alert": None
                    }
                else:
                    return 200, {
                        "risk_level": "high",
                        "trust_score": 25,
                        "scam_alert": {
                            "is_scam": True,
                            "confidence": 80,
                            "detected_patterns": ["suspicious_domain"]
                        }
                    }
            
            tester._make_request_with_retry = mock_mixed_request
            
            await tester.test_url_risk_analysis_batch()
            
            # Should have mixed results
            results = tester.test_results
            assert len(results) > 0
            
            # All should pass (proper handling of both legitimate and suspicious)
            for result in results:
                assert result.status == TestStatus.PASS

class TestPayGuardSystemIntegration:
    """Test system-level integration"""
    
    @pytest.mark.asyncio
    async def test_full_system_integration(self):
        """Test full system integration with all components"""
        config = TestConfig(
            backend_url="http://localhost:8002",
            timeout=20,
            max_concurrent=5
        )
        
        async with PayGuardFeatureTesterOptimized(config) as tester:
            # Mock comprehensive system responses
            response_map = {
                "/api/health": (200, {"status": "healthy", "uptime": "2h"}),
                "/api/stats": (200, {"total_checks": 5000}),
                "/api/merchants": (200, []),
                "/api/fraud-reports": (200, []),
                "/api/": (200, {"message": "PayGuard API v1.0"}),
            }
            
            async def mock_system_request(method, url, **kwargs):
                for endpoint, response in response_map.items():
                    if endpoint in url:
                        return response
                
                # Default response for other endpoints
                return 200, {"status": "ok"}
            
            tester._make_request_with_retry = mock_system_request
            
            # Run comprehensive test suite
            success = await tester.run_all_tests()
            
            # Should complete successfully
            assert isinstance(success, bool)
            
            # Should have comprehensive results
            assert len(tester.test_results) > 10
            
            # Should have results from all major test categories
            test_categories = set()
            for result in tester.test_results:
                if "Health Check" in result.test_name:
                    test_categories.add("health")
                elif "API Endpoint" in result.test_name:
                    test_categories.add("api")
                elif "URL Risk" in result.test_name:
                    test_categories.add("url")
                elif "Scam Pattern" in result.test_name:
                    test_categories.add("scam")
                elif "Performance" in result.test_name:
                    test_categories.add("performance")
                elif "Agent Status" in result.test_name:
                    test_categories.add("agent")
            
            # Should have tested multiple categories
            assert len(test_categories) >= 4
    
    @pytest.mark.asyncio
    async def test_report_generation_integration(self):
        """Test report generation integration"""
        config = TestConfig()
        
        async with PayGuardFeatureTesterOptimized(config) as tester:
            # Add some test results
            tester._log_result("Test 1", TestStatus.PASS, "Success", 1.0)
            tester._log_result("Test 2", TestStatus.FAIL, "Failed", 0.5, "Error occurred")
            tester._log_result("Test 3", TestStatus.SKIP, "Skipped", 0.0)
            
            # Generate report
            with patch('builtins.open', create=True) as mock_open:
                with patch('json.dump') as mock_json_dump:
                    success = tester._generate_final_report(10.0)
                    
                    # Should generate report
                    mock_open.assert_called_once()
                    mock_json_dump.assert_called_once()
                    
                    # Should return appropriate success status
                    assert isinstance(success, bool)
                    
                    # Check report structure
                    report_data = mock_json_dump.call_args[0][0]
                    assert "summary" in report_data
                    assert "config" in report_data
                    assert "results" in report_data
                    assert "timestamp" in report_data

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])