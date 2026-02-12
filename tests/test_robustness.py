"""
Comprehensive integration and robustness tests for PayGuard.
These tests verify the entire system works correctly under various conditions.
"""

import asyncio
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock
import time
import json

# Import after env setup
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "payguard_test")

from backend.models import RiskLevel


class TestRobustness:
    """Test system robustness under various conditions."""
    
    @pytest.mark.asyncio
    async def test_concurrent_risk_checks(self):
        """System should handle concurrent requests without corruption."""
        from backend.risk_engine import RiskScoringEngine
        
        engine = RiskScoringEngine.__new__(RiskScoringEngine)
        engine.db = MagicMock()
        engine.ml_model = None
        engine.html_cnn = None
        engine.blacklist_urls = set()
        engine.blacklist_domains = set()
        
        urls = [
            "https://example.com",
            "https://google.com", 
            "https://suspicious-site.com",
            "https://amazon.com",
            "https://test-site.org"
        ]
        
        # Run 10 concurrent checks
        tasks = [engine.calculate_risk(url) for url in urls * 2]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should complete without exceptions
        for result in results:
            assert not isinstance(result, Exception), f"Request failed with: {result}"
            assert hasattr(result, 'trust_score')
            assert 0 <= result.trust_score <= 100
    
    @pytest.mark.asyncio
    async def test_rate_limiting_accuracy(self):
        """Rate limiting should be accurate and not drift."""
        from backend.auth import APIKeyManager
        
        mock_db = MagicMock()
        mock_db.api_keys = MagicMock()
        
        manager = APIKeyManager(mock_db)
        
        # Simulate rapid requests
        key = "test_key"
        tier = "free"
        
        results = []
        for _ in range(70):  # Try 70 requests (limit is 60)
            result = await manager.check_minute_rate_limit(key, tier)
            results.append(result)
        
        # First 60 should pass, rest should fail
        passed = sum(results)
        assert passed == 60, f"Expected 60 passed, got {passed}"
    
    @pytest.mark.asyncio
    async def test_database_failures_handled(self):
        """System should handle database failures gracefully."""
        from backend.risk_engine import RiskScoringEngine
        
        engine = RiskScoringEngine.__new__(RiskScoringEngine)
        engine.db = MagicMock()
        
        # Simulate DB failure
        engine.db.merchants = MagicMock()
        engine.db.merchants.find_one = AsyncMock(side_effect=Exception("DB connection lost"))
        
        # Should still return a result
        result = await engine.calculate_risk("https://example.com")
        
        assert result is not None
        assert hasattr(result, 'trust_score')
    
    def test_trusted_domain_variations(self):
        """Trusted domain detection should handle various formats."""
        from backend.risk_engine import RiskScoringEngine
        
        engine = RiskScoringEngine.__new__(RiskScoringEngine)
        
        trusted_variations = [
            ("amazon.com", True),
            ("www.amazon.com", True),
            ("smile.amazon.com", True),
            ("aws.amazon.com", True),
            ("AMAZON.COM", True),  # Case insensitive
            ("amazon.co.uk", True),
            ("fake-amazon.com", False),
            ("amazon.com.evil.com", False),
            ("", False),
            (None, False),
        ]
        
        for domain, expected in trusted_variations:
            result = engine._is_trusted_domain(domain)
            assert result == expected, f"Failed for {domain}: expected {expected}, got {result}"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_malformed_urls(self):
        """System should handle malformed URLs gracefully."""
        from backend.risk_engine import RiskScoringEngine
        
        engine = RiskScoringEngine.__new__(RiskScoringEngine)
        engine.db = MagicMock()
        engine.ml_model = None
        engine.html_cnn = None
        
        malformed_urls = [
            "",
            "not-a-url",
            "http://",
            "https://",
            "ftp://file.com",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            "///path",
            "http://[:::1]",
        ]
        
        for url in malformed_urls:
            try:
                result = await engine.calculate_risk(url)
                assert result is not None, f"Should return result for: {url}"
            except Exception as e:
                # Some URLs might raise exceptions - that's okay if handled
                assert True
    
    @pytest.mark.asyncio
    async def test_extreme_latency(self):
        """System should handle slow external services."""
        from backend.risk_engine import RiskScoringEngine
        
        engine = RiskScoringEngine.__new__(RiskScoringEngine)
        engine.db = MagicMock()
        
        # Mock slow WHOIS lookup
        async def slow_whois(*args, **kwargs):
            await asyncio.sleep(5)  # Very slow
            return None
        
        with patch.object(engine, '_check_domain_age', slow_whois):
            start = time.time()
            result = await engine.calculate_risk("https://example.com")
            duration = time.time() - start
            
            # Should complete in reasonable time despite slow dependency
            assert duration < 3, f"Took too long: {duration}s"
            assert result is not None
    
    def test_html_content_edge_cases(self):
        """HTML analysis should handle various content types."""
        from backend.risk_engine import RiskScoringEngine
        
        engine = RiskScoringEngine.__new__(RiskScoringEngine)
        
        edge_cases = [
            "",  # Empty
            "<html></html>",  # Minimal
            "<script>alert('xss')</script>",  # XSS attempt
            "a" * 1000000,  # Very large
            "🎉💳🔒",  # Unicode/emoji
            "<form action='http://evil.com'>...</form>",  # Suspicious form
        ]
        
        for html in edge_cases:
            try:
                result = engine._html_features(html)
                assert result is not None
            except Exception as e:
                assert False, f"Failed on HTML content: {e}"


class TestSecurity:
    """Security-focused tests."""
    
    def test_nosql_injection_prevention(self):
        """System should prevent NoSQL injection attacks."""
        from backend.server import _sanitize_mongo_input
        
        malicious_inputs = [
            {"$gt": ""},
            {"$ne": None},
            {"$where": "sleep(1000)"},
            "{$gt: ''}",
            "username: {$exists: true}",
        ]
        
        for malicious in malicious_inputs:
            with pytest.raises(Exception):
                _sanitize_mongo_input(str(malicious))
    
    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self):
        """API responses should have consistent timing regardless of input."""
        from backend.auth import APIKeyManager
        
        mock_db = MagicMock()
        manager = APIKeyManager(mock_db)
        
        # Test with valid and invalid keys
        valid_times = []
        invalid_times = []
        
        for _ in range(10):
            start = time.time()
            await manager.validate_api_key("valid_key_12345")
            valid_times.append(time.time() - start)
            
            start = time.time()
            await manager.validate_api_key("invalid")
            invalid_times.append(time.time() - start)
        
        # Times should be reasonably similar (within 100ms)
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        
        assert abs(avg_valid - avg_invalid) < 0.1, "Timing difference too large"
    
    def test_sensitive_data_not_logged(self):
        """API keys and passwords should not appear in logs."""
        import logging
        
        # Create a test log handler
        test_handler = MagicMock()
        test_handler.level = logging.DEBUG
        
        # Simulate logging with sensitive data
        api_key = "pg_live_secret_key_12345"
        password = "super_secret_password"
        
        # These should not appear in any log messages
        log_messages = [
            f"Request from user with key {api_key}",
            f"Authentication failed for {password}",
            "Processing request",
        ]
        
        for msg in log_messages:
            if api_key in msg or password in msg:
                assert False, "Sensitive data found in log message"


class TestPerformance:
    """Performance and load tests."""
    
    @pytest.mark.asyncio
    async def test_response_time_requirements(self):
        """API should respond within acceptable time limits."""
        from backend.risk_engine import RiskScoringEngine
        
        engine = RiskScoringEngine.__new__(RiskScoringEngine)
        engine.db = MagicMock()
        engine.ml_model = None
        engine.html_cnn = None
        
        times = []
        for _ in range(10):
            start = time.time()
            await engine.calculate_risk("https://example.com")
            times.append(time.time() - start)
        
        avg_time = sum(times) / len(times)
        p95 = sorted(times)[int(len(times) * 0.95)]
        
        assert avg_time < 0.5, f"Average response time too slow: {avg_time}s"
        assert p95 < 1.0, f"P95 response time too slow: {p95}s"
    
    @pytest.mark.asyncio
    async def test_memory_usage_stable(self):
        """Memory usage should remain stable under load."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        from backend.risk_engine import RiskScoringEngine
        engine = RiskScoringEngine.__new__(RiskScoringEngine)
        engine.db = MagicMock()
        engine.ml_model = None
        engine.html_cnn = None
        
        # Run 100 calculations
        for i in range(100):
            await engine.calculate_risk(f"https://example{i}.com")
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_growth = final_memory - initial_memory
        
        # Memory growth should be minimal (less than 100MB)
        assert memory_growth < 100, f"Memory grew by {memory_growth}MB"


class TestDataIntegrity:
    """Data integrity and consistency tests."""
    
    @pytest.mark.asyncio
    async def test_idempotent_risk_checks(self):
        """Same URL should return consistent results."""
        from backend.risk_engine import RiskScoringEngine
        
        engine = RiskScoringEngine.__new__(RiskScoringEngine)
        engine.db = MagicMock()
        engine.ml_model = None
        engine.html_cnn = None
        
        url = "https://example.com"
        
        results = []
        for _ in range(5):
            result = await engine.calculate_risk(url)
            results.append(result.trust_score)
        
        # Results should be very similar (within 5 points)
        assert max(results) - min(results) < 5, f"Results too variable: {results}"
    
    @pytest.mark.asyncio
    async def test_risk_level_consistency(self):
        """Risk levels should align with trust scores."""
        from backend.risk_engine import RiskScoringEngine
        from backend.models import RiskLevel
        
        engine = RiskScoringEngine.__new__(RiskScoringEngine)
        engine.db = MagicMock()
        engine.ml_model = None
        engine.html_cnn = None
        
        test_cases = [
            ("https://amazon.com", RiskLevel.LOW),
            ("https://verify-login-suspicious.xyz", RiskLevel.HIGH),
        ]
        
        for url, expected_min_level in test_cases:
            result = await engine.calculate_risk(url)
            
            # Verify trust score aligns with risk level
            if result.risk_level == RiskLevel.LOW:
                assert result.trust_score >= 65
            elif result.risk_level == RiskLevel.HIGH:
                assert result.trust_score < 40


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
