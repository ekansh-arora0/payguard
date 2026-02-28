"""
Tests for PayGuard V2 Secure API Gateway

Tests cover:
- TLS 1.3 configuration (Requirements 4.1, 4.2, 4.6)
- HSTS headers (Requirement 4.5)
- API key authentication (Requirement 4.4)
- Rate limiting (Requirement 4.10)
- Authentication failure logging (Requirement 4.9)
"""

import asyncio
import hashlib
import os
import ssl
import sys
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api_gateway import (BLOCKED_CIPHER_SUITES, SECURE_CIPHER_SUITES,
                         AuthFailureEvent, AuthFailureLogger, HSTSMiddleware,
                         RateLimitConfig, RateLimiter, SecureAPIGateway,
                         SecureAPIKeyManager, TLSConfig, TLSVersionChecker,
                         create_tls_ssl_context)


class TestTLSConfiguration:
    """Tests for TLS 1.3 configuration (Requirements 4.1, 4.2, 4.6)"""

    def test_tls_config_defaults_to_tls_1_3(self):
        """TLS config should default to TLS 1.3 only"""
        config = TLSConfig()
        assert config.min_version == ssl.TLSVersion.TLSv1_3
        assert config.max_version == ssl.TLSVersion.TLSv1_3

    def test_tls_config_uses_secure_ciphers(self):
        """TLS config should use only secure cipher suites"""
        config = TLSConfig()
        for cipher in config.cipher_suites:
            # Verify no blocked ciphers
            for blocked in BLOCKED_CIPHER_SUITES:
                assert (
                    blocked.upper() not in cipher.upper()
                ), f"Blocked cipher {blocked} found in {cipher}"

    def test_ssl_context_creation(self):
        """SSL context should be created with TLS 1.3 settings"""
        config = TLSConfig()
        context = config.create_ssl_context()

        assert context.minimum_version == ssl.TLSVersion.TLSv1_3
        assert context.maximum_version == ssl.TLSVersion.TLSv1_3

    def test_tls_version_checker_validates_tls_1_3(self):
        """TLS version checker should validate TLS 1.3 only config"""
        config = TLSConfig()
        context = config.create_ssl_context()

        assert TLSVersionChecker.is_tls_1_3_only(context) is True

    def test_tls_version_checker_detects_non_tls_1_3(self):
        """TLS version checker should detect non-TLS 1.3 configs"""
        # Create a context that allows TLS 1.2
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        assert TLSVersionChecker.is_tls_1_3_only(context) is False

    def test_tls_version_checker_validates_secure_ciphers(self):
        """TLS version checker should validate secure cipher suites"""
        config = TLSConfig()
        context = config.create_ssl_context()

        assert TLSVersionChecker.has_secure_ciphers_only(context) is True

    def test_validate_config_returns_complete_info(self):
        """validate_config should return complete validation info"""
        config = TLSConfig()
        context = config.create_ssl_context()

        result = TLSVersionChecker.validate_config(context)

        assert "tls_1_3_only" in result
        assert "secure_ciphers" in result
        assert "min_version" in result
        assert "max_version" in result
        assert result["tls_1_3_only"] is True
        assert result["secure_ciphers"] is True


class TestHSTSMiddleware:
    """Tests for HSTS headers (Requirement 4.5)"""

    def test_hsts_default_max_age_is_one_year(self):
        """HSTS should default to 1 year max-age"""
        assert HSTSMiddleware.DEFAULT_MAX_AGE == 31536000  # 1 year in seconds

    def test_hsts_header_value_format(self):
        """HSTS header should have correct format"""
        app = MagicMock()
        middleware = HSTSMiddleware(app)

        assert "max-age=31536000" in middleware.hsts_value
        assert "includeSubDomains" in middleware.hsts_value

    def test_hsts_preload_option(self):
        """HSTS should support preload option"""
        app = MagicMock()
        middleware = HSTSMiddleware(app, preload=True)

        assert "preload" in middleware.hsts_value

    def test_hsts_custom_max_age(self):
        """HSTS should support custom max-age"""
        app = MagicMock()
        custom_age = 86400  # 1 day
        middleware = HSTSMiddleware(app, max_age=custom_age)

        assert f"max-age={custom_age}" in middleware.hsts_value


class TestAuthFailureLogger:
    """Tests for authentication failure logging (Requirement 4.9)"""

    def _create_mock_request(self):
        """Create a mock request object"""
        request = MagicMock()
        request.url.path = "/api/test"
        request.headers = {
            "user-agent": "TestAgent/1.0",
            "x-request-id": "test-123",
        }
        request.client = MagicMock()
        request.client.host = "192.168.1.1"
        return request

    def test_log_failure_creates_event(self):
        """log_failure should create an AuthFailureEvent"""
        logger = AuthFailureLogger(db=None)
        mock_request = self._create_mock_request()

        event = asyncio.get_event_loop().run_until_complete(
            logger.log_failure(mock_request, "Invalid API key", "test_api_key_12345678")
        )

        assert isinstance(event, AuthFailureEvent)
        assert event.failure_reason == "Invalid API key"
        assert event.ip_address == "192.168.1.1"
        assert event.endpoint == "/api/test"
        assert event.api_key_prefix == "test_api"  # First 8 chars

    def test_log_failure_handles_missing_api_key(self):
        """log_failure should handle missing API key"""
        logger = AuthFailureLogger(db=None)
        mock_request = self._create_mock_request()

        event = asyncio.get_event_loop().run_until_complete(
            logger.log_failure(mock_request, "Missing API key", None)
        )

        assert event.api_key_prefix is None

    def test_log_failure_extracts_forwarded_ip(self):
        """log_failure should extract IP from X-Forwarded-For header"""
        logger = AuthFailureLogger(db=None)
        mock_request = self._create_mock_request()
        mock_request.headers["x-forwarded-for"] = "10.0.0.1, 192.168.1.1"

        event = asyncio.get_event_loop().run_until_complete(
            logger.log_failure(mock_request, "Test", None)
        )

        assert event.ip_address == "10.0.0.1"

    def test_anomaly_detection_tracks_failures(self):
        """Logger should track failures for anomaly detection"""
        logger = AuthFailureLogger(db=None)
        mock_request = self._create_mock_request()

        # Log multiple failures from same IP
        for _ in range(5):
            asyncio.get_event_loop().run_until_complete(
                logger.log_failure(mock_request, "Test", None)
            )

        assert logger._failure_count.get("192.168.1.1", 0) == 5

    def test_auth_failure_event_to_dict(self):
        """AuthFailureEvent should serialize to dict"""
        event = AuthFailureEvent(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            ip_address="192.168.1.1",
            endpoint="/api/test",
            failure_reason="Invalid key",
            api_key_prefix="test1234",
            user_agent="TestAgent",
            request_id="req-123",
        )

        result = event.to_dict()

        assert result["ip_address"] == "192.168.1.1"
        assert result["endpoint"] == "/api/test"
        assert result["failure_reason"] == "Invalid key"
        assert result["api_key_prefix"] == "test1234"


class TestRateLimiter:
    """Tests for rate limiting (Requirement 4.10)"""

    def _create_limiter(self):
        """Create a rate limiter"""
        config = RateLimitConfig(
            requests_per_minute=5,
            requests_per_hour=20,
        )
        return RateLimiter(config=config)

    def test_allows_requests_under_limit(self):
        """Rate limiter should allow requests under the limit"""
        limiter = self._create_limiter()

        allowed, reason = asyncio.get_event_loop().run_until_complete(
            limiter.check_rate_limit("test_key")
        )

        assert allowed is True
        assert reason is None

    def test_blocks_requests_over_minute_limit(self):
        """Rate limiter should block requests over minute limit"""
        limiter = self._create_limiter()

        # Make 5 requests (the limit) - all should be allowed
        for i in range(5):
            allowed, _ = asyncio.get_event_loop().run_until_complete(
                limiter.check_rate_limit("test_key_block")
            )
            assert allowed is True, f"Request {i+1} should be allowed"

        # 6th request should be blocked
        allowed, reason = asyncio.get_event_loop().run_until_complete(
            limiter.check_rate_limit("test_key_block")
        )

        assert allowed is False, "6th request should be blocked"
        assert reason is not None and "per minute" in reason

    def test_different_identifiers_have_separate_limits(self):
        """Different identifiers should have separate rate limits"""
        limiter = self._create_limiter()

        # Max out key1
        for _ in range(5):
            asyncio.get_event_loop().run_until_complete(
                limiter.check_rate_limit("key1")
            )

        # key2 should still be allowed
        allowed, _ = asyncio.get_event_loop().run_until_complete(
            limiter.check_rate_limit("key2")
        )
        assert allowed is True

    def test_tier_specific_limits(self):
        """Different tiers should have different limits"""
        limiter = self._create_limiter()

        free_limits = limiter._get_tier_limits("free")
        premium_limits = limiter._get_tier_limits("premium")
        enterprise_limits = limiter._get_tier_limits("enterprise")

        assert premium_limits["per_minute"] > free_limits["per_minute"]
        assert enterprise_limits["per_minute"] > premium_limits["per_minute"]


class TestSecureAPIKeyManager:
    """Tests for secure API key management (Requirement 4.4)"""

    def _create_mock_db(self):
        """Create a mock database"""
        db = MagicMock()
        db.api_keys = MagicMock()
        db.api_keys.find_one = AsyncMock()
        db.api_keys.insert_one = AsyncMock()
        db.api_keys.update_one = AsyncMock()
        db.auth_failures = MagicMock()
        db.auth_failures.insert_one = AsyncMock()
        return db

    def _create_mock_request(self):
        """Create a mock request"""
        request = MagicMock()
        request.url.path = "/api/test"
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        return request

    def test_validate_rejects_missing_key(self):
        """validate_api_key should reject missing API key"""
        mock_db = self._create_mock_db()
        manager = SecureAPIKeyManager(db=mock_db)
        mock_request = self._create_mock_request()

        with pytest.raises(Exception) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                manager.validate_api_key(None, mock_request)
            )

        assert "API key required" in str(exc_info.value.detail)

    def test_validate_rejects_invalid_key(self):
        """validate_api_key should reject invalid API key"""
        mock_db = self._create_mock_db()
        mock_db.api_keys.find_one.return_value = None
        manager = SecureAPIKeyManager(db=mock_db)
        mock_request = self._create_mock_request()

        with pytest.raises(Exception) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                manager.validate_api_key("invalid_key", mock_request)
            )

        assert "Invalid API key" in str(exc_info.value.detail)

    def test_validate_rejects_inactive_key(self):
        """validate_api_key should reject inactive API key"""
        mock_db = self._create_mock_db()
        mock_db.api_keys.find_one.return_value = {
            "key_hash": hashlib.sha256(b"test_key").hexdigest(),
            "is_active": False,
            "tier": "free",
        }
        manager = SecureAPIKeyManager(db=mock_db)
        mock_request = self._create_mock_request()

        with pytest.raises(Exception) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                manager.validate_api_key("test_key", mock_request)
            )

        assert "inactive" in str(exc_info.value.detail).lower()

    def test_validate_accepts_valid_key(self):
        """validate_api_key should accept valid API key"""
        mock_db = self._create_mock_db()
        test_key = "valid_test_key_12345"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        mock_db.api_keys.find_one.return_value = {
            "key_hash": key_hash,
            "is_active": True,
            "tier": "free",
            "institution_name": "Test Institution",
        }
        manager = SecureAPIKeyManager(db=mock_db)
        mock_request = self._create_mock_request()

        result = asyncio.get_event_loop().run_until_complete(
            manager.validate_api_key(test_key, mock_request)
        )

        assert result["is_active"] is True
        assert result["institution_name"] == "Test Institution"

    def test_generate_api_key_creates_secure_key(self):
        """generate_api_key should create a secure random key"""
        mock_db = self._create_mock_db()
        manager = SecureAPIKeyManager(db=mock_db)

        result = asyncio.get_event_loop().run_until_complete(
            manager.generate_api_key(institution_name="Test Corp", tier="premium")
        )

        assert "api_key" in result
        assert len(result["api_key"]) >= 32  # Secure length
        assert result["institution_name"] == "Test Corp"
        assert result["tier"] == "premium"

    def test_revoke_api_key(self):
        """revoke_api_key should deactivate the key"""
        mock_db = self._create_mock_db()
        mock_db.api_keys.update_one.return_value = MagicMock(modified_count=1)
        manager = SecureAPIKeyManager(db=mock_db)

        result = asyncio.get_event_loop().run_until_complete(
            manager.revoke_api_key("test_key")
        )

        assert result is True
        mock_db.api_keys.update_one.assert_called_once()


class TestSecureAPIGateway:
    """Tests for the complete secure API gateway"""

    def test_gateway_initialization(self):
        """Gateway should initialize with all components"""
        from fastapi import FastAPI

        app = FastAPI()

        gateway = SecureAPIGateway(
            app=app,
            db=None,
            enable_hsts=False,  # Disable for testing
            enable_auth=False,  # Disable for testing
        )

        assert gateway.api_key_manager is not None
        assert gateway.tls_config is not None

    def test_gateway_ssl_context(self):
        """Gateway should provide TLS 1.3 SSL context"""
        from fastapi import FastAPI

        app = FastAPI()

        gateway = SecureAPIGateway(
            app=app, db=None, enable_hsts=False, enable_auth=False
        )

        context = gateway.get_ssl_context()

        assert context.minimum_version == ssl.TLSVersion.TLSv1_3
        assert context.maximum_version == ssl.TLSVersion.TLSv1_3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
