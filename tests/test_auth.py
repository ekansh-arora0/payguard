#!/usr/bin/env python3
"""
Tests for backend/auth.py — APIKeyManager, require_api_key, rate limiting.

Uses an in-memory mock MongoDB collection via unittest.mock.
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from backend.auth import APIKeyManager, require_api_key, _MINUTE_LIMITS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    """Lightweight mock DB with api_keys collection."""
    db = MagicMock()
    db.api_keys = MagicMock()
    db.api_keys.insert_one = AsyncMock()
    db.api_keys.find_one = AsyncMock(return_value=None)
    db.api_keys.update_one = AsyncMock()
    return db


@pytest.fixture
def manager(mock_db):
    return APIKeyManager(mock_db)


# ---------------------------------------------------------------------------
# generate_api_key
# ---------------------------------------------------------------------------

class TestGenerateApiKey:
    @pytest.mark.asyncio
    async def test_returns_raw_key(self, manager):
        result = await manager.generate_api_key("TestBank")
        assert "api_key" in result
        assert len(result["api_key"]) > 20
        assert result["institution_name"] == "TestBank"
        assert result["tier"] == "free"

    @pytest.mark.asyncio
    async def test_default_limits(self, manager):
        result = await manager.generate_api_key("Bank", tier="premium")
        assert result["daily_limit"] == 10000

    @pytest.mark.asyncio
    async def test_enterprise_limit(self, manager):
        result = await manager.generate_api_key("Big Corp", tier="enterprise")
        assert result["daily_limit"] == 100000

    @pytest.mark.asyncio
    async def test_inserts_hashed_key(self, manager, mock_db):
        result = await manager.generate_api_key("Bank")
        raw_key = result["api_key"]
        expected_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        call_args = mock_db.api_keys.insert_one.call_args[0][0]
        assert call_args["key_hash"] == expected_hash
        assert "api_key" not in call_args  # Raw key must NOT be stored


# ---------------------------------------------------------------------------
# validate_api_key
# ---------------------------------------------------------------------------

class TestValidateApiKey:
    @pytest.mark.asyncio
    async def test_empty_key_raises_401(self, manager):
        with pytest.raises(HTTPException) as exc_info:
            await manager.validate_api_key("")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_key_raises_401(self, manager, mock_db):
        mock_db.api_keys.find_one = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc_info:
            await manager.validate_api_key("fake-key-12345")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_inactive_key_raises_401(self, manager, mock_db):
        mock_db.api_keys.find_one = AsyncMock(return_value={
            "key_hash": "x", "is_active": False, "tier": "free",
            "requests_count": 0, "daily_limit": 1000,
            "last_reset": datetime.utcnow(),
        })
        with pytest.raises(HTTPException) as exc_info:
            await manager.validate_api_key("some-key")
        assert exc_info.value.status_code == 401
        assert "inactive" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_daily_limit_exceeded_raises_429(self, manager, mock_db):
        mock_db.api_keys.find_one = AsyncMock(return_value={
            "key_hash": "x", "is_active": True, "tier": "free",
            "requests_count": 1000, "daily_limit": 1000,
            "last_reset": datetime.utcnow(),
        })
        with pytest.raises(HTTPException) as exc_info:
            await manager.validate_api_key("some-key")
        assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_valid_key_increments_count(self, manager, mock_db):
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        mock_db.api_keys.find_one = AsyncMock(return_value={
            "key_hash": key_hash, "is_active": True, "tier": "free",
            "requests_count": 5, "daily_limit": 1000,
            "last_reset": datetime.utcnow(),
        })
        doc = await manager.validate_api_key(raw_key)
        assert doc["is_active"] is True
        mock_db.api_keys.update_one.assert_called_once()

    @pytest.mark.asyncio
    async def test_daily_counter_resets_after_24h(self, manager, mock_db):
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        mock_db.api_keys.find_one = AsyncMock(return_value={
            "key_hash": key_hash, "is_active": True, "tier": "free",
            "requests_count": 999, "daily_limit": 1000,
            "last_reset": datetime.utcnow() - timedelta(days=2),
        })
        doc = await manager.validate_api_key(raw_key)
        # Should have called update_one twice: once for reset, once for increment
        assert mock_db.api_keys.update_one.call_count == 2


# ---------------------------------------------------------------------------
# _check_minute_limit (per-minute in-memory rate limiting)
# ---------------------------------------------------------------------------

class TestMinuteRateLimit:
    def test_under_limit_passes(self, manager):
        # Should not raise for first request
        manager._check_minute_limit("hash123", "free")

    def test_at_limit_raises_429(self, manager):
        limit = _MINUTE_LIMITS["free"]  # 60
        for _ in range(limit):
            manager._check_minute_limit("hash_over", "free")
        with pytest.raises(HTTPException) as exc_info:
            manager._check_minute_limit("hash_over", "free")
        assert exc_info.value.status_code == 429
        assert "60" in exc_info.value.detail

    def test_enterprise_has_higher_limit(self, manager):
        limit = _MINUTE_LIMITS["enterprise"]  # 1000
        # Should be able to make 999 requests without error
        for _ in range(limit - 1):
            manager._check_minute_limit("ent_hash", "enterprise")
        # 1000th should still pass
        manager._check_minute_limit("ent_hash", "enterprise")
        # 1001st should fail
        with pytest.raises(HTTPException):
            manager._check_minute_limit("ent_hash", "enterprise")

    def test_old_entries_pruned(self, manager):
        """Entries older than 1 minute should be pruned."""
        old_time = datetime.utcnow() - timedelta(minutes=2)
        manager._minute_log["prune_test"] = [old_time] * 100
        # This call should prune old entries and succeed
        manager._check_minute_limit("prune_test", "free")
        assert len(manager._minute_log["prune_test"]) == 1


# ---------------------------------------------------------------------------
# require_api_key dependency
# ---------------------------------------------------------------------------

class TestRequireApiKey:
    @pytest.mark.asyncio
    async def test_missing_key_raises_401(self):
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(api_key=None)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_empty_string_raises_401(self):
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(api_key="")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_present_key_returned(self):
        result = await require_api_key(api_key="test-key-abc")
        assert result == "test-key-abc"
