"""
Tests for PayGuard V2 URL Reputation Service

Tests cover:
- Threat feed integration (OpenPhish, PhishTank, URLhaus)
- Bloom filter functionality
- Domain age checking
- SSL certificate inspection
- Whitelist management
- Cache operations
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from url_reputation import (
    URLReputationService,
    BloomFilter,
    OpenPhishFeed,
    PhishTankFeed,
    URLhausFeed,
    DomainAgeChecker,
    SSLInspector,
    WhitelistManager,
    ThreatType,
    ThreatSource,
    ReputationResult,
    SSLInfo,
    create_url_reputation_service,
)


def run_async(coro):
    """Helper to run async functions in sync tests"""
    return asyncio.get_event_loop().run_until_complete(coro)


# ============= Bloom Filter Tests =============

class TestBloomFilter:
    """Tests for BloomFilter implementation"""
    
    def test_add_and_contains(self):
        """Test adding items and checking membership"""
        bf = BloomFilter(size=10000, hash_count=5)
        
        bf.add("http://malicious.com/phish")
        bf.add("http://evil.com/malware")
        
        assert bf.contains("http://malicious.com/phish")
        assert bf.contains("http://evil.com/malware")
    
    def test_false_negatives_not_possible(self):
        """Bloom filters should never have false negatives"""
        bf = BloomFilter(size=10000, hash_count=5)
        
        urls = [f"http://test{i}.com" for i in range(100)]
        for url in urls:
            bf.add(url)
        
        # All added items must be found
        for url in urls:
            assert bf.contains(url), f"False negative for {url}"
    
    def test_clear(self):
        """Test clearing the bloom filter"""
        bf = BloomFilter(size=10000, hash_count=5)
        
        bf.add("http://test.com")
        assert bf.contains("http://test.com")
        
        bf.clear()
        # After clear, item should likely not be found
        # (technically could still be false positive, but very unlikely)
        assert bf.item_count == 0
    
    def test_item_count(self):
        """Test item count tracking"""
        bf = BloomFilter(size=10000, hash_count=5)
        
        assert bf.item_count == 0
        
        bf.add("http://test1.com")
        assert bf.item_count == 1
        
        bf.add("http://test2.com")
        assert bf.item_count == 2
    
    def test_estimated_false_positive_rate(self):
        """Test false positive rate estimation"""
        bf = BloomFilter(size=10000, hash_count=5)
        
        # Empty filter should have 0 FP rate
        assert bf.estimated_false_positive_rate == 0.0
        
        # Add some items
        for i in range(100):
            bf.add(f"http://test{i}.com")
        
        # FP rate should be small but non-zero
        fpr = bf.estimated_false_positive_rate
        assert 0 < fpr < 0.1  # Should be very low for this size


# ============= Whitelist Manager Tests =============

class TestWhitelistManager:
    """Tests for WhitelistManager"""
    
    def test_default_whitelist(self):
        """Test that default whitelist contains major domains"""
        wl = WhitelistManager()
        
        assert wl.is_whitelisted("google.com")
        assert wl.is_whitelisted("paypal.com")
        assert wl.is_whitelisted("github.com")
    
    def test_subdomain_whitelisting(self):
        """Test that subdomains of whitelisted domains are also whitelisted"""
        wl = WhitelistManager()
        
        # mail.google.com should be whitelisted because google.com is
        assert wl.is_whitelisted("mail.google.com")
        assert wl.is_whitelisted("accounts.google.com")
    
    def test_custom_whitelist(self):
        """Test adding custom whitelist entries"""
        custom = {"mycompany.com", "trusted-partner.org"}
        wl = WhitelistManager(custom_whitelist=custom)
        
        assert wl.is_whitelisted("mycompany.com")
        assert wl.is_whitelisted("trusted-partner.org")
    
    def test_add_to_whitelist(self):
        """Test dynamically adding to whitelist"""
        wl = WhitelistManager()
        
        assert not wl.is_whitelisted("newdomain.com")
        
        wl.add_to_whitelist("newdomain.com")
        
        assert wl.is_whitelisted("newdomain.com")
    
    def test_remove_from_whitelist(self):
        """Test removing custom entries from whitelist"""
        custom = {"removable.com"}
        wl = WhitelistManager(custom_whitelist=custom)
        
        assert wl.is_whitelisted("removable.com")
        
        result = wl.remove_from_whitelist("removable.com")
        
        assert result is True
        assert not wl.is_whitelisted("removable.com")
    
    def test_cannot_remove_default_entries(self):
        """Test that default whitelist entries cannot be removed"""
        wl = WhitelistManager()
        
        # google.com is a default entry
        result = wl.remove_from_whitelist("google.com")
        
        # Should return False (not removed) and still be whitelisted
        assert result is False
        assert wl.is_whitelisted("google.com")
    
    def test_case_insensitive(self):
        """Test that whitelist checks are case-insensitive"""
        wl = WhitelistManager()
        
        assert wl.is_whitelisted("GOOGLE.COM")
        assert wl.is_whitelisted("Google.Com")


# ============= URL Reputation Service Tests =============

class TestURLReputationService:
    """Tests for URLReputationService"""
    
    @pytest.fixture
    def service(self):
        """Create a service instance for testing"""
        return URLReputationService(
            enable_domain_age_check=False,  # Disable for faster tests
            enable_ssl_inspection=False
        )
    
    def test_check_whitelisted_url(self, service):
        """Test that whitelisted URLs are marked as safe"""
        result = run_async(service.check_url("https://google.com/search"))
        
        assert result.is_malicious is False
        assert result.is_whitelisted is True
        assert result.confidence == 1.0
    
    def test_check_unknown_url(self, service):
        """Test checking an unknown URL"""
        result = run_async(service.check_url("https://unknown-site-12345.com"))
        
        assert result.domain == "unknown-site-12345.com"
        assert result.is_whitelisted is False
    
    def test_result_caching(self, service):
        """Test that results are cached"""
        url = "https://test-caching.com"
        
        # First check
        result1 = run_async(service.check_url(url))
        assert result1.cached is False
        
        # Second check should be cached
        result2 = run_async(service.check_url(url))
        assert result2.cached is True
    
    def test_batch_check(self, service):
        """Test batch URL checking"""
        urls = [
            "https://google.com",
            "https://unknown1.com",
            "https://unknown2.com"
        ]
        
        results = run_async(service.check_urls(urls))
        
        assert len(results) == 3
        assert "https://google.com" in results
        assert results["https://google.com"].is_whitelisted is True
    
    def test_whitelist_management(self, service):
        """Test whitelist management through service"""
        domain = "my-safe-domain.com"
        
        assert not service.is_whitelisted(domain)
        
        service.add_to_whitelist(domain)
        assert service.is_whitelisted(domain)
        
        service.remove_from_whitelist(domain)
        assert not service.is_whitelisted(domain)
    
    def test_cache_stats(self, service):
        """Test getting cache statistics"""
        stats = service.get_cache_stats()
        
        assert stats.total_entries >= 0
        assert stats.bloom_filter_size > 0
        assert stats.false_positive_rate >= 0


# ============= Domain Age Checker Tests =============

class TestDomainAgeChecker:
    """Tests for DomainAgeChecker"""
    
    def test_is_new_domain(self):
        """Test new domain detection"""
        checker = DomainAgeChecker()
        
        # Less than 30 days is new
        assert checker.is_new_domain(15) is True
        assert checker.is_new_domain(29) is True
        
        # 30 days or more is not new
        assert checker.is_new_domain(30) is False
        assert checker.is_new_domain(365) is False
        
        # None means unknown, don't flag
        assert checker.is_new_domain(None) is False


# ============= SSL Inspector Tests =============

class TestSSLInspector:
    """Tests for SSLInspector"""
    
    def test_domain_matches_cert_exact(self):
        """Test exact domain matching"""
        inspector = SSLInspector()
        
        assert inspector._domain_matches_cert(
            "example.com",
            "example.com",
            []
        ) is True
    
    def test_domain_matches_cert_wildcard(self):
        """Test wildcard certificate matching"""
        inspector = SSLInspector()
        
        assert inspector._domain_matches_cert(
            "sub.example.com",
            "*.example.com",
            []
        ) is True
        
        assert inspector._domain_matches_cert(
            "example.com",
            "*.example.com",
            []
        ) is True
    
    def test_domain_matches_cert_san(self):
        """Test SAN matching"""
        inspector = SSLInspector()
        
        assert inspector._domain_matches_cert(
            "api.example.com",
            "example.com",
            ["api.example.com", "www.example.com"]
        ) is True
    
    def test_organization_match(self):
        """Test organization matching heuristic"""
        inspector = SSLInspector()
        
        # Domain part appears in organization
        assert inspector._check_organization_match(
            "google.com",
            "Google LLC",
            "google.com"
        ) is True
        
        # No match
        assert inspector._check_organization_match(
            "example.com",
            "Unrelated Corp",
            "example.com"
        ) is False


# ============= Threat Feed Tests =============

class TestOpenPhishFeed:
    """Tests for OpenPhish feed"""
    
    def test_check_url_not_in_feed(self):
        """Test checking URL not in feed"""
        feed = OpenPhishFeed()
        
        result = run_async(feed.check_url("https://safe-site.com"))
        
        assert result is None
    
    def test_check_url_in_feed(self):
        """Test checking URL that's in the feed"""
        feed = OpenPhishFeed()
        
        # Manually add a URL to simulate fetched data
        test_url = "http://phishing-test.com/login"
        feed._urls.add(test_url)
        feed._bloom.add(test_url)
        
        result = run_async(feed.check_url(test_url))
        
        assert result == ThreatType.PHISHING


class TestPhishTankFeed:
    """Tests for PhishTank feed"""
    
    def test_check_url_not_in_feed(self):
        """Test checking URL not in feed"""
        feed = PhishTankFeed()
        
        result = run_async(feed.check_url("https://safe-site.com"))
        
        assert result is None


class TestURLhausFeed:
    """Tests for URLhaus feed"""
    
    def test_check_url_not_in_feed(self):
        """Test checking URL not in feed"""
        feed = URLhausFeed()
        
        result = run_async(feed.check_url("https://safe-site.com"))
        
        assert result is None
    
    def test_check_url_in_feed(self):
        """Test checking URL that's in the feed"""
        feed = URLhausFeed()
        
        # Manually add a URL to simulate fetched data
        test_url = "http://malware-host.com/payload.exe"
        feed._urls.add(test_url)
        feed._bloom.add(test_url)
        
        result = run_async(feed.check_url(test_url))
        
        assert result == ThreatType.MALWARE


# ============= Factory Function Tests =============

class TestFactoryFunction:
    """Tests for create_url_reputation_service factory"""
    
    def test_create_default_service(self):
        """Test creating service with defaults"""
        service = create_url_reputation_service()
        
        assert service is not None
        assert isinstance(service, URLReputationService)
    
    def test_create_service_with_custom_whitelist(self):
        """Test creating service with custom whitelist"""
        custom = {"custom-domain.com"}
        service = create_url_reputation_service(custom_whitelist=custom)
        
        assert service.is_whitelisted("custom-domain.com")
    
    def test_create_service_disabled_features(self):
        """Test creating service with disabled features"""
        service = create_url_reputation_service(
            enable_domain_age_check=False,
            enable_ssl_inspection=False
        )
        
        assert service._domain_age_checker is None
        assert service._ssl_inspector is None


# ============= Integration Tests =============

class TestIntegration:
    """Integration tests for URL Reputation Service"""
    
    def test_full_check_flow(self):
        """Test complete URL check flow"""
        service = URLReputationService(
            enable_domain_age_check=False,
            enable_ssl_inspection=False
        )
        
        # Check a whitelisted URL
        result = run_async(service.check_url("https://github.com/test/repo"))
        assert result.is_malicious is False
        assert result.is_whitelisted is True
        
        # Check an unknown URL
        result = run_async(service.check_url("https://random-unknown-site.xyz"))
        assert result.is_whitelisted is False
        assert result.domain == "random-unknown-site.xyz"
    
    def test_cache_update_without_network(self):
        """Test cache update handles network errors gracefully"""
        service = URLReputationService(
            enable_domain_age_check=False,
            enable_ssl_inspection=False
        )
        
        # This will fail to fetch from real feeds but should not crash
        result = run_async(service.update_cache())
        
        # Should complete (may have errors due to network)
        assert result is not None
        assert isinstance(result.duration_seconds, float)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
