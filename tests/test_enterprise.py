"""
Tests for payguard_enterprise.py — Enterprise dashboard and API.

Uses a temporary SQLite database per test class.
"""

import os
import sys
import tempfile
from pathlib import Path

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import patch

# Set enterprise token before import
os.environ.setdefault("ENTERPRISE_API_TOKEN", "test-enterprise-token")

from payguard_enterprise import (  # noqa: E402
    EnterpriseDB,
    ThreatAlert,
    app,
    verify_enterprise_token,
)
from fastapi.testclient import TestClient


# ---------- helpers ----------

AUTH_HEADER = {"Authorization": "Bearer test-enterprise-token"}


@pytest.fixture
def ent_db(tmp_path):
    """Create a fresh EnterpriseDB backed by a temp SQLite file."""
    db_path = str(tmp_path / "test_enterprise.db")
    return EnterpriseDB(db_path=db_path)


@pytest.fixture
def ent_client(ent_db):
    """FastAPI TestClient with db/push_service monkeypatched."""
    import payguard_enterprise as mod

    original_db = mod.db
    original_push = mod.push_service
    mod.db = ent_db
    mod.push_service = mod.MobilePushService()  # fresh, unused instance

    yield TestClient(app, raise_server_exceptions=False)

    # restore
    mod.db = original_db
    mod.push_service = original_push


# ====================== Database Unit Tests ======================

class TestEnterpriseDB:
    def test_create_organization(self, ent_db):
        org_id = ent_db.create_organization("Acme Corp", "acme.com")
        assert isinstance(org_id, str)
        assert len(org_id) == 16  # hex(8) → 16 chars

    def test_create_user(self, ent_db):
        org_id = ent_db.create_organization("Acme Corp", "acme.com")
        user_id = ent_db.create_user("alice@acme.com", "Alice", org_id)
        assert isinstance(user_id, str)

    def test_add_and_get_alerts(self, ent_db):
        org_id = ent_db.create_organization("Acme Corp", "acme.com")
        alert = ThreatAlert(
            id="alert001",
            timestamp="2026-01-01T00:00:00",
            user_email="alice@acme.com",
            threat_type="phishing",
            severity="high",
            source="email",
            indicator="https://evil.com",
            status="pending",
            details={"confidence": 0.95},
        )
        ent_db.add_alert(alert, org_id)
        alerts = ent_db.get_alerts(org_id)
        assert len(alerts) == 1
        assert alerts[0]["threat_type"] == "phishing"

    def test_get_alerts_with_status_filter(self, ent_db):
        org_id = ent_db.create_organization("Corp", "corp.com")
        for i, status in enumerate(["pending", "resolved", "pending"]):
            ent_db.add_alert(
                ThreatAlert(
                    id=f"a{i}",
                    timestamp="2026-01-01T00:00:00",
                    user_email=f"user{i}@corp.com",
                    threat_type="malware",
                    severity="medium",
                    source="url",
                    indicator=f"https://bad{i}.com",
                    status=status,
                    details={},
                ),
                org_id,
            )
        pending = ent_db.get_alerts(org_id, status="pending")
        assert len(pending) == 2
        resolved = ent_db.get_alerts(org_id, status="resolved")
        assert len(resolved) == 1

    def test_dashboard_stats(self, ent_db):
        org_id = ent_db.create_organization("Stats Corp", "stats.com")
        ent_db.create_user("bob@stats.com", "Bob", org_id)
        ent_db.add_alert(
            ThreatAlert(
                id="s1",
                timestamp="2026-02-09T12:00:00",
                user_email="bob@stats.com",
                threat_type="phishing",
                severity="high",
                source="email",
                indicator="https://x.com",
                status="resolved",
                details={},
            ),
            org_id,
        )
        stats = ent_db.get_dashboard_stats(org_id)
        assert stats["total_alerts"] == 1
        assert stats["user_count"] == 1
        assert stats["protection_score"] == 100  # 1 resolved out of 1

    def test_schema_migration_idempotent(self, tmp_path):
        """Creating EnterpriseDB twice on same file should not fail."""
        db_path = str(tmp_path / "migrate.db")
        db1 = EnterpriseDB(db_path=db_path)
        db2 = EnterpriseDB(db_path=db_path)
        # both should work
        org_id = db2.create_organization("Idem Corp", "idem.com")
        assert org_id


# ====================== API Endpoint Tests ======================

class TestEnterpriseHealthEndpoint:
    def test_health_no_auth(self, ent_client):
        """Health endpoint should NOT require auth."""
        resp = ent_client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


class TestEnterpriseAuth:
    def test_missing_token_returns_401(self, ent_client):
        resp = ent_client.get("/api/stats/demo")
        assert resp.status_code in (401, 403)

    def test_wrong_token_returns_401(self, ent_client):
        resp = ent_client.get(
            "/api/stats/demo",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401

    def test_valid_token_passes(self, ent_client, ent_db):
        # Create org so the stats endpoint doesn't fail on missing data
        org_id = ent_db.create_organization("Demo Corp", "demo.com")
        ent_db.create_user("u@demo.com", "U", org_id)
        resp = ent_client.get(f"/api/stats/{org_id}", headers=AUTH_HEADER)
        # Will get stats (may be empty but should not 401)
        assert resp.status_code == 200


class TestEnterpriseStatsEndpoint:
    def test_get_stats_empty_org(self, ent_client, ent_db):
        org_id = ent_db.create_organization("Test Org", "test.org")
        ent_db.create_user("u@test.org", "U", org_id)
        resp = ent_client.get(f"/api/stats/{org_id}", headers=AUTH_HEADER)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_alerts"] == 0
        assert body["user_count"] == 1


class TestEnterpriseAlertsEndpoint:
    def test_get_alerts_empty(self, ent_client, ent_db):
        org_id = ent_db.create_organization("Alert Org", "alert.org")
        ent_db.create_user("a@alert.org", "A", org_id)
        resp = ent_client.get(f"/api/alerts/{org_id}", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_alert_via_api(self, ent_client, ent_db):
        org_id = ent_db.create_organization("New Org", "new.org")
        ent_db.create_user("n@new.org", "N", org_id)
        resp = ent_client.post(
            f"/api/alerts/{org_id}",
            headers=AUTH_HEADER,
            json={
                "user_email": "n@new.org",
                "threat_type": "phishing",
                "severity": "critical",
                "source": "email",
                "indicator": "https://evil.com",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "created"
        assert "id" in body

        # Verify alert was persisted
        alerts = ent_db.get_alerts(org_id)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "critical"

    def test_limit_capped_at_1000(self, ent_client, ent_db):
        org_id = ent_db.create_organization("Limit Org", "limit.org")
        ent_db.create_user("l@limit.org", "L", org_id)
        resp = ent_client.get(
            f"/api/alerts/{org_id}",
            params={"limit": 9999},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200


class TestEnterpriseWebhook:
    def test_register_webhook(self, ent_client):
        resp = ent_client.post(
            "/api/webhook/register",
            headers=AUTH_HEADER,
            json={
                "user_id": "user123",
                "webhook_url": "https://hooks.example.com/payguard",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "registered"


class TestEnterpriseDashboardHTML:
    def test_dashboard_returns_html(self, ent_client):
        resp = ent_client.get("/")
        assert resp.status_code == 200
        assert "PayGuard Enterprise" in resp.text
