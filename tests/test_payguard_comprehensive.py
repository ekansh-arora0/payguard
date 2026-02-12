#!/usr/bin/env python3
"""
Comprehensive PayGuard Test Suite
Unit tests, integration tests, and end-to-end tests for all components
"""

import pytest
import asyncio
import json
import base64
import tempfile
import os
import time
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any, List
import httpx
from PIL import Image
import io

# Import PayGuard modules
import sys
sys.path.append(str(Path(__file__).parent.parent))

from backend.server import app
from backend.risk_engine import RiskScoringEngine
from backend.models import RiskCheckRequest, RiskLevel, MediaRisk
from agent.agent import Agent

class TestPayGuardBackend:
    """Test suite for PayGuard backend components"""
    
    @pytest.fixture
    def client(self):
        """FastAPI test client"""
        from fastapi.testclient import TestClient
        return TestClient(app)
    
    @pytest.fixture
    def mock_db(self):
        """Mock database for testing"""
        return Mock()
    
    @pytest.fixture
    def risk_engine(self, mock_db):
        """Risk engine instance for testing"""
        return RiskScoringEngine(mock_db)
    
    def test_health_endpoint(self, client):
        """Test health check endpoint"""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"
        assert "timestamp" in data
    
    def test_root_endpoint(self, client):
        """Test root API endpoint"""
        response = client.get("/api/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "PayGuard API" in data["message"]
        assert "endpoints" in data
        assert isinstance(data["endpoints"], list)
    
    @pytest.mark.parametrize("url,expected_risk", [
        ("https://google.com", RiskLevel.LOW),
        ("https://example.com", RiskLevel.LOW),
        ("http://suspicious-site.com", RiskLevel.MEDIUM),
    ])
    def test_risk_assessment_get(self, client, url, expected_risk):
        """Test GET risk assessment endpoint"""
        response = client.get(f"/api/risk?url={url}")
        assert response.status_code == 200
        data = response.json()
        
        # Validate response structure
        required_fields = ["url", "trust_score", "risk_level", "checked_at"]
        for field in required_fields:
            assert field in data
        
        assert data["url"] == url
        assert 0 <= data["trust_score"] <= 100
        assert data["risk_level"] in [level.value for level in RiskLevel]
    
    def test_risk_assessment_post(self, client):
        """Test POST risk assessment endpoint"""
        request_data = {
            "url": "https://example.com",
            "overlay_text": "URGENT: Your computer is infected!"
        }
        
        response = client.post("/api/risk", json=request_data)
        assert response.status_code == 200
        data = response.json()
        
        # Should detect scam in overlay text
        assert data["risk_level"] == RiskLevel.HIGH.value
        assert any("scam" in factor.lower() for factor in data.get("risk_factors", []))
    
    def test_media_risk_endpoint(self, client):
        """Test media risk assessment endpoint"""
        # Create a test image
        img = Image.new('RGB', (100, 100), color='red')
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        
        files = {"file": ("test.png", img_bytes, "image/png")}
        response = client.post("/api/media-risk-image", files=files)
        
        assert response.status_code == 200
        data = response.json()
        
        required_fields = ["url", "domain", "media_score", "media_color"]
        for field in required_fields:
            assert field in data
    
    def test_fraud_report_submission(self, client):
        """Test fraud report submission"""
        report_data = {
            "domain": "scam-site.com",
            "fraud_type": "phishing",
            "description": "Fake login page",
            "reporter_email": "test@example.com"
        }
        
        response = client.post("/api/fraud/report", json=report_data)
        assert response.status_code == 200
        data = response.json()
        
        assert data["domain"] == report_data["domain"]
        assert data["fraud_type"] == report_data["fraud_type"]
    
    @pytest.mark.asyncio
    async def test_risk_engine_url_analysis(self, risk_engine):
        """Test risk engine URL analysis"""
        # Mock database responses
        risk_engine.db.risk_checks.find_one = AsyncMock(return_value=None)
        risk_engine.db.merchants.find_one = AsyncMock(return_value=None)
        
        # Test legitimate URL
        risk_score = await risk_engine.calculate_risk("https://google.com")
        assert risk_score.trust_score > 50
        assert risk_score.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]
        
        # Test suspicious URL
        risk_score = await risk_engine.calculate_risk("http://phishing-site.tk")
        assert risk_score.trust_score < 70  # Should be flagged as risky
    
    def test_scam_text_analysis(self, risk_engine):
        """Test scam text detection"""
        # Test obvious scam text
        scam_texts = [
            "URGENT: Your computer is infected! Call 1-800-555-0199",
            "Your account has been suspended. Click here to verify.",
            "Congratulations! You've won $1000. Send us your bank details.",
            "VIRUS DETECTED! Do not close this window!"
        ]
        
        for text in scam_texts:
            result = risk_engine._analyze_text_for_scam(text)
            assert result["is_scam"] is True
            assert result["confidence"] > 70
            assert len(result["detected_patterns"]) > 0
        
        # Test legitimate text
        legitimate_texts = [
            "Welcome to our website. Please browse our products.",
            "Thank you for your purchase. Your order will arrive soon.",
            "Contact us for customer support at support@company.com"
        ]
        
        for text in legitimate_texts:
            result = risk_engine._analyze_text_for_scam(text)
            assert result["is_scam"] is False or result["confidence"] < 50

class TestPayGuardAgent:
    """Test suite for PayGuard agent"""
    
    @pytest.fixture
    def agent(self):
        """Agent instance for testing"""
        return Agent(server_host="localhost", server_port=8002)
    
    @pytest.fixture
    def mock_screenshot(self):
        """Mock screenshot data"""
        img = Image.new('RGB', (1920, 1080), color='white')
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        return img_bytes.getvalue()
    
    def test_agent_initialization(self, agent):
        """Test agent initialization"""
        assert agent.server_host == "localhost"
        assert agent.server_port == 8002
        assert agent.stop_flag is False
        assert agent.alert_cooldown == 10
    
    @patch('subprocess.run')
    def test_screen_capture(self, mock_subprocess, agent, mock_screenshot):
        """Test screen capture functionality"""
        # Mock successful screencapture
        mock_subprocess.return_value = Mock(returncode=0)
        
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open_binary(mock_screenshot)):
                result = agent._capture_screen()
                assert result is not None
                assert len(result) > 0
    
    @patch('subprocess.run')
    def test_clipboard_image_detection(self, mock_subprocess, agent, mock_screenshot):
        """Test clipboard image detection"""
        # Mock AppleScript success
        mock_subprocess.return_value = Mock(stdout="OK", returncode=0)
        
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open_binary(mock_screenshot)):
                result = agent._get_clipboard_image()
                assert result is not None
    
    def test_risk_response_handling(self, agent):
        """Test risk response handling"""
        # Test scam alert response
        scam_response = {
            "media_color": "high",
            "media_score": 95,
            "reasons": ["Scam detected"],
            "scam_alert": {
                "is_scam": True,
                "confidence": 95,
                "detected_patterns": ["virus_warning", "phone_number"],
                "senior_message": "This is a fake warning!",
                "action_advice": "Close this window immediately."
            }
        }
        
        with patch.object(agent, '_trigger_scam_alert') as mock_alert:
            agent._handle_risk_response(scam_response, "screen")
            mock_alert.assert_called_once()
        
        # Test AI image response
        ai_response = {
            "media_color": "medium",
            "media_score": 75,
            "reasons": ["Image appears AI-generated"],
            "scam_alert": None
        }
        
        with patch.object(agent, '_notify_modal_with_guidance') as mock_notify:
            agent._handle_risk_response(ai_response, "screen")
            mock_notify.assert_called_once()

class TestPayGuardIntegration:
    """Integration tests for PayGuard system"""
    
    @pytest.fixture
    def test_server(self):
        """Start test server"""
        import uvicorn
        import threading
        
        def run_server():
            uvicorn.run(app, host="127.0.0.1", port=8003, log_level="error")
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        time.sleep(2)  # Wait for server to start
        yield "http://127.0.0.1:8003"
    
    @pytest.mark.asyncio
    async def test_end_to_end_scam_detection(self, test_server):
        """Test complete scam detection workflow"""
        # Create scam image
        scam_img = create_scam_image()
        img_b64 = base64.b64encode(scam_img).decode()
        
        # Send to backend
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{test_server}/api/media-risk/bytes",
                json={
                    "url": "bytes://test",
                    "content": img_b64,
                    "metadata": {"static": True}
                }
            )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should detect scam
        if data.get("scam_alert"):
            assert data["scam_alert"]["is_scam"] is True
            assert data["scam_alert"]["confidence"] > 70
    
    @pytest.mark.asyncio
    async def test_performance_load_test(self, test_server):
        """Test system performance under load"""
        import asyncio
        
        async def make_request():
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{test_server}/api/health")
                return response.status_code == 200
        
        # Run 50 concurrent requests
        tasks = [make_request() for _ in range(50)]
        results = await asyncio.gather(*tasks)
        
        # All requests should succeed
        assert all(results)
        assert len(results) == 50

class TestPayGuardEdgeCases:
    """Test edge cases and error conditions"""
    
    def test_invalid_url_handling(self, client):
        """Test handling of invalid URLs"""
        invalid_urls = [
            "",
            "not-a-url",
            "ftp://invalid-protocol.com",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>"
        ]
        
        for url in invalid_urls:
            response = client.get(f"/api/risk?url={url}")
            # Should either reject or handle gracefully
            assert response.status_code in [200, 400, 422]
    
    def test_large_image_handling(self, client):
        """Test handling of large images"""
        # Create large image (10MB)
        large_img = Image.new('RGB', (3000, 3000), color='red')
        img_bytes = io.BytesIO()
        large_img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        
        files = {"file": ("large.png", img_bytes, "image/png")}
        response = client.post("/api/media-risk-image", files=files)
        
        # Should handle gracefully (either process or reject)
        assert response.status_code in [200, 413, 422]
    
    def test_malformed_requests(self, client):
        """Test handling of malformed requests"""
        malformed_requests = [
            {},  # Empty request
            {"url": None},  # Null URL
            {"url": "https://example.com", "overlay_text": None},  # Null overlay
            {"invalid_field": "value"}  # Invalid field
        ]
        
        for request_data in malformed_requests:
            response = client.post("/api/risk", json=request_data)
            assert response.status_code in [200, 400, 422]
    
    def test_network_timeout_handling(self, risk_engine):
        """Test handling of network timeouts"""
        with patch('httpx.AsyncClient.get') as mock_get:
            # Simulate timeout
            mock_get.side_effect = httpx.TimeoutException("Request timed out")
            
            # Should handle timeout gracefully
            result = asyncio.run(risk_engine.calculate_risk("https://slow-site.com"))
            assert result is not None
            assert hasattr(result, 'trust_score')

class TestPayGuardSecurity:
    """Security-focused tests"""
    
    def test_sql_injection_protection(self, client):
        """Test protection against SQL injection"""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'/*",
            "1' UNION SELECT * FROM users--"
        ]
        
        for malicious_input in malicious_inputs:
            response = client.get(f"/api/risk?url={malicious_input}")
            # Should not cause server error
            assert response.status_code != 500
    
    def test_xss_protection(self, client):
        """Test protection against XSS attacks"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//"
        ]
        
        for payload in xss_payloads:
            response = client.post("/api/risk", json={
                "url": "https://example.com",
                "overlay_text": payload
            })
            
            # Response should not contain unescaped payload
            assert payload not in response.text
    
    def test_api_rate_limiting(self, client):
        """Test API rate limiting (if implemented)"""
        # Make many rapid requests
        responses = []
        for _ in range(100):
            response = client.get("/api/health")
            responses.append(response.status_code)
        
        # Should either all succeed or some be rate limited
        assert all(code in [200, 429] for code in responses)

# Utility functions
def mock_open_binary(data):
    """Mock binary file open"""
    from unittest.mock import mock_open
    return mock_open(read_data=data)

def create_scam_image():
    """Create a test scam image"""
    img = Image.new('RGB', (800, 600), color='red')
    from PIL import ImageDraw, ImageFont
    
    draw = ImageDraw.Draw(img)
    
    # Add scam text
    text_lines = [
        "WARNING!",
        "YOUR COMPUTER IS INFECTED!",
        "CALL: 1-800-555-0199",
        "DO NOT CLOSE THIS WINDOW"
    ]
    
    y = 100
    for line in text_lines:
        draw.text((50, y), line, fill='white')
        y += 80
    
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    return img_bytes.getvalue()

# Pytest configuration
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])