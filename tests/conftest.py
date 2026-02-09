#!/usr/bin/env python3
"""
PyTest configuration and fixtures for PayGuard test suite
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
import os
import sys
import logging
from unittest.mock import Mock, AsyncMock
import httpx
from fastapi.testclient import TestClient

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure logging for tests
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()

@pytest.fixture(scope="session")
def temp_dir():
    """Create temporary directory for test files"""
    temp_path = Path(tempfile.mkdtemp(prefix="payguard_test_"))
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)

@pytest.fixture
def mock_db():
    """Mock MongoDB database"""
    db = Mock()
    
    # Mock collections
    db.risk_checks = Mock()
    db.merchants = Mock()
    db.fraud_reports = Mock()
    db.custom_rules = Mock()
    db.api_keys = Mock()
    db.media_checks = Mock()
    db.metrics = Mock()
    db.labels_feedback = Mock()
    db.transaction_checks = Mock()
    
    # Mock async methods
    for collection in [db.risk_checks, db.merchants, db.fraud_reports, 
                      db.custom_rules, db.api_keys, db.media_checks, 
                      db.metrics, db.labels_feedback, db.transaction_checks]:
        collection.find_one = AsyncMock(return_value=None)
        collection.find = Mock()
        collection.find.return_value.to_list = AsyncMock(return_value=[])
        collection.find.return_value.limit = Mock(return_value=collection.find.return_value)
        collection.find.return_value.sort = Mock(return_value=collection.find.return_value)
        collection.insert_one = AsyncMock()
        collection.update_one = AsyncMock()
        collection.delete_one = AsyncMock()
        collection.count_documents = AsyncMock(return_value=0)
        collection.aggregate = Mock()
        collection.aggregate.return_value.to_list = AsyncMock(return_value=[])
    
    return db

@pytest.fixture
def risk_engine(mock_db):
    """Risk engine instance with mocked database"""
    from backend.risk_engine import RiskScoringEngine
    return RiskScoringEngine(mock_db)

@pytest.fixture
def api_client():
    """FastAPI test client"""
    from backend.server import app
    return TestClient(app)

@pytest.fixture
def agent_instance():
    """PayGuard agent instance for testing"""
    from agent.agent import Agent
    agent = Agent(server_host="localhost", server_port=8002)
    agent.stop_flag = False
    return agent

@pytest.fixture
def sample_urls():
    """Sample URLs for testing"""
    return {
        "legitimate": [
            "https://google.com",
            "https://github.com",
            "https://stackoverflow.com",
            "https://wikipedia.org"
        ],
        "suspicious": [
            "http://suspicious-site.tk",
            "https://phishing-example.com",
            "http://malware-test.org"
        ],
        "invalid": [
            "",
            "not-a-url",
            "ftp://invalid-protocol.com",
            "javascript:alert('xss')"
        ]
    }

@pytest.fixture
def sample_scam_texts():
    """Sample scam texts for testing"""
    return [
        "URGENT: Your computer is infected! Call 1-800-555-0199 immediately!",
        "Your account has been suspended. Click here to verify your information.",
        "Congratulations! You've won $1000. Send us your bank details to claim.",
        "VIRUS DETECTED! Do not close this window or your files will be deleted.",
        "Your payment failed. Update your credit card information now.",
        "Microsoft Security Alert: Call +1-888-555-0123 for immediate assistance."
    ]

@pytest.fixture
def sample_legitimate_texts():
    """Sample legitimate texts for testing"""
    return [
        "Welcome to our website. Please browse our products and services.",
        "Thank you for your purchase. Your order will arrive in 3-5 business days.",
        "Our customer support team is available Monday through Friday.",
        "Please read our terms of service and privacy policy.",
        "Sign up for our newsletter to receive updates and special offers.",
        "Contact us at support@company.com for any questions."
    ]

@pytest.fixture
def test_images(temp_dir):
    """Create test images for testing"""
    from PIL import Image, ImageDraw
    
    images = {}
    
    # Create clean image
    clean_img = Image.new('RGB', (800, 600), color='white')
    clean_path = temp_dir / "clean_image.png"
    clean_img.save(clean_path)
    images['clean'] = clean_path
    
    # Create scam-like image
    scam_img = Image.new('RGB', (800, 600), color='red')
    draw = ImageDraw.Draw(scam_img)
    draw.text((50, 50), "WARNING! VIRUS DETECTED!", fill='white')
    draw.text((50, 150), "Call 1-800-555-0199", fill='yellow')
    scam_path = temp_dir / "scam_image.png"
    scam_img.save(scam_path)
    images['scam'] = scam_path
    
    # Create large image
    large_img = Image.new('RGB', (3000, 2000), color='blue')
    large_path = temp_dir / "large_image.png"
    large_img.save(large_path)
    images['large'] = large_path
    
    return images

@pytest.fixture
def mock_http_responses():
    """Mock HTTP responses for testing"""
    responses = {
        "https://google.com": {
            "status_code": 200,
            "text": "<html><head><title>Google</title></head><body>Search</body></html>",
            "headers": {"content-type": "text/html"}
        },
        "https://phishing-example.com": {
            "status_code": 200,
            "text": "<html><body><h1>Urgent Security Alert</h1><p>Your account has been compromised!</p></body></html>",
            "headers": {"content-type": "text/html"}
        },
        "https://timeout-site.com": {
            "status_code": None,  # Will raise timeout
            "exception": httpx.TimeoutException("Request timed out")
        }
    }
    return responses

@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch, temp_dir):
    """Set up test environment variables"""
    # Set test environment variables
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("TEST_DATA_DIR", str(temp_dir))
    
    # Mock external dependencies that might not be available in test environment
    monkeypatch.setattr("pytesseract.image_to_string", lambda x: "mocked ocr text")

@pytest.fixture
def performance_config():
    """Configuration for performance tests"""
    return {
        "max_response_time": 5.0,  # seconds
        "min_requests_per_second": 1.0,
        "max_memory_usage_mb": 500,
        "max_cpu_usage_percent": 80,
        "success_rate_threshold": 0.90
    }

# Pytest markers
def pytest_configure(config):
    """Configure pytest markers"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests"
    )
    config.addinivalue_line(
        "markers", "property: marks tests as property-based tests"
    )

# Test collection hooks
def pytest_collection_modifyitems(config, items):
    """Modify test collection"""
    # Add markers based on test names/paths
    for item in items:
        if "performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)
        if "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        if "property" in item.nodeid:
            item.add_marker(pytest.mark.property)
        if "slow" in item.name or "load" in item.name:
            item.add_marker(pytest.mark.slow)

# Custom assertions
def assert_valid_risk_score(risk_score):
    """Assert that a risk score is valid"""
    assert hasattr(risk_score, 'trust_score')
    assert hasattr(risk_score, 'risk_level')
    assert hasattr(risk_score, 'url')
    assert 0 <= risk_score.trust_score <= 100
    assert risk_score.risk_level in ['low', 'medium', 'high']

def assert_valid_media_risk(media_risk):
    """Assert that a media risk result is valid"""
    assert hasattr(media_risk, 'media_score')
    assert hasattr(media_risk, 'media_color')
    assert 0 <= media_risk.media_score <= 100
    assert media_risk.media_color in ['low', 'medium', 'high']

# Add custom assertions to pytest namespace
pytest.assert_valid_risk_score = assert_valid_risk_score
pytest.assert_valid_media_risk = assert_valid_media_risk