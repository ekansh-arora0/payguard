#!/usr/bin/env python3
"""
Integration Tests for PayGuard Menu Bar
End-to-end testing of complete workflows and system integration
"""

import pytest
import threading
import time
import tempfile
import subprocess
import os
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys
from PIL import Image
import io

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from payguard_menubar_optimized import (
    PayGuardMenuBarOptimized, ScamDetector, NotificationManager,
    AlertType, DetectionResult
)

class TestPayGuardIntegration:
    """Integration tests for PayGuard system"""
    
    @pytest.fixture
    def payguard_config(self):
        """Test configuration for PayGuard"""
        return {
            "alert_cooldown": 0.5,
            "screen_check_interval": 0.5,
            "clipboard_check_interval": 0.5,
            "status_update_interval": 2,
            "enable_performance_monitoring": True,
            "log_level": "DEBUG"
        }
    
    @pytest.fixture
    def payguard(self, payguard_config):
        """PayGuard instance for testing"""
        guard = PayGuardMenuBarOptimized(payguard_config)
        yield guard
        guard.shutdown()
    
    def test_complete_scam_detection_workflow(self, payguard):
        """Test complete scam detection from input to notification"""
        scam_scenarios = [
            {
                'name': 'Tech Support Scam',
                'text': 'URGENT: Your computer is infected with malware! Call Microsoft at 1-800-555-0199 immediately!',
                'expected_patterns': ['urgency', 'virus_warning', 'phone_number', 'fake_company'],
                'expected_alert_type': AlertType.PHONE_SCAM
            },
            {
                'name': 'Phishing Email',
                'text': 'Your Amazon account has been suspended. Click here to verify your payment information.',
                'expected_patterns': ['account_threat', 'phishing'],
                'expected_alert_type': AlertType.PHISHING
            },
            {
                'name': 'Fake Virus Warning',
                'text': 'VIRUS DETECTED! Your files will be deleted in 5 minutes. Download our antivirus now!',
                'expected_patterns': ['virus_warning', 'urgency'],
                'expected_alert_type': AlertType.VIRUS_WARNING
            }
        ]
        
        for scenario in scam_scenarios:
            # Analyze text
            result = payguard.detector.analyze_text(scenario['text'])
            
            # Verify detection
            assert result.is_scam is True, f"Failed to detect scam: {scenario['name']}"
            assert result.confidence > 70, f"Low confidence for {scenario['name']}: {result.confidence}"
            
            # Verify expected patterns
            for pattern in scenario['expected_patterns']:
                assert pattern in result.patterns, f"Missing pattern {pattern} in {scenario['name']}"
            
            # Verify alert type
            if scenario['expected_alert_type']:
                assert result.alert_type == scenario['expected_alert_type'], \
                    f"Wrong alert type for {scenario['name']}: {result.alert_type}"
            
            # Test notification handling
            with patch.object(payguard.notification_manager, 'notify_user') as mock_notify:
                mock_notify.return_value = True
                
                initial_count = payguard.scam_count
                payguard.handle_detection(result, "integration_test")
                
                # Verify scam count increased
                assert payguard.scam_count == initial_count + 1
                
                # Verify notification was sent
                mock_notify.assert_called_once()
                call_args = mock_notify.call_args
                assert "PayGuard" in call_args[0][0]  # Title contains PayGuard
                assert len(call_args[0][1]) > 0  # Message is not empty
                assert call_args[1]['critical'] is True  # Critical notification
    
    def test_screen_monitoring_workflow(self, payguard):
        """Test complete screen monitoring workflow"""
        # Create test scam image
        scam_image_data = self._create_scam_image()
        
        with patch.object(payguard, 'capture_screen') as mock_capture, \
             patch.object(payguard.notification_manager, 'notify_user') as mock_notify:
            
            mock_capture.return_value = scam_image_data
            mock_notify.return_value = True
            
            # Simulate screen check
            image_data = payguard.capture_screen()
            assert image_data is not None
            
            # Analyze screen
            result = payguard.analyze_screen(image_data)
            
            # Handle detection
            payguard.handle_detection(result, "screen")
            
            # Verify workflow
            mock_capture.assert_called_once()
            if result.is_scam:
                mock_notify.assert_called_once()
                assert payguard.scam_count > 0
    
    def test_clipboard_monitoring_workflow(self, payguard):
        """Test complete clipboard monitoring workflow"""
        scam_texts = [
            "URGENT: Call Microsoft Support at 1-800-555-0199",
            "Your computer is infected with malware!",
            "Account suspended - verify immediately"
        ]
        
        for scam_text in scam_texts:
            with patch('subprocess.run') as mock_subprocess, \
                 patch.object(payguard.notification_manager, 'notify_user') as mock_notify:
                
                # Mock clipboard content
                mock_subprocess.return_value = Mock(
                    returncode=0,
                    stdout=scam_text
                )
                mock_notify.return_value = True
                
                # Reset clipboard content to ensure detection
                payguard.last_clipboard_content = ""
                
                # Check clipboard
                result = payguard.check_clipboard()
                
                # Handle detection
                payguard.handle_detection(result, "clipboard")
                
                # Verify workflow
                mock_subprocess.assert_called_once()
                if result.is_scam:
                    mock_notify.assert_called_once()
    
    def test_monitoring_loop_integration(self, payguard):
        """Test monitoring loop integration"""
        # Mock all monitoring functions
        with patch.object(payguard, 'capture_screen') as mock_capture, \
             patch.object(payguard, 'analyze_screen') as mock_analyze, \
             patch.object(payguard, 'check_clipboard') as mock_clipboard, \
             patch.object(payguard, 'handle_detection') as mock_handle, \
             patch.object(payguard, 'update_menu_bar') as mock_update:
            
            # Setup mocks
            mock_capture.return_value = b"fake_image_data"
            mock_analyze.return_value = DetectionResult(is_scam=False)
            mock_clipboard.return_value = DetectionResult(is_scam=False)
            
            # Start monitoring in thread
            monitor_thread = threading.Thread(target=payguard.monitor_loop, daemon=True)
            monitor_thread.start()
            
            # Let it run for a short time
            time.sleep(2)
            
            # Stop monitoring
            payguard.running = False
            monitor_thread.join(timeout=1)
            
            # Verify functions were called
            assert mock_capture.call_count > 0
            assert mock_analyze.call_count > 0
            assert mock_clipboard.call_count > 0
    
    def test_performance_monitoring_integration(self, payguard):
        """Test performance monitoring throughout workflow"""
        # Enable performance monitoring
        payguard.config["enable_performance_monitoring"] = True
        
        # Simulate operations that should be monitored
        with patch('subprocess.run') as mock_subprocess:
            mock_subprocess.return_value = Mock(returncode=0, stdout="test clipboard")
            
            # Perform monitored operations
            for _ in range(5):
                payguard.check_clipboard()
                time.sleep(0.1)
        
        # Check performance stats
        stats = payguard.performance_monitor.get_stats()
        
        assert stats["clipboard"]["avg"] > 0
        assert len(payguard.performance_monitor.clipboard_times) > 0
    
    def test_error_recovery_integration(self, payguard):
        """Test error recovery in integrated workflows"""
        error_scenarios = [
            {
                'name': 'Screen Capture Failure',
                'mock_target': 'capture_screen',
                'side_effect': Exception("Screen capture failed")
            },
            {
                'name': 'Clipboard Access Failure', 
                'mock_target': 'check_clipboard',
                'side_effect': Exception("Clipboard access failed")
            },
            {
                'name': 'Notification Failure',
                'mock_target': 'notification_manager.notify_user',
                'side_effect': Exception("Notification failed")
            }
        ]
        
        for scenario in error_scenarios:
            with patch.object(payguard, scenario['mock_target'].split('.')[0]) as mock_func:
                if '.' in scenario['mock_target']:
                    # Handle nested attributes
                    nested_mock = Mock()
                    setattr(nested_mock, scenario['mock_target'].split('.')[1], 
                           Mock(side_effect=scenario['side_effect']))
                    mock_func = nested_mock
                else:
                    mock_func.side_effect = scenario['side_effect']
                
                # System should handle errors gracefully
                try:
                    if 'screen' in scenario['name'].lower():
                        payguard.capture_screen()
                    elif 'clipboard' in scenario['name'].lower():
                        payguard.check_clipboard()
                    elif 'notification' in scenario['name'].lower():
                        result = DetectionResult(is_scam=True, message="Test")
                        payguard.handle_detection(result, "test")
                    
                    # Should not crash
                    assert True, f"System handled {scenario['name']} gracefully"
                    
                except Exception as e:
                    pytest.fail(f"System failed to handle {scenario['name']}: {e}")
    
    def test_concurrent_operations(self, payguard):
        """Test concurrent operations safety"""
        results = []
        
        def worker_screen():
            """Worker for screen operations"""
            try:
                with patch.object(payguard, 'capture_screen') as mock_capture:
                    mock_capture.return_value = b"fake_data"
                    for _ in range(10):
                        payguard.capture_screen()
                        time.sleep(0.01)
                results.append(("screen", True))
            except Exception as e:
                results.append(("screen", False, str(e)))
        
        def worker_clipboard():
            """Worker for clipboard operations"""
            try:
                with patch('subprocess.run') as mock_subprocess:
                    mock_subprocess.return_value = Mock(returncode=0, stdout="test")
                    for _ in range(10):
                        payguard.check_clipboard()
                        time.sleep(0.01)
                results.append(("clipboard", True))
            except Exception as e:
                results.append(("clipboard", False, str(e)))
        
        def worker_detection():
            """Worker for detection operations"""
            try:
                for i in range(10):
                    result = DetectionResult(is_scam=i % 3 == 0, message=f"Test {i}")
                    payguard.handle_detection(result, "concurrent_test")
                    time.sleep(0.01)
                results.append(("detection", True))
            except Exception as e:
                results.append(("detection", False, str(e)))
        
        # Start concurrent workers
        threads = [
            threading.Thread(target=worker_screen),
            threading.Thread(target=worker_clipboard),
            threading.Thread(target=worker_detection)
        ]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join(timeout=5)
        
        # Verify all operations completed successfully
        assert len(results) == 3
        for result in results:
            assert result[1] is True, f"Concurrent operation failed: {result}"
    
    def test_memory_management_integration(self, payguard):
        """Test memory management during extended operation"""
        import psutil
        import gc
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Simulate extended operation
        with patch.object(payguard, 'capture_screen') as mock_capture, \
             patch('subprocess.run') as mock_subprocess:
            
            mock_capture.return_value = b"fake_image_data" * 1000  # Larger data
            mock_subprocess.return_value = Mock(returncode=0, stdout="test clipboard content")
            
            # Perform many operations
            for i in range(100):
                payguard.capture_screen()
                payguard.check_clipboard()
                
                # Vary clipboard content to test caching
                payguard.last_clipboard_content = f"content_{i}"
                
                if i % 10 == 0:
                    gc.collect()  # Force garbage collection
        
        # Check memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_growth = final_memory - initial_memory
        
        # Memory growth should be reasonable (less than 50MB for this test)
        assert memory_growth < 50, f"Excessive memory growth: {memory_growth:.2f}MB"
    
    def test_configuration_integration(self, payguard):
        """Test configuration integration across components"""
        # Test that configuration affects behavior
        original_cooldown = payguard.config["alert_cooldown"]
        
        # Modify configuration
        payguard.config["alert_cooldown"] = 0.1
        payguard.notification_manager.cooldown_seconds = 0.1
        
        # Test rapid notifications
        result = DetectionResult(is_scam=True, message="Test 1")
        
        with patch.object(payguard.notification_manager, '_send_notification_sync'):
            # First notification should succeed
            success1 = payguard.notification_manager.notify_user("Test", "Message 1", critical=True)
            assert success1 is True
            
            # Second notification should be throttled
            success2 = payguard.notification_manager.notify_user("Test", "Message 2", critical=True)
            assert success2 is False
            
            # After cooldown, should succeed again
            time.sleep(0.15)
            success3 = payguard.notification_manager.notify_user("Test", "Message 3", critical=True)
            assert success3 is True
    
    def _create_scam_image(self) -> bytes:
        """Create a test scam image with red background"""
        try:
            img = Image.new('RGB', (800, 600), color='red')
            
            # Add some text to make it more realistic
            from PIL import ImageDraw
            draw = ImageDraw.Draw(img)
            draw.text((50, 50), "WARNING!", fill='white')
            draw.text((50, 100), "VIRUS DETECTED!", fill='white')
            
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            return img_bytes.getvalue()
            
        except ImportError:
            # If PIL is not available, return fake data
            return b"fake_red_image_data"

class TestRealWorldScenarios:
    """Test real-world usage scenarios"""
    
    @pytest.fixture
    def payguard(self):
        """PayGuard with realistic configuration"""
        config = {
            "alert_cooldown": 5,
            "screen_check_interval": 3,
            "clipboard_check_interval": 2,
            "status_update_interval": 30,
            "enable_performance_monitoring": True
        }
        guard = PayGuardMenuBarOptimized(config)
        yield guard
        guard.shutdown()
    
    def test_tech_support_scam_scenario(self, payguard):
        """Test complete tech support scam scenario"""
        # Simulate user encountering tech support scam
        scam_content = """
        ⚠️ CRITICAL SECURITY ALERT ⚠️
        
        Your computer has been infected with malware!
        
        Windows Security has detected:
        - Trojan.Win32.Generic
        - Adware.Suspicious.Activity
        - Potentially Unwanted Program
        
        DO NOT RESTART YOUR COMPUTER!
        
        Call Microsoft Support immediately:
        1-800-555-0199
        
        Reference ID: WIN-SEC-2024-7891
        """
        
        # Test detection
        result = payguard.detector.analyze_text(scam_content)
        
        assert result.is_scam is True
        assert result.confidence > 85
        assert 'virus_warning' in result.patterns
        assert 'phone_number' in result.patterns
        assert 'fake_company' in result.patterns
        assert 'scare_tactic' in result.patterns
        
        # Test user notification
        with patch.object(payguard.notification_manager, 'notify_user') as mock_notify:
            mock_notify.return_value = True
            payguard.handle_detection(result, "screen")
            
            # Should trigger critical alert
            mock_notify.assert_called_once()
            args = mock_notify.call_args
            assert "SCAM" in args[0][1].upper()  # Message should mention scam
    
    def test_phishing_email_scenario(self, payguard):
        """Test phishing email detection scenario"""
        phishing_content = """
        Amazon Security Notice
        
        Your account has been temporarily suspended due to unusual activity.
        
        To restore your account access, please verify your payment information
        within 24 hours or your account will be permanently closed.
        
        Click here to verify your account: https://amazon-security-verify.com
        
        If you did not request this, please contact our security team.
        
        Reference: AMZ-SEC-2024-1234
        """
        
        result = payguard.detector.analyze_text(phishing_content)
        
        assert result.is_scam is True
        assert result.confidence > 60
        assert 'account_threat' in result.patterns
        assert 'phishing' in result.patterns
        assert result.alert_type == AlertType.PHISHING
    
    def test_legitimate_content_scenario(self, payguard):
        """Test that legitimate content is not flagged"""
        legitimate_contents = [
            """
            Welcome to our newsletter!
            
            This month's highlights:
            - New product launches
            - Customer success stories
            - Upcoming events
            
            Contact us at support@company.com for questions.
            """,
            """
            Your order confirmation
            
            Thank you for your purchase! Your order #12345 will be
            shipped within 2-3 business days.
            
            Tracking information will be sent to your email.
            """,
            """
            Meeting reminder
            
            Don't forget about our team meeting tomorrow at 2 PM.
            
            Agenda:
            - Project updates
            - Budget review
            - Next quarter planning
            """
        ]
        
        for content in legitimate_contents:
            result = payguard.detector.analyze_text(content)
            assert result.is_scam is False or result.confidence < 40
    
    def test_mixed_content_scenario(self, payguard):
        """Test scenarios with mixed legitimate and suspicious content"""
        mixed_scenarios = [
            {
                'content': """
                Thank you for contacting our support team.
                
                For urgent technical issues, you can reach us at 1-800-555-0199.
                Our support hours are Monday-Friday 9 AM to 5 PM.
                """,
                'expected_scam': False,  # Legitimate business contact
                'note': 'Business phone number should not trigger scam detection'
            },
            {
                'content': """
                Your subscription expires soon.
                
                Renew now to continue enjoying our premium features.
                Click here to manage your subscription.
                """,
                'expected_scam': False,  # Legitimate renewal notice
                'note': 'Renewal notices should not be flagged as scams'
            },
            {
                'content': """
                URGENT: Your account shows suspicious activity!
                
                Verify immediately or face permanent suspension.
                Call our security team at 1-800-555-0199 now!
                """,
                'expected_scam': True,  # Combines urgency with threats
                'note': 'Urgent account threats should be flagged'
            }
        ]
        
        for scenario in mixed_scenarios:
            result = payguard.detector.analyze_text(scenario['content'])
            assert result.is_scam == scenario['expected_scam'], \
                f"Wrong classification: {scenario['note']}"

class TestSystemIntegration:
    """Test system-level integration"""
    
    def test_startup_shutdown_cycle(self):
        """Test complete startup and shutdown cycle"""
        config = {
            "alert_cooldown": 1,
            "enable_performance_monitoring": True
        }
        
        # Test startup
        payguard = PayGuardMenuBarOptimized(config)
        
        assert payguard.running is True
        assert payguard.scam_count == 0
        assert payguard.detector is not None
        assert payguard.notification_manager is not None
        assert payguard.performance_monitor is not None
        
        # Test shutdown
        payguard.shutdown()
        
        assert payguard.running is False
        assert len(payguard.temp_files) == 0
    
    def test_configuration_loading(self):
        """Test configuration loading and validation"""
        # Test with custom configuration file
        config_data = {
            "alert_cooldown": 15,
            "screen_check_interval": 5,
            "clipboard_check_interval": 3,
            "enable_performance_monitoring": False,
            "log_level": "WARNING"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name
        
        try:
            # Test loading configuration
            payguard = PayGuardMenuBarOptimized(config_data)
            
            assert payguard.config["alert_cooldown"] == 15
            assert payguard.config["screen_check_interval"] == 5
            assert payguard.config["clipboard_check_interval"] == 3
            assert payguard.config["enable_performance_monitoring"] is False
            
            payguard.shutdown()
            
        finally:
            os.unlink(config_file)

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])