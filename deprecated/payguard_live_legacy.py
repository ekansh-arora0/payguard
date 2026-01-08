#!/usr/bin/env python3
"""
PayGuard Live - Optimized version with proper notifications and performance improvements
"""

import subprocess
import time
import base64
import json
import os
import re
from PIL import Image
import io
import threading
import logging
from typing import Dict, Optional, Tuple, List, Any
from dataclasses import dataclass
from enum import Enum
from contextlib import contextmanager
import tempfile
from pathlib import Path
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AlertLevel(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

@dataclass
class ScamAnalysisResult:
    """Result of scam analysis"""
    is_scam: bool
    confidence: float
    reason: str
    message: str
    advice: str
    patterns: List[str] = None
    alert_level: AlertLevel = AlertLevel.INFO

class PayGuardLive:
    """Optimized PayGuard Live monitoring system"""
    
    # Pre-compiled regex patterns for better performance
    SCAM_PATTERNS = [
        (re.compile(r'\b1-\d{3}-\d{3}-\d{4}\b'), 'phone_number', 30),
        (re.compile(r'(?i)\b(urgent|immediate|act now)\b'), 'urgency', 25),
        (re.compile(r'(?i)\b(virus|infected|malware)\b'), 'virus_warning', 35),
        (re.compile(r'(?i)\b(microsoft|apple|amazon).*(support|security)\b'), 'fake_company', 20),
        (re.compile(r'(?i)do not (close|restart|shut down)'), 'scare_tactic', 25),
        (re.compile(r'(?i)\b(suspended|blocked|expired)\b'), 'account_threat', 20),
    ]
    
    def __init__(self, alert_cooldown: int = 5, screen_check_interval: int = 3, 
                 clipboard_check_interval: int = 2):
        self.running = True
        self.last_alert_time = 0
        self.alert_cooldown = alert_cooldown
        self.screen_check_interval = screen_check_interval
        self.clipboard_check_interval = clipboard_check_interval
        self.last_clipboard_hash = ""
        self.temp_files: List[Path] = []
        self._stats = {
            'screens_analyzed': 0,
            'clipboard_checks': 0,
            'scams_detected': 0,
            'alerts_sent': 0
        }
    
    @contextmanager
    def _temp_file_manager(self, suffix: str = '.png'):
        """Context manager for temporary files with automatic cleanup"""
        temp_file = None
        try:
            temp_file = Path(tempfile.mktemp(suffix=suffix))
            self.temp_files.append(temp_file)
            yield temp_file
        finally:
            if temp_file and temp_file.exists():
                try:
                    temp_file.unlink()
                    if temp_file in self.temp_files:
                        self.temp_files.remove(temp_file)
                except OSError as e:
                    logger.warning(f"Failed to cleanup temp file {temp_file}: {e}")
    
    def cleanup(self):
        """Clean up any remaining temporary files"""
        for temp_file in self.temp_files[:]:
            try:
                if temp_file.exists():
                    temp_file.unlink()
                self.temp_files.remove(temp_file)
            except OSError as e:
                logger.warning(f"Failed to cleanup temp file {temp_file}: {e}")
    
    def get_stats(self) -> Dict[str, int]:
        """Get monitoring statistics"""
        return self._stats.copy()
        
    def notify_user(self, title: str, message: str, alert_level: AlertLevel = AlertLevel.INFO):
        """Send macOS notification with improved error handling and performance"""
        try:
            # Rate limiting check
            current_time = time.time()
            if current_time - self.last_alert_time < self.alert_cooldown:
                logger.debug(f"Alert rate limited: {title}")
                return False
            
            # Clean the message for AppleScript (more efficient)
            clean_title = self._sanitize_for_applescript(title)
            clean_message = self._sanitize_for_applescript(message)
            
            commands = []
            
            if alert_level == AlertLevel.CRITICAL:
                # Play sound and show notification
                commands.append(["osascript", "-e", "beep 3"])
                
                # Show notification with sound
                cmd = f'display notification "{clean_message}" with title "{clean_title}" sound name "Hero"'
                commands.append(["osascript", "-e", cmd])
                
                # Show dialog for critical alerts
                dialog_cmd = f'display dialog "{clean_message}" with title "{clean_title}" buttons {{"OK"}} default button 1 with icon stop giving up after 30'
                commands.append(["osascript", "-e", dialog_cmd])
                
                logger.critical(f"ALERT: {title} - {message}")
                
            elif alert_level == AlertLevel.WARNING:
                # Notification with warning sound
                cmd = f'display notification "{clean_message}" with title "{clean_title}" sound name "Basso"'
                commands.append(["osascript", "-e", cmd])
                logger.warning(f"WARNING: {title} - {message}")
                
            else:
                # Just notification
                cmd = f'display notification "{clean_message}" with title "{clean_title}"'
                commands.append(["osascript", "-e", cmd])
                logger.info(f"INFO: {title} - {message}")
            
            # Execute commands with timeout
            for command in commands:
                try:
                    subprocess.run(command, capture_output=True, timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Notification command timed out: {command}")
            
            self.last_alert_time = current_time
            self._stats['alerts_sent'] += 1
            return True
                
        except Exception as e:
            logger.error(f"Notification error: {e}")
            return False
    
    def _sanitize_for_applescript(self, text: str) -> str:
        """Sanitize text for AppleScript (optimized)"""
        # Use translate for better performance than multiple replace calls
        translation_table = str.maketrans({
            '"': '\\"',
            "'": "\\'",
            '\\': '\\\\',
            '\n': ' ',
            '\r': ' ',
            '\t': ' '
        })
        return text.translate(translation_table)[:200]  # Limit length
    
    def capture_screen(self) -> Optional[bytes]:
        """Capture screen screenshot with improved error handling"""
        try:
            with self._temp_file_manager('.png') as tmp_path:
                result = subprocess.run(
                    ["screencapture", "-x", "-C", str(tmp_path)], 
                    capture_output=True, 
                    timeout=10  # Increased timeout
                )
                
                if result.returncode == 0 and tmp_path.exists():
                    with open(tmp_path, "rb") as f:
                        data = f.read()
                    return data
                else:
                    logger.warning(f"Screen capture failed: {result.stderr}")
                    
        except subprocess.TimeoutExpired:
            logger.error("Screen capture timed out")
        except Exception as e:
            logger.error(f"Screen capture error: {e}")
        return None
    
    def _calculate_color_dominance(self, img: Image.Image) -> Tuple[float, float, float]:
        """Calculate color dominance ratios efficiently"""
        try:
            # Resize image for faster processing
            if img.size[0] * img.size[1] > 1000000:  # 1MP
                img = img.resize((800, 600), Image.Resampling.LANCZOS)
            
            colors = img.getcolors(maxcolors=256*256*256)
            if not colors:
                return 0.0, 0.0, 0.0
            
            total_pixels = sum(count for count, color in colors)
            red_pixels = orange_pixels = yellow_pixels = 0
            
            for count, color in colors:
                if isinstance(color, tuple) and len(color) >= 3:
                    r, g, b = color[:3]
                    
                    # Optimized color detection
                    if r > 180 and g < 100 and b < 100:  # Red
                        red_pixels += count
                    elif r > 200 and 100 < g < 200 and b < 100:  # Orange
                        orange_pixels += count
                    elif r > 200 and g > 200 and b < 100:  # Yellow
                        yellow_pixels += count
            
            return (
                red_pixels / total_pixels,
                orange_pixels / total_pixels,
                yellow_pixels / total_pixels
            )
        except Exception as e:
            logger.error(f"Color analysis error: {e}")
            return 0.0, 0.0, 0.0
    
    def analyze_screen_for_scams(self, image_data: bytes) -> ScamAnalysisResult:
        """Analyze screen image for scam content with improved algorithms"""
        try:
            self._stats['screens_analyzed'] += 1
            
            # Convert to PIL Image for analysis
            img = Image.open(io.BytesIO(image_data))
            
            # Calculate color dominance
            red_ratio, orange_ratio, yellow_ratio = self._calculate_color_dominance(img)
            
            # Visual scam indicators
            visual_score = 0
            reasons = []
            
            if red_ratio > 0.2:
                visual_score += 40
                reasons.append(f'High red content ({red_ratio:.1%})')
            elif red_ratio > 0.1:
                visual_score += 20
                reasons.append(f'Moderate red content ({red_ratio:.1%})')
            
            if orange_ratio > 0.15:
                visual_score += 25
                reasons.append(f'Orange warning colors ({orange_ratio:.1%})')
            
            if yellow_ratio > 0.15:
                visual_score += 15
                reasons.append(f'Yellow alert colors ({yellow_ratio:.1%})')
            
            # Determine if it's a scam based on visual cues
            if visual_score >= 40:
                confidence = min(60 + visual_score, 95)
                alert_level = AlertLevel.CRITICAL if confidence > 80 else AlertLevel.WARNING
                
                return ScamAnalysisResult(
                    is_scam=True,
                    confidence=confidence,
                    reason='; '.join(reasons),
                    message='STOP! This looks like a fake security alert.',
                    advice='Close this window immediately. Do NOT call any phone numbers.',
                    alert_level=alert_level
                )
            
            return ScamAnalysisResult(
                is_scam=False,
                confidence=10,
                reason='No suspicious visual indicators',
                message='Screen appears normal',
                advice='Continue with caution'
            )
            
        except Exception as e:
            logger.error(f"Screen analysis error: {e}")
            return ScamAnalysisResult(
                is_scam=False,
                confidence=0,
                reason=f'Analysis error: {str(e)}',
                message='Could not analyze screen',
                advice='Manual review recommended'
            )
    
    def check_clipboard_for_scams(self) -> ScamAnalysisResult:
        """Check clipboard for suspicious content with improved pattern matching"""
        try:
            self._stats['clipboard_checks'] += 1
            
            # Get clipboard text
            result = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=3)
            if result.returncode != 0:
                return ScamAnalysisResult(
                    is_scam=False,
                    confidence=0,
                    reason='Could not access clipboard',
                    message='Clipboard check failed',
                    advice='Manual review recommended'
                )
            
            text = result.stdout.strip()
            if not text:
                return ScamAnalysisResult(
                    is_scam=False,
                    confidence=0,
                    reason='Empty clipboard',
                    message='No content to analyze',
                    advice='Continue normally'
                )
            
            # Check if clipboard content changed (optimization)
            text_hash = hashlib.md5(text.encode()).hexdigest()
            if text_hash == self.last_clipboard_hash:
                return ScamAnalysisResult(is_scam=False, confidence=0, reason='No change', message='', advice='')
            
            self.last_clipboard_hash = text_hash
            
            # Analyze text with pre-compiled patterns
            detected_patterns = []
            total_score = 0
            
            for pattern, name, score in self.SCAM_PATTERNS:
                if pattern.search(text):
                    detected_patterns.append(name)
                    total_score += score
            
            # Calculate confidence based on pattern density and text length
            text_length = len(text)
            pattern_density = len(detected_patterns) / max(text_length / 100, 1)
            confidence = min(total_score + (pattern_density * 10), 100)
            
            if len(detected_patterns) >= 2 or confidence >= 60:
                alert_level = AlertLevel.CRITICAL if confidence > 80 else AlertLevel.WARNING
                
                return ScamAnalysisResult(
                    is_scam=True,
                    confidence=confidence,
                    reason=f'Detected patterns: {", ".join(detected_patterns)}',
                    message='STOP! Suspicious content detected in clipboard.',
                    advice='This looks like scam content. Do not follow any instructions.',
                    patterns=detected_patterns,
                    alert_level=alert_level
                )
            
            return ScamAnalysisResult(
                is_scam=False,
                confidence=total_score,
                reason='Insufficient scam indicators',
                message='Clipboard content appears normal',
                advice='Continue with caution',
                patterns=detected_patterns
            )
            
        except subprocess.TimeoutExpired:
            logger.error("Clipboard check timed out")
        except Exception as e:
            logger.error(f"Clipboard check error: {e}")
        
        return ScamAnalysisResult(
            is_scam=False,
            confidence=0,
            reason='Check failed',
            message='Could not analyze clipboard',
            advice='Manual review recommended'
        )
    
    def monitor_screen(self):
        """Monitor screen for scams with improved error handling"""
        logger.info("🖥️ Screen monitoring started...")
        
        consecutive_failures = 0
        max_failures = 5
        
        while self.running:
            try:
                # Capture screen
                image_data = self.capture_screen()
                if image_data:
                    consecutive_failures = 0  # Reset failure counter
                    
                    # Analyze for scams
                    result = self.analyze_screen_for_scams(image_data)
                    
                    if result.is_scam and time.time() - self.last_alert_time > self.alert_cooldown:
                        self.notify_user(
                            "🚨 PayGuard Scam Alert",
                            result.message,
                            result.alert_level
                        )
                        self._stats['scams_detected'] += 1
                        logger.warning(f"Scam detected: {result.reason}")
                else:
                    consecutive_failures += 1
                    if consecutive_failures >= max_failures:
                        logger.error("Too many consecutive screen capture failures, reducing frequency")
                        time.sleep(self.screen_check_interval * 3)  # Back off
                        consecutive_failures = 0
                
                time.sleep(self.screen_check_interval)
                
            except Exception as e:
                logger.error(f"Screen monitoring error: {e}")
                consecutive_failures += 1
                time.sleep(self.screen_check_interval * 2)  # Back off on error
    
    def monitor_clipboard(self):
        """Monitor clipboard for scams with improved efficiency"""
        logger.info("📋 Clipboard monitoring started...")
        
        consecutive_failures = 0
        max_failures = 10
        
        while self.running:
            try:
                # Check clipboard
                result = self.check_clipboard_for_scams()
                
                if result.is_scam and time.time() - self.last_alert_time > self.alert_cooldown:
                    self.notify_user(
                        "🚨 PayGuard Clipboard Alert", 
                        result.message,
                        result.alert_level
                    )
                    self._stats['scams_detected'] += 1
                    logger.warning(f"Clipboard scam detected: {result.reason}")
                
                consecutive_failures = 0  # Reset on success
                time.sleep(self.clipboard_check_interval)
                
            except Exception as e:
                logger.error(f"Clipboard monitoring error: {e}")
                consecutive_failures += 1
                if consecutive_failures >= max_failures:
                    logger.error("Too many clipboard failures, increasing interval")
                    time.sleep(self.clipboard_check_interval * 3)
                    consecutive_failures = 0
                else:
                    time.sleep(self.clipboard_check_interval * 2)
    
    def start(self):
        """Start PayGuard monitoring with improved lifecycle management"""
        logger.info("🛡️ PAYGUARD LIVE - STARTING")
        print("🛡️ PAYGUARD LIVE - STARTING")
        print("=" * 50)
        
        try:
            # Send startup notification
            self.notify_user(
                "🛡️ PayGuard Active",
                "Your device is now protected from scams!",
                AlertLevel.INFO
            )
            
            # Start monitoring threads with proper daemon setting
            screen_thread = threading.Thread(
                target=self.monitor_screen, 
                name="PayGuard-Screen",
                daemon=True
            )
            clipboard_thread = threading.Thread(
                target=self.monitor_clipboard, 
                name="PayGuard-Clipboard",
                daemon=True
            )
            
            screen_thread.start()
            clipboard_thread.start()
            
            print("✅ PayGuard is now monitoring your device!")
            print("🖥️ Screen monitoring: Active")
            print("📋 Clipboard monitoring: Active")
            print("📱 Notifications: Enabled")
            print(f"⚙️ Alert cooldown: {self.alert_cooldown}s")
            print(f"⚙️ Screen check interval: {self.screen_check_interval}s")
            print(f"⚙️ Clipboard check interval: {self.clipboard_check_interval}s")
            print("\nPress Ctrl+C to stop PayGuard")
            
            # Main monitoring loop with stats reporting
            last_stats_time = time.time()
            stats_interval = 300  # Report stats every 5 minutes
            
            while True:
                time.sleep(1)
                
                # Periodic stats reporting
                current_time = time.time()
                if current_time - last_stats_time > stats_interval:
                    stats = self.get_stats()
                    logger.info(f"Stats: {stats}")
                    last_stats_time = current_time
                    
        except KeyboardInterrupt:
            logger.info("🛑 Stopping PayGuard...")
            print("\n🛑 Stopping PayGuard...")
            self.stop()
        except Exception as e:
            logger.error(f"PayGuard startup error: {e}")
            self.stop()
            raise
    
    def stop(self):
        """Stop PayGuard monitoring"""
        self.running = False
        
        # Send shutdown notification
        self.notify_user(
            "PayGuard Stopped",
            "Protection has been disabled.",
            AlertLevel.INFO
        )
        
        # Cleanup resources
        self.cleanup()
        
        # Print final stats
        stats = self.get_stats()
        print(f"\n📊 Final Statistics:")
        print(f"   Screens analyzed: {stats['screens_analyzed']}")
        print(f"   Clipboard checks: {stats['clipboard_checks']}")
        print(f"   Scams detected: {stats['scams_detected']}")
        print(f"   Alerts sent: {stats['alerts_sent']}")
        print("✅ PayGuard stopped")
        
        logger.info(f"PayGuard stopped. Final stats: {stats}")

def test_notifications() -> bool:
    """Test if notifications work with improved error handling"""
    logger.info("🧪 Testing notifications...")
    
    try:
        # Test basic notification
        result1 = subprocess.run([
            "osascript", "-e", 
            'display notification "This is a test notification" with title "PayGuard Test"'
        ], capture_output=True, timeout=10)
        
        if result1.returncode != 0:
            logger.error(f"Basic notification failed: {result1.stderr}")
            return False
        
        # Test with sound
        result2 = subprocess.run(["osascript", "-e", 'beep 1'], capture_output=True, timeout=5)
        
        if result2.returncode != 0:
            logger.warning(f"Sound test failed: {result2.stderr}")
        
        # Test dialog
        result3 = subprocess.run([
            "osascript", "-e",
            'display dialog "PayGuard notification test successful!" with title "Test" buttons {"OK"} default button 1 giving up after 5'
        ], capture_output=True, timeout=10)
        
        if result3.returncode != 0:
            logger.warning(f"Dialog test failed: {result3.stderr}")
        
        logger.info("✅ Notification test completed!")
        print("✅ Notification test completed!")
        return True
        
    except subprocess.TimeoutExpired:
        logger.error("❌ Notification test timed out")
        print("❌ Notification test timed out")
        return False
    except Exception as e:
        logger.error(f"❌ Notification test failed: {e}")
        print(f"❌ Notification test failed: {e}")
        return False

def main():
    """Main function with improved error handling"""
    print("🛡️ PAYGUARD LIVE")
    print("=" * 30)
    
    try:
        # Test notifications first
        if not test_notifications():
            print("❌ Notifications not working properly")
            return 1
        
        # Start PayGuard
        payguard = PayGuardLive()
        payguard.start()
        return 0
        
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        return 0
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"❌ Fatal error: {e}")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())