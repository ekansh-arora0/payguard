#!/usr/bin/env python3
"""
PayGuard Live - Privacy-First Version

PRIVACY NOTICE: This version has been completely redesigned with privacy-first principles:
- NO continuous screen capture
- NO background clipboard monitoring
- All scans require explicit user action (button click, menu selection, or keyboard shortcut)
- User data stays on device unless explicitly approved

This module provides user-initiated scanning capabilities for scam detection.
"""

import subprocess
import time
import base64
import json
import os
import re
from PIL import Image
import io
import logging
from typing import Dict, Optional, Tuple, List, Any
from dataclasses import dataclass, field
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
    patterns: List[str] = field(default_factory=list)
    alert_level: AlertLevel = AlertLevel.INFO


class PayGuardLive:
    """
    PayGuard Live - Privacy-First Scam Detection
    
    All scanning capabilities require explicit user action.
    NO background monitoring or continuous capture.
    """
    
    # Pre-compiled regex patterns for scam detection
    SCAM_PATTERNS = [
        (re.compile(r'\b1-\d{3}-\d{3}-\d{4}\b'), 'phone_number', 30),
        (re.compile(r'(?i)\b(urgent|immediate|act now)\b'), 'urgency', 25),
        (re.compile(r'(?i)\b(virus|infected|malware)\b'), 'virus_warning', 35),
        (re.compile(r'(?i)\b(microsoft|apple|amazon).*(support|security)\b'), 'fake_company', 20),
        (re.compile(r'(?i)do not (close|restart|shut down)'), 'scare_tactic', 25),
        (re.compile(r'(?i)\b(suspended|blocked|expired)\b'), 'account_threat', 20),
    ]
    
    def __init__(self, alert_cooldown: int = 5):
        """
        Initialize PayGuard Live in privacy-first mode.
        
        Args:
            alert_cooldown: Minimum seconds between alerts
        """
        self.last_alert_time = 0
        self.alert_cooldown = alert_cooldown
        self.temp_files: List[Path] = []
        self._stats = {
            'screens_analyzed': 0,
            'texts_analyzed': 0,
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
            except OSError:
                pass
    
    def notify(self, title: str, message: str, critical: bool = False) -> bool:
        """
        Send a notification to the user.
        
        Args:
            title: Notification title
            message: Notification message
            critical: If True, use alert sound and dialog
            
        Returns:
            True if notification was sent successfully
        """
        current_time = time.time()
        if current_time - self.last_alert_time < self.alert_cooldown:
            logger.info(f"Alert suppressed (cooldown): {title}")
            return False
        
        try:
            clean_title = title.replace('"', '\\"').replace('\n', ' ')
            clean_message = message.replace('"', '\\"').replace('\n', ' ')
            
            if critical:
                # Play alert sound
                subprocess.run(
                    ["afplay", "/System/Library/Sounds/Sosumi.aiff"], 
                    capture_output=True, timeout=5
                )
                
                # Show notification with sound
                cmd = f'display notification "{clean_message}" with title "{clean_title}" sound name "Hero"'
                subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=5)
                
                # Show dialog
                dialog_cmd = f'display dialog "{clean_message}" with title "{clean_title}" buttons {{"OK", "More Info"}} default button "OK" with icon stop giving up after 30'
                result = subprocess.run(
                    ["osascript", "-e", dialog_cmd], 
                    capture_output=True, text=True, timeout=60
                )
                
                if "More Info" in result.stdout:
                    self._show_more_info()
            else:
                cmd = f'display notification "{clean_message}" with title "{clean_title}"'
                subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=5)
            
            self.last_alert_time = current_time
            self._stats['alerts_sent'] += 1
            return True
            
        except Exception as e:
            logger.error(f"Notification error: {e}")
            return False
    
    def _show_more_info(self):
        """Show educational information about scams"""
        info_msg = (
            "PayGuard detected suspicious content that may be a scam. "
            "Common scam tactics include:\\n\\n"
            "• Fake virus warnings\\n"
            "• Urgent security alerts\\n"
            "• Requests to call phone numbers\\n"
            "• Fake company support messages\\n\\n"
            "NEVER call random phone numbers or download software from pop-ups!"
        )
        info_cmd = f'display dialog "{info_msg}" with title "PayGuard - Scam Information" buttons {{"OK"}} default button "OK" with icon caution'
        subprocess.run(["osascript", "-e", info_cmd], capture_output=True, timeout=60)
    
    def capture_screen_now(self) -> Optional[bytes]:
        """
        Capture screen - USER-INITIATED ONLY
        
        This method captures the current screen. It should only be called
        in response to an explicit user action (button click, menu selection,
        or keyboard shortcut).
        
        Returns:
            Screen capture data as bytes, or None if capture failed
        """
        logger.info("User-initiated screen capture...")
        
        with self._temp_file_manager('.png') as tmp_path:
            try:
                result = subprocess.run(
                    ["screencapture", "-x", "-C", str(tmp_path)],
                    capture_output=True,
                    timeout=5
                )
                
                if result.returncode == 0 and tmp_path.exists():
                    with open(tmp_path, "rb") as f:
                        data = f.read()
                    return data
                    
            except subprocess.TimeoutExpired:
                logger.error("Screen capture timed out")
            except Exception as e:
                logger.error(f"Screen capture error: {e}")
        
        return None
    
    def _calculate_color_dominance(self, img: Image.Image) -> Tuple[float, float, float]:
        """Calculate color dominance ratios for scam detection"""
        try:
            # Resize image for faster processing
            if img.size[0] * img.size[1] > 1000000:
                img = img.resize((800, 600), Image.Resampling.LANCZOS)
            
            colors = img.getcolors(maxcolors=256*256*256)
            if not colors:
                return 0.0, 0.0, 0.0
            
            total_pixels = sum(count for count, color in colors)
            red_pixels = orange_pixels = yellow_pixels = 0
            
            for count, color in colors:
                if isinstance(color, tuple) and len(color) >= 3:
                    r, g, b = color[:3]
                    
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
    
    def analyze_screen(self, image_data: bytes) -> ScamAnalysisResult:
        """
        Analyze screen image for scam content - USER-INITIATED ONLY
        
        This method analyzes a screen capture for potential scam indicators.
        Should only be called after user explicitly requests a scan.
        
        Args:
            image_data: Screen capture bytes
            
        Returns:
            ScamAnalysisResult with detection details
        """
        self._stats['screens_analyzed'] += 1
        
        try:
            img = Image.open(io.BytesIO(image_data))
            red_ratio, orange_ratio, yellow_ratio = self._calculate_color_dominance(img)
            
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
            
            if visual_score >= 40:
                confidence = min(60 + visual_score, 95)
                alert_level = AlertLevel.CRITICAL if confidence > 80 else AlertLevel.WARNING
                self._stats['scams_detected'] += 1
                
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
                confidence=100 - visual_score,
                reason='No visual scam indicators detected',
                message='Screen appears safe',
                advice='Continue browsing safely',
                alert_level=AlertLevel.INFO
            )
            
        except Exception as e:
            logger.error(f"Screen analysis error: {e}")
            return ScamAnalysisResult(
                is_scam=False,
                confidence=0,
                reason=f'Analysis error: {e}',
                message='Could not analyze screen',
                advice='Try again',
                alert_level=AlertLevel.INFO
            )
    
    def analyze_text(self, text: str) -> ScamAnalysisResult:
        """
        Analyze text for scam content - USER-INITIATED ONLY
        
        This method analyzes provided text for potential scam indicators.
        Should only be called after user explicitly requests a scan.
        
        Args:
            text: Text content to analyze
            
        Returns:
            ScamAnalysisResult with detection details
        """
        self._stats['texts_analyzed'] += 1
        
        if not text or len(text) < 10:
            return ScamAnalysisResult(
                is_scam=False,
                confidence=100,
                reason='Text too short to analyze',
                message='No scam indicators',
                advice='Text appears safe',
                alert_level=AlertLevel.INFO
            )
        
        score = 0
        detected_patterns = []
        
        for pattern, name, weight in self.SCAM_PATTERNS:
            if pattern.search(text):
                score += weight
                detected_patterns.append(name)
        
        if score >= 40:
            self._stats['scams_detected'] += 1
            confidence = min(score, 100)
            alert_level = AlertLevel.CRITICAL if confidence > 70 else AlertLevel.WARNING
            
            return ScamAnalysisResult(
                is_scam=True,
                confidence=confidence,
                reason=f'Detected patterns: {", ".join(detected_patterns)}',
                message='SCAM CONTENT DETECTED!',
                advice='Do NOT follow any instructions from this text!',
                patterns=detected_patterns,
                alert_level=alert_level
            )
        
        return ScamAnalysisResult(
            is_scam=False,
            confidence=100 - score,
            reason='No scam patterns detected',
            message='Text appears safe',
            advice='Continue carefully',
            alert_level=AlertLevel.INFO
        )
    
    def scan_screen_now(self) -> ScamAnalysisResult:
        """
        User-initiated screen scan.
        
        Call this method when user explicitly requests a screen scan
        (e.g., clicks "Scan Now" button or uses keyboard shortcut).
        
        Returns:
            ScamAnalysisResult with detection details
        """
        logger.info("🔍 User-initiated screen scan...")
        
        image_data = self.capture_screen_now()
        if not image_data:
            return ScamAnalysisResult(
                is_scam=False,
                confidence=0,
                reason='Failed to capture screen',
                message='Screen capture failed',
                advice='Try again',
                alert_level=AlertLevel.INFO
            )
        
        result = self.analyze_screen(image_data)
        
        if result.is_scam:
            self.notify(
                "🚨 PayGuard Alert",
                result.message,
                critical=result.alert_level == AlertLevel.CRITICAL
            )
        
        return result
    
    def scan_text_now(self, text: str) -> ScamAnalysisResult:
        """
        User-initiated text scan.
        
        Call this method when user explicitly requests a text scan
        (e.g., pastes text and clicks "Scan" button).
        
        Args:
            text: Text content to analyze
            
        Returns:
            ScamAnalysisResult with detection details
        """
        logger.info("🔍 User-initiated text scan...")
        
        result = self.analyze_text(text)
        
        if result.is_scam:
            self.notify(
                "🚨 PayGuard Text Alert",
                result.message,
                critical=result.alert_level == AlertLevel.CRITICAL
            )
        
        return result
    
    def get_stats(self) -> Dict[str, int]:
        """Get scanning statistics"""
        return self._stats.copy()
    
    def start_interactive(self):
        """
        Start PayGuard in interactive mode.
        
        In privacy-first mode, PayGuard waits for user commands
        instead of continuously monitoring.
        """
        print("🛡️ PAYGUARD LIVE - PRIVACY-FIRST MODE")
        print("=" * 50)
        print("\nPayGuard is ready. All scans require your action.")
        print("\nCommands:")
        print("  s - Scan screen now")
        print("  t - Scan text (enter text after)")
        print("  i - Show statistics")
        print("  q - Quit")
        print("\n" + "=" * 50)
        
        self.notify("🛡️ PayGuard Ready", "Use 'Scan Now' to check for scams.", critical=False)
        
        while True:
            try:
                cmd = input("\nPayGuard> ").strip().lower()
                
                if cmd == 'q':
                    print("🛑 PayGuard stopped.")
                    break
                elif cmd == 's':
                    result = self.scan_screen_now()
                    self._print_result(result)
                elif cmd == 't':
                    text = input("Enter text to scan: ")
                    result = self.scan_text_now(text)
                    self._print_result(result)
                elif cmd == 'i':
                    stats = self.get_stats()
                    print("\n📊 Statistics:")
                    for key, value in stats.items():
                        print(f"  {key}: {value}")
                else:
                    print("Unknown command. Use 's', 't', 'i', or 'q'.")
                    
            except KeyboardInterrupt:
                print("\n🛑 PayGuard stopped.")
                break
            except EOFError:
                break
        
        self.cleanup()
    
    def _print_result(self, result: ScamAnalysisResult):
        """Print analysis result to console"""
        if result.is_scam:
            print(f"\n🚨 SCAM DETECTED!")
            print(f"   Confidence: {result.confidence:.1f}%")
            print(f"   Reason: {result.reason}")
            print(f"   Message: {result.message}")
            print(f"   Advice: {result.advice}")
        else:
            print(f"\n✅ No scam detected")
            print(f"   Confidence: {result.confidence:.1f}%")


def main():
    """Main entry point"""
    guard = PayGuardLive()
    guard.start_interactive()


if __name__ == "__main__":
    main()
