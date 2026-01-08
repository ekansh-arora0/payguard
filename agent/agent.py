#!/usr/bin/env python3
"""
PayGuard Agent - Privacy-First Version

PRIVACY NOTICE: This version has been completely redesigned with privacy-first principles:
- NO continuous screen capture
- NO background clipboard monitoring
- All scans require explicit user action
- User data stays on device unless explicitly approved

This agent provides user-initiated scanning via a menu bar interface.
"""

import subprocess
import time
import base64
import json
import os
import sys
import hashlib
import http.client
import urllib.request
from datetime import datetime
from typing import Optional, Dict, Any


class Agent:
    """
    PayGuard Agent - Privacy-First Design
    
    This agent operates in user-initiated mode only.
    NO background monitoring or continuous capture.
    """
    
    def __init__(self, server_host: str = "localhost", server_port: int = 8002):
        """
        Initialize the PayGuard agent.
        
        Args:
            server_host: Backend server hostname
            server_port: Backend server port
        """
        self.server_host = server_host
        self.server_port = server_port
        self.last_alert_time = 0.0
        self.alert_cooldown = 10  # Minimum seconds between alerts
        
        # Statistics
        self._stats = {
            'scans_performed': 0,
            'scams_detected': 0,
            'alerts_sent': 0
        }
        
        # Ensure data directory exists
        os.makedirs("./data/agent", exist_ok=True)

    def start(self):
        """
        Start the PayGuard agent in user-initiated mode.
        
        In privacy-first mode, the agent waits for user commands
        instead of continuously monitoring.
        """
        print("""
    🛡️  PAYGUARD AGENT - PRIVACY-FIRST MODE
    ==========================================
    
    All scans require your explicit action.
    NO background monitoring or continuous capture.
    
    Commands:
      s - Scan screen now
      q - Quit
        """)
        print(f"Backend: http://{self.server_host}:{self.server_port}")
        
        # Notify user that PayGuard is ready
        self._notify_native(
            "🛡️ PayGuard Ready", 
            "Use 'Scan Now' to check for scams.", 
            is_critical=False
        )
        
        try:
            while True:
                cmd = input("\nPayGuard> ").strip().lower()
                
                if cmd == 'q':
                    print("🛑 Stopping PayGuard Agent...")
                    break
                elif cmd == 's':
                    self.scan_screen_now()
                elif cmd == 'i':
                    self._show_stats()
                else:
                    print("Commands: s=scan, i=info, q=quit")
                    
        except KeyboardInterrupt:
            print("\n🛑 Stopping PayGuard Agent...")
        except EOFError:
            pass
    
    def scan_screen_now(self) -> Optional[Dict[str, Any]]:
        """
        User-initiated screen scan.
        
        Captures the current screen and sends it to the backend for analysis.
        This method should only be called in response to explicit user action.
        
        Returns:
            Analysis result dictionary, or None if scan failed
        """
        print("🔍 Scanning screen...")
        self._stats['scans_performed'] += 1
        
        # Capture screen
        screenshot_bytes = self._capture_screen()
        if not screenshot_bytes:
            print("❌ Failed to capture screen")
            return None
        
        # Send to backend for analysis
        result = self._analyze_with_backend(screenshot_bytes)
        
        if result:
            scam_alert = result.get("scam_alert")
            if scam_alert and scam_alert.get("is_scam"):
                self._stats['scams_detected'] += 1
                self._trigger_scam_alert(scam_alert)
                print(f"🚨 SCAM DETECTED: {scam_alert.get('senior_message', 'Scam detected!')}")
            else:
                print("✅ Screen appears safe")
        
        return result
    
    def _capture_screen(self) -> Optional[bytes]:
        """
        Capture the current screen - USER-INITIATED ONLY
        
        Returns:
            Screen capture as bytes, or None if capture failed
        """
        try:
            tmp_path = "/tmp/payguard_agent_screen.png"
            result = subprocess.run(
                ["screencapture", "-x", "-C", tmp_path],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode == 0 and os.path.exists(tmp_path):
                with open(tmp_path, "rb") as f:
                    data = f.read()
                os.remove(tmp_path)
                return data
                
        except subprocess.TimeoutExpired:
            print("Screen capture timed out")
        except Exception as e:
            print(f"Screen capture error: {e}")
        
        return None
    
    def _analyze_with_backend(self, image_bytes: bytes) -> Optional[Dict[str, Any]]:
        """
        Send image to backend for analysis.
        
        Args:
            image_bytes: Screen capture bytes
            
        Returns:
            Analysis result from backend, or None if request failed
        """
        try:
            b64_data = base64.b64encode(image_bytes).decode('utf-8')
            
            payload = json.dumps({
                "url": "screen://local",
                "content": b64_data,
                "metadata": {"source": "agent", "user_initiated": True}
            }).encode('utf-8')
            
            conn = http.client.HTTPConnection(
                self.server_host, 
                self.server_port, 
                timeout=30
            )
            
            conn.request(
                "POST",
                "/api/media-risk/bytes",
                body=payload,
                headers={"Content-Type": "application/json"}
            )
            
            response = conn.getresponse()
            if response.status == 200:
                return json.loads(response.read().decode('utf-8'))
            else:
                print(f"Backend error: {response.status}")
                
        except Exception as e:
            print(f"Backend communication error: {e}")
        
        return None
    
    def _trigger_scam_alert(self, scam_data: Dict[str, Any]):
        """
        Show scam alert to user.
        
        Args:
            scam_data: Scam detection data from backend
        """
        current_time = time.time()
        if current_time - self.last_alert_time < self.alert_cooldown:
            return
        
        confidence = scam_data.get("confidence", 0)
        patterns = scam_data.get("detected_patterns", [])
        senior_msg = scam_data.get("senior_message", "Scam Detected!")
        advice = scam_data.get("action_advice", "Close the window immediately.")
        
        # Determine alert title based on pattern
        title = "🛡️ PayGuard Security Alert"
        if "phone_number" in patterns:
            title = "📞 Fake Support Number"
        elif "virus_warning" in patterns or "scare_tactics" in patterns:
            title = "⚠️ Fake Virus Warning"
        elif "phishing_attempt" in patterns:
            title = "🎣 Phishing Attempt"
        
        message = f"{senior_msg}\n\n{advice}"
        
        self._notify_native(title, message, is_critical=True)
        self.last_alert_time = current_time
        self._stats['alerts_sent'] += 1
    
    def _notify_native(self, title: str, message: str, is_critical: bool = False):
        """
        Send native macOS notification.
        
        Args:
            title: Notification title
            message: Notification message
            is_critical: If True, show dialog and play sound
        """
        try:
            clean_title = title.replace('"', '\\"').replace('\n', ' ')
            clean_message = message.replace('"', '\\"').replace('\n', ' ')
            
            if is_critical:
                # Play alert sound
                subprocess.run(
                    ["afplay", "/System/Library/Sounds/Sosumi.aiff"],
                    capture_output=True, timeout=5
                )
                
                # Show notification with sound
                cmd = f'display notification "{clean_message}" with title "{clean_title}" sound name "Hero"'
                subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=5)
                
                # Show dialog
                dialog_cmd = f'display dialog "{clean_message}" with title "{clean_title}" buttons {{"OK"}} default button "OK" with icon stop giving up after 30'
                subprocess.run(
                    ["osascript", "-e", dialog_cmd],
                    capture_output=True, timeout=60
                )
            else:
                cmd = f'display notification "{clean_message}" with title "{clean_title}"'
                subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=5)
                
        except Exception as e:
            print(f"Notification error: {e}")
    
    def _show_stats(self):
        """Display agent statistics"""
        print("\n📊 Agent Statistics:")
        print(f"   Scans performed: {self._stats['scans_performed']}")
        print(f"   Scams detected: {self._stats['scams_detected']}")
        print(f"   Alerts sent: {self._stats['alerts_sent']}")


def main():
    """Main entry point"""
    agent = Agent()
    agent.start()


if __name__ == "__main__":
    main()
