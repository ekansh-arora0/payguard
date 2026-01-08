#!/usr/bin/env python3
"""
PayGuard Menu Bar App

A native macOS menu bar application for PayGuard with:
- One-click screen scanning
- Status indicator
- Quick access to all features
- Service control

Requires: pip3 install rumps requests pillow
"""

import rumps
import subprocess
import threading
import requests
import base64
import os
import sys
from datetime import datetime
from pathlib import Path

# PayGuard directory
PAYGUARD_DIR = Path(__file__).parent.absolute()


class PayGuardMenuBar(rumps.App):
    """PayGuard Menu Bar Application"""
    
    def __init__(self):
        super(PayGuardMenuBar, self).__init__(
            "🛡️",
            title="🛡️",
            quit_button=None  # We'll add custom quit
        )
        
        self.backend_running = False
        self.scans_today = 0
        self.threats_blocked = 0
        self.last_scan = None
        
        # Build menu
        self.menu = [
            rumps.MenuItem("PayGuard - Protection Active", callback=None),
            None,  # Separator
            rumps.MenuItem("🔍 Scan Screen Now", callback=self.scan_screen),
            rumps.MenuItem("📋 Scan Clipboard", callback=self.scan_clipboard),
            rumps.MenuItem("🌐 Check URL...", callback=self.check_url),
            None,
            rumps.MenuItem("📊 Status", callback=None),
            rumps.MenuItem(f"   Scans today: {self.scans_today}", callback=None),
            rumps.MenuItem(f"   Threats blocked: {self.threats_blocked}", callback=None),
            None,
            rumps.MenuItem("⚙️ Settings", callback=None),
            rumps.MenuItem("   🟢 Start Service", callback=self.start_service),
            rumps.MenuItem("   🔴 Stop Service", callback=self.stop_service),
            rumps.MenuItem("   📁 View Logs", callback=self.view_logs),
            None,
            rumps.MenuItem("📖 Help", callback=self.show_help),
            rumps.MenuItem("ℹ️ About PayGuard", callback=self.show_about),
            None,
            rumps.MenuItem("Quit PayGuard", callback=self.quit_app),
        ]
        
        # Start health check timer
        self.timer = rumps.Timer(self.check_health, 30)
        self.timer.start()
        
        # Initial health check
        self.check_health(None)
    
    def check_health(self, _):
        """Check if backend is running"""
        try:
            response = requests.get("http://localhost:8002/api/health", timeout=2)
            self.backend_running = response.status_code == 200
            
            if self.backend_running:
                self.title = "🛡️"
                self.menu["PayGuard - Protection Active"].title = "PayGuard - Protection Active ✓"
            else:
                self.title = "🛡️⚠️"
                self.menu["PayGuard - Protection Active"].title = "PayGuard - Service Offline"
        except Exception:
            self.backend_running = False
            self.title = "🛡️❌"
            self.menu["PayGuard - Protection Active"].title = "PayGuard - Service Offline"
    
    def update_stats(self):
        """Update menu stats"""
        self.menu[f"   Scans today: {self.scans_today}"].title = f"   Scans today: {self.scans_today}"
        self.menu[f"   Threats blocked: {self.threats_blocked}"].title = f"   Threats blocked: {self.threats_blocked}"
    
    @rumps.clicked("🔍 Scan Screen Now")
    def scan_screen(self, _):
        """Capture and analyze screen"""
        if not self.backend_running:
            rumps.notification(
                "PayGuard",
                "Service Not Running",
                "Please start the PayGuard service first."
            )
            return
        
        # Show scanning notification
        rumps.notification("PayGuard", "Scanning...", "Analyzing your screen for threats")
        
        # Run scan in background thread
        thread = threading.Thread(target=self._do_screen_scan)
        thread.start()
    
    def _do_screen_scan(self):
        """Perform screen scan (runs in background)"""
        try:
            # Capture screen
            tmp_path = "/tmp/payguard_menubar_scan.png"
            result = subprocess.run(
                ["screencapture", "-x", "-C", tmp_path],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode != 0 or not os.path.exists(tmp_path):
                rumps.notification("PayGuard", "Error", "Failed to capture screen")
                return
            
            with open(tmp_path, "rb") as f:
                img_data = f.read()
            os.remove(tmp_path)
            
            # Send to API
            b64_data = base64.b64encode(img_data).decode()
            response = requests.post(
                "http://localhost:8002/api/media-risk/bytes",
                json={
                    "url": "screen://menubar-scan",
                    "content": b64_data,
                    "metadata": {"source": "menubar", "user_initiated": True}
                },
                timeout=30
            )
            
            self.scans_today += 1
            self.last_scan = datetime.now()
            
            if response.status_code == 200:
                data = response.json()
                scam_alert = data.get("scam_alert")
                media_score = data.get("media_score", 0)
                
                if scam_alert and scam_alert.get("is_scam"):
                    self.threats_blocked += 1
                    confidence = scam_alert.get("confidence", 0)
                    message = scam_alert.get("senior_message", "Potential scam detected!")
                    
                    # Critical alert
                    rumps.notification(
                        "🚨 SCAM DETECTED",
                        f"Confidence: {confidence}%",
                        message,
                        sound=True
                    )
                    
                    # Show dialog
                    self._show_alert_dialog(message)
                    
                elif media_score > 70:
                    rumps.notification(
                        "⚠️ PayGuard Warning",
                        "Suspicious Content",
                        f"Risk score: {media_score}%. Exercise caution."
                    )
                else:
                    rumps.notification(
                        "✅ PayGuard",
                        "Scan Complete",
                        "No threats detected on your screen."
                    )
            else:
                rumps.notification("PayGuard", "Error", f"API error: {response.status_code}")
                
        except Exception as e:
            rumps.notification("PayGuard", "Error", str(e)[:100])
    
    def _show_alert_dialog(self, message):
        """Show critical alert dialog"""
        try:
            script = f'''
            display dialog "{message}

This appears to be a SCAM. Do NOT:
• Call any phone numbers shown
• Enter any personal information
• Download any software
• Pay any money

Close the suspicious window immediately!" with title "🚨 PayGuard Security Alert" buttons {{"Close Threat", "OK"}} default button 1 with icon stop
            '''
            subprocess.run(["osascript", "-e", script], capture_output=True, timeout=60)
        except Exception:
            pass
    
    @rumps.clicked("📋 Scan Clipboard")
    def scan_clipboard(self, _):
        """Scan clipboard text for threats"""
        try:
            result = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=5)
            text = result.stdout
            
            if not text:
                rumps.notification("PayGuard", "Clipboard Empty", "No text to scan")
                return
            
            # Use local scam detector
            sys.path.insert(0, str(PAYGUARD_DIR))
            from payguard_menubar_optimized import ScamDetector
            
            detector = ScamDetector()
            result = detector.analyze_text(text)
            
            self.scans_today += 1
            
            if result.is_scam:
                self.threats_blocked += 1
                rumps.notification(
                    "🚨 SCAM DETECTED",
                    f"Confidence: {result.confidence:.0f}%",
                    f"Patterns: {', '.join(result.patterns)}",
                    sound=True
                )
            else:
                rumps.notification(
                    "✅ PayGuard",
                    "Clipboard Scan Complete",
                    "No scam patterns detected in clipboard text."
                )
                
        except Exception as e:
            rumps.notification("PayGuard", "Error", str(e)[:100])
    
    @rumps.clicked("🌐 Check URL...")
    def check_url(self, _):
        """Check a URL for threats"""
        # Get URL from user
        try:
            script = '''
            set theURL to text returned of (display dialog "Enter URL to check:" default answer "https://" with title "PayGuard - Check URL")
            return theURL
            '''
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            url = result.stdout.strip()
            if not url or url == "https://":
                return
            
            if not self.backend_running:
                rumps.notification("PayGuard", "Service Offline", "Cannot check URL")
                return
            
            # Check URL
            response = requests.get(
                f"http://localhost:8002/api/risk?url={url}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                risk_level = data.get("risk_level", "unknown")
                trust_score = data.get("trust_score", 0)
                factors = data.get("risk_factors", [])
                
                if risk_level == "high":
                    self.threats_blocked += 1
                    rumps.notification(
                        "🚨 HIGH RISK URL",
                        f"Trust Score: {trust_score}",
                        f"Risks: {', '.join(factors[:2]) if factors else 'Suspicious'}"
                    )
                elif risk_level == "medium":
                    rumps.notification(
                        "⚠️ CAUTION",
                        f"Trust Score: {trust_score}",
                        "This URL has some risk factors"
                    )
                else:
                    rumps.notification(
                        "✅ URL Appears Safe",
                        f"Trust Score: {trust_score}",
                        url[:50]
                    )
            else:
                rumps.notification("PayGuard", "Error", "Could not check URL")
                
        except Exception as e:
            if "User canceled" not in str(e):
                rumps.notification("PayGuard", "Error", str(e)[:100])
    
    @rumps.clicked("   🟢 Start Service")
    def start_service(self, _):
        """Start the PayGuard backend service"""
        try:
            subprocess.run(
                ["launchctl", "load", os.path.expanduser("~/Library/LaunchAgents/com.payguard.service.plist")],
                capture_output=True
            )
            rumps.notification("PayGuard", "Starting Service", "Please wait...")
            
            # Check after delay
            threading.Timer(5.0, self.check_health, args=[None]).start()
            
        except Exception as e:
            rumps.notification("PayGuard", "Error", str(e)[:100])
    
    @rumps.clicked("   🔴 Stop Service")
    def stop_service(self, _):
        """Stop the PayGuard backend service"""
        try:
            subprocess.run(
                ["launchctl", "unload", os.path.expanduser("~/Library/LaunchAgents/com.payguard.service.plist")],
                capture_output=True
            )
            rumps.notification("PayGuard", "Service Stopped", "PayGuard protection is now disabled")
            self.check_health(None)
            
        except Exception as e:
            rumps.notification("PayGuard", "Error", str(e)[:100])
    
    @rumps.clicked("   📁 View Logs")
    def view_logs(self, _):
        """Open log directory in Finder"""
        log_dir = os.path.expanduser("~/Library/Logs/PayGuard")
        if os.path.exists(log_dir):
            subprocess.run(["open", log_dir])
        else:
            rumps.notification("PayGuard", "No Logs", "Log directory not found")
    
    @rumps.clicked("📖 Help")
    def show_help(self, _):
        """Show help information"""
        help_text = """PayGuard Menu Bar Help

🔍 Scan Screen Now
   Captures your screen and checks for scam warnings,
   fake virus alerts, and phishing pop-ups.

📋 Scan Clipboard
   Analyzes any text in your clipboard for scam
   patterns like fake phone numbers or phishing links.

🌐 Check URL
   Enter any URL to check if it's safe before visiting.

⚙️ Service Control
   Start or stop the PayGuard background service.

Tips:
• Keep PayGuard running for best protection
• Scan your screen if you see suspicious pop-ups
• Copy suspicious text and scan clipboard
• Check URLs before entering personal info"""
        
        rumps.alert("PayGuard Help", help_text)
    
    @rumps.clicked("ℹ️ About PayGuard")
    def show_about(self, _):
        """Show about dialog"""
        about_text = """PayGuard v2.0.0
Privacy-First Scam Protection

Features:
• Scam message detection
• Phishing email detection
• AI image detection
• Visual scam detection
• URL reputation checking

🔒 Privacy First:
No background monitoring.
All scans require your action.
Your data stays on your device.

© 2026 PayGuard"""
        
        rumps.alert("About PayGuard", about_text)
    
    @rumps.clicked("Quit PayGuard")
    def quit_app(self, _):
        """Quit the menu bar app"""
        rumps.quit_application()


def main():
    """Run the menu bar app"""
    print("🛡️ Starting PayGuard Menu Bar...")
    print("   Look for the shield icon (🛡️) in your menu bar")
    
    app = PayGuardMenuBar()
    app.run()


if __name__ == "__main__":
    main()
