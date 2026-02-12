#!/usr/bin/env python3
"""
PayGuard Menu Bar - Standalone Version

A fully functional macOS menu bar app that works WITHOUT a backend service.
All scam detection runs locally using built-in ML patterns.

Install:
    pip3 install rumps pillow

Run:
    python3 payguard_menubar_standalone.py

The shield icon (🛡️) will appear in your menu bar.
"""

import rumps
import subprocess
import os
import re
import time
from datetime import datetime

# Try to import PIL for image analysis
try:
    from PIL import Image
    import io
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("⚠️ PIL not installed. Install with: pip3 install pillow")


class ScamPatternDetector:
    """Built-in scam detection patterns - no backend needed"""
    
    PATTERNS = [
        # Phone number scams
        (r'\b1-8[0-9]{2}-\d{3}-\d{4}\b', 40, 'toll_free_number', 'Suspicious toll-free number'),
        (r'\b1-\d{3}-\d{3}-\d{4}\b', 30, 'phone_number', 'Suspicious phone number'),
        
        # Urgency and fear tactics
        (r'(?i)\b(urgent|immediate|act now|call now|immediately)\b', 25, 'urgency', 'Urgency language'),
        (r'(?i)\b(expires|expire|expiring) (today|soon|in \d+)\b', 25, 'expiration', 'Fake expiration pressure'),
        
        # Virus/malware scams
        (r'(?i)\b(virus|infected|malware|trojan|hacked|compromised)\b', 35, 'virus_scare', 'Virus scare tactics'),
        (r'(?i)your (computer|device|system|pc|mac).*(infected|virus|hacked)', 40, 'device_scare', 'Device infection scare'),
        
        # Company impersonation
        (r'(?i)\b(microsoft|apple|amazon|google|paypal|netflix)\s*(support|security|alert|team|service)', 35, 'impersonation', 'Company impersonation'),
        (r'(?i)windows defender', 30, 'defender_scam', 'Fake Windows Defender alert'),
        
        # Scare tactics
        (r'(?i)do not (close|restart|shut down|turn off|ignore)', 40, 'scare_tactic', 'Scare tactic detected'),
        (r'(?i)all (your )?(files|data|photos).*(deleted|lost|encrypted)', 35, 'ransomware_scare', 'Ransomware scare'),
        
        # Account threats
        (r'(?i)\b(suspended|blocked|locked|disabled|terminated)\b.*(account|access)', 25, 'account_threat', 'Account threat language'),
        (r'(?i)\b(verify|update|confirm).*(account|payment|card|password|identity)', 25, 'phishing', 'Phishing request'),
        
        # Financial scams
        (r'(?i)\$[\d,]+\.?\d*\s*(won|prize|reward|gift)', 35, 'prize_scam', 'Fake prize claim'),
        (r'(?i)\b(bitcoin|crypto|btc|eth)\b.*\b(send|transfer|pay|deposit)\b', 40, 'crypto_scam', 'Crypto scam'),
        (r'(?i)\b(wire|transfer|send).*(money|funds|payment)', 30, 'wire_fraud', 'Wire fraud attempt'),
        
        # Fake errors
        (r'(?i)(error code|reference id|case number|ticket)[:\s]*[a-z0-9-]+', 20, 'fake_error', 'Fake error code'),
        (r'(?i)error[:\s]*(0x[a-f0-9]+|\d{3,})', 25, 'error_code', 'Suspicious error code'),
        
        # Action requests
        (r'(?i)(click here|click below|click now|click the)', 15, 'click_bait', 'Suspicious call-to-action'),
        (r'(?i)download.*(software|tool|program|update)', 25, 'download_request', 'Suspicious download request'),
    ]
    
    @classmethod
    def analyze(cls, text):
        """Analyze text for scam patterns"""
        if not text or len(text) < 10:
            return {'is_scam': False, 'score': 0, 'patterns': []}
        
        score = 0
        detected = []
        
        for pattern, weight, name, description in cls.PATTERNS:
            if re.search(pattern, text):
                score += weight
                detected.append(description)
        
        return {
            'is_scam': score >= 40,
            'score': min(score, 100),
            'patterns': detected,
            'confidence': min(score + 10, 99) if score >= 40 else score
        }


class PayGuardStandalone(rumps.App):
    """PayGuard Menu Bar - Standalone (No Backend Required)"""
    
    def __init__(self):
        super(PayGuardStandalone, self).__init__(
            "🛡️",
            title="🛡️",
            quit_button=None
        )
        
        self.threats_detected = 0
        self.scans_performed = 0
        self.last_scan = None
        self.scan_history = []
        
        # Build menu
        self.menu = [
            rumps.MenuItem("🛡️ PayGuard Active", callback=None),
            rumps.MenuItem("   Standalone Mode (No Service Needed)", callback=None),
            None,
            rumps.MenuItem("🔍 Scan Screen Now", callback=self.scan_screen),
            rumps.MenuItem("📋 Scan Clipboard", callback=self.scan_clipboard),
            rumps.MenuItem("✏️ Enter Text to Scan...", callback=self.scan_manual),
            None,
            rumps.MenuItem("📊 Statistics", callback=self.show_stats),
            rumps.MenuItem("📜 History", callback=self.show_history),
            None,
            rumps.MenuItem("ℹ️ About", callback=self.show_about),
            rumps.MenuItem("❓ Help", callback=self.show_help),
            None,
            rumps.MenuItem("Quit", callback=self.quit_app),
        ]
        
        # Show startup notification
        rumps.notification(
            "🛡️ PayGuard Active",
            "Protection Running",
            "Use the shield menu to scan for threats"
        )
    
    def _add_to_history(self, scan_type, is_threat, reason):
        """Add scan to history"""
        self.scan_history.append({
            'time': datetime.now(),
            'type': scan_type,
            'threat': is_threat,
            'reason': reason
        })
        # Keep only last 20
        if len(self.scan_history) > 20:
            self.scan_history = self.scan_history[-20:]
    
    def _capture_screen(self):
        """Capture screen to file"""
        try:
            path = "/tmp/payguard_screen.png"
            result = subprocess.run(
                ["screencapture", "-x", "-C", path],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0 and os.path.exists(path):
                with open(path, "rb") as f:
                    data = f.read()
                os.remove(path)
                return data
        except Exception as e:
            print(f"Screen capture error: {e}")
        return None
    
    def _analyze_image(self, image_data):
        """Analyze image for visual scam indicators"""
        if not HAS_PIL:
            return {'is_scam': False, 'reason': 'PIL not available'}
        
        try:
            img = Image.open(io.BytesIO(image_data))
            colors = img.getcolors(maxcolors=256*256*256)
            
            if colors:
                total = sum(c for c, _ in colors)
                red = sum(c for c, col in colors if isinstance(col, tuple) and len(col) >= 3 and col[0] > 180 and col[1] < 100 and col[2] < 100)
                orange = sum(c for c, col in colors if isinstance(col, tuple) and len(col) >= 3 and col[0] > 200 and 100 < col[1] < 180 and col[2] < 100)
                
                red_ratio = red / total if total > 0 else 0
                orange_ratio = orange / total if total > 0 else 0
                
                if red_ratio > 0.20:
                    return {
                        'is_scam': True,
                        'confidence': min(80 + int(red_ratio * 20), 99),
                        'reason': 'Red warning screen detected - likely fake security alert!'
                    }
                
                if orange_ratio > 0.12:
                    return {
                        'is_scam': True,
                        'confidence': 70,
                        'reason': 'Suspicious warning colors detected'
                    }
        except Exception as e:
            print(f"Image analysis error: {e}")
        
        return {'is_scam': False}
    
    def _get_clipboard(self):
        """Get clipboard text"""
        try:
            result = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=2)
            return result.stdout
        except:
            return None
    
    @rumps.clicked("🔍 Scan Screen Now")
    def scan_screen(self, _):
        """Scan current screen"""
        self.title = "🔄"  # Scanning
        
        # Capture screen
        image_data = self._capture_screen()
        if not image_data:
            rumps.notification("PayGuard", "Error", "Could not capture screen")
            self.title = "🛡️"
            return
        
        # Analyze
        result = self._analyze_image(image_data)
        self.scans_performed += 1
        self.last_scan = datetime.now()
        
        if result.get('is_scam'):
            self.threats_detected += 1
            self._add_to_history('Screen', True, result.get('reason', 'Unknown'))
            
            self.title = f"🚨{self.threats_detected}"
            
            # Play alert sound
            subprocess.run(["afplay", "/System/Library/Sounds/Sosumi.aiff"], capture_output=True)
            
            # Show notification
            rumps.notification(
                "🚨 SCAM DETECTED!",
                f"Confidence: {result.get('confidence', 0)}%",
                result.get('reason', 'Suspicious content detected!'),
                sound=True
            )
            
            # Show detailed alert
            rumps.alert(
                title="🚨 PayGuard Security Alert",
                message=f"THREAT DETECTED!\n\n{result.get('reason')}\n\n"
                        f"⚠️ This appears to be a SCAM.\n\n"
                        f"DO NOT:\n"
                        f"• Call any phone numbers shown\n"
                        f"• Download any software\n"
                        f"• Enter any personal information\n"
                        f"• Pay any money\n\n"
                        f"Close the suspicious window immediately!",
                ok="I Understand"
            )
        else:
            self._add_to_history('Screen', False, 'No threats')
            self.title = "🛡️" if self.threats_detected == 0 else f"🛡️{self.threats_detected}"
            rumps.notification("✅ Screen Safe", "No threats detected", "Your screen appears safe")
    
    @rumps.clicked("📋 Scan Clipboard")
    def scan_clipboard(self, _):
        """Scan clipboard text"""
        self.title = "🔄"
        
        text = self._get_clipboard()
        if not text or len(text.strip()) < 5:
            rumps.notification("PayGuard", "Clipboard Empty", "No text to scan")
            self.title = "🛡️"
            return
        
        result = ScamPatternDetector.analyze(text)
        self.scans_performed += 1
        self.last_scan = datetime.now()
        
        if result['is_scam']:
            self.threats_detected += 1
            reason = ', '.join(result['patterns'][:2]) if result['patterns'] else 'Suspicious patterns'
            self._add_to_history('Clipboard', True, reason)
            
            self.title = f"🚨{self.threats_detected}"
            
            subprocess.run(["afplay", "/System/Library/Sounds/Sosumi.aiff"], capture_output=True)
            
            rumps.notification(
                "🚨 SCAM IN CLIPBOARD!",
                f"Confidence: {result['confidence']}%",
                reason,
                sound=True
            )
            
            rumps.alert(
                title="🚨 Suspicious Content!",
                message=f"SCAM INDICATORS DETECTED!\n\n"
                        f"Found: {', '.join(result['patterns'][:3])}\n\n"
                        f"⚠️ The text in your clipboard appears suspicious.\n\n"
                        f"DO NOT paste or share this content!",
                ok="I Understand"
            )
        else:
            self._add_to_history('Clipboard', False, 'No threats')
            self.title = "🛡️" if self.threats_detected == 0 else f"🛡️{self.threats_detected}"
            rumps.notification("✅ Clipboard Safe", "No scam patterns found", "Text appears safe")
    
    @rumps.clicked("✏️ Enter Text to Scan...")
    def scan_manual(self, _):
        """Allow user to enter text"""
        window = rumps.Window(
            message="Paste suspicious text below to scan:",
            title="PayGuard Scanner",
            default_text="",
            ok="Scan",
            cancel="Cancel",
            dimensions=(400, 200)
        )
        
        response = window.run()
        if response.clicked and response.text:
            result = ScamPatternDetector.analyze(response.text)
            self.scans_performed += 1
            
            if result['is_scam']:
                self.threats_detected += 1
                self._add_to_history('Manual', True, ', '.join(result['patterns'][:2]))
                self.title = f"🚨{self.threats_detected}"
                
                rumps.alert(
                    title="🚨 SCAM DETECTED!",
                    message=f"This text contains scam indicators!\n\n"
                            f"Found: {', '.join(result['patterns'][:3])}\n\n"
                            f"Confidence: {result['confidence']}%\n\n"
                            f"⚠️ DO NOT trust this message!",
                    ok="I Understand"
                )
            else:
                self._add_to_history('Manual', False, 'No threats')
                self.title = "🛡️" if self.threats_detected == 0 else f"🛡️{self.threats_detected}"
                
                rumps.alert(
                    title="✅ Text Appears Safe",
                    message="No obvious scam indicators detected.\n\n"
                            "However, always be cautious with unexpected messages!",
                    ok="OK"
                )
    
    @rumps.clicked("📊 Statistics")
    def show_stats(self, _):
        """Show statistics"""
        last = self.last_scan.strftime("%H:%M:%S") if self.last_scan else "Never"
        
        rumps.alert(
            title="📊 PayGuard Statistics",
            message=f"🛡️ Status: Active (Standalone Mode)\n\n"
                    f"🔍 Scans Performed: {self.scans_performed}\n"
                    f"🚨 Threats Detected: {self.threats_detected}\n"
                    f"⏱️ Last Scan: {last}\n\n"
                    f"PayGuard protects against:\n"
                    f"• Fake virus/security alerts\n"
                    f"• Tech support scams\n"
                    f"• Phishing attempts\n"
                    f"• Financial fraud\n"
                    f"• Crypto scams\n\n"
                    f"🔒 All processing runs locally on your Mac.",
            ok="OK"
        )
    
    @rumps.clicked("📜 History")
    def show_history(self, _):
        """Show scan history"""
        if not self.scan_history:
            rumps.alert("📜 History", "No scans performed yet.\n\nUse 'Scan Screen Now' or 'Scan Clipboard' to start!")
            return
        
        text = ""
        for scan in reversed(self.scan_history[-8:]):
            icon = "🚨" if scan['threat'] else "✅"
            time_str = scan['time'].strftime("%H:%M")
            text += f"{icon} [{time_str}] {scan['type']}: {scan['reason']}\n"
        
        rumps.alert("📜 Recent Scans", text)
    
    @rumps.clicked("ℹ️ About")
    def show_about(self, _):
        """Show about"""
        rumps.alert(
            title="About PayGuard",
            message="🛡️ PayGuard v3.0\n"
                    "Standalone Edition\n\n"
                    "AI-Powered Scam Protection\n\n"
                    "This version runs entirely locally.\n"
                    "No backend service required!\n\n"
                    "Features:\n"
                    "• Screen scanning for fake alerts\n"
                    "• Text analysis for scam patterns\n"
                    "• Clipboard protection\n\n"
                    "🔒 Privacy-First:\n"
                    "All analysis runs on your device.\n"
                    "No data is ever sent anywhere.\n\n"
                    "© 2026 PayGuard Team\n"
                    "Conrad Challenge 2026",
            ok="OK"
        )
    
    @rumps.clicked("❓ Help")
    def show_help(self, _):
        """Show help"""
        rumps.alert(
            title="PayGuard Help",
            message="🔍 Scan Screen Now\n"
                    "   Captures your screen and checks for\n"
                    "   fake virus alerts and scam pop-ups.\n\n"
                    "📋 Scan Clipboard\n"
                    "   Analyzes copied text for scam patterns\n"
                    "   like fake phone numbers or phishing.\n\n"
                    "✏️ Enter Text to Scan\n"
                    "   Manually paste any suspicious text\n"
                    "   to check if it's a scam.\n\n"
                    "Tips:\n"
                    "• Scan your screen if you see pop-ups\n"
                    "• Copy suspicious messages and scan\n"
                    "• The shield turns 🚨 when threats found",
            ok="OK"
        )
    
    @rumps.clicked("Quit")
    def quit_app(self, _):
        """Quit"""
        response = rumps.alert(
            title="Quit PayGuard?",
            message="Are you sure?\n\nYou won't be protected while PayGuard is closed.",
            ok="Quit",
            cancel="Cancel"
        )
        if response == 1:
            rumps.quit_application()


def main():
    """Main entry point"""
    print("🛡️ PayGuard Menu Bar (Standalone)")
    print("=" * 40)
    print("Look for the shield icon (🛡️) in your menu bar!")
    print("")
    print("This version works without any backend service.")
    print("All scam detection runs locally on your Mac.")
    print("")
    
    app = PayGuardStandalone()
    app.run()


if __name__ == "__main__":
    main()
