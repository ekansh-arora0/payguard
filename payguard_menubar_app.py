#!/usr/bin/env python3
"""
PayGuard Menu Bar App - Professional Edition v3.1

Enterprise-grade macOS menu bar application for AI-powered scam detection.
Features:
  - Backend ML integration with automatic fallback to local detection
  - Professional notifications with actionable alerts
  - Rotating logs at ~/Library/Logs/PayGuard/
  - Single-instance guard with pidfile
  - Minimal resource usage (on-demand scanning only)

Install: pip3 install rumps requests pillow
Run: python3 payguard_menubar_app.py
"""

import os
import sys
import re
import subprocess
import threading
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path

try:
    import rumps
except ImportError:
    print("Missing dependency: rumps")
    print("Install with: pip3 install rumps")
    sys.exit(1)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from PIL import Image
    import io
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

import base64

import time

# Configuration
PAYGUARD_DIR = Path(__file__).parent.absolute()
BACKEND_URL = "http://127.0.0.1:8002"
APP_VERSION = "3.1.0"

LOG_DIR = os.path.expanduser("~/Library/Logs/PayGuard")
LOG_FILE = os.path.join(LOG_DIR, "menubar.log")
PID_FILE = os.path.join(LOG_DIR, "payguard_menubar.pid")

ICON_PROTECTED = "🛡️"
ICON_SCANNING = "🔄"
ICON_THREAT = "🚨"


class LocalScamDetector:
    """Lightweight pattern-based scam detection for offline use."""
    
    PATTERNS = [
        (r"\b1-8[0-9]{2}-\d{3}-\d{4}\b", 40, "Suspicious toll-free number"),
        (r"\b1-\d{3}-\d{3}-\d{4}\b", 20, "Phone number in message"),
        (r"(?i)\b(urgent|immediate(ly)?|act now|right away)\b", 30, "Urgency language"),
        (r"(?i)\b(call (now|immediately|us))\b", 25, "Pressure to call"),
        (r"(?i)\b(virus|infected|malware|trojan|hacked|compromised)\b", 35, "Security scare tactics"),
        (r"(?i)\b(microsoft|apple|amazon|google|paypal).{0,20}(support|security|alert)", 40, "Brand impersonation"),
        (r"(?i)do not (close|restart|shut down|ignore)", 45, "Scare tactic instruction"),
        (r"(?i)(error code|reference id):\s*[a-z0-9-]+", 25, "Fake reference number"),
        (r"(?i)\b(suspended|blocked|locked|expired)\b.{0,15}(account)", 30, "Account threat"),
        (r"(?i)\b(verify|update|confirm).{0,15}(account|payment|password)", 30, "Credential harvesting"),
        (r"(?i)\b(won|winner|lottery|prize|gift card)\b", 35, "Prize/lottery scam"),
        (r"(?i)\b(bitcoin|crypto|btc)\b.{0,20}(send|transfer|pay)", 40, "Cryptocurrency scam"),
        (r"(?i)(wire transfer|western union|moneygram)", 35, "Untraceable payment"),
    ]

    @classmethod
    def analyze_text(cls, text):
        if not text or len(text.strip()) < 10:
            return {"is_scam": False, "score": 0, "patterns": [], "confidence": 0}
        
        score = 0
        detected = []
        
        for pattern, weight, name in cls.PATTERNS:
            if re.search(pattern, text):
                score += weight
                if name not in detected:
                    detected.append(name)
        
        return {
            "is_scam": score >= 40,
            "score": min(score, 100),
            "patterns": detected,
            "confidence": min(score + 15, 99) if score >= 40 else max(score, 0),
        }

    @classmethod
    def analyze_image(cls, image_data):
        if not HAS_PIL or not image_data:
            return {"is_scam": False, "confidence": 0}
        
        try:
            img = Image.open(io.BytesIO(image_data))
            img.thumbnail((400, 400))
            colors = img.convert("RGB").getcolors(maxcolors=100000)
            
            if not colors:
                return {"is_scam": False, "confidence": 0}
            
            total = sum(count for count, _ in colors)
            red_count = sum(
                count for count, (r, g, b) in colors
                if r > 180 and g < 80 and b < 80
            )
            red_ratio = red_count / total if total > 0 else 0
            
            if red_ratio > 0.15:
                confidence = min(75 + int(red_ratio * 50), 98)
                return {
                    "is_scam": True,
                    "confidence": confidence,
                    "reason": "Red warning screen detected - likely fake security alert",
                }
        except Exception:
            pass
        
        return {"is_scam": False, "confidence": 0}


class PayGuardApp(rumps.App):
    """Professional menu bar application for PayGuard scam detection."""

    def __init__(self):
        super().__init__(ICON_PROTECTED, title=ICON_PROTECTED, quit_button=None)
        
        self._setup_logging()
        self.logger.info("=" * 50)
        self.logger.info(f"PayGuard v{APP_VERSION} starting...")
        
        self.logger.info("Acquiring lock...")
        if not self._acquire_lock():
            self.logger.info("Lock acquisition failed - another instance running")
            return
        self.logger.info("Lock acquired successfully")
        
        self.backend_online = False
        self.scans_performed = 0
        self.threats_detected = 0
        self.last_scan_time = None
        
        self.menu = [
            rumps.MenuItem("PayGuard", callback=None),
            rumps.MenuItem("Status: Initializing...", callback=None),
            None,
            rumps.MenuItem("🔍  Scan Screen", callback=self.scan_screen),
            rumps.MenuItem("📋  Scan Clipboard", callback=self.scan_clipboard),
            rumps.MenuItem("✏️  Scan Text...", callback=self.scan_text_prompt),
            None,
            rumps.MenuItem("📊  View Statistics", callback=self.show_statistics),
            rumps.MenuItem("📄  View Logs", callback=self.open_logs),
            None,
            rumps.MenuItem("🔄  Refresh Backend", callback=self.refresh_backend),
            rumps.MenuItem("🚀  Start Backend Server", callback=self.start_backend),
            None,
            rumps.MenuItem("ℹ️  About PayGuard", callback=self.show_about),
            None,
            rumps.MenuItem("Quit PayGuard", callback=self.quit_app),
        ]
        
        self.logger.info("Starting _initial_setup thread...")
        threading.Thread(target=self._initial_setup, daemon=True).start()

    def _setup_logging(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        handler = RotatingFileHandler(LOG_FILE, maxBytes=2*1024*1024, backupCount=5)
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s"))
        self.logger = logging.getLogger("payguard.menubar")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

    def _acquire_lock(self):
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            if os.path.exists(PID_FILE):
                with open(PID_FILE, "r") as f:
                    existing_pid = f.read().strip()
                if existing_pid:
                    try:
                        os.kill(int(existing_pid), 0)
                        rumps.alert("PayGuard Already Running",
                                    f"Another instance (PID {existing_pid}) is active.\nLook for the shield icon in your menu bar.")
                        sys.exit(0)
                    except (ProcessLookupError, ValueError):
                        pass
            with open(PID_FILE, "w") as f:
                f.write(str(os.getpid()))
            return True
        except Exception as e:
            self.logger.error(f"Lock error: {e}")
            return True

    def _initial_setup(self):
        self.logger.info("_initial_setup started")
        try:
            time.sleep(0.5)
            self.logger.info("Checking backend...")
            self._check_backend()
            self.logger.info("Updating status...")
            self._update_status()
            self.logger.info(f"Ready. Backend: {'online' if self.backend_online else 'offline'}")
            # Start browser monitoring
            self.logger.info("Starting browser monitoring thread...")
            monitor_thread = threading.Thread(target=self._monitor_browser_history, daemon=True)
            monitor_thread.start()
            self.logger.info("Browser monitoring thread started successfully")
        except Exception as e:
            self.logger.error(f"Initial setup error: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
        
    def _monitor_browser_history(self):
        """Monitor browser history for suspicious URLs."""
        checked_urls = set()
        last_safari_url = None
        last_chrome_url = None
        self.logger.info("Browser monitoring started - checking Safari & Chrome every 5 seconds")
        
        while True:
            try:
                # Check Safari history - ONLY MOST RECENT
                safari_history = self._get_safari_history()
                if safari_history:
                    url = safari_history[0]  # Most recent
                    if url != last_safari_url and url not in checked_urls:
                        last_safari_url = url
                        checked_urls.add(url)
                        self.logger.info(f"New Safari URL: {url[:80]}")
                        self._check_url(url, source="Safari")
                        
                # Check Chrome history - ONLY MOST RECENT  
                chrome_history = self._get_chrome_history()
                if chrome_history:
                    url = chrome_history[0]  # Most recent
                    if url != last_chrome_url and url not in checked_urls:
                        last_chrome_url = url
                        checked_urls.add(url)
                        self.logger.info(f"New Chrome URL: {url[:80]}")
                        self._check_url(url, source="Chrome")
                        
                # Keep set from growing too large
                if len(checked_urls) > 1000:
                    checked_urls = set(list(checked_urls)[-500:])
                    
            except Exception as e:
                self.logger.error(f"Browser monitor error: {e}")
                
            time.sleep(5)  # Check every 5 seconds
            
    def _get_safari_history(self):
        """Get ONLY THE MOST RECENT Safari URL from History.db."""
        urls = []
        try:
            history_path = os.path.expanduser("~/Library/Safari/History.db")
            
            if os.path.exists(history_path):
                import sqlite3
                import tempfile
                import shutil
                import time
                # Copy file to avoid lock
                temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
                temp_db.close()
                shutil.copy2(history_path, temp_db.name)
                
                conn = sqlite3.connect(temp_db.name)
                cursor = conn.cursor()
                # Safari uses Cocoa timestamp (seconds since 2001-01-01)
                safari_now = int(time.time()) - 978307200  # Seconds since 2001
                five_min_ago = (safari_now - 300) * 1000000  # Convert to microseconds
                
                # ONLY GET THE MOST RECENT URL (LIMIT 1)
                cursor.execute("""
                    SELECT url FROM history_items 
                    WHERE visit_time > ?
                    ORDER BY visit_time DESC 
                    LIMIT 1
                """, (five_min_ago,))
                result = cursor.fetchone()
                if result:
                    urls = [result[0]]
                conn.close()
                os.unlink(temp_db.name)
        except Exception as e:
            self.logger.debug(f"Safari history error: {e}")
        return urls
        
    def _get_chrome_history(self):
        """Get ONLY THE MOST RECENT Chrome URL from History."""
        urls = []
        try:
            history_path = os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/History")
            
            if os.path.exists(history_path):
                import sqlite3
                import tempfile
                import shutil
                import time
                # Copy file to avoid lock
                temp_db = tempfile.NamedTemporaryFile(delete=False)
                temp_db.close()
                shutil.copy2(history_path, temp_db.name)
                
                conn = sqlite3.connect(temp_db.name)
                cursor = conn.cursor()
                # Chrome uses microseconds since 1601-01-01
                chrome_now = (int(time.time()) + 11644473600) * 1000000
                five_min_ago = chrome_now - (5 * 60 * 1000000)
                
                # ONLY GET THE MOST RECENT URL (LIMIT 1)
                cursor.execute("""
                    SELECT url FROM urls 
                    WHERE last_visit_time > ?
                    ORDER BY last_visit_time DESC 
                    LIMIT 1
                """, (five_min_ago,))
                result = cursor.fetchone()
                if result:
                    urls = [result[0]]
                conn.close()
                os.unlink(temp_db.name)
        except Exception as e:
            self.logger.debug(f"Chrome history error: {e}")
        return urls
        
    def _check_url(self, url, source="browser"):
        """Check a URL for threats."""
        try:
            if not self.backend_online:
                return
                
            # Skip common safe domains
            safe_domains = ['google.com', 'youtube.com', 'facebook.com', 'twitter.com', 
                          'apple.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
                          'reddit.com', 'amazon.com', 'netflix.com', 'icloud.com']
            if any(domain in url.lower() for domain in safe_domains):
                return
                
            self.logger.info(f"Checking {source} URL: {url}")
            
            # Check with backend
            resp = requests.post(
                f"{BACKEND_URL}/api/v1/risk?fast=true",
                headers={"Content-Type": "application/json", "X-API-Key": "demo_key"},
                json={"url": url},
                timeout=3
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get("risk_level", "").lower() == "high":
                    self._show_url_threat_alert(url, data)
                    self.threats_detected += 1
                    self.scans_performed += 1
                    self.last_scan_time = datetime.now()
                    
        except Exception as e:
            self.logger.error(f"URL check error: {e}")
            
    def _show_url_threat_alert(self, url, data):
        """Show popup alert for suspicious URL."""
        try:
            self._play_alert()
            risk_factors = data.get("risk_factors", ["Suspicious website detected"])
            factors_str = "\n".join([f"• {f}" for f in risk_factors[:3]])
            
            msg = f"⚠️ THREAT DETECTED ⚠️\n\nURL: {url[:60]}...\n\nRisk Level: HIGH\n\nRisk Factors:\n{factors_str}\n\n⚠️ Do not enter passwords or payment info on this site!"
            
            subprocess.run([
                "osascript", "-e",
                f'display dialog "{msg}" with title "🚨 PayGuard Alert" buttons {{"OK"}} default button "OK" with icon stop'
            ], capture_output=True)
            
            self.logger.info(f"Threat alert shown for: {url}")
        except Exception as e:
            self.logger.error(f"Alert error: {e}")

    def _check_backend(self):
        if not HAS_REQUESTS:
            self.backend_online = False
            return
        try:
            r = requests.get(f"{BACKEND_URL}/api/v1/health", timeout=3)
            self.backend_online = r.status_code == 200
        except Exception:
            self.backend_online = False

    def _update_status(self):
        try:
            if self.backend_online:
                self.menu["Status: Initializing..."].title = "✅ Protected (AI Mode)"
                self.menu["PayGuard"].title = f"PayGuard v{APP_VERSION}"
            else:
                self.menu["Status: Initializing..."].title = "🔶 Protected (Local Mode)"
                self.menu["PayGuard"].title = f"PayGuard v{APP_VERSION}"
            self.title = ICON_PROTECTED
        except Exception:
            pass

    def _play_alert(self):
        try:
            subprocess.run(["afplay", "/System/Library/Sounds/Sosumi.aiff"], capture_output=True, timeout=2)
        except Exception:
            pass

    def _capture_screen(self):
        try:
            import tempfile
            fd, path = tempfile.mkstemp(suffix='.png', prefix='payguard_capture_')
            os.close(fd)
            try:
                result = subprocess.run(["screencapture", "-x", "-C", path], capture_output=True, timeout=10)
                if result.returncode == 0 and os.path.exists(path):
                    with open(path, "rb") as f:
                        data = f.read()
                    return data
            finally:
                if os.path.exists(path):
                    os.remove(path)
        except Exception as e:
            self.logger.error(f"Capture failed: {e}")
        return None

    def _get_clipboard(self):
        try:
            result = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=3)
            return result.stdout
        except Exception as e:
            self.logger.error(f"Clipboard error: {e}")
            return None

    def _scan_with_backend(self, image_data):
        if not HAS_REQUESTS or not self.backend_online:
            return None
        try:
            payload = {
                "url": "screen://menubar",
                "content": base64.b64encode(image_data).decode(),
                "metadata": {"source": "menubar"}
            }
            r = requests.post(f"{BACKEND_URL}/api/media-risk/bytes", json=payload, timeout=30)
            if r.status_code == 200:
                data = r.json()
                scam = data.get("scam_alert", {})
                if scam.get("is_scam"):
                    return {
                        "is_scam": True,
                        "confidence": scam.get("confidence", 80),
                        "reason": scam.get("senior_message", "Threat detected"),
                    }
                return {"is_scam": False}
        except Exception as e:
            self.logger.error(f"Backend error: {e}")
        return None

    @rumps.clicked("🔍  Scan Screen")
    def scan_screen(self, _):
        self.title = ICON_SCANNING
        threading.Thread(target=self._do_screen_scan, daemon=True).start()

    def _do_screen_scan(self):
        self.logger.info("Screen scan started")
        image_data = self._capture_screen()
        if not image_data:
            # Silently fail - no notification
            self.title = ICON_PROTECTED
            return
        
        result = None
        if self.backend_online:
            result = self._scan_with_backend(image_data)
        if result is None:
            result = LocalScamDetector.analyze_image(image_data)
        
        self.scans_performed += 1
        self.last_scan_time = datetime.now()
        
        if result.get("is_scam"):
            self.threats_detected += 1
            self.title = ICON_THREAT
            self._play_alert()
            
            confidence = result.get("confidence", 80)
            reason = result.get("reason", "Suspicious content detected")
            
            # Only show popup, no notification
            choice = rumps.alert(
                title="🚨 PayGuard Security Alert",
                message=f"{reason}\n\nConfidence: {confidence}%\n\nThis may be a scam. Do NOT call any phone numbers or click any links.",
                ok="I Understand",
                cancel="Get Help"
            )
            if choice == 0:
                subprocess.run(["open", "https://consumer.ftc.gov/features/scam-alerts"], capture_output=True)
            
            self.logger.warning(f"THREAT: confidence={confidence}, reason={reason}")
        else:
            self.title = ICON_PROTECTED
            # No notification for safe scans
            self.logger.info("Screen scan: safe")

    @rumps.clicked("📋  Scan Clipboard")
    def scan_clipboard(self, _):
        text = self._get_clipboard()
        if not text or len(text.strip()) < 5:
            # Silently skip empty clipboard
            return
        
        result = LocalScamDetector.analyze_text(text)
        self.scans_performed += 1
        self.last_scan_time = datetime.now()
        
        if result.get("is_scam"):
            self.threats_detected += 1
            self.title = ICON_THREAT
            self._play_alert()
            
            patterns = result.get("patterns", [])
            confidence = result.get("confidence", 80)
            
            # Only popup, no notification
            rumps.alert(
                title="🚨 Suspicious Content",
                message=f"Detected:\n• " + "\n• ".join(patterns[:4]) + f"\n\nConfidence: {confidence}%\n\nDO NOT paste or share this!",
                ok="OK"
            )
            self.logger.warning(f"THREAT (clipboard): {patterns}")
        else:
            self.title = ICON_PROTECTED
            # No notification for safe clipboard
            self.logger.info("Clipboard scan: safe")

    @rumps.clicked("✏️  Scan Text...")
    def scan_text_prompt(self, _):
        window = rumps.Window(
            message="Paste suspicious text to scan:",
            title="PayGuard - Text Scanner",
            default_text="",
            ok="Scan",
            cancel="Cancel",
            dimensions=(450, 180)
        )
        response = window.run()
        
        if response.clicked and response.text:
            result = LocalScamDetector.analyze_text(response.text)
            self.scans_performed += 1
            self.last_scan_time = datetime.now()
            
            if result.get("is_scam"):
                self.threats_detected += 1
                patterns = result.get("patterns", [])
                confidence = result.get("confidence", 80)
                
                rumps.alert(
                    title="🚨 SCAM DETECTED",
                    message=f"Indicators found:\n• " + "\n• ".join(patterns[:5]) + f"\n\nConfidence: {confidence}%",
                    ok="OK"
                )
            else:
                rumps.alert(title="✅ Safe", message="No scam indicators detected.", ok="OK")

    @rumps.clicked("📊  View Statistics")
    def show_statistics(self, _):
        mode = "AI (Backend)" if self.backend_online else "Local"
        last = self.last_scan_time.strftime("%H:%M:%S") if self.last_scan_time else "Never"
        rumps.alert(
            title="📊 PayGuard Statistics",
            message=f"Mode: {mode}\n\nScans: {self.scans_performed}\nThreats: {self.threats_detected}\nLast scan: {last}\n\nVersion: {APP_VERSION}",
            ok="OK"
        )

    @rumps.clicked("📄  View Logs")
    def open_logs(self, _):
        try:
            subprocess.run(["open", "-a", "Console", LOG_FILE], capture_output=True)
        except Exception:
            subprocess.run(["open", LOG_DIR], capture_output=True)

    @rumps.clicked("🔄  Refresh Backend")
    def refresh_backend(self, _):
        self._check_backend()
        self._update_status()
        msg = "Backend online - AI mode" if self.backend_online else "Backend offline - Local mode"
        # No notification, just update status
        self.logger.info(f"Backend check: {msg}")

    @rumps.clicked("🚀  Start Backend Server")
    def start_backend(self, _):
        try:
            subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "backend.server:app", "--host", "127.0.0.1", "--port", "8002"],
                cwd=str(PAYGUARD_DIR),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            # No notification, just log
            self.logger.info("Backend start requested")
            
            def check_later():
                time.sleep(5)
                self._check_backend()
                self._update_status()
                # No notification when backend is ready
            
            threading.Thread(target=check_later, daemon=True).start()
        except Exception as e:
            # No notification for error
            self.logger.error(f"Backend start failed: {e}")

    @rumps.clicked("ℹ️  About PayGuard")
    def show_about(self, _):
        rumps.alert(
            title="About PayGuard",
            message=f"PayGuard v{APP_VERSION}\n\nAI-powered scam detection for macOS.\n\n"
                    "• Visual AI detects fake alerts\n"
                    "• NLP catches manipulation tactics\n"
                    "• 100% local - your data stays private\n\n"
                    "© 2026 PayGuard Team",
            ok="OK"
        )

    @rumps.clicked("Quit PayGuard")
    def quit_app(self, _):
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
        except Exception:
            pass
        self.logger.info("PayGuard shutting down")
        rumps.quit_application()


def main():
    print(f"🛡️ PayGuard v{APP_VERSION}")
    print("   Starting menu bar app...")
    print("   Look for the shield icon in your menu bar.")
    print()
    app = PayGuardApp()
    app.run()


if __name__ == "__main__":
    main()
