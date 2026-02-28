#!/usr/bin/env python3
"""
PayGuard - Cross-Platform Phishing & Scam Detection
Works on Windows, macOS, and Linux
"""

import os
import sys
import time
import threading
import base64
import platform
import logging
import subprocess
import requests
import io

from PIL import Image, ImageDraw, ImageFont

# Setup logging
LOG_DIR = os.path.expanduser("~/Library/Logs/PayGuard")
if platform.system() == "Windows":
    LOG_DIR = os.path.expanduser("~/AppData/Local/PayGuard/Logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/payguard.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
BACKEND_URL = "http://127.0.0.1:8002"
API_KEY = "demo_key"
CACHE_TTL = 300  # 5 minutes

# Check for PIL
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    logger.warning("PIL not available - image features disabled")

# Cross-platform tray icon using pystray
try:
    import pystray
    HAS_PYTRAY = True
except ImportError:
    HAS_PYTRAY = False
    logger.warning("pystray not available")


class PayGuardApp:
    def __init__(self):
        self.url_cache = {}
        self.cache_ttl = CACHE_TTL
        self.last_checked_url = None
        self.scans_performed = 0
        self.threats_detected = 0
        self.backend_online = False
        self.request_session = None
        self.protection_enabled = True  # Simple ON/OFF
        self.monitoring_active = False
        self.monitor_thread = None
        self.voice_alerts = True  # Voice alert option
        self._check_backend()
        
        # Auto-start on launch if enabled
        if self.protection_enabled:
            self.start_monitoring()
        
        # Setup auto-start
        self.setup_auto_start()
        
        # Safe domains whitelist
        self.safe_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
            'apple.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
            'reddit.com', 'amazon.com', 'netflix.com', 'icloud.com',
            'linkedin.com', 'instagram.com', 'yahoo.com', 'bing.com',
            '.edu', '.gov', '.mil',  # Trusted TLDs
            'wikipedia.org', 'mozilla.org', 'w3.org',
            'openai.com', 'anthropic.com', 'deepmind.com',
            'localhost', '127.0.0.1', '0.0.0.0',
        ]
        
        logger.info("PayGuard initialized")
    
    def setup_auto_start(self):
        """Setup auto-start on system boot"""
        try:
            if platform.system() == "Darwin":
                # macOS: Add to LaunchAgents
                plist_path = os.path.expanduser("~/Library/LaunchAgents/com.payguard.menubar.plist")
                plist_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.payguard.menubar</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>{}/payguard_crossplatform.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>'''.format(os.path.dirname(os.path.abspath(__file__)))
                
                if not os.path.exists(plist_path):
                    with open(plist_path, 'w') as f:
                        f.write(plist_content)
                    logger.info(f"Auto-start configured: {plist_path}")
                    
            elif platform.system() == "Windows":
                # Windows: Add to startup registry
                import winreg
                exe_path = sys.executable
                script_path = os.path.abspath(__file__)
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                    winreg.SetValueEx(key, "PayGuard", 0, winreg.REG_SZ, f'"{exe_path}" "{script_path}"')
                    winreg.CloseKey(key)
                    logger.info("Auto-start configured for Windows")
                except:
                    logger.warning("Could not configure Windows auto-start")
        except Exception as e:
            logger.warning(f"Auto-start setup failed: {e}")
    
    def start_monitoring(self):
        """Start background monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("Monitoring stopped")
    
    def _monitor_loop(self):
        """Background monitoring loop - checks clipboard periodically"""
        while self.monitoring_active:
            try:
                if self.protection_enabled:
                    self.scan_clipboard()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                time.sleep(5)
    
    def play_alert(self):
        """Play loud alert sound for danger"""
        if not self.voice_alerts:
            return
            
        try:
            if platform.system() == "Darwin":
                # Use say command for voice alert
                subprocess.run(["say", "Danger! Threat detected. Close the website now."], 
                            capture_output=True)
            elif platform.system() == "Windows":
                # Windows TTS
                import win32com.client
                speaker = win32com.client.Dispatch("SAPI.SpVoice")
                speaker.Speak("Danger! Threat detected. Close the website now.")
        except Exception as e:
            logger.warning(f"Voice alert failed: {e}")
    
    def _check_backend(self):
        """Check if backend is running"""
        try:
            r = requests.get(f"{BACKEND_URL}/api/health", timeout=2)
            self.backend_online = r.status_code == 200
        except:
            self.backend_online = False
        logger.info(f"Backend online: {self.backend_online}")
    
    def _capture_screen(self):
        """Capture screenshot"""
        try:
            if platform.system() == "Darwin":
                # macOS
                result = subprocess.run(
                    ["screencapture", "-x", "/tmp/payguard_screen.png"],
                    capture_output=True, timeout=10
                )
                if result.returncode == 0:
                    with open("/tmp/payguard_screen.png", "rb") as f:
                        return f.read()
            elif platform.system() == "Windows":
                # Windows using PIL
                import pyautogui
                img = pyautogui.screenshot()
                buf = io.BytesIO()
                img.save(buf, format='PNG')
                return buf.getvalue()
            else:
                # Linux
                import pyscreenshot
                img = pyscreenshot.grab()
                buf = io.BytesIO()
                img.save(buf, format='PNG')
                return buf.getvalue()
        except Exception as e:
            logger.error(f"Capture failed: {e}")
        return None
    
    def _scan_with_backend(self, image_data):
        """Send image to backend for AI/scam detection"""
        if not self.backend_online:
            return None
        
        try:
            payload = {
                "url": "screen://menubar",
                "content": base64.b64encode(image_data).decode(),
                "metadata": {"source": "menubar"}
            }
            r = requests.post(
                f"{BACKEND_URL}/api/media-risk/bytes",
                json=payload,
                headers={"X-API-Key": API_KEY},
                timeout=60
            )
            
            if r.status_code == 200:
                data = r.json()
                
                # Check AI-generated images
                image_fake_prob = data.get("image_fake_prob", 0)
                if image_fake_prob and image_fake_prob >= 30:
                    return {
                        "is_scam": True,
                        "confidence": int(image_fake_prob),
                        "reason": f"AI-generated image detected ({int(image_fake_prob)}%)"
                    }
                
                # Check scam alerts
                scam = data.get("scam_alert", {})
                if scam.get("is_scam"):
                    return {
                        "is_scam": True,
                        "confidence": scam.get("confidence", 80),
                        "reason": scam.get("senior_message", "Threat detected")
                    }
                
                # Check visual cues
                reasons = data.get("reasons", [])
                for reason in reasons:
                    if "visual scam" in reason.lower() or "red" in reason.lower():
                        return {
                            "is_scam": True,
                            "confidence": 75,
                            "reason": reason
                        }
                
            return {"is_scam": False}
        except Exception as e:
            logger.error(f"Backend error: {e}")
        return None
    
    def _local_detect(self, image_data):
        """Local scam detection based on colors"""
        if not HAS_PIL or not image_data:
            return {"is_scam": False, "confidence": 0}
        
        try:
            img = Image.open(io.BytesIO(image_data))
            img.thumbnail((400, 400))
            colors = img.convert("RGB").getcolors(maxcolors=100000)
            
            if not colors:
                return {"is_scam": False, "confidence": 0}
            
            total = sum(count for count, _ in colors)
            
            # Count danger colors
            red_count = sum(c for c, (r, g, b) in colors if r > 180 and g < 80 and b < 80)
            blue_count = sum(c for c, (r, g, b) in colors if b > 150 and r < 100 and g < 150)
            orange_count = sum(c for c, (r, g, b) in colors if r > 200 and g > 100 and g < 220 and b < 100)
            
            red_ratio = red_count / total if total > 0 else 0
            blue_ratio = blue_count / total if total > 0 else 0
            orange_ratio = orange_count / total if total > 0 else 0
            
            if red_ratio > 0.15:
                return {"is_scam": True, "confidence": 75, "reason": "Red warning screen detected"}
            if blue_ratio > 0.20:
                return {"is_scam": True, "confidence": 65, "reason": "Blue tech support scam detected"}
            if orange_ratio > 0.15:
                return {"is_scam": True, "confidence": 60, "reason": "Warning color detected"}
            
        except Exception as e:
            logger.error(f"Local detection error: {e}")
        
        return {"is_scam": False, "confidence": 0}
    
    def scan_screen(self):
        """Perform screen scan"""
        logger.info("Screen scan started")
        
        image_data = self._capture_screen()
        if not image_data:
            logger.warning("No image captured")
            return {"is_scam": False, "message": "Failed to capture screen"}
        
        logger.info(f"Captured {len(image_data)} bytes")
        
        # Try backend first
        result = self._scan_with_backend(image_data)
        
        # Fallback to local detection
        if not result or not result.get("is_scam"):
            local_result = self._local_detect(image_data)
            if local_result.get("is_scam"):
                result = local_result
        
        self.scans_performed += 1
        
        if result and result.get("is_scam"):
            self.threats_detected += 1
            logger.warning(f"THREAT DETECTED: {result.get('reason')}")
            return result
        
        logger.info("Screen scan: safe")
        return {"is_scam": False, "message": "No threats detected"}
    
    def scan_clipboard(self):
        """Scan clipboard text/URLs for scams - LIVE MONITORING"""
        try:
            # Get clipboard content
            if platform.system() == "Darwin":
                text = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=3).stdout
            elif platform.system() == "Windows":
                import pyperclip
                text = pyperclip.paste()
            else:
                import pyperclip
                text = pyperclip.paste()
            
            if not text:
                return {"is_scam": False, "message": "Empty clipboard"}
            
            # Check if it's a URL
            import re
            url_match = re.search(r'https?://[^\s<>"{}|\\^`\[\]]+', text.strip())
            
            if url_match and self.backend_online:
                # LIVE URL CHECK - Check URL against backend
                url = url_match.group(0)
                
                # Don't re-check same URL
                if url == self.last_checked_url:
                    return {"is_scam": False, "message": "Already checked"}
                
                try:
                    r = requests.post(
                        f"{BACKEND_URL}/api/v1/risk",
                        json={"url": url},
                        headers={"X-API-Key": API_KEY},
                        timeout=5
                    )
                    if r.status_code == 200:
                        result = r.json()
                        risk_level = result.get("risk_level", "low")
                        
                        if risk_level in ["high", "critical"]:
                            self.last_checked_url = url
                            self.threats_detected += 1
                            self.scans_performed += 1
                            self.play_alert()  # Voice alert!
                            logger.warning(f"DANGEROUS URL: {url} - {risk_level}")
                            return {
                                "is_scam": True,
                                "confidence": 90,
                                "reason": f"DANGEROUS! {result.get('risk_factors', ['Unknown threat'])[0]}"
                            }
                        elif risk_level == "medium":
                            self.last_checked_url = url
                            self.scans_performed += 1
                            logger.warning(f"SUSPICIOUS URL: {url}")
                            return {
                                "is_scam": False,
                                "confidence": 50,
                                "reason": "Caution: Suspicious website"
                            }
                except Exception as e:
                    logger.error(f"URL check failed: {e}")
            
            # Simple scam keyword detection
            scam_keywords = [
                "call now", "1-800", "urgent", "immediately",
                "your account", "suspended", "verify", "password",
                "bitcoin", "gift card", "western union", "winner",
                "congratulations", "prize", "claim now", "act now"
            ]
            
            text_lower = text.lower()
            matches = [kw for kw in scam_keywords if kw in text_lower]
            
            if matches:
                self.threats_detected += 1
                self.scans_performed += 1
                self.play_alert()  # Voice alert!
                logger.warning(f"Clipboard scam detected: {matches}")
                return {
                    "is_scam": True,
                    "confidence": 80,
                    "reason": f"SCAM! {matches[0].upper()} - Don't fall for it!"
                }
            
            self.scans_performed += 1
            return {"is_scam": False, "message": "✅ Safe"}
             
        except Exception as e:
            logger.error(f"Clipboard scan error: {e}")
            return {"is_scam": False, "message": str(e)}


def create_icon():
    """Create tray icon image"""
    size = (64, 64)
    img = Image.new('RGB', size, color=(40, 167, 69))  # Green
    draw = ImageDraw.Draw(img)
    
    # Draw shield shape
    draw.polygon([(32, 8), (56, 20), (56, 40), (32, 58), (8, 40), (8, 20)], 
                 outline='white', width=3)
    draw.line([(32, 18), (32, 40)], fill='white', width=3)
    draw.line([(22, 28), (32, 38), (42, 28)], fill='white', width=2)
    
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


def create_menu(app):
    """Create simplified system tray menu - one button ON/OFF"""
    from pystray import MenuItem as Item
    
    def toggle_protection(icon, item):
        app.protection_enabled = not app.protection_enabled
        if app.protection_enabled:
            show_notification("🛡️ PayGuard ON", "Protection is now active")
            app.start_monitoring()
        else:
            show_notification("🛡️ PayGuard OFF", "Protection paused")
            app.stop_monitoring()
    
    def scan_now(icon, item):
        result = app.scan_clipboard()
        if result.get("is_scam"):
            show_notification("🚨 DANGER!", result.get("reason", "Threat detected!"))
            app.play_alert()
        else:
            show_notification("✅ Safe", "No threats detected")
    
    def status_click(icon, item):
        app._check_backend()
        status = "🟢 ACTIVE" if app.protection_enabled else "🔴 PAUSED"
        show_notification(
            f"📊 PayGuard Status",
            f"Status: {status}\nBackend: {'Online' if app.backend_online else 'Offline'}\nThreats blocked: {app.threats_detected}"
        )
    
    def quit_click(icon, item):
        app.stop_monitoring()
        icon.stop()
    
    # Simple menu with just a few options
    menu = (
        Item("🛡️ Toggle ON/OFF", toggle_protection),
        Item("🔍 Scan Now", scan_now),
        Item("📊 Status", status_click),
        Item("❌ Quit", quit_click),
    )
    return menu


def show_notification(title, message):
    """Show SIMPLE system notification - senior friendly"""
    try:
        # Simplify messages for seniors
        simple_title = title
        simple_message = message
        
        # Make messages super simple
        if "DANGER" in message.upper() or "THREAT" in message.upper():
            simple_title = "🚨 DANGER!"
            simple_message = "CLOSE THIS WEBSITE NOW! It's a scam!"
        elif "SAFE" in message.upper():
            simple_title = "✅ SAFE"
            simple_message = "This website is OK"
        elif "ON" in message.upper():
            simple_title = "🛡️ PROTECTION ON"
            simple_message = "PayGuard is protecting you"
        elif "OFF" in message.upper():
            simple_title = "⏸️ PROTECTION OFF"
            simple_message = "PayGuard is paused"
        
        if platform.system() == "Darwin":
            subprocess.run([
                "osascript", "-e",
                f'display notification "{simple_message}" with title "{simple_title}"'
            ], capture_output=True)
        elif platform.system() == "Windows":
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(simple_title, simple_message, duration=5)
        else:
            subprocess.run(["notify-send", simple_title, simple_message], capture_output=True)
    except Exception as e:
        logger.error(f"Notification error: {e}")


def main():
    """Main entry point"""
    logger.info(f"PayGuard starting on {platform.system()}...")
    
    # Check dependencies
    if not HAS_PYTRAY:
        logger.error("pystray not installed. Run: pip install pystray Pillow")
        sys.exit(1)
    
    # Create app
    app = PayGuardApp()
    
    # Create icon
    icon_image = create_icon()
    icon = pystray.Icon(
        "payguard",
        icon_image,
        "PayGuard",
        create_menu(app)
    )
    
    # Run
    logger.info("PayGuard ready!")
    try:
        icon.run()
    except KeyboardInterrupt:
        logger.info("PayGuard stopped")


if __name__ == "__main__":
    main()
