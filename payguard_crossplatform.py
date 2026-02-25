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
        self._check_backend()
        
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
        """Scan clipboard text for scams"""
        try:
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
            
            # Simple scam keyword detection
            scam_keywords = [
                "call now", "1-800", "urgent", "immediately",
                "your account", "suspended", "verify", "password",
                "bitcoin", "gift card", "western union"
            ]
            
            text_lower = text.lower()
            matches = [kw for kw in scam_keywords if kw in text_lower]
            
            if matches:
                self.threats_detected += 1
                self.scans_performed += 1
                logger.warning(f"Clipboard scam detected: {matches}")
                return {
                    "is_scam": True,
                    "confidence": 80,
                    "reason": f"Scam keywords found: {matches}"
                }
            
            self.scans_performed += 1
            return {"is_scam": False, "message": "Clipboard appears safe"}
            
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
    """Create system tray menu"""
    def scan_screen_click(icon, item):
        result = app.scan_screen()
        if result.get("is_scam"):
            show_notification(
                "🚨 PayGuard Alert",
                result.get("reason", "Threat detected!")
            )
        else:
            show_notification(
                "✅ PayGuard Scan Complete",
                result.get("message", "Your screen appears safe")
            )
    
    def scan_clipboard_click(icon, item):
        result = app.scan_clipboard()
        if result.get("is_scam"):
            show_notification(
                "🚨 PayGuard Alert",
                result.get("reason", "Scam detected!")
            )
        else:
            show_notification(
                "✅ Clipboard Scan Complete",
                result.get("message", "No threats found")
            )
    
    def status_click(icon, item):
        app._check_backend()
        show_notification(
            "📊 PayGuard Status",
            f"Backend: {'Online' if app.backend_online else 'Offline'}\nScans: {app.scans_performed}\nThreats: {app.threats_detected}"
        )
    
    def quit_click(icon, item):
        icon.stop()
    
    from pystray import MenuItem as Item
    
    menu = (
        Item("🖥️ Scan Screen", scan_screen_click),
        Item("📋 Scan Clipboard", scan_clipboard_click),
        Item("📊 Status", status_click),
        Item("❌ Quit", quit_click),
    )
    return menu


def show_notification(title, message):
    """Show system notification"""
    try:
        if platform.system() == "Darwin":
            subprocess.run([
                "osascript", "-e",
                f'display notification "{message}" with title "{title}"'
            ], capture_output=True)
        elif platform.system() == "Windows":
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(title, message, duration=5)
        else:
            # Linux
            subprocess.run([
                "notify-send", title, message
            ], capture_output=True)
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
