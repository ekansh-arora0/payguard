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
    def analyze_image(cls, image_data, logger=None):
        if not HAS_PIL or not image_data:
            return {"is_scam": False, "confidence": 0}
        
        try:
            img = Image.open(io.BytesIO(image_data))
            w, h = img.size
            
            # First check overall screen
            img_small = img.copy()
            img_small.thumbnail((400, 400))
            colors = img_small.convert("RGB").getcolors(maxcolors=100000)
            
            if not colors:
                return {"is_scam": False, "confidence": 0}
            
            total = sum(count for count, _ in colors)
            
            # Count different danger colors
            red_count = sum(
                count for count, (r, g, b) in colors
                if r > 180 and g < 80 and b < 80
            )
            blue_count = sum(
                count for count, (r, g, b) in colors
                if b > 150 and r < 100 and g < 150
            )
            orange_count = sum(
                count for count, (r, g, b) in colors
                if r > 200 and g > 100 and g < 220 and b < 100
            )
            
            red_ratio = red_count / total if total > 0 else 0
            blue_ratio = blue_count / total if total > 0 else 0
            orange_ratio = orange_count / total if total > 0 else 0
            
            # Check tiles/grids for localized detection (popup is small part of screen)
            # Use larger image for tile detection
            img_medium = img.copy()
            img_medium.thumbnail((800, 800))
            w_m, h_m = img_medium.size
            
            # Use finer grid (8x8 = 100x100 tiles) to catch smaller popups
            grid = 8
            th = h_m // grid
            tw = w_m // grid
            max_tile_red = 0
            max_tile_blue = 0
            max_tile_orange = 0
            
            # Track consecutive colored tiles (indicates a popup box)
            popup_candidates = []
            
            for gy in range(grid):
                for gx in range(grid):
                    x0, y0 = gx * tw, gy * th
                    x1 = (gx + 1) * tw if gx < grid - 1 else w_m
                    y1 = (gy + 1) * th if gy < grid - 1 else h_m
                    tile = img_medium.crop((x0, y0, x1, y1))
                    tile_colors = tile.convert("RGB").getcolors(maxcolors=100000)
                    if not tile_colors:
                        continue
                    tile_total = sum(c for c, _ in tile_colors)
                    if tile_total == 0:
                        continue
                    tile_red = sum(c for c, (r, g, b) in tile_colors if r > 180 and g < 80 and b < 80) / tile_total
                    tile_blue = sum(c for c, (r, g, b) in tile_colors if b > 150 and r < 100 and g < 150) / tile_total
                    tile_orange = sum(c for c, (r, g, b) in tile_colors if r > 200 and g > 100 and g < 220 and b < 100) / tile_total
                    
                    max_tile_red = max(max_tile_red, tile_red)
                    max_tile_blue = max(max_tile_blue, tile_blue)
                    max_tile_orange = max(max_tile_orange, tile_orange)
                    
                    # Track tiles with warning colors for popup detection
                    if tile_red > 0.10 or tile_blue > 0.10 or tile_orange > 0.10:
                        popup_candidates.append({
                            'gx': gx, 'gy': gy, 'red': tile_red, 'blue': tile_blue, 'orange': tile_orange
                        })
            
            # Check for popup pattern: consecutive tiles in center area
            center_popup = False
            if len(popup_candidates) >= 4:
                # Check if colored tiles form a rectangular region (popup shape)
                xs = [c['gx'] for c in popup_candidates]
                ys = [c['gy'] for c in popup_candidates]
                
                # Look for clusters in center (where popups usually appear)
                center_x_min, center_x_max = grid // 3, 2 * grid // 3
                center_y_min, center_y_max = grid // 4, 3 * grid // 4
                
                center_tiles = [c for c in popup_candidates 
                               if center_x_min <= c['gx'] <= center_x_max 
                               and center_y_min <= c['gy'] <= center_y_max]
                
                if len(center_tiles) >= 4:
                    # Check if they form a box-like shape
                    unique_x = len(set(c['gx'] for c in center_tiles))
                    unique_y = len(set(c['gy'] for c in center_tiles))
                    if unique_x >= 2 and unique_y >= 2:
                        center_popup = True
                        if logger:
                            logger.debug(f"Center popup detected: {len(center_tiles)} tiles")
            
            # Use the maximum of overall ratio OR highest tile ratio
            # Boost detection if we found a center popup pattern
            red_ratio = max(red_ratio, max_tile_red)
            blue_ratio = max(blue_ratio, max_tile_blue)
            orange_ratio = max(orange_ratio, max_tile_orange)
            
            # Lower thresholds if we detected a popup pattern in the center
            if center_popup:
                red_threshold = 0.08  # Lower from 0.15
                blue_threshold = 0.08  # Lower from 0.20
                orange_threshold = 0.08  # Lower from 0.15
            else:
                red_threshold = 0.15
                blue_threshold = 0.20
                orange_threshold = 0.15
            
            if logger:
                logger.debug(f"Screen colors: red={red_ratio:.1%}, blue={blue_ratio:.1%}, orange={orange_ratio:.1%} (max tile)")
            
            # Smart detection: combine color with text analysis using OCR
            # First find regions with warning colors
            warning_regions = []
            for gy in range(grid):
                for gx in range(grid):
                    x0, y0 = gx * tw, gy * th
                    x1 = (gx + 1) * tw if gx < grid - 1 else w_m
                    y1 = (gy + 1) * th if gy < grid - 1 else h_m
                    tile = img_medium.crop((x0, y0, x1, y1))
                    tile_colors = tile.convert("RGB").getcolors(maxcolors=100000)
                    if not tile_colors:
                        continue
                    tile_total = sum(c for c, _ in tile_colors)
                    if tile_total == 0:
                        continue
                    tile_red = sum(c for c, (r, g, b) in tile_colors if r > 180 and g < 80 and b < 80) / tile_total
                    tile_blue = sum(c for c, (r, g, b) in tile_colors if b > 150 and r < 100 and g < 150) / tile_total
                    tile_orange = sum(c for c, (r, g, b) in tile_colors if r > 200 and g > 100 and g < 220 and b < 100) / tile_total
                    
                    # If this tile has warning colors, analyze it with OCR
                    if tile_red > 0.20 or tile_blue > 0.15 or tile_orange > 0.20:
                        warning_regions.append({
                            'tile': tile,
                            'red': tile_red,
                            'blue': tile_blue,
                            'orange': tile_orange,
                            'x': x0, 'y': y0
                        })
            
            # Analyze warning regions with OCR for scam text patterns
            # Merge adjacent tiles to handle small popups better
            merged_regions = []
            used_tiles = set()
            
            for i, region in enumerate(warning_regions):
                if i in used_tiles:
                    continue
                
                # Find all connected tiles
                connected = [region]
                used_tiles.add(i)
                
                # Check neighbors
                for j, other in enumerate(warning_regions):
                    if j in used_tiles:
                        continue
                    # Check if adjacent (within 1 tile)
                    if abs(region['x'] - other['x']) <= tw and abs(region['y'] - other['y']) <= th:
                        connected.append(other)
                        used_tiles.add(j)
                
                if len(connected) >= 2:
                    # Merge tiles into larger region
                    min_x = min(r['x'] for r in connected)
                    min_y = min(r['y'] for r in connected)
                    max_x = max(r['x'] + tw for r in connected)
                    max_y = max(r['y'] + th for r in connected)
                    
                    merged_tile = img_medium.crop((min_x, min_y, max_x, max_y))
                    avg_red = sum(r['red'] for r in connected) / len(connected)
                    avg_blue = sum(r['blue'] for r in connected) / len(connected)
                    
                    merged_regions.append({
                        'tile': merged_tile,
                        'red': avg_red,
                        'blue': avg_blue,
                        'size': len(connected)
                    })
            
            # Also add individual tiles if they didn't merge
            for i, region in enumerate(warning_regions):
                if i not in used_tiles:
                    merged_regions.append(region)
            
            scam_indicators = []
            for region in merged_regions:
                try:
                    # Skip tiny regions
                    if region['tile'].size[0] < 50 or region['tile'].size[1] < 50:
                        continue
                    
                    # Use pytesseract if available
                    import pytesseract
                    text = pytesseract.image_to_string(region['tile'], config='--psm 6').lower()
                    
                    # Scam popup patterns
                    phone_pattern = r'\b1-\d{3}-\d{3}-\d{4}\b|\b1-8\d{2}-\d{3}-\d{4}\b|\(\d{3}\)\s*\d{3}-\d{4}'
                    urgency_words = ['immediately', 'urgent', 'right now', 'act now', 'within', 'hours', 'asap']
                    action_words = ['call now', 'click here', 'download', 'install now', 'allow', 'support']
                    threat_words = ['virus', 'infected', 'hacked', 'compromised', 'stolen', 'suspended', 'blocked', 'locked']
                    fake_brands = ['microsoft', 'apple', 'windows', 'macos', 'security', 'alert', 'warning']
                    
                    has_phone = bool(re.search(phone_pattern, text))
                    has_urgency = any(word in text for word in urgency_words)
                    has_action = any(word in text for word in action_words)
                    has_threat = any(word in text for word in threat_words)
                    has_brand = any(brand in text for brand in fake_brands)
                    
                    # Score the region
                    score = 0
                    if has_phone: score += 40
                    if has_urgency: score += 20
                    if has_action: score += 15
                    if has_threat: score += 25
                    if has_brand: score += 10
                    
                    # Color bonus - lower thresholds for small popups
                    if region['red'] > 0.10: score += 15
                    if region['blue'] > 0.08: score += 10
                    if region.get('size', 1) >= 4: score += 10  # Bonus for popup-sized regions
                    
                    if score >= 40:  # Lower threshold from 50
                        scam_indicators.append({
                            'score': score,
                            'text': text[:100],
                            'has_phone': has_phone,
                            'has_urgency': has_urgency,
                            'has_threat': has_threat,
                            'colors': f"R:{region['red']:.0%} B:{region['blue']:.0%}"
                        })
                except:
                    pass
            
            # If we found strong scam indicators, report it
            if scam_indicators:
                best = max(scam_indicators, key=lambda x: x['score'])
                confidence = min(best['score'], 98)
                
                # Determine the type of scam
                if best['has_phone'] and best['has_threat']:
                    reason = "Tech support scam detected - fake virus alert with phone number"
                elif best['has_threat']:
                    reason = "Fake security warning detected"
                elif best['has_phone']:
                    reason = "Suspicious phone number in alert popup"
                else:
                    reason = "Suspicious popup detected"
                
                if logger:
                    logger.info(f"Scam popup detected: {reason} (confidence: {confidence}%)")
                
                return {
                    "is_scam": True,
                    "confidence": confidence,
                    "reason": reason,
                }
            
            # Fallback: simple color detection for obvious cases
            # Use lower thresholds if we detected a center popup pattern
            if center_popup:
                red_min = 0.08
                blue_min = 0.08
            else:
                red_min = 0.15
                blue_min = 0.20
            
            if red_ratio > red_min:
                return {
                    "is_scam": True,
                    "confidence": 70 if not center_popup else 60,
                    "reason": "Red warning screen detected - likely fake security alert",
                }
            
            if blue_ratio > blue_min:
                return {
                    "is_scam": True,
                    "confidence": 65 if not center_popup else 55,
                    "reason": "Blue tech support screen detected - common scam pattern",
                }
                
        except Exception:
            pass
        
        return {"is_scam": False, "confidence": 0}


class PayGuardApp(rumps.App):
    """Professional menu bar application for PayGuard scam detection."""

    def __init__(self):
        super().__init__(ICON_PROTECTED, title=ICON_PROTECTED, quit_button=None)
        
        self._setup_logging()
        self.logger.info(f"PayGuard v{APP_VERSION} starting...")
        
        if not self._acquire_lock():
            self.logger.info("Another instance already running")
            return
        
        self.backend_online = False
        self.scans_performed = 0
        self.threats_detected = 0
        self.last_scan_time = None
        self.last_alert_time = 0  # Track last popup to prevent spam
        self.alert_cooldown = 30  # Seconds between alerts
        
        # Performance optimizations
        self.url_cache = {}  # Cache URL results: {url: (timestamp, result)}
        self.cache_ttl = 300  # 5 minutes cache TTL
        self.last_checked_url = None  # Track last URL to avoid re-checking
        self.request_session = requests.Session() if HAS_REQUESTS else None  # Reuse connections
        self.check_interval = 5  # Start with 5s, increase when idle
        
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
        try:
            time.sleep(0.5)
            self._check_backend()
            self._update_status()
            # Start browser monitoring
            monitor_thread = threading.Thread(target=self._monitor_browser_history, daemon=True)
            monitor_thread.start()
            self.logger.info("PayGuard ready - monitoring browsers silently")
        except Exception as e:
            self.logger.error(f"Setup error: {e}")
        
    def _monitor_browser_history(self):
        """Monitor browser history for suspicious URLs - runs silently in background."""
        checked_urls = set()
        last_safari_url = None
        last_chrome_url = None
        self.logger.info("Browser monitoring started silently")
        
        while True:
            try:
                # Check Safari history - ONLY MOST RECENT
                safari_history = self._get_safari_history()
                if safari_history:
                    url = safari_history[0]  # Most recent
                    if url != last_safari_url and url not in checked_urls:
                        last_safari_url = url
                        checked_urls.add(url)
                        self.logger.debug(f"New Safari URL: {url[:80]}")  # Debug level - quiet
                        self._check_url(url, source="Safari")
                        
                # Check Chrome history - ONLY MOST RECENT  
                chrome_history = self._get_chrome_history()
                if chrome_history:
                    url = chrome_history[0]  # Most recent
                    if url != last_chrome_url and url not in checked_urls:
                        last_chrome_url = url
                        checked_urls.add(url)
                        self.logger.debug(f"New Chrome URL: {url[:80]}")  # Debug level - quiet
                        self._check_url(url, source="Chrome")
                        
                # Keep set from growing too large
                if len(checked_urls) > 1000:
                    checked_urls = set(list(checked_urls)[-500:])
                    
            except Exception as e:
                self.logger.debug(f"Browser monitor error: {e}")  # Debug level
                
            time.sleep(5)  # Check every 5 seconds - better for performance
            
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
        """Check a URL for threats with caching, URL analysis, and optional HTML analysis."""
        try:
            if not self.backend_online:
                return
            
            # Skip if same as last checked URL
            if url == self.last_checked_url:
                return
            self.last_checked_url = url
            
            # Check cache first
            current_time = time.time()
            if url in self.url_cache:
                cache_time, cached_result = self.url_cache[url]
                if current_time - cache_time < self.cache_ttl:
                    # Use cached result
                    if cached_result.get('risk_level') in ['HIGH', 'MEDIUM', 'CRITICAL']:
                        self._show_url_threat_alert(url, cached_result)
                    return
            
            # Quick whitelist check (faster than API call)
            safe_domains = ['google.com', 'youtube.com', 'facebook.com', 'twitter.com', 
                          'apple.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
                          'reddit.com', 'amazon.com', 'netflix.com', 'icloud.com',
                          'linkedin.com', 'instagram.com', 'yahoo.com', 'bing.com',
                          'pearson.com', 'pearsoned.com', 'fcps.edu', 'k12.com',
                          'vercel.app', 'netlify.app', 'opencode.ai', 'canvas.instructure.com',
                          'localhost', '127.0.0.1', '0.0.0.0']
            domain = url.lower().split('/')[2] if '//' in url else url.lower()
            if any(safe in domain for safe in safe_domains):
                return
            
            self.logger.info(f"🔍 CHECKING {source} URL: {url[:80]}")
            
            # First: Quick URL-only check
            if self.request_session:
                resp = self.request_session.post(
                    f"{BACKEND_URL}/api/v1/risk?fast=true",
                    headers={"Content-Type": "application/json", "X-API-Key": "demo_key"},
                    json={"url": url},
                    timeout=2
                )
            else:
                resp = requests.post(
                    f"{BACKEND_URL}/api/v1/risk?fast=true",
                    headers={"Content-Type": "application/json", "X-API-Key": "demo_key"},
                    json={"url": url},
                    timeout=2
                )
            
            self.logger.info(f"Backend response status: {resp.status_code}")
            
            if resp.status_code == 200:
                data = resp.json()
                risk_level = data.get("risk_level", "unknown")
                trust_score = data.get("trust_score", 0)
                
                # If clearly safe or clearly dangerous, use that result
                # Otherwise, do HTML analysis for more accurate detection
                should_analyze_html = False
                
                if trust_score >= 70:
                    # Clearly safe - no need for HTML analysis
                    self.logger.info(f"✅ URL is clearly safe ({trust_score}% trust) - skipping HTML analysis")
                    self.url_cache[url] = (time.time(), data)
                    return
                elif trust_score <= 30:
                    # Clearly dangerous - alert immediately
                    self.logger.info(f"🚨 URL is clearly dangerous ({trust_score}% trust) - skipping HTML analysis")
                else:
                    # Doubtful case (30% < trust < 70%) - do HTML analysis for better detection
                    self.logger.info(f"⚠️ URL is uncertain ({trust_score}% trust) - doing HTML analysis...")
                    should_analyze_html = True
                
                # If we need HTML analysis, make a second call
                if should_analyze_html:
                    if self.request_session:
                        resp2 = self.request_session.post(
                            f"{BACKEND_URL}/api/v1/risk?fast=false",
                            headers={"Content-Type": "application/json", "X-API-Key": "demo_key"},
                            json={"url": url},
                            timeout=10
                        )
                    else:
                        resp2 = requests.post(
                            f"{BACKEND_URL}/api/v1/risk?fast=false",
                            headers={"Content-Type": "application/json", "X-API-Key": "demo_key"},
                            json={"url": url},
                            timeout=10
                        )
                    
                    if resp2.status_code == 200:
                        data = resp2.json()
                        risk_level = data.get("risk_level", "unknown")
                        trust_score = data.get("trust_score", 0)
                        self.logger.info(f"📄 HTML analysis result: {risk_level} ({trust_score}% trust)")
                
                # Cache the result
                self.url_cache[url] = (time.time(), data)
                
                # Show alert for HIGH, MEDIUM, or CRITICAL risk
                if risk_level.lower() in ["high", "medium", "critical"]:
                    self.logger.info(f"🚨 {risk_level.upper()} RISK DETECTED")
                    self._show_url_threat_alert(url, data)
                    self.threats_detected += 1
                self.scans_performed += 1
                self.last_scan_time = datetime.now()
            else:
                self.logger.error(f"Backend error: {resp.status_code}")
                    
        except Exception as e:
            self.logger.error(f"URL check error: {e}")
            
    def _show_url_threat_alert(self, url, data):
        """Show popup alert for suspicious URL - with cooldown to prevent spam."""
        try:
            # Check cooldown to prevent spam
            current_time = time.time()
            if current_time - self.last_alert_time < self.alert_cooldown:
                self.logger.info(f"Alert cooldown active, skipping popup for: {url[:60]}")
                return
            
            # Play alert sound
            self._play_alert()
            
            risk_level = data.get("risk_level", "HIGH")
            risk_factors = data.get("risk_factors", ["Suspicious website detected"])
            factors_str = "\n".join([f"• {f}" for f in risk_factors[:3]])
            
            msg = f"⚠️ THREAT DETECTED ⚠️\n\nURL: {url[:60]}...\n\nRisk Level: {risk_level}\n\nRisk Factors:\n{factors_str}\n\n⚠️ Do not enter passwords or payment info on this site!"
            
            # Show popup - run synchronously to ensure it shows
            result = subprocess.run([
                "osascript", "-e",
                f'display dialog "{msg}" with title "🚨 PAYGUARD ALERT" buttons {{"OK"}} default button "OK" with icon stop'
            ], capture_output=True, timeout=30)
            
            self.last_alert_time = current_time
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
            r = requests.post(f"{BACKEND_URL}/api/media-risk/bytes", json=payload, headers={"X-API-Key": "demo_key"}, timeout=30)
            self.logger.info(f"Backend response status: {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                self.logger.info(f"Backend data: {data}")
                
                # Check for AI-generated images
                image_fake_prob = data.get("image_fake_prob", 0)
                self.logger.info(f"AI fake probability: {image_fake_prob}%")
                if image_fake_prob and image_fake_prob >= 60:
                    return {
                        "is_scam": True,
                        "confidence": min(int(image_fake_prob), 98),
                        "reason": f"AI-generated image detected on screen ({int(image_fake_prob)}% fake probability)",
                    }
                
                scam = data.get("scam_alert", {})
                if scam.get("is_scam"):
                    return {
                        "is_scam": True,
                        "confidence": scam.get("confidence", 80),
                        "reason": scam.get("senior_message", "Threat detected"),
                    }
                # Check visual cues
                reasons = data.get("reasons", [])
                for reason in reasons:
                    if "visual scam" in reason.lower() or "red" in reason.lower():
                        return {
                            "is_scam": True,
                            "confidence": 75,
                            "reason": reason,
                        }
                return {"is_scam": False}
            else:
                self.logger.error(f"Backend error: {r.text}")
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
        
        self.logger.info(f"Captured image: {len(image_data)} bytes")
        
        result = None
        if self.backend_online:
            self.logger.info("Backend is online, scanning...")
            result = self._scan_with_backend(image_data)
            self.logger.info(f"Backend result: {result}")
        else:
            self.logger.info("Backend is offline")
        
        # Also run local detector as backup - combine results
        local_result = LocalScamDetector.analyze_image(image_data, self.logger)
        self.logger.info(f"Local result: {local_result}")
        if local_result.get("is_scam"):
            # Local detector found something - use that result
            result = local_result
        elif result is None:
            # Backend failed, use local result
            result = local_result
        
        self.scans_performed += 1
        self.last_scan_time = datetime.now()
        
        if result.get("is_scam"):
            self.threats_detected += 1
            self.title = ICON_THREAT
            self._play_alert()
            
            confidence = result.get("confidence", 80)
            reason = result.get("reason", "Suspicious content detected")
            
            # Show popup for threats - use osascript for reliability
            try:
                script = f'''display dialog "🚨 PAYGUARD SECURITY ALERT

{reason}

Confidence: {confidence}%

This may be a scam. Do NOT call any phone numbers or click any links." with title "PayGuard Alert" buttons {{"I Understand", "Get Help"}} default button "I Understand"'''
                result = subprocess.run(["osascript", "-e", script], capture_output=True, timeout=10)
                if "Get Help" in result.stderr.decode():
                    subprocess.run(["open", "https://consumer.ftc.gov/features/scam-alerts"], capture_output=True)
            except:
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
            # ALWAYS show popup for safe scans too - use osascript for reliability
            try:
                script = '''display dialog "✅ PayGuard Scan Complete

Screen scan complete.
No threats detected.
Your screen appears safe." with title "PayGuard" buttons {"Great!"} default button "Great!"'''
                subprocess.run(["osascript", "-e", script], capture_output=True, timeout=10)
            except:
                rumps.alert(
                    title="✅ PayGuard Scan Complete",
                    message="Screen scan complete.\n\nNo threats detected.\n\nYour screen appears safe.",
                    ok="Great!"
                )
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
