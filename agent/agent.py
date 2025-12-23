import subprocess
import time
import threading
import json
import urllib.parse
import http.client
import urllib.request
import os
import base64
from datetime import datetime

class Agent:
    def __init__(self, server_host="localhost", server_port=8002):
        self.server_host = server_host
        self.server_port = server_port
        self.stop_flag = False
        self.last_alert_time = 0
        self.alert_cooldown = 10
        self.check_interval = 0.6
        self._backend_down_until = 0.0
        self._retry_backoff = 0.0
        
        # Ensure screenshot directory exists
        os.makedirs("./data/agent/screenshots", exist_ok=True)
        
        # Cache for clipboard to avoid re-processing same content
        self.last_clipboard_content = None
        self.last_screen_hash = None
        self._static_counter = 0
        self._last_change_ts = 0.0

    def start(self):
        print("""
    🛡️  PAYGUARD ACTIVE
    ==================
    Monitoring Screen & Clipboard
    Protecting your device...
        """)
        print(f"Connecting to backend at http://{self.server_host}:{self.server_port}")
        
        # Notify user that PayGuard is active
        self._notify_native("🛡️ PayGuard Active", "Your device is now being protected from scams and AI fakes.", is_critical=False)
        
        # Start threads
        t_screen = threading.Thread(target=self._monitor_screen, daemon=True)
        t_clipboard = threading.Thread(target=self._monitor_clipboard, daemon=True)
        
        t_screen.start()
        t_clipboard.start()
        
        try:
            while not self.stop_flag:
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("\n🛑 Stopping PayGuard Agent...")
            self.stop_flag = True

    def _monitor_screen(self):
        """Continuously capture screen and check for scams"""
        print("   [Screen Monitor] Active")
        while not self.stop_flag:
            try:
                # 1. Capture Screen
                screenshot_bytes = self._capture_screen()
                if screenshot_bytes:
                    import hashlib
                    h = hashlib.md5(screenshot_bytes).hexdigest()
                    if h == self.last_screen_hash:
                        time.sleep(self.check_interval)
                        self._static_counter += 1
                    else:
                        self.last_screen_hash = h
                        self._static_counter = 0
                        self._last_change_ts = time.time()
                    # 2. Send to Backend
                    is_static = (self._static_counter >= 3) and ((time.time() - self._last_change_ts) >= 1.5)
                    is_static = (self._static_counter >= 2) and ((time.time() - self._last_change_ts) >= 1.2)
                    self._check_media_bytes(screenshot_bytes, source="screen", static=is_static)
            except Exception as e:
                print(f"Error in screen monitor: {e}")
            
            time.sleep(self.check_interval)

    def _monitor_clipboard(self):
        """Monitor clipboard for images"""
        print("   [Clipboard Monitor] Active")
        while not self.stop_flag:
            try:
                # 1. Get Clipboard Content (Image)
                # We use osascript to check if clipboard has image data
                # This is a bit tricky in pure python without heavy libs, 
                # so we'll try to use swift or applescript to get data if possible,
                # or just rely on the user copying an image file.
                # For now, let's try to read image data from clipboard using pbpaste if it's text,
                # but for images we might need a helper.
                
                # Simplified: Check if clipboard has a URL that looks like an image, or base64
                # For actual image data in clipboard, we can use a temporary file approach with osascript
                
                img_bytes = self._get_clipboard_image()
                if img_bytes:
                    # Hash it to avoid spamming
                    h = hash(img_bytes)
                    if h != self.last_clipboard_content:
                        self.last_clipboard_content = h
                        print("   [Clipboard] New image detected, checking...")
                        self._check_media_bytes(img_bytes, source="clipboard", static=True)
                
            except Exception as e:
                print(f"Error in clipboard monitor: {e}")
            
            time.sleep(2.0)

    def _capture_screen(self):
        """Capture screen to memory using screencapture"""
        try:
            # Capture to stdout (-c is clipboard, -x is no sound, -C is cursor)
            # We want bytes. screencapture -x -c is clipboard. 
            # screencapture -x /tmp/file is file.
            # Let's use a temp file for reliability.
            tmp_path = "/tmp/payguard_agent_screen.png"
            subprocess.run(["screencapture", "-x", "-C", tmp_path], check=True, capture_output=True)
            
            if os.path.exists(tmp_path):
                with open(tmp_path, "rb") as f:
                    data = f.read()
                return self._prepare_image(data)
            return None
        except Exception:
            return None

    def _get_clipboard_image(self):
        """Try to get image from clipboard"""
        try:
            # Use AppleScript to save clipboard to file if it's an image
            tmp_path = "/tmp/payguard_agent_clip.png"
            # Clean up previous
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
                
            script = '''
            try
                set theData to the clipboard as «class PNGf»
                set theFile to open for access POSIX file "/tmp/payguard_agent_clip.png" with write permission
                set eof of theFile to 0
                write theData to theFile
                close access theFile
                return "OK"
            on error
                return "NO_IMAGE"
            end try
            '''
            r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
            if "OK" in r.stdout and os.path.exists(tmp_path):
                with open(tmp_path, "rb") as f:
                    data = f.read()
                return self._prepare_image(data)
            return None
        except Exception:
            return None

    def _check_media_bytes(self, image_bytes, source="screen", static=False):
        """Send bytes to backend for analysis"""
        try:
            if time.time() < self._backend_down_until:
                return
            # Encode to base64
            b64_data = base64.b64encode(image_bytes).decode('utf-8')
            
            payload = json.dumps({
                "url": f"local://{source}",
                "content": b64_data,
                "metadata": {"static": bool(static), "source": source}
            })
            
            conn = http.client.HTTPConnection(self.server_host, self.server_port, timeout=15)
            conn.request("POST", "/api/media-risk/bytes", body=payload, headers={
                "Content-Type": "application/json"
            })
            
            resp = conn.getresponse()
            # print(f"DEBUG: Backend response {resp.status}")
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                # print(f"DEBUG: Data: {json.dumps(data)}")
                self._handle_risk_response(data, source)
                self._retry_backoff = 0.0
                self._backend_down_until = 0.0
            else:
                print(f"DEBUG: Backend returned {resp.status}")
            conn.close()
        except Exception as e:
            if self._retry_backoff == 0.0:
                self._retry_backoff = 2.0
            else:
                self._retry_backoff = min(self._retry_backoff * 2.0, 20.0)
            self._backend_down_until = time.time() + self._retry_backoff
            pass

    def _compress_to_jpeg(self, image_bytes):
        """Compress image to JPEG for faster transmission, and resize if too large"""
        try:
            from PIL import Image
            import io
            img = Image.open(io.BytesIO(image_bytes))
            
            # Speed optimization: Downscale high-res screens
            # AI model works on smaller patches anyway, and OCR is fine with 1080p
            max_w = 1920
            if img.width > max_w:
                ratio = max_w / img.width
                img = img.resize((max_w, int(img.height * ratio)), Image.Resampling.LANCZOS)
            
            out = io.BytesIO()
            img.convert('RGB').save(out, format='JPEG', quality=65) # Lower quality = faster
            return out.getvalue()
        except Exception:
            return image_bytes

    def _prepare_image(self, image_bytes):
        try:
            from PIL import Image
            import io
            bio = io.BytesIO(image_bytes)
            img = Image.open(bio).convert('RGB')
            w, h = img.size
            max_dim = 1600
            if max(w, h) > max_dim:
                s = float(max_dim) / float(max(w, h))
                img = img.resize((int(w * s), int(h * s)))
            out = io.BytesIO()
            img.save(out, format='JPEG', quality=80)
            return out.getvalue()
        except Exception:
            return self._compress_to_jpeg(image_bytes)

    def _handle_risk_response(self, data, source):
        """Process the risk analysis result"""
        risk_color = data.get("media_color", "low")
        score = data.get("media_score", 0)
        reasons = data.get("reasons", [])
        scam_alert = data.get("scam_alert")
        
        # Log for debugging (will show in terminal)
        if scam_alert and scam_alert.get("is_scam"):
            print(f"   [Analysis] {source.capitalize()} check: 🚨 SCAM FOUND (Conf: {scam_alert.get('confidence')}%)")
        else:
            # Only print if there's at least some risk score to avoid spamming
            if score > 5: # Lowered from 20 to 5 to see more activity
                print(f"   [Analysis] {source.capitalize()} check: Clean (Score: {score}%)")
        
        # 1. Handle Scam Alerts (Highest Priority)
        if scam_alert and scam_alert.get("is_scam"):
            self._trigger_scam_alert(scam_alert)
            return

        # 2. Handle AI Images
        is_ai_image = any("AI-generated" in r for r in reasons)
        if is_ai_image:
            if time.time() - self.last_alert_time < 5.0:
                return
                
            title = "⚠️ Fake AI Image Detected"
            msg = "Warning: This image appears to be generated by AI (Artificial Intelligence)."
            guidance = "AI-generated images are often used by scammers to create fake identities or documents. Do NOT provide any personal information or money to anyone associated with this image."
            
            if source == "clipboard":
                title = "⚠️ Fake Image in Clipboard"
            
            print(f"   [Analysis] {title}: {msg}")
            # Use modal with guidance for AI images to ensure user sees it
            self._notify_modal_with_guidance(title, msg, guidance)
            self.last_alert_time = time.time()
            return

    def _trigger_scam_alert(self, scam_data):
        """Show a specific native notification based on the scam type"""
        if time.time() - self.last_alert_time < 3.0:
            return
            
        confidence = scam_data.get("confidence", 0)
        patterns = scam_data.get("detected_patterns", [])
        senior_msg = scam_data.get("senior_message", "Scam Detected!")
        advice = scam_data.get("action_advice", "Close the window immediately.")
        
        # Determine specific title and icon based on pattern
        title = "🛡️ PayGuard Security Alert"
        if "phone_number" in patterns:
            title = "📞 Fake Support Number"
        elif "virus_warning" in patterns or "scare_tactics" in patterns:
            title = "⚠️ Fake Virus Warning"
        elif "phishing_attempt" in patterns:
            title = "🎣 Phishing Attempt"
        elif "suspicious_email" in str(patterns):
            title = "📧 Fake Email Address"
        elif "payment_request" in patterns:
            title = "💰 Payment Scam"

        full_msg = f"{senior_msg}\n{advice}"
        
        self._notify_native(title, full_msg, is_critical=True)
        self.last_alert_time = time.time()

    def _notify_native(self, title, message, is_critical=False):
        """Send a standard macOS notification"""
        try:
            # Escape quotes
            title = title.replace('"', '\\"')
            message = message.replace('"', '\\"')
            
            sound = 'sound name "Hero"' if is_critical else ''
            
            cmd = f'display notification "{message}" with title "{title}" {sound}'
            subprocess.run(["osascript", "-e", cmd], capture_output=True, text=True)
        except Exception:
            pass

    def _notify_modal(self, title, message):
        """Show a modal dialog (Script Editor style)"""
        try:
            # Escape quotes
            title = title.replace('"', '\\"')
            message = message.replace('"', '\\"')
            
            # Icon note: 'stop' or 'caution'
            subprocess.run(["osascript", "-e", 'beep 2'], capture_output=True, text=True)
            script = f'display dialog "{message}" with title "{title}" buttons {{"OK"}} default button 1 with icon stop giving up after 30'
            subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
        except Exception:
            # Fallback to native notification
            self._notify_native(title, message, is_critical=True)

    def _notify_modal_with_guidance(self, title, message, guidance):
        try:
            title = title.replace('"', '\\"')
            message = message.replace('"', '\\"')
            guidance = guidance.replace('"', '\\"')
            subprocess.run(["osascript", "-e", 'beep 2'], capture_output=True, text=True)
            script = f'display dialog "{message}" with title "{title}" buttons {{"What can I do?","OK"}} default button "OK" with icon stop giving up after 30'
            r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
            out = (r.stdout or "")
            if "button returned:What can I do?" in out:
                script2 = f'display dialog "{guidance}" with title "{title}" buttons {{"OK"}} default button "OK" with icon caution giving up after 60'
                subprocess.run(["osascript", "-e", script2], capture_output=True, text=True)
        except Exception:
            self._notify_native(title, guidance, is_critical=True)

if __name__ == "__main__":
    Agent().start()
