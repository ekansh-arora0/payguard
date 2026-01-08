#!/usr/bin/env python3
"""
PayGuard Menu Bar App - Privacy-First Version

PRIVACY NOTICE: This version has been redesigned with privacy-first principles:
- NO continuous screen capture
- NO background clipboard monitoring  
- All scans require explicit user action (button click, menu selection, or keyboard shortcut)
- User data stays on device unless explicitly approved
"""

import subprocess
import time
import os
import re
from PIL import Image
import io

class PayGuardMenuBar:
    """
    PayGuard Menu Bar Application - Privacy-First Design
    
    All monitoring capabilities require explicit user action.
    No background capture or clipboard snooping.
    """
    
    def __init__(self):
        self.running = True
        self.last_alert_time = 0
        self.alert_cooldown = 10  # 10 seconds between alerts
        self.scam_count = 0
        
    def notify_user(self, title, message, critical=True):
        """Send notification with sound"""
        try:
            clean_title = title.replace('"', '\\"')
            clean_message = message.replace('"', '\\"')
            
            if critical:
                # Play alert sound
                subprocess.run(["afplay", "/System/Library/Sounds/Sosumi.aiff"], capture_output=True)
                
                # Show notification
                cmd = f'display notification "{clean_message}" with title "{clean_title}" sound name "Hero"'
                subprocess.run(["osascript", "-e", cmd], capture_output=True)
                
                # Show dialog
                dialog_cmd = f'display dialog "{clean_message}\\n\\nThis is PayGuard protecting you from scams!" with title "{clean_title}" buttons {{"OK", "More Info"}} default button "OK" with icon stop giving up after 30'
                result = subprocess.run(["osascript", "-e", dialog_cmd], capture_output=True, text=True)
                
                if "More Info" in result.stdout:
                    info_msg = "PayGuard detected suspicious content that looks like a scam. Common scam tactics include:\\n\\n• Fake virus warnings\\n• Urgent security alerts\\n• Requests to call phone numbers\\n• Fake company support messages\\n\\nNEVER call random phone numbers or download software from pop-ups!"
                    info_cmd = f'display dialog "{info_msg}" with title "PayGuard - Scam Information" buttons {{"OK"}} default button "OK" with icon caution'
                    subprocess.run(["osascript", "-e", info_cmd], capture_output=True)
                
                self.scam_count += 1
                print(f"🚨 SCAM #{self.scam_count} BLOCKED: {title}")
            else:
                cmd = f'display notification "{clean_message}" with title "{clean_title}"'
                subprocess.run(["osascript", "-e", cmd], capture_output=True)
                
        except Exception as e:
            print(f"Notification error: {e}")
    
    def update_menu_bar(self):
        """Update menu bar status"""
        try:
            status = f"🛡️ PayGuard Active - {self.scam_count} scams blocked"
            # This would require a proper menu bar app framework
            # For now, we'll just print status
            print(f"Status: {status}")
        except:
            pass
    
    def capture_screen(self):
        """
        Capture screen - USER-INITIATED ONLY
        
        This method should only be called in response to explicit user action
        (button click, menu selection, or keyboard shortcut).
        
        Returns:
            bytes: Screen capture data, or None if capture failed
        """
        try:
            tmp_path = "/tmp/payguard_screen.png"
            result = subprocess.run(
                ["screencapture", "-x", "-C", tmp_path], 
                capture_output=True, 
                timeout=3
            )
            
            if result.returncode == 0 and os.path.exists(tmp_path):
                with open(tmp_path, "rb") as f:
                    data = f.read()
                os.remove(tmp_path)
                return data
        except:
            pass
        return None
    
    def analyze_screen(self, image_data):
        """
        Analyze screen for scams - USER-INITIATED ONLY
        
        This method analyzes screen content for potential scam indicators.
        Should only be called after user explicitly requests a scan.
        
        Args:
            image_data: Screen capture bytes from capture_screen()
            
        Returns:
            dict: Detection result with is_scam, confidence, type, message, advice
        """
        try:
            img = Image.open(io.BytesIO(image_data))
            
            # Check for suspicious colors
            colors = img.getcolors(maxcolors=256*256*256)
            if colors:
                total_pixels = sum(count for count, color in colors)
                red_pixels = orange_pixels = yellow_pixels = 0
                
                for count, color in colors:
                    if isinstance(color, tuple) and len(color) >= 3:
                        r, g, b = color[:3]
                        
                        # Red (common in scam alerts)
                        if r > 180 and g < 100 and b < 100:
                            red_pixels += count
                        # Orange (warning colors)
                        elif r > 200 and 100 < g < 180 and b < 100:
                            orange_pixels += count
                        # Yellow (attention grabbing)
                        elif r > 200 and g > 200 and b < 100:
                            yellow_pixels += count
                
                red_ratio = red_pixels / total_pixels
                orange_ratio = orange_pixels / total_pixels
                yellow_ratio = yellow_pixels / total_pixels
                
                # High red content = likely scam alert
                if red_ratio > 0.25:
                    return {
                        'is_scam': True,
                        'confidence': min(85 + (red_ratio * 15), 100),
                        'type': 'visual_red_alert',
                        'message': 'FAKE SECURITY ALERT DETECTED!',
                        'advice': 'This red warning screen is FAKE. Close it immediately!'
                    }
                
                # Orange/yellow warnings
                elif orange_ratio > 0.15 or yellow_ratio > 0.15:
                    return {
                        'is_scam': True,
                        'confidence': 70,
                        'type': 'visual_warning',
                        'message': 'Suspicious warning screen detected!',
                        'advice': 'Be careful - this looks like a fake warning.'
                    }
            
        except Exception as e:
            print(f"Screen analysis error: {e}")
        
        return {'is_scam': False}
    
    def analyze_text(self, text):
        """
        Analyze text for scam content - USER-INITIATED ONLY
        
        This method analyzes provided text for potential scam indicators.
        Should only be called after user explicitly requests a scan.
        
        Args:
            text: Text content to analyze
            
        Returns:
            dict: Detection result with is_scam, confidence, patterns, message, advice
        """
        if not text or len(text) < 10:  # Skip very short text
            return {'is_scam': False}
        
        # Scam patterns with weights
        patterns = [
            (r'\b1-\d{3}-\d{3}-\d{4}\b', 30, 'phone_number'),
            (r'(?i)\b(urgent|immediate|act now|call now)\b', 25, 'urgency'),
            (r'(?i)\b(virus|infected|malware|trojan)\b', 30, 'virus_warning'),
            (r'(?i)\b(microsoft|apple|amazon|google).*(support|security|alert)\b', 25, 'fake_company'),
            (r'(?i)do not (close|restart|shut down)', 30, 'scare_tactic'),
            (r'(?i)\b(suspended|blocked|expired|compromised)\b', 20, 'account_threat'),
            (r'(?i)\b(verify|update|confirm).*(account|payment|card)\b', 20, 'phishing'),
            (r'(?i)\b(error code|reference id):\s*[a-z0-9-]+', 15, 'fake_error'),
        ]
        
        score = 0
        detected = []
        
        for pattern, weight, name in patterns:
            if re.search(pattern, text):
                score += weight
                detected.append(name)
        
        if score >= 40:  # Threshold for scam detection
            return {
                'is_scam': True,
                'confidence': min(score, 100),
                'patterns': detected,
                'message': 'SCAM CONTENT DETECTED!',
                'advice': 'This text contains suspicious scam content. Do not follow any instructions from this text!'
            }
        
        return {'is_scam': False}
    
    def scan_screen_now(self):
        """
        User-initiated screen scan
        
        Call this method when user explicitly requests a screen scan
        (e.g., clicks "Scan Now" button or uses keyboard shortcut).
        
        Returns:
            dict: Detection result
        """
        print("🔍 User-initiated screen scan...")
        image_data = self.capture_screen()
        if image_data:
            result = self.analyze_screen(image_data)
            if result.get('is_scam'):
                current_time = time.time()
                if current_time - self.last_alert_time > self.alert_cooldown:
                    self.notify_user(
                        "🚨 PayGuard Visual Alert",
                        result.get('message', 'Scam detected on screen!'),
                        critical=True
                    )
                    self.last_alert_time = current_time
            return result
        return {'is_scam': False, 'error': 'Failed to capture screen'}
    
    def scan_text_now(self, text):
        """
        User-initiated text scan
        
        Call this method when user explicitly requests a text scan
        (e.g., pastes text and clicks "Scan" button).
        
        Args:
            text: Text content to analyze
            
        Returns:
            dict: Detection result
        """
        print("🔍 User-initiated text scan...")
        result = self.analyze_text(text)
        if result.get('is_scam'):
            current_time = time.time()
            if current_time - self.last_alert_time > self.alert_cooldown:
                self.notify_user(
                    "🚨 PayGuard Text Alert",
                    result.get('message', 'Scam content detected!'),
                    critical=True
                )
                self.last_alert_time = current_time
        return result
    
    def start(self):
        """
        Start PayGuard in user-initiated mode
        
        PayGuard now operates in a privacy-first mode where all scans
        require explicit user action. No background monitoring.
        """
        print("🛡️ PAYGUARD MENU BAR - PRIVACY-FIRST MODE")
        print("=" * 50)
        
        # Send startup notification
        self.notify_user(
            "🛡️ PayGuard Active",
            "PayGuard is ready. Use 'Scan Now' to check for scams.",
            critical=False
        )
        
        print("✅ PayGuard is now running in privacy-first mode!")
        print("")
        print("🔒 PRIVACY FEATURES:")
        print("   • NO continuous screen capture")
        print("   • NO background clipboard monitoring")
        print("   • All scans require YOUR explicit action")
        print("")
        print("📱 AVAILABLE COMMANDS:")
        print("   • scan_screen_now() - Scan current screen")
        print("   • scan_text_now(text) - Scan provided text")
        print("")
        print("Press Ctrl+C to stop PayGuard")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping PayGuard...")
            self.running = False
            self.notify_user(
                "PayGuard Stopped",
                "Scam protection has been disabled.",
                critical=False
            )
            print("✅ PayGuard stopped")

def main():
    """Main function"""
    payguard = PayGuardMenuBar()
    payguard.start()

if __name__ == "__main__":
    main()