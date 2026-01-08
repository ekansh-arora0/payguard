#!/usr/bin/env python3
"""
PayGuard Quick Scan - User-Initiated Screen Scanner

This script captures your screen and checks it for scams.
Run this whenever you see something suspicious!

Usage:
    python3 payguard_scan.py          # Scan screen
    python3 payguard_scan.py --text   # Scan clipboard text
"""

import subprocess
import requests
import base64
import sys
import os


def notify(title: str, message: str, critical: bool = False):
    """Send macOS notification"""
    try:
        clean_title = title.replace('"', '\\"')
        clean_message = message.replace('"', '\\"')
        sound = ' sound name "Hero"' if critical else ''
        cmd = f'display notification "{clean_message}" with title "{clean_title}"{sound}'
        subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=5)
        
        if critical:
            # Show alert dialog for critical warnings
            dialog = f'display dialog "{clean_message}" with title "{clean_title}" buttons {{"OK"}} default button 1 with icon stop'
            subprocess.run(["osascript", "-e", dialog], capture_output=True, timeout=30)
    except Exception as e:
        print(f"Notification error: {e}")


def capture_screen() -> bytes:
    """Capture the current screen"""
    tmp_path = "/tmp/payguard_scan.png"
    
    try:
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
    except Exception as e:
        print(f"Screen capture error: {e}")
    
    return None


def get_clipboard_text() -> str:
    """Get text from clipboard"""
    try:
        result = subprocess.run(
            ["pbpaste"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout
    except Exception:
        return ""


def analyze_screen(img_data: bytes) -> dict:
    """Send screen to PayGuard for analysis"""
    try:
        b64_data = base64.b64encode(img_data).decode()
        
        response = requests.post(
            "http://localhost:8002/api/media-risk/bytes",
            json={
                "url": "screen://user-scan",
                "content": b64_data,
                "metadata": {"user_initiated": True, "source": "quick_scan"}
            },
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API error: {response.status_code}"}
            
    except requests.exceptions.ConnectionError:
        return {"error": "PayGuard backend not running. Start with: python3 payguard_service.py run"}
    except Exception as e:
        return {"error": str(e)}


def scan_screen():
    """Perform a screen scan"""
    print("🔍 Capturing screen...")
    img_data = capture_screen()
    
    if not img_data:
        print("❌ Failed to capture screen")
        notify("PayGuard", "Failed to capture screen")
        return
    
    print("🔍 Analyzing for threats...")
    result = analyze_screen(img_data)
    
    if "error" in result:
        print(f"❌ Error: {result['error']}")
        notify("PayGuard Error", result['error'])
        return
    
    scam_alert = result.get("scam_alert")
    media_score = result.get("media_score", 0)
    
    if scam_alert and scam_alert.get("is_scam"):
        confidence = scam_alert.get("confidence", 0)
        message = scam_alert.get("senior_message", "Potential scam detected!")
        patterns = scam_alert.get("detected_patterns", [])
        
        print(f"🚨 SCAM DETECTED (Confidence: {confidence}%)")
        print(f"   Message: {message}")
        print(f"   Patterns: {', '.join(patterns)}")
        
        notify("🚨 SCAM ALERT", message, critical=True)
        
    elif media_score > 70:
        print(f"⚠️ Suspicious content detected (Score: {media_score})")
        notify("⚠️ PayGuard Warning", f"Suspicious content detected (Risk: {media_score}%)")
        
    else:
        print(f"✅ Screen appears safe (Risk score: {media_score})")
        notify("✅ PayGuard", "Screen scan complete - No threats detected")


def scan_clipboard():
    """Scan clipboard text for scam content"""
    print("🔍 Reading clipboard...")
    text = get_clipboard_text()
    
    if not text:
        print("❌ Clipboard is empty")
        notify("PayGuard", "Clipboard is empty")
        return
    
    print(f"🔍 Analyzing {len(text)} characters...")
    
    # Simple local pattern check
    import re
    
    scam_patterns = [
        (r'\b1-\d{3}-\d{3}-\d{4}\b', 'phone_number', 'Suspicious phone number'),
        (r'(?i)\b(urgent|immediate|act now|call now)\b', 'urgency', 'Urgency language'),
        (r'(?i)\b(virus|infected|malware|trojan)\b', 'virus_warning', 'Virus/malware warning'),
        (r'(?i)\b(microsoft|apple|amazon|google).*(support|security|alert)\b', 'fake_company', 'Fake company reference'),
        (r'(?i)do not (close|restart|shut down)', 'scare_tactic', 'Scare tactic'),
    ]
    
    detected = []
    for pattern, name, desc in scam_patterns:
        if re.search(pattern, text):
            detected.append(desc)
    
    if detected:
        print(f"🚨 SCAM INDICATORS FOUND:")
        for d in detected:
            print(f"   • {d}")
        notify("🚨 SCAM ALERT", f"Clipboard contains scam indicators: {', '.join(detected)}", critical=True)
    else:
        print("✅ No obvious scam patterns detected")
        notify("✅ PayGuard", "Clipboard scan complete - No threats detected")


def main():
    print("🛡️ PayGuard Quick Scan")
    print("=" * 40)
    
    if "--text" in sys.argv or "-t" in sys.argv:
        scan_clipboard()
    else:
        scan_screen()


if __name__ == "__main__":
    main()
