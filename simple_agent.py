
import subprocess
import time
import base64
import json
import requests
from PIL import Image
import io
import os

def notify(title, message):
    try:
        cmd = f'display notification "{message}" with title "{title}" sound name "Hero"'
        subprocess.run(["osascript", "-e", cmd], capture_output=True)
    except:
        pass

def capture_screen():
    try:
        tmp_path = "/tmp/payguard_screen.png"
        subprocess.run(["screencapture", "-x", "-C", tmp_path], check=True, capture_output=True)
        
        if os.path.exists(tmp_path):
            with open(tmp_path, "rb") as f:
                data = f.read()
            os.remove(tmp_path)
            return data
    except:
        pass
    return None

def analyze_screen():
    img_data = capture_screen()
    if not img_data:
        return
    
    try:
        b64_data = base64.b64encode(img_data).decode()
        
        payload = {
            "url": "screen://local",
            "content": b64_data,
            "metadata": {"static": False}
        }
        
        response = requests.post(
            "http://localhost:8002/api/media-risk/bytes",
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            scam_alert = data.get("scam_alert")
            
            if scam_alert and scam_alert.get("is_scam"):
                title = "🚨 PAYGUARD SCAM ALERT"
                message = scam_alert.get("senior_message", "Scam detected!")
                notify(title, message)
                print(f"SCAM DETECTED: {message}")
                
                # Show dialog
                try:
                    dialog_cmd = f'display dialog "{message}" with title "{title}" buttons {{"OK"}} default button 1 with icon stop'
                    subprocess.run(["osascript", "-e", dialog_cmd], capture_output=True)
                except:
                    pass
    except Exception as e:
        print(f"Analysis error: {e}")

print("🛡️ PayGuard Agent Active - Monitoring your screen...")
notify("PayGuard Agent", "Now protecting your device from scams!")

while True:
    try:
        analyze_screen()
        time.sleep(2)  # Check every 2 seconds
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"Agent error: {e}")
        time.sleep(5)
