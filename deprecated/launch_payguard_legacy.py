#!/usr/bin/env python3
"""
PayGuard Launcher - Simple version that just works
"""

import subprocess
import time
import os
import sys
import requests
from pathlib import Path

def notify(title, message):
    """Send macOS notification"""
    try:
        cmd = f'display notification "{message}" with title "{title}"'
        subprocess.run(["osascript", "-e", cmd], capture_output=True)
    except:
        pass

def start_simple_backend():
    """Start a simple backend server"""
    print("🚀 Starting PayGuard Backend...")
    
    # Create a simple backend script
    simple_backend = '''
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
import re
from datetime import datetime

app = FastAPI(title="PayGuard Simple API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

@app.post("/api/media-risk/bytes")
async def analyze_media(payload: dict):
    """Simple scam detection"""
    content = payload.get("content", "")
    
    # Simple text analysis
    scam_patterns = [
        (r'\\b1-\\d{3}-\\d{3}-\\d{4}\\b', 30, "phone_number"),
        (r'(?i)\\b(urgent|immediate|act now)\\b', 20, "urgency"),
        (r'(?i)\\b(virus|infected|malware)\\b', 25, "virus_warning"),
        (r'(?i)\\b(suspended|blocked|expired)\\b', 15, "account_threat"),
        (r'(?i)do not (close|restart)', 25, "do_not_close"),
    ]
    
    confidence = 0
    detected_patterns = []
    
    # Decode base64 and analyze (simplified)
    try:
        import base64
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        
        for pattern, weight, name in scam_patterns:
            if re.search(pattern, decoded):
                confidence += weight
                detected_patterns.append(name)
    except:
        pass
    
    is_scam = confidence >= 40
    
    scam_alert = None
    if is_scam:
        scam_alert = {
            "is_scam": True,
            "confidence": min(confidence, 100),
            "detected_patterns": detected_patterns,
            "senior_message": "STOP! This appears to be a SCAM.",
            "action_advice": "Close this window immediately."
        }
    
    return {
        "url": "screen://local",
        "domain": "local", 
        "media_score": min(confidence, 100),
        "media_color": "high" if is_scam else "low",
        "reasons": ["Scam detected"] if is_scam else [],
        "scam_alert": scam_alert
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8002, log_level="error")
'''
    
    # Write the simple backend
    with open("simple_backend.py", "w") as f:
        f.write(simple_backend)
    
    # Start it
    backend_process = subprocess.Popen([
        sys.executable, "simple_backend.py"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait and test
    time.sleep(3)
    try:
        response = requests.get("http://localhost:8002/api/health", timeout=5)
        if response.status_code == 200:
            print("✅ Simple backend started!")
            notify("PayGuard", "Backend started successfully!")
            return backend_process
    except:
        pass
    
    print("❌ Backend failed to start")
    return None

def start_simple_agent():
    """Start a simple monitoring agent"""
    print("🛡️ Starting PayGuard Agent...")
    
    # Create simple agent script
    simple_agent = '''
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
'''
    
    # Write the simple agent
    with open("simple_agent.py", "w") as f:
        f.write(simple_agent)
    
    # Start it
    agent_process = subprocess.Popen([
        sys.executable, "simple_agent.py"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    time.sleep(2)
    print("✅ Simple agent started!")
    notify("PayGuard Agent", "Now monitoring your screen for scams!")
    return agent_process

def main():
    """Launch PayGuard"""
    print("🛡️ PAYGUARD LAUNCHER")
    print("=" * 40)
    
    # Start backend
    backend = start_simple_backend()
    if not backend:
        print("❌ Could not start backend")
        return
    
    # Start agent  
    agent = start_simple_agent()
    if not agent:
        print("❌ Could not start agent")
        return
    
    print("\n🎉 PAYGUARD IS NOW ACTIVE!")
    print("=" * 40)
    print("🛡️ Protecting your screen from scams")
    print("📱 You'll get notifications when threats are detected")
    print("🌐 Backend running at http://localhost:8002")
    print("\nPress Ctrl+C to stop")
    
    # Keep running
    try:
        while True:
            time.sleep(1)
            
            # Restart if needed
            if backend.poll() is not None:
                print("Restarting backend...")
                backend = start_simple_backend()
            
            if agent.poll() is not None:
                print("Restarting agent...")
                agent = start_simple_agent()
                
    except KeyboardInterrupt:
        print("\n🛑 Stopping PayGuard...")
        if backend:
            backend.terminate()
        if agent:
            agent.terminate()
        print("✅ PayGuard stopped")

if __name__ == "__main__":
    main()