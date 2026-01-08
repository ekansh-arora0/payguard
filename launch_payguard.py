#!/usr/bin/env python3
"""
PayGuard Launcher - Privacy-First Version

PRIVACY NOTICE: This launcher starts PayGuard in privacy-first mode:
- NO continuous screen capture
- NO background clipboard monitoring
- All scans require explicit user action
- User data stays on device unless explicitly approved

This launcher provides a simple way to start the PayGuard backend and UI.
"""

import subprocess
import time
import os
import sys
import requests
from pathlib import Path


def notify(title: str, message: str):
    """Send macOS notification"""
    try:
        clean_title = title.replace('"', '\\"')
        clean_message = message.replace('"', '\\"')
        cmd = f'display notification "{clean_message}" with title "{clean_title}"'
        subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=5)
    except Exception:
        pass


def start_backend() -> subprocess.Popen:
    """
    Start the PayGuard backend server.
    
    Returns:
        Backend process handle
    """
    print("🚀 Starting PayGuard Backend...")
    
    # Check if uvicorn is available
    try:
        import uvicorn
    except ImportError:
        print("Installing uvicorn...")
        subprocess.run([sys.executable, "-m", "pip", "install", "uvicorn", "fastapi"], 
                      capture_output=True)
    
    # Start the backend
    backend_path = Path(__file__).parent / "backend" / "server.py"
    
    if backend_path.exists():
        backend_process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.server:app", 
             "--host", "127.0.0.1", "--port", "8002", "--log-level", "warning"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(Path(__file__).parent)
        )
    else:
        # Use simple backend as fallback
        backend_process = subprocess.Popen(
            [sys.executable, "simple_backend.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    
    # Wait for backend to start
    time.sleep(3)
    
    # Verify backend is running
    try:
        response = requests.get("http://localhost:8002/api/health", timeout=5)
        if response.status_code == 200:
            print("✅ Backend started successfully!")
            notify("PayGuard", "Backend started successfully!")
            return backend_process
    except Exception:
        pass
    
    print("⚠️ Backend may not be fully ready, continuing...")
    return backend_process


def start_interactive_mode():
    """
    Start PayGuard in interactive (privacy-first) mode.
    
    In this mode, all scans require explicit user action.
    """
    print("""
🛡️ PAYGUARD - PRIVACY-FIRST MODE
================================

PayGuard is now ready in privacy-first mode.
All scans require your explicit action - NO background monitoring.

Commands:
  s - Scan screen now
  t - Scan text (enter text after)
  i - Show statistics
  q - Quit

Press Enter to start...
    """)
    
    input()
    
    # Import and use PayGuardLive
    try:
        from payguard_live import PayGuardLive
        guard = PayGuardLive()
        guard.start_interactive()
    except ImportError:
        print("Using basic interactive mode...")
        _basic_interactive_mode()


def _basic_interactive_mode():
    """Basic interactive mode without full PayGuardLive"""
    import base64
    
    def capture_screen():
        try:
            tmp_path = "/tmp/payguard_screen.png"
            subprocess.run(["screencapture", "-x", "-C", tmp_path], 
                          check=True, capture_output=True, timeout=5)
            
            if os.path.exists(tmp_path):
                with open(tmp_path, "rb") as f:
                    data = f.read()
                os.remove(tmp_path)
                return data
        except Exception:
            pass
        return None
    
    def analyze_screen(img_data: bytes):
        try:
            b64_data = base64.b64encode(img_data).decode()
            
            payload = {
                "url": "screen://local",
                "content": b64_data,
                "metadata": {"user_initiated": True}
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
                    message = scam_alert.get("senior_message", "Scam detected!")
                    print(f"🚨 SCAM DETECTED: {message}")
                    notify("🚨 PAYGUARD ALERT", message)
                    
                    dialog_cmd = f'display dialog "{message}" with title "PayGuard Alert" buttons {{"OK"}} default button 1 with icon stop'
                    subprocess.run(["osascript", "-e", dialog_cmd], capture_output=True, timeout=30)
                else:
                    print("✅ Screen appears safe")
        except Exception as e:
            print(f"Analysis error: {e}")
    
    print("🛡️ PayGuard Interactive Mode - Ready")
    notify("PayGuard", "Ready for user-initiated scans")
    
    while True:
        try:
            cmd = input("\nPayGuard> ").strip().lower()
            
            if cmd == 'q':
                print("🛑 PayGuard stopped.")
                break
            elif cmd == 's':
                print("🔍 Scanning screen...")
                img_data = capture_screen()
                if img_data:
                    analyze_screen(img_data)
                else:
                    print("❌ Failed to capture screen")
            else:
                print("Commands: s=scan, q=quit")
                
        except KeyboardInterrupt:
            print("\n🛑 PayGuard stopped.")
            break
        except EOFError:
            break


def main():
    """
    Launch PayGuard in privacy-first mode.
    """
    print("🛡️ PAYGUARD LAUNCHER - Privacy-First")
    print("=" * 40)
    
    # Start backend
    backend = start_backend()
    
    print("\n🎉 PAYGUARD IS NOW READY!")
    print("=" * 40)
    print("🛡️ Privacy-first mode: All scans require user action")
    print("📱 You'll get notifications when threats are detected")
    print("🌐 Backend running at http://localhost:8002")
    
    # Start interactive mode
    try:
        start_interactive_mode()
    except KeyboardInterrupt:
        print("\n🛑 Stopping PayGuard...")
    finally:
        if backend:
            backend.terminate()
        print("✅ PayGuard stopped")


if __name__ == "__main__":
    main()
