#!/usr/bin/env python3
"""
PayGuard Background Service - Privacy-First

This service runs PayGuard as a background process with:
- Backend API server for threat detection
- Menu bar status indicator
- User-initiated scan support via hotkey or menu

PRIVACY: No background monitoring. All scans require user action.
"""

import subprocess
import time
import os
import sys
import signal
import logging
from pathlib import Path
from datetime import datetime

# Setup logging
LOG_DIR = Path.home() / "Library" / "Logs" / "PayGuard"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "payguard.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class PayGuardService:
    """
    PayGuard Background Service
    
    Manages the PayGuard backend and provides system integration.
    """
    
    def __init__(self):
        self.backend_process = None
        self.running = False
        self.payguard_dir = Path(__file__).parent
        self.start_time = None
        
    def notify(self, title: str, message: str, sound: bool = False):
        """Send macOS notification"""
        try:
            clean_title = title.replace('"', '\\"')
            clean_message = message.replace('"', '\\"')
            sound_str = ' sound name "Hero"' if sound else ''
            cmd = f'display notification "{clean_message}" with title "{clean_title}"{sound_str}'
            subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=5)
        except Exception as e:
            logger.error(f"Notification error: {e}")
    
    def start_backend(self) -> bool:
        """Start the PayGuard backend server"""
        logger.info("Starting PayGuard backend...")
        
        try:
            # Start uvicorn with the backend server
            self.backend_process = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "backend.server:app",
                 "--host", "127.0.0.1", "--port", "8002", "--log-level", "warning"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.payguard_dir)
            )
            
            # Wait for backend to be ready
            for i in range(30):  # 30 second timeout
                time.sleep(1)
                try:
                    import requests
                    response = requests.get("http://localhost:8002/api/health", timeout=2)
                    if response.status_code == 200:
                        logger.info("Backend started successfully on port 8002")
                        return True
                except Exception:
                    pass
            
            logger.warning("Backend may not be fully ready")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start backend: {e}")
            return False
    
    def stop_backend(self):
        """Stop the backend server"""
        if self.backend_process:
            logger.info("Stopping backend...")
            self.backend_process.terminate()
            try:
                self.backend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.backend_process.kill()
            self.backend_process = None
    
    def check_health(self) -> dict:
        """Check system health"""
        health = {
            "backend": False,
            "uptime": None,
            "scans_available": True
        }
        
        try:
            import requests
            response = requests.get("http://localhost:8002/api/health", timeout=2)
            health["backend"] = response.status_code == 200
        except Exception:
            pass
        
        if self.start_time:
            health["uptime"] = str(datetime.now() - self.start_time)
        
        return health
    
    def handle_signal(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        self.stop()
    
    def start(self):
        """Start the PayGuard service"""
        logger.info("=" * 50)
        logger.info("PayGuard Service Starting")
        logger.info("=" * 50)
        
        # Register signal handlers
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)
        
        self.running = True
        self.start_time = datetime.now()
        
        # Start backend
        if not self.start_backend():
            logger.error("Failed to start backend, exiting")
            return
        
        # Notify user
        self.notify("🛡️ PayGuard Active", "Privacy-first protection is now running", sound=True)
        
        logger.info("PayGuard service is now running")
        logger.info("Backend: http://localhost:8002")
        logger.info("Logs: " + str(LOG_FILE))
        
        # Keep running
        while self.running:
            try:
                # Periodic health check (every 60 seconds)
                time.sleep(60)
                
                # Check if backend is still running
                if self.backend_process and self.backend_process.poll() is not None:
                    logger.warning("Backend process died, restarting...")
                    self.start_backend()
                    
            except KeyboardInterrupt:
                logger.info("Keyboard interrupt received")
                break
    
    def stop(self):
        """Stop the PayGuard service"""
        logger.info("Stopping PayGuard service...")
        self.running = False
        self.stop_backend()
        self.notify("PayGuard", "Service stopped")
        logger.info("PayGuard service stopped")


def install_launchd():
    """Install as a macOS LaunchAgent for auto-start"""
    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.payguard.service</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{Path(__file__).absolute()}</string>
        <string>run</string>
    </array>
    
    <key>WorkingDirectory</key>
    <string>{Path(__file__).parent.absolute()}</string>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <true/>
    
    <key>StandardOutPath</key>
    <string>{LOG_DIR}/payguard.out.log</string>
    
    <key>StandardErrorPath</key>
    <string>{LOG_DIR}/payguard.err.log</string>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
"""
    
    plist_path = Path.home() / "Library" / "LaunchAgents" / "com.payguard.service.plist"
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write plist
    plist_path.write_text(plist_content)
    print(f"✅ LaunchAgent installed: {plist_path}")
    
    # Load the service
    subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True)
    result = subprocess.run(["launchctl", "load", str(plist_path)], capture_output=True)
    
    if result.returncode == 0:
        print("✅ PayGuard service started and will run automatically on login")
        print(f"📁 Logs: {LOG_DIR}")
        print("\nCommands:")
        print("  Stop:    launchctl unload ~/Library/LaunchAgents/com.payguard.service.plist")
        print("  Start:   launchctl load ~/Library/LaunchAgents/com.payguard.service.plist")
        print("  Status:  launchctl list | grep payguard")
    else:
        print("⚠️ Failed to start service. Try running manually:")
        print(f"  python3 {__file__} run")


def uninstall_launchd():
    """Uninstall the LaunchAgent"""
    plist_path = Path.home() / "Library" / "LaunchAgents" / "com.payguard.service.plist"
    
    if plist_path.exists():
        subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True)
        plist_path.unlink()
        print("✅ PayGuard service uninstalled")
    else:
        print("PayGuard service is not installed")


def show_status():
    """Show service status"""
    print("🛡️ PayGuard Service Status")
    print("=" * 40)
    
    # Check if service is loaded
    result = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
    if "com.payguard.service" in result.stdout:
        print("✅ Service: Running (launchd)")
    else:
        print("❌ Service: Not running")
    
    # Check backend health
    try:
        import requests
        response = requests.get("http://localhost:8002/api/health", timeout=2)
        if response.status_code == 200:
            print("✅ Backend: Running on port 8002")
        else:
            print("⚠️ Backend: Responding but unhealthy")
    except Exception:
        print("❌ Backend: Not responding")
    
    # Show log location
    print(f"\n📁 Logs: {LOG_DIR}")
    
    # Show recent log entries
    if LOG_FILE.exists():
        print("\n📋 Recent logs:")
        try:
            with open(LOG_FILE) as f:
                lines = f.readlines()
                for line in lines[-5:]:
                    print(f"   {line.strip()}")
        except Exception:
            pass


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="PayGuard Background Service")
    parser.add_argument("command", nargs="?", default="run",
                       choices=["run", "install", "uninstall", "status"],
                       help="Command to execute")
    
    args = parser.parse_args()
    
    if args.command == "run":
        service = PayGuardService()
        service.start()
    elif args.command == "install":
        install_launchd()
    elif args.command == "uninstall":
        uninstall_launchd()
    elif args.command == "status":
        show_status()


if __name__ == "__main__":
    main()
