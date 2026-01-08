#!/usr/bin/env python3
"""
Install PayGuard as a macOS service that runs automatically
"""

import os
import subprocess
import sys
from pathlib import Path

def create_launch_daemon():
    """Create a macOS LaunchAgent to run PayGuard automatically"""
    
    # Get the current directory and Python path
    current_dir = Path(__file__).parent.absolute()
    python_path = sys.executable
    script_path = current_dir / "payguard_live.py"
    
    # Create the plist content
    plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.payguard.agent</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>{python_path}</string>
        <string>{script_path}</string>
    </array>
    
    <key>WorkingDirectory</key>
    <string>{current_dir}</string>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <true/>
    
    <key>StandardOutPath</key>
    <string>{current_dir}/payguard.log</string>
    
    <key>StandardErrorPath</key>
    <string>{current_dir}/payguard.error.log</string>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin</string>
    </dict>
</dict>
</plist>'''
    
    # Write the plist file
    plist_path = Path.home() / "Library" / "LaunchAgents" / "com.payguard.agent.plist"
    plist_path.parent.mkdir(exist_ok=True)
    
    with open(plist_path, 'w') as f:
        f.write(plist_content)
    
    print(f"✅ Created LaunchAgent: {plist_path}")
    return plist_path

def install_service():
    """Install PayGuard as a system service"""
    print("🛡️ PAYGUARD SERVICE INSTALLER")
    print("=" * 50)
    
    # Create the launch daemon
    plist_path = create_launch_daemon()
    
    # Load the service
    try:
        subprocess.run(["launchctl", "load", str(plist_path)], check=True)
        print("✅ PayGuard service loaded successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to load service: {e}")
        return False
    
    # Start the service
    try:
        subprocess.run(["launchctl", "start", "com.payguard.agent"], check=True)
        print("✅ PayGuard service started!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start service: {e}")
        return False
    
    print("\n🎉 PAYGUARD INSTALLED SUCCESSFULLY!")
    print("=" * 50)
    print("✅ PayGuard will now run automatically when you log in")
    print("✅ PayGuard will restart automatically if it crashes")
    print("✅ PayGuard will protect you from scams 24/7")
    print()
    print("📋 Service Management Commands:")
    print(f"   Stop:    launchctl stop com.payguard.agent")
    print(f"   Start:   launchctl start com.payguard.agent")
    print(f"   Restart: launchctl kickstart -k gui/{os.getuid()}/com.payguard.agent")
    print(f"   Unload:  launchctl unload {plist_path}")
    print()
    print("📄 Log files:")
    print(f"   Output: {Path.cwd()}/payguard.log")
    print(f"   Errors: {Path.cwd()}/payguard.error.log")
    
    return True

def uninstall_service():
    """Uninstall PayGuard service"""
    print("🗑️ UNINSTALLING PAYGUARD SERVICE")
    print("=" * 50)
    
    plist_path = Path.home() / "Library" / "LaunchAgents" / "com.payguard.agent.plist"
    
    # Stop the service
    try:
        subprocess.run(["launchctl", "stop", "com.payguard.agent"], capture_output=True)
        print("✅ Service stopped")
    except:
        pass
    
    # Unload the service
    try:
        subprocess.run(["launchctl", "unload", str(plist_path)], capture_output=True)
        print("✅ Service unloaded")
    except:
        pass
    
    # Remove the plist file
    try:
        plist_path.unlink()
        print("✅ Service file removed")
    except:
        pass
    
    print("✅ PayGuard service uninstalled")

def check_service_status():
    """Check if PayGuard service is running"""
    try:
        result = subprocess.run(
            ["launchctl", "list", "com.payguard.agent"], 
            capture_output=True, 
            text=True
        )
        
        if result.returncode == 0:
            print("✅ PayGuard service is running")
            print(result.stdout)
        else:
            print("❌ PayGuard service is not running")
    except Exception as e:
        print(f"❌ Error checking service status: {e}")

def main():
    """Main installer function"""
    if len(sys.argv) > 1:
        if sys.argv[1] == "uninstall":
            uninstall_service()
            return
        elif sys.argv[1] == "status":
            check_service_status()
            return
    
    print("This will install PayGuard as a system service that runs automatically.")
    print("PayGuard will start when you log in and protect you 24/7.")
    print()
    
    choice = input("Install PayGuard service? (y/n): ").lower().strip()
    
    if choice == 'y' or choice == 'yes':
        if install_service():
            print("\n🛡️ PayGuard is now protecting your computer!")
            
            # Send a test notification
            try:
                subprocess.run([
                    "osascript", "-e",
                    'display notification "PayGuard service installed and running!" with title "🛡️ PayGuard Active" sound name "Hero"'
                ], capture_output=True)
            except:
                pass
    else:
        print("Installation cancelled.")

if __name__ == "__main__":
    main()