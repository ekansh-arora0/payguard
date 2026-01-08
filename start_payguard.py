#!/usr/bin/env python3
"""
PayGuard Startup Script
Starts the backend and agent as persistent services
"""

import subprocess
import time
import os
import sys
import signal
from pathlib import Path

def start_backend():
    """Start the PayGuard backend server"""
    print("🚀 Starting PayGuard Backend...")
    
    # Set environment variables
    env = os.environ.copy()
    env['MONGO_URL'] = 'mongodb://localhost:27017'
    env['DB_NAME'] = 'payguard'
    
    # Start uvicorn server
    backend_cmd = [
        sys.executable, "-m", "uvicorn", 
        "backend.server:app", 
        "--host", "0.0.0.0", 
        "--port", "8002",
        "--reload"
    ]
    
    backend_process = subprocess.Popen(
        backend_cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait a moment for startup
    time.sleep(3)
    
    # Check if it's running
    try:
        import requests
        response = requests.get("http://localhost:8002/api/health", timeout=5)
        if response.status_code == 200:
            print("✅ Backend started successfully!")
            return backend_process
        else:
            print(f"❌ Backend health check failed: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Backend startup failed: {e}")
        return None

def start_agent():
    """Start the PayGuard agent"""
    print("🛡️ Starting PayGuard Agent...")
    
    agent_cmd = [sys.executable, "agent/agent.py"]
    
    agent_process = subprocess.Popen(
        agent_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    time.sleep(2)
    print("✅ Agent started successfully!")
    return agent_process

def main():
    """Main startup function"""
    print("🛡️ PAYGUARD STARTUP")
    print("=" * 50)
    
    # Check if MongoDB is running
    try:
        subprocess.run(["pgrep", "-f", "mongod"], check=True, capture_output=True)
        print("✅ MongoDB is running")
    except subprocess.CalledProcessError:
        print("❌ MongoDB not running. Please start MongoDB first:")
        print("   brew services start mongodb-community")
        return
    
    # Start backend
    backend_process = start_backend()
    if not backend_process:
        print("❌ Failed to start backend")
        return
    
    # Start agent
    agent_process = start_agent()
    if not agent_process:
        print("❌ Failed to start agent")
        return
    
    print("\n🎉 PayGuard is now running!")
    print("=" * 50)
    print("🌐 Backend: http://localhost:8002")
    print("🛡️ Agent: Monitoring your screen")
    print("📱 You'll receive notifications when scams are detected")
    print("\nPress Ctrl+C to stop PayGuard")
    
    # Keep running and handle shutdown
    try:
        while True:
            time.sleep(1)
            
            # Check if processes are still running
            if backend_process.poll() is not None:
                print("❌ Backend process died, restarting...")
                backend_process = start_backend()
            
            if agent_process.poll() is not None:
                print("❌ Agent process died, restarting...")
                agent_process = start_agent()
                
    except KeyboardInterrupt:
        print("\n🛑 Shutting down PayGuard...")
        
        # Terminate processes
        if backend_process:
            backend_process.terminate()
            backend_process.wait()
        
        if agent_process:
            agent_process.terminate()
            agent_process.wait()
        
        print("✅ PayGuard stopped")

if __name__ == "__main__":
    main()