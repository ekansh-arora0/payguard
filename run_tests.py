#!/usr/bin/env python3
"""
PayGuard Test Runner
Opens test scam pages to verify the screen monitoring is working
"""

import subprocess
import time
import os

def test_scam_detection():
    print("🧪 PayGuard Test Suite")
    print("=" * 50)
    
    # Check if backend is running
    try:
        result = subprocess.run(['curl', '-s', 'http://localhost:8002/api/health'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print("❌ Backend not running! Please start it first:")
            print("   cd /Users/ekans/payguard")
            print("   source .venv/bin/activate")
            print("   python -m backend.server")
            return
        print("✅ Backend is running")
    except:
        print("❌ Backend not accessible")
        return
    
    print("\n📋 Test Scenarios:")
    print("1. Tech Support Scam (fake virus warning)")
    print("2. Phishing Scam (fake Amazon)")
    print("3. AI Image Test (if available)")
    
    input("\nMake sure PayGuard agent is running, then press Enter to start tests...")
    
    # Test 1: Tech Support Scam
    print("\n🚨 Test 1: Opening tech support scam page...")
    scam_path = os.path.abspath("test_scam_page.html")
    subprocess.run(['open', scam_path])
    print("   → Page opened. PayGuard should detect this in 1-2 seconds...")
    time.sleep(8)
    
    # Test 2: Phishing
    print("\n🎣 Test 2: Opening phishing scam page...")
    phishing_path = os.path.abspath("test_phishing_page.html")
    subprocess.run(['open', phishing_path])
    print("   → Page opened. PayGuard should detect this in 1-2 seconds...")
    time.sleep(8)
    
    # Test 3: AI Image (if exists)
    ai_test_images = ['ai_test.png', 'test.png', 'test_scam.png']
    for img in ai_test_images:
        if os.path.exists(img):
            print(f"\n🤖 Test 3: Opening AI test image: {img}")
            subprocess.run(['open', img])
            print("   → Image opened. PayGuard should analyze it...")
            time.sleep(5)
            break
    
    print("\n✅ Tests completed!")
    print("\nExpected Results:")
    print("- You should have received macOS notifications for scam detection")
    print("- Check the agent terminal for analysis logs")
    print("- If no alerts appeared, check that both backend and agent are running")
    
    # Cleanup
    print("\nCleaning up test files...")
    try:
        os.remove("test_scam_page.html")
        os.remove("test_phishing_page.html")
        print("✅ Test files cleaned up")
    except:
        pass

if __name__ == "__main__":
    test_scam_detection()