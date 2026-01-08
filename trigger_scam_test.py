#!/usr/bin/env python3
"""
Trigger a scam alert to test PayGuard notifications
"""

import subprocess
import time
import tempfile
import os

def test_clipboard_scam():
    """Test clipboard scam detection"""
    print("📋 Testing clipboard scam detection...")
    
    # Put scam text in clipboard
    scam_text = "URGENT: Your computer is infected with a virus! Call Microsoft Support at 1-800-555-0199 immediately! Do not close this window!"
    
    # Copy to clipboard
    process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
    process.communicate(scam_text.encode())
    
    print("✅ Scam text copied to clipboard")
    print("🛡️ PayGuard should detect this in 2-5 seconds...")
    
    # Wait for detection
    for i in range(10, 0, -1):
        print(f"   Waiting {i} seconds...", end='\r')
        time.sleep(1)
    print()

def test_visual_scam():
    """Test visual scam detection by opening a red scam page"""
    print("🖥️ Testing visual scam detection...")
    
    # Create a very red scam page
    scam_html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SCAM TEST</title>
        <style>
            body {
                background-color: #ff0000 !important;
                color: white;
                font-family: Arial, sans-serif;
                text-align: center;
                padding: 100px;
                font-size: 48px;
                font-weight: bold;
            }
            .alert {
                background-color: #ff0000 !important;
                border: 10px solid #ff0000;
                padding: 50px;
                margin: 50px;
            }
        </style>
    </head>
    <body>
        <div class="alert">
            ⚠️ CRITICAL SECURITY ALERT ⚠️
            <br><br>
            YOUR COMPUTER IS INFECTED!
            <br><br>
            CALL 1-800-555-0199 NOW!
            <br><br>
            DO NOT CLOSE THIS WINDOW!
        </div>
    </body>
    </html>
    '''
    
    # Create and open the file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write(scam_html)
        scam_file = f.name
    
    try:
        # Open in browser
        subprocess.run(["open", scam_file])
        print("✅ Red scam page opened in browser")
        print("🛡️ PayGuard should detect the red background in 3-6 seconds...")
        
        # Wait for detection
        for i in range(15, 0, -1):
            print(f"   Waiting {i} seconds...", end='\r')
            time.sleep(1)
        print()
        
    finally:
        # Cleanup
        try:
            os.unlink(scam_file)
        except:
            pass

def main():
    print("🧪 PAYGUARD SCAM DETECTION TEST")
    print("=" * 50)
    print("This will test PayGuard's scam detection capabilities.")
    print("You should receive notifications and alerts!")
    print()
    
    # Test 1: Clipboard
    test_clipboard_scam()
    
    print("\n" + "="*30 + "\n")
    
    # Test 2: Visual
    test_visual_scam()
    
    print("\n✅ Tests completed!")
    print("Did you receive PayGuard notifications?")
    print("If not, check that PayGuard is running with: python payguard_live.py")

if __name__ == "__main__":
    main()