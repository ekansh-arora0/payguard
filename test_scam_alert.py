#!/usr/bin/env python3
"""
Test PayGuard scam detection by creating a fake scam page
"""

import subprocess
import time
import tempfile
import os

def create_scam_page():
    """Create a test scam page"""
    scam_html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>URGENT: System Security Alert</title>
        <style>
            body {
                background-color: #ff0000;
                color: white;
                font-family: Arial, sans-serif;
                text-align: center;
                padding: 50px;
                animation: blink 1s infinite;
            }
            @keyframes blink {
                0% { background-color: #ff0000; }
                50% { background-color: #cc0000; }
                100% { background-color: #ff0000; }
            }
            .warning {
                font-size: 48px;
                font-weight: bold;
                margin: 20px 0;
            }
            .phone {
                font-size: 36px;
                background-color: yellow;
                color: black;
                padding: 20px;
                border: 5px solid white;
                margin: 30px 0;
            }
        </style>
    </head>
    <body>
        <div class="warning">⚠️ CRITICAL SECURITY ALERT ⚠️</div>
        
        <div style="font-size: 24px; margin: 20px 0;">
            YOUR COMPUTER HAS BEEN INFECTED WITH A TROJAN VIRUS!
        </div>
        
        <div style="font-size: 24px; margin: 20px 0;">
            DO NOT RESTART OR SHUT DOWN YOUR COMPUTER!
        </div>
        
        <div class="phone">
            CALL MICROSOFT SUPPORT IMMEDIATELY:
            <br><br>
            📞 1-800-555-0199
        </div>
        
        <div style="font-size: 18px; margin: 20px 0;">
            Error Code: WIN32/Trojan.Gen!Eldorado
        </div>
        
        <div style="font-size: 18px; margin: 20px 0;">
            Your personal files and banking information are at risk!
        </div>
        
        <div style="font-size: 16px; margin-top: 40px;">
            This window will close automatically in 5 minutes unless you call for help.
        </div>
    </body>
    </html>
    '''
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write(scam_html)
        return f.name

def main():
    print("🧪 Testing PayGuard Scam Detection")
    print("=" * 50)
    print("This will open a fake scam page to test if PayGuard detects it.")
    print("You should receive a notification within 5-10 seconds.")
    print()
    
    input("Press Enter to start the test...")
    
    # Create and open scam page
    scam_file = create_scam_page()
    print(f"📄 Created test scam page: {scam_file}")
    
    try:
        # Open in browser
        subprocess.run(["open", scam_file])
        print("🌐 Opened scam page in browser")
        print("🛡️ PayGuard should detect this and send you an alert!")
        print()
        print("⏰ Waiting 15 seconds for detection...")
        
        for i in range(15, 0, -1):
            print(f"   {i} seconds remaining...", end='\r')
            time.sleep(1)
        
        print("\n")
        print("✅ Test complete!")
        print("Did you receive a PayGuard scam alert notification?")
        
    finally:
        # Cleanup
        try:
            os.unlink(scam_file)
            print(f"🧹 Cleaned up test file")
        except:
            pass

if __name__ == "__main__":
    main()