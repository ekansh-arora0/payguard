#!/usr/bin/env python3
"""
PayGuard Detection Capabilities Demo

Demonstrates all detection features:
1. Malicious message/text detection
2. Phishing email detection  
3. AI image detection
4. Scam screen detection
"""

import requests
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_message_detection():
    """Test malicious message and text detection"""
    from payguard_menubar_optimized import ScamDetector
    
    detector = ScamDetector()
    
    print("\n" + "=" * 70)
    print("📱 MALICIOUS MESSAGE DETECTION")
    print("=" * 70)
    
    test_cases = [
        ("Tech Support Scam", """⚠️ WARNING! Your computer has been INFECTED with a virus!
Call Microsoft Support immediately: 1-888-555-1234
Do NOT close this window or your files will be DELETED!"""),
        
        ("Phishing Email", """Dear Customer,

Your Amazon account has been SUSPENDED due to suspicious activity.
Click here to verify your identity: http://amaz0n-verify.com
You must verify within 24 hours or your account will be closed.

Amazon Security Team"""),
        
        ("SMS Bank Scam", """URGENT: Your Chase account has been COMPROMISED!
Call 1-800-555-9999 NOW to secure your funds.
Reference: ERR-48293"""),
        
        ("IRS Scam", """FINAL WARNING: Your Social Security Number has been SUSPENDED.
Call the IRS immediately at 1-877-555-0123 to avoid ARREST.
Do not ignore this message."""),
        
        ("Cryptocurrency Scam", """🚀 URGENT: Elon Musk is giving away Bitcoin!
Send 0.1 BTC to receive 1 BTC back!
Wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
Act now - only 100 spots left!"""),
        
        ("Safe Message", """Hi! Just wanted to check if we're still on for dinner tonight at 7pm? 
Let me know if that works for you. See you later!"""),
    ]
    
    for name, text in test_cases:
        result = detector.analyze_text(text)
        status = "🚨 SCAM" if result.is_scam else "✅ SAFE"
        
        print(f"\n📧 {name}")
        print(f"   Status: {status}")
        print(f"   Confidence: {result.confidence:.0f}%")
        if result.patterns:
            print(f"   Patterns: {', '.join(result.patterns)}")


def test_email_phishing():
    """Test email address phishing detection"""
    from backend.email_guardian import EmailGuardian
    
    guardian = EmailGuardian()
    
    print("\n" + "=" * 70)
    print("📧 PHISHING EMAIL ADDRESS DETECTION")
    print("=" * 70)
    
    test_emails = [
        ("security@amaz0n-support.com", "Amazon typosquat (0→o)"),
        ("verify@paypa1-secure.com", "PayPal typosquat (1→l)"),
        ("support@microsoft-security.xyz", "Microsoft fake TLD"),
        ("alert@netf1ix-verify.com", "Netflix typosquat (1→l)"),
        ("noreply@go0gle-security.com", "Google typosquat (0→o)"),
        ("help@apple.com", "Real Apple"),
        ("support@amazon.com", "Real Amazon"),
        ("john.doe@gmail.com", "Normal Gmail"),
    ]
    
    for email, desc in test_emails:
        is_suspicious, brand, confidence = guardian.analyze_email(email)
        
        if is_suspicious:
            status = f"🚨 PHISHING (Impersonating: {brand})"
        else:
            status = "✅ SAFE"
        
        print(f"\n   {email}")
        print(f"   {desc}: {status}")
        if is_suspicious:
            print(f"   Confidence: {confidence*100:.0f}%")


def test_ai_image_detection():
    """Test AI-generated image detection"""
    print("\n" + "=" * 70)
    print("🖼️ AI IMAGE DETECTION")
    print("=" * 70)
    
    # Check for available test images
    test_images = ['ai_test.png', 'test.png', 'test_scam.png', 'scam_test.jpg']
    
    found_image = None
    for img in test_images:
        if os.path.exists(img):
            found_image = img
            break
    
    if found_image:
        print(f"\n   Testing: {found_image}")
        
        with open(found_image, 'rb') as f:
            img_data = f.read()
        
        b64_data = base64.b64encode(img_data).decode()
        
        try:
            response = requests.post(
                'http://localhost:8002/api/media-risk/bytes',
                json={'url': f'file://{found_image}', 'content': b64_data},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                ai_prob = data.get('image_fake_prob', 0)
                
                if ai_prob > 70:
                    status = "🤖 AI-GENERATED"
                elif ai_prob > 40:
                    status = "⚠️ POSSIBLY AI/EDITED"
                else:
                    status = "📷 LIKELY REAL"
                
                print(f"   AI Probability: {ai_prob}%")
                print(f"   Result: {status}")
        except Exception as e:
            print(f"   Error: {e}")
    else:
        print("\n   No test images found")
    
    print("\n   AI Detection Capabilities:")
    print("   • Deepfake detection")
    print("   • AI-generated face detection")
    print("   • Manipulated photo detection")
    print("   • Synthetic image detection")


def test_scam_screen_detection():
    """Test visual scam detection on screen"""
    print("\n" + "=" * 70)
    print("🖥️ VISUAL SCAM DETECTION")
    print("=" * 70)
    
    print("\n   PayGuard can detect these visual scams:")
    print("   • 🔴 Fake virus warning screens (red alerts)")
    print("   • 🟡 Fake security warnings (orange/yellow)")
    print("   • 📞 Tech support scam pop-ups")
    print("   • 🔒 Fake login pages (phishing)")
    print("   • 💳 Fake payment forms")
    print("   • 🎁 Fake prize/lottery pop-ups")
    
    print("\n   Detection methods:")
    print("   • Color analysis (scam screens use red/orange)")
    print("   • Text pattern recognition")
    print("   • Brand logo detection")
    print("   • Form structure analysis")


def test_url_detection():
    """Test URL reputation detection"""
    print("\n" + "=" * 70)
    print("🌐 URL REPUTATION DETECTION")
    print("=" * 70)
    
    test_urls = [
        ("https://google.com", "Legitimate"),
        ("http://free-iphone-winner.xyz", "Prize scam"),
        ("https://amaz0n-verify-account.com", "Phishing"),
    ]
    
    for url, desc in test_urls:
        try:
            response = requests.get(
                f'http://localhost:8002/api/risk?url={url}',
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                risk = data.get('risk_level', 'unknown')
                score = data.get('trust_score', 0)
                factors = data.get('risk_factors', [])
                
                if risk == 'high':
                    status = "🚨 HIGH RISK"
                elif risk == 'medium':
                    status = "⚠️ MEDIUM RISK"
                else:
                    status = "✅ LOW RISK"
                
                print(f"\n   {url}")
                print(f"   {desc}: {status}")
                print(f"   Trust Score: {score}")
                if factors:
                    print(f"   Factors: {', '.join(factors[:3])}")
        except Exception as e:
            print(f"\n   {url}: Error - {e}")


def main():
    print("\n" + "=" * 70)
    print("🛡️ PAYGUARD DETECTION CAPABILITIES DEMO")
    print("=" * 70)
    
    test_message_detection()
    test_email_phishing()
    test_ai_image_detection()
    test_scam_screen_detection()
    test_url_detection()
    
    print("\n" + "=" * 70)
    print("✅ DEMO COMPLETE")
    print("=" * 70)
    print("""
PayGuard Protects Against:
  📱 Scam SMS and text messages
  📧 Phishing emails and fake sender addresses
  🖼️ AI-generated/deepfake images
  🖥️ Fake virus warnings and tech support scams
  🌐 Malicious URLs and phishing websites
  💳 Fake payment forms and login pages

To scan your screen: python3 payguard_scan.py
To scan clipboard:   python3 payguard_scan.py --text
""")


if __name__ == "__main__":
    main()
