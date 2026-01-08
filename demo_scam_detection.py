#!/usr/bin/env python3
"""
PayGuard Scam Detection Demo
Demonstrates the scam detection capabilities without requiring backend
"""

import re
import time
from PIL import Image, ImageDraw, ImageFont
import io
import base64
import tempfile
import os
import subprocess
from pathlib import Path

class ScamDetectionDemo:
    """Demo of PayGuard's scam detection capabilities"""
    
    def __init__(self):
        self.scam_patterns = {
            'phone_number': r'\b1-\d{3}-\d{3}-\d{4}\b',
            'urgency': r'(?i)\b(urgent|immediate|act now|call now|do not close)\b',
            'virus_warning': r'(?i)\b(virus|infected|malware|trojan|security alert)\b',
            'account_threat': r'(?i)\b(suspended|blocked|expired|compromised)\b',
            'phishing': r'(?i)\b(verify|update|confirm).*(account|payment|card|information)\b',
            'scare_tactics': r'(?i)\b(warning|alert|critical|error|danger)\b',
            'payment_request': r'(?i)\b(pay|payment|charge|bill|invoice|refund)\b',
            'do_not_close': r'(?i)do not (close|restart|shut down)',
            'fake_company': r'(?i)\b(microsoft|amazon|apple|google|paypal).*(support|security|alert)\b'
        }
    
    def analyze_text_for_scam(self, text: str) -> dict:
        """Analyze text for scam indicators"""
        detected_patterns = []
        confidence = 0
        
        for pattern_name, pattern in self.scam_patterns.items():
            if re.search(pattern, text):
                detected_patterns.append(pattern_name)
                # Weight different patterns differently
                weights = {
                    'phone_number': 30,
                    'urgency': 20,
                    'virus_warning': 25,
                    'account_threat': 15,
                    'phishing': 20,
                    'scare_tactics': 10,
                    'payment_request': 15,
                    'do_not_close': 25,
                    'fake_company': 20
                }
                confidence += weights.get(pattern_name, 10)
        
        # Cap confidence at 100
        confidence = min(confidence, 100)
        is_scam = confidence >= 40
        
        # Generate senior-friendly message
        if is_scam:
            if 'virus_warning' in detected_patterns:
                senior_message = "STOP! This is a FAKE virus warning. Your computer is SAFE."
                action_advice = "Close this window immediately. Do NOT call any phone numbers."
            elif 'phishing' in detected_patterns:
                senior_message = "STOP! This is a FAKE security alert trying to steal your information."
                action_advice = "Do NOT enter any passwords or personal information. Close this window."
            elif 'phone_number' in detected_patterns:
                senior_message = "STOP! This is a SCAM. Do NOT call this number."
                action_advice = "Real companies don't ask you to call random phone numbers."
            else:
                senior_message = "STOP! This appears to be a SCAM."
                action_advice = "Close this window and do not follow any instructions."
        else:
            senior_message = "This appears to be legitimate content."
            action_advice = "Proceed with normal caution."
        
        return {
            'is_scam': is_scam,
            'confidence': confidence,
            'detected_patterns': detected_patterns,
            'senior_message': senior_message,
            'action_advice': action_advice
        }
    
    def create_scam_image(self, text_lines: list, bg_color='red') -> bytes:
        """Create a scam image for testing"""
        img = Image.new('RGB', (800, 600), color=bg_color)
        draw = ImageDraw.Draw(img)
        
        # Try to use a larger font
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 36)
        except:
            font = ImageFont.load_default()
        
        y = 50
        for line in text_lines:
            draw.text((50, y), line, fill='white', font=font)
            y += 80
        
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        return img_bytes.getvalue()
    
    def analyze_visual_cues(self, image_bytes: bytes) -> dict:
        """Analyze image for visual scam cues"""
        try:
            img = Image.open(io.BytesIO(image_bytes))
            
            # Get dominant colors
            colors = img.getcolors(maxcolors=256*256*256)
            if not colors:
                return {'visual_scam_any': False}
            
            total_pixels = sum(count for count, color in colors)
            
            # Check for red/orange/yellow dominance (common in scam alerts)
            red_pixels = 0
            orange_pixels = 0
            yellow_pixels = 0
            
            for count, color in colors:
                if isinstance(color, tuple) and len(color) >= 3:
                    r, g, b = color[:3]
                    
                    # Red detection
                    if r > 200 and g < 100 and b < 100:
                        red_pixels += count
                    
                    # Orange detection  
                    elif r > 200 and g > 100 and g < 200 and b < 100:
                        orange_pixels += count
                    
                    # Yellow detection
                    elif r > 200 and g > 200 and b < 100:
                        yellow_pixels += count
            
            red_ratio = red_pixels / total_pixels
            orange_ratio = orange_pixels / total_pixels
            yellow_ratio = yellow_pixels / total_pixels
            
            # Visual scam indicators
            visual_scam_any = (red_ratio > 0.3 or orange_ratio > 0.2 or yellow_ratio > 0.2)
            
            return {
                'visual_scam_any': visual_scam_any,
                'red_ratio': round(red_ratio, 3),
                'orange_ratio': round(orange_ratio, 3),
                'yellow_ratio': round(yellow_ratio, 3)
            }
            
        except Exception as e:
            return {'visual_scam_any': False, 'error': str(e)}
    
    def demo_text_analysis(self):
        """Demo text-based scam detection"""
        print("🔍 TEXT-BASED SCAM DETECTION DEMO")
        print("=" * 60)
        
        test_cases = [
            {
                'name': 'Tech Support Scam',
                'text': 'URGENT: Your computer is infected with a virus! Call Microsoft Support at 1-800-555-0199 immediately. Do not close this window!'
            },
            {
                'name': 'Phishing Scam',
                'text': 'Your Amazon account has been suspended due to suspicious activity. Please verify your payment information immediately to avoid charges.'
            },
            {
                'name': 'Fake Invoice',
                'text': 'Invoice #12345 for $299.99 has been charged to your account. If you did not authorize this, call 1-888-555-0123 to cancel.'
            },
            {
                'name': 'Legitimate Email',
                'text': 'Thank you for your recent purchase. Your order will be shipped within 2-3 business days. Contact customer service if you have questions.'
            },
            {
                'name': 'Newsletter',
                'text': 'Welcome to our monthly newsletter! Here are the latest updates about our products and services.'
            }
        ]
        
        for case in test_cases:
            print(f"\n📝 {case['name']}:")
            print(f"   Text: {case['text'][:80]}...")
            
            result = self.analyze_text_for_scam(case['text'])
            
            status = "🚨 SCAM DETECTED" if result['is_scam'] else "✅ APPEARS SAFE"
            print(f"   Result: {status} (Confidence: {result['confidence']}%)")
            print(f"   Patterns: {', '.join(result['detected_patterns'])}")
            print(f"   Message: {result['senior_message']}")
            print(f"   Advice: {result['action_advice']}")
    
    def demo_image_analysis(self):
        """Demo image-based scam detection"""
        print("\n\n🖼️ IMAGE-BASED SCAM DETECTION DEMO")
        print("=" * 60)
        
        test_images = [
            {
                'name': 'Tech Support Scam',
                'lines': [
                    '⚠️ CRITICAL ERROR ⚠️',
                    'YOUR COMPUTER IS INFECTED!',
                    'CALL: 1-800-555-0199',
                    'DO NOT CLOSE THIS WINDOW'
                ],
                'bg_color': 'red'
            },
            {
                'name': 'Fake Security Alert',
                'lines': [
                    'WINDOWS SECURITY ALERT',
                    'Trojan Detected!',
                    'Call Microsoft: 1-888-555-0123',
                    'Error Code: WIN32/Trojan'
                ],
                'bg_color': 'orange'
            },
            {
                'name': 'Clean Website',
                'lines': [
                    'Welcome to Our Website',
                    'Browse our products',
                    'Contact us for support',
                    'Thank you for visiting'
                ],
                'bg_color': 'lightblue'
            }
        ]
        
        for img_case in test_images:
            print(f"\n🖼️ {img_case['name']}:")
            
            # Create test image
            img_bytes = self.create_scam_image(img_case['lines'], img_case['bg_color'])
            
            # Analyze visual cues
            visual_result = self.analyze_visual_cues(img_bytes)
            
            # Analyze text content
            text_content = ' '.join(img_case['lines'])
            text_result = self.analyze_text_for_scam(text_content)
            
            # Combined analysis
            visual_risk = visual_result.get('visual_scam_any', False)
            text_risk = text_result['is_scam']
            
            if visual_risk and text_risk:
                overall_status = "🚨 HIGH RISK SCAM"
                confidence = min(95, text_result['confidence'] + 20)
            elif text_risk:
                overall_status = "⚠️ TEXT-BASED SCAM"
                confidence = text_result['confidence']
            elif visual_risk:
                overall_status = "⚠️ SUSPICIOUS VISUALS"
                confidence = 60
            else:
                overall_status = "✅ APPEARS SAFE"
                confidence = 10
            
            print(f"   Visual Analysis: {'🚨 Suspicious' if visual_risk else '✅ Normal'}")
            print(f"   Text Analysis: {'🚨 Scam' if text_risk else '✅ Safe'} ({text_result['confidence']}%)")
            print(f"   Overall: {overall_status} (Confidence: {confidence}%)")
            
            if text_risk:
                print(f"   Senior Message: {text_result['senior_message']}")
                print(f"   Action Advice: {text_result['action_advice']}")
    
    def demo_html_analysis(self):
        """Demo HTML-based scam detection"""
        print("\n\n📄 HTML-BASED SCAM DETECTION DEMO")
        print("=" * 60)
        
        html_samples = [
            {
                'name': 'Fake Virus Warning Page',
                'html': '''
                <html>
                <body style="background-color: red; color: white; text-align: center;">
                    <h1>⚠️ CRITICAL SECURITY ALERT ⚠️</h1>
                    <p style="font-size: 24px;">YOUR COMPUTER HAS BEEN INFECTED!</p>
                    <p style="font-size: 20px;">Call Microsoft Support: 1-800-555-0199</p>
                    <p>DO NOT CLOSE THIS WINDOW OR RESTART YOUR COMPUTER</p>
                    <p>Error Code: WIN32/Trojan.Gen!Eldorado</p>
                </body>
                </html>
                '''
            },
            {
                'name': 'Phishing Login Page',
                'html': '''
                <html>
                <body>
                    <div style="background: #232f3e; color: white; padding: 20px;">
                        <h2 style="color: #ff9900;">Amazon Security Notice</h2>
                        <p>Your account has been suspended due to suspicious activity.</p>
                        <p style="color: red;">Please verify your account immediately!</p>
                        <form>
                            <input type="email" placeholder="Email">
                            <input type="password" placeholder="Password">
                            <button style="background: #ff9900;">Verify Account</button>
                        </form>
                    </div>
                </body>
                </html>
                '''
            },
            {
                'name': 'Legitimate Business Page',
                'html': '''
                <html>
                <body>
                    <header>
                        <h1>Welcome to Our Company</h1>
                    </header>
                    <main>
                        <p>We provide excellent services to our customers.</p>
                        <p>Contact us at support@company.com for assistance.</p>
                        <p>Thank you for choosing our services.</p>
                    </main>
                </body>
                </html>
                '''
            }
        ]
        
        for html_case in html_samples:
            print(f"\n📄 {html_case['name']}:")
            
            # Extract text from HTML (simple approach)
            import re
            text_content = re.sub(r'<[^>]+>', ' ', html_case['html'])
            text_content = re.sub(r'\s+', ' ', text_content).strip()
            
            # Analyze text content
            result = self.analyze_text_for_scam(text_content)
            
            # Check for HTML-specific scam indicators
            html_indicators = 0
            if 'background.*red' in html_case['html'].lower():
                html_indicators += 15
            if 'input.*password' in html_case['html'].lower():
                html_indicators += 10
            if 'style.*color.*red' in html_case['html'].lower():
                html_indicators += 10
            
            total_confidence = min(100, result['confidence'] + html_indicators)
            is_scam = total_confidence >= 40
            
            status = "🚨 SCAM DETECTED" if is_scam else "✅ APPEARS SAFE"
            print(f"   Result: {status} (Confidence: {total_confidence}%)")
            print(f"   Text Patterns: {', '.join(result['detected_patterns'])}")
            print(f"   HTML Risk Score: +{html_indicators}%")
            
            if is_scam:
                print(f"   Senior Message: {result['senior_message']}")
                print(f"   Action Advice: {result['action_advice']}")
    
    def create_test_files(self):
        """Create test HTML files and open them"""
        print("\n\n🚀 CREATING TEST FILES FOR LIVE DEMO")
        print("=" * 60)
        
        # Create scam HTML file
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
        </body>
        </html>
        '''
        
        # Save and open the file
        scam_path = Path("demo_scam_page.html")
        scam_path.write_text(scam_html)
        
        print(f"✅ Created: {scam_path}")
        print("🌐 Opening in browser...")
        
        try:
            subprocess.run(["open", str(scam_path)])
            print("📱 If you have the PayGuard agent running, it should detect this scam!")
            print("⏰ Waiting 10 seconds for detection...")
            time.sleep(10)
        except Exception as e:
            print(f"❌ Could not open browser: {e}")
        
        # Cleanup
        try:
            scam_path.unlink()
            print("🧹 Cleaned up test file")
        except:
            pass
    
    def run_full_demo(self):
        """Run the complete demo"""
        print("🛡️ PAYGUARD SCAM DETECTION DEMO")
        print("=" * 80)
        print("This demo shows how PayGuard detects various types of scams")
        print("without requiring the full backend system to be running.")
        print("=" * 80)
        
        # Run all demos
        self.demo_text_analysis()
        self.demo_image_analysis()
        self.demo_html_analysis()
        self.create_test_files()
        
        print("\n\n🎉 DEMO COMPLETE!")
        print("=" * 80)
        print("PayGuard's scam detection system can identify:")
        print("✅ Tech support scams with fake phone numbers")
        print("✅ Phishing attempts impersonating legitimate companies")
        print("✅ Visual scam indicators (red backgrounds, urgent styling)")
        print("✅ Fake virus warnings and security alerts")
        print("✅ Suspicious payment requests and invoices")
        print("\nThis protects users from common online scams and fraud attempts.")

def main():
    """Run the scam detection demo"""
    demo = ScamDetectionDemo()
    demo.run_full_demo()

if __name__ == "__main__":
    main()