#!/usr/bin/env python3
"""
PayGuard Complete Feature Test Suite
Tests every single capability of PayGuard
"""

import subprocess
import time
import tempfile
import os
import threading
from pathlib import Path

class PayGuardComprehensiveTest:
    def __init__(self):
        self.test_results = []
        self.temp_files = []
        
    def log_test(self, test_name, description, expected_result):
        """Log test information"""
        print(f"\n🧪 TEST: {test_name}")
        print(f"   Description: {description}")
        print(f"   Expected: {expected_result}")
        print("   Status: Running...")
        
    def create_temp_html(self, content, filename=None):
        """Create temporary HTML file"""
        if filename is None:
            filename = f"test_{int(time.time())}.html"
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False)
        temp_file.write(content)
        temp_file.close()
        
        self.temp_files.append(temp_file.name)
        return temp_file.name
    
    def cleanup_files(self):
        """Clean up temporary files"""
        for file_path in self.temp_files:
            try:
                os.unlink(file_path)
            except:
                pass
        self.temp_files.clear()
    
    def test_visual_red_alert_detection(self):
        """Test 1: Red Alert Screen Detection"""
        self.log_test(
            "Visual Red Alert Detection",
            "Creates a red scam warning page to test visual detection",
            "PayGuard should detect red background and show alert"
        )
        
        red_scam_html = '''
        <!DOCTYPE html>
        <html>
        <head><title>Red Scam Test</title></head>
        <body style="background-color: #ff0000; color: white; padding: 100px; text-align: center; font-size: 48px;">
            <div style="background: #ff0000; padding: 50px; border: 10px solid #ff0000;">
                ⚠️ CRITICAL SECURITY ALERT ⚠️
                <br><br>
                YOUR COMPUTER IS INFECTED!
                <br><br>
                CALL 1-800-555-0199 NOW!
            </div>
        </body>
        </html>
        '''
        
        file_path = self.create_temp_html(red_scam_html)
        subprocess.run(["open", file_path])
        time.sleep(8)  # Wait for detection
        
    def test_visual_orange_alert_detection(self):
        """Test 2: Orange Warning Screen Detection"""
        self.log_test(
            "Visual Orange Alert Detection", 
            "Creates an orange warning page to test color-based detection",
            "PayGuard should detect orange warning colors"
        )
        
        orange_scam_html = '''
        <!DOCTYPE html>
        <html>
        <head><title>Orange Scam Test</title></head>
        <body style="background-color: #ff8800; color: white; padding: 100px; text-align: center; font-size: 36px;">
            <div style="background: #ff8800; padding: 40px;">
                🚨 WINDOWS SECURITY WARNING 🚨
                <br><br>
                Suspicious Activity Detected!
                <br><br>
                Contact Support: 1-888-555-0123
            </div>
        </body>
        </html>
        '''
        
        file_path = self.create_temp_html(orange_scam_html)
        subprocess.run(["open", file_path])
        time.sleep(8)
        
    def test_visual_yellow_alert_detection(self):
        """Test 3: Yellow Alert Screen Detection"""
        self.log_test(
            "Visual Yellow Alert Detection",
            "Creates a yellow attention-grabbing scam page",
            "PayGuard should detect yellow warning indicators"
        )
        
        yellow_scam_html = '''
        <!DOCTYPE html>
        <html>
        <head><title>Yellow Scam Test</title></head>
        <body style="background-color: #ffff00; color: black; padding: 100px; text-align: center; font-size: 36px;">
            <div style="background: #ffff00; padding: 40px; border: 5px solid #ffaa00;">
                ⚠️ URGENT SYSTEM ALERT ⚠️
                <br><br>
                Your Windows License Has Expired!
                <br><br>
                Renew Now: 1-877-555-0199
            </div>
        </body>
        </html>
        '''
        
        file_path = self.create_temp_html(yellow_scam_html)
        subprocess.run(["open", file_path])
        time.sleep(8)
        
    def test_phone_number_detection(self):
        """Test 4: Phone Number Scam Detection"""
        self.log_test(
            "Phone Number Scam Detection",
            "Tests detection of fake support phone numbers",
            "PayGuard should detect 1-800 format phone numbers"
        )
        
        phone_scam_text = "URGENT: Your computer is infected! Call Microsoft Support at 1-800-555-0199 immediately!"
        
        # Copy to clipboard
        process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
        process.communicate(phone_scam_text.encode())
        time.sleep(5)
        
    def test_urgency_tactics_detection(self):
        """Test 5: Urgency Language Detection"""
        self.log_test(
            "Urgency Tactics Detection",
            "Tests detection of urgent/immediate language",
            "PayGuard should detect urgency manipulation tactics"
        )
        
        urgency_text = "IMMEDIATE ACTION REQUIRED! ACT NOW before your account is permanently suspended! URGENT response needed!"
        
        process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
        process.communicate(urgency_text.encode())
        time.sleep(5)
        
    def test_virus_warning_detection(self):
        """Test 6: Virus Warning Detection"""
        self.log_test(
            "Virus Warning Detection",
            "Tests detection of fake virus/malware warnings",
            "PayGuard should detect virus/malware terminology"
        )
        
        virus_text = "CRITICAL: Your system is infected with a Trojan virus! Malware detected on your computer!"
        
        process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
        process.communicate(virus_text.encode())
        time.sleep(5)
        
    def test_company_impersonation_detection(self):
        """Test 7: Company Impersonation Detection"""
        self.log_test(
            "Company Impersonation Detection",
            "Tests detection of fake company security alerts",
            "PayGuard should detect fake Microsoft/Apple/Amazon alerts"
        )
        
        company_text = "Microsoft Security Alert: Your Windows license has expired. Contact Microsoft Support immediately!"
        
        process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
        process.communicate(company_text.encode())
        time.sleep(5)
        
    def test_scare_tactics_detection(self):
        """Test 8: Scare Tactics Detection"""
        self.log_test(
            "Scare Tactics Detection",
            "Tests detection of 'do not close' scare tactics",
            "PayGuard should detect scare tactic language"
        )
        
        scare_text = "DO NOT CLOSE this window or your files will be deleted! DO NOT RESTART your computer!"
        
        process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
        process.communicate(scare_text.encode())
        time.sleep(5)
        
    def test_account_threat_detection(self):
        """Test 9: Account Threat Detection"""
        self.log_test(
            "Account Threat Detection",
            "Tests detection of account suspension threats",
            "PayGuard should detect account threat language"
        )
        
        threat_text = "Your account has been suspended due to suspicious activity. Your account is blocked and will expire in 24 hours."
        
        process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
        process.communicate(threat_text.encode())
        time.sleep(5)
        
    def test_phishing_detection(self):
        """Test 10: Phishing Attempt Detection"""
        self.log_test(
            "Phishing Attempt Detection",
            "Tests detection of verify account/payment requests",
            "PayGuard should detect phishing language patterns"
        )
        
        phishing_text = "Please verify your account information immediately. Update your payment details to avoid service interruption."
        
        process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
        process.communicate(phishing_text.encode())
        time.sleep(5)
        
    def test_fake_error_code_detection(self):
        """Test 11: Fake Error Code Detection"""
        self.log_test(
            "Fake Error Code Detection",
            "Tests detection of fake error codes and reference IDs",
            "PayGuard should detect fake error code patterns"
        )
        
        error_text = "Error Code: WIN32/Trojan.Gen!Eldorado - Reference ID: SEC-2024-7891234"
        
        process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
        process.communicate(error_text.encode())
        time.sleep(5)
        
    def test_tech_support_scam_page(self):
        """Test 12: Complete Tech Support Scam Page"""
        self.log_test(
            "Tech Support Scam Page",
            "Tests a complete fake tech support scam webpage",
            "PayGuard should detect multiple scam indicators"
        )
        
        tech_support_html = '''
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
            </style>
        </head>
        <body>
            <h1>⚠️ CRITICAL SECURITY ALERT ⚠️</h1>
            <p style="font-size: 24px;">YOUR COMPUTER HAS BEEN INFECTED WITH A TROJAN VIRUS!</p>
            <p style="font-size: 20px;">DO NOT RESTART OR SHUT DOWN YOUR COMPUTER!</p>
            <div style="background: yellow; color: black; padding: 20px; margin: 20px; font-size: 24px;">
                CALL MICROSOFT SUPPORT IMMEDIATELY:<br>
                📞 1-800-555-0199
            </div>
            <p>Error Code: WIN32/Trojan.Gen!Eldorado</p>
            <p>Your personal files and banking information are at risk!</p>
        </body>
        </html>
        '''
        
        file_path = self.create_temp_html(tech_support_html)
        subprocess.run(["open", file_path])
        time.sleep(10)
        
    def test_phishing_login_page(self):
        """Test 13: Phishing Login Page"""
        self.log_test(
            "Phishing Login Page",
            "Tests detection of fake login/verification pages",
            "PayGuard should detect phishing attempt"
        )
        
        phishing_html = '''
        <!DOCTYPE html>
        <html>
        <head><title>Amazon Security Verification</title></head>
        <body style="background: #232f3e; color: white; padding: 50px; font-family: Arial;">
            <div style="background: white; color: black; padding: 30px; border-radius: 8px;">
                <h2 style="color: #ff9900;">🔒 Amazon Security Notice</h2>
                <p style="color: red; font-weight: bold;">Your account has been suspended due to suspicious activity!</p>
                <p>Please verify your account immediately to avoid permanent suspension.</p>
                <form>
                    <input type="email" placeholder="Email Address" style="width: 100%; padding: 10px; margin: 10px 0;">
                    <input type="password" placeholder="Password" style="width: 100%; padding: 10px; margin: 10px 0;">
                    <button style="background: #ff9900; color: white; padding: 15px 30px; border: none; font-size: 16px;">
                        Verify Account Now
                    </button>
                </form>
                <p style="font-size: 12px; color: #666;">
                    If you did not request this, contact security@amazon-alerts.com
                </p>
            </div>
        </body>
        </html>
        '''
        
        file_path = self.create_temp_html(phishing_html)
        subprocess.run(["open", file_path])
        time.sleep(8)
        
    def test_fake_invoice_scam(self):
        """Test 14: Fake Invoice Scam"""
        self.log_test(
            "Fake Invoice Scam",
            "Tests detection of fake invoice/payment scams",
            "PayGuard should detect fake payment requests"
        )
        
        invoice_html = '''
        <!DOCTYPE html>
        <html>
        <head><title>Invoice Payment Required</title></head>
        <body style="padding: 50px; font-family: Arial;">
            <div style="border: 2px solid #ff8800; padding: 30px; background: #fff8f0;">
                <h2 style="color: #ff8800;">📄 INVOICE PENDING PAYMENT</h2>
                <p><strong>Invoice #INV-2024-9012</strong></p>
                <p>Amount Due: <strong style="color: red; font-size: 24px;">$499.99</strong></p>
                <p>Service: Geek Squad Computer Protection Plan</p>
                <p style="color: red; font-weight: bold;">
                    URGENT: Payment required within 24 hours to avoid automatic charge!
                </p>
                <p>If you did not authorize this purchase, call immediately:</p>
                <div style="background: #ff8800; color: white; padding: 15px; text-align: center; font-size: 20px;">
                    📞 1-888-555-0199
                </div>
                <p style="font-size: 12px; color: #666;">
                    Reference ID: GS-2024-INV-7891234
                </p>
            </div>
        </body>
        </html>
        '''
        
        file_path = self.create_temp_html(invoice_html)
        subprocess.run(["open", file_path])
        time.sleep(8)
        
    def test_browser_hijack_attempt(self):
        """Test 15: Browser Hijacking Attempt"""
        self.log_test(
            "Browser Hijacking Attempt",
            "Tests detection of browser takeover attempts",
            "PayGuard should detect browser hijacking"
        )
        
        hijack_html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Browser Security Alert</title>
            <style>
                body { margin: 0; padding: 0; background: #ff0000; color: white; font-family: Arial; }
                .fullscreen { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 9999; }
                .center { display: flex; align-items: center; justify-content: center; height: 100%; text-align: center; }
            </style>
        </head>
        <body>
            <div class="fullscreen">
                <div class="center">
                    <div>
                        <h1 style="font-size: 48px;">🚨 BROWSER SECURITY BREACH 🚨</h1>
                        <p style="font-size: 24px;">Your browser has been compromised!</p>
                        <p style="font-size: 20px;">Malicious software detected!</p>
                        <div style="background: yellow; color: black; padding: 20px; margin: 20px; font-size: 24px;">
                            DO NOT CLOSE THIS WINDOW!<br>
                            CALL SECURITY: 1-877-555-0199
                        </div>
                        <p>Error: BROWSER_HIJACK_DETECTED_2024</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        '''
        
        file_path = self.create_temp_html(hijack_html)
        subprocess.run(["open", file_path])
        time.sleep(8)
        
    def test_clipboard_duplicate_prevention(self):
        """Test 16: Clipboard Duplicate Prevention"""
        self.log_test(
            "Clipboard Duplicate Prevention",
            "Tests that same clipboard content only alerts once",
            "PayGuard should NOT alert multiple times for same content"
        )
        
        duplicate_text = "Test duplicate: Call 1-800-555-0199 for urgent support!"
        
        # Copy same text multiple times
        for i in range(3):
            process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
            process.communicate(duplicate_text.encode())
            time.sleep(2)
            print(f"   Copied duplicate text #{i+1}")
        
        print("   Expected: Only ONE alert for all three copies")
        
    def test_legitimate_content_no_alert(self):
        """Test 17: Legitimate Content (No False Positives)"""
        self.log_test(
            "Legitimate Content Test",
            "Tests that normal content doesn't trigger false alerts",
            "PayGuard should NOT alert on legitimate content"
        )
        
        legitimate_html = '''
        <!DOCTYPE html>
        <html>
        <head><title>Legitimate Business Website</title></head>
        <body style="padding: 50px; font-family: Arial; background: white; color: black;">
            <header style="background: #0066cc; color: white; padding: 20px; text-align: center;">
                <h1>Welcome to Our Company</h1>
            </header>
            <main style="padding: 30px;">
                <h2>About Our Services</h2>
                <p>We provide excellent customer service and high-quality products.</p>
                <p>Our support team is available Monday through Friday, 9 AM to 5 PM.</p>
                <p>Contact us at support@company.com for assistance.</p>
                <p>Thank you for choosing our services!</p>
                <div style="background: #f0f0f0; padding: 20px; margin: 20px 0;">
                    <h3>Customer Testimonials</h3>
                    <p>"Great service and friendly staff!" - Happy Customer</p>
                    <p>"Highly recommend this company." - Satisfied Client</p>
                </div>
            </main>
        </body>
        </html>
        '''
        
        legitimate_text = "Thank you for your recent purchase. Your order will be shipped within 2-3 business days. Contact customer service if you have any questions."
        
        # Test legitimate webpage
        file_path = self.create_temp_html(legitimate_html)
        subprocess.run(["open", file_path])
        time.sleep(5)
        
        # Test legitimate clipboard content
        process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
        process.communicate(legitimate_text.encode())
        time.sleep(3)
        
        print("   Expected: NO alerts for legitimate content")
        
    def run_all_tests(self):
        """Run all PayGuard feature tests"""
        print("🛡️ PAYGUARD COMPREHENSIVE FEATURE TEST")
        print("=" * 80)
        print("This will test EVERY capability of PayGuard systematically.")
        print("Make sure PayGuard is running before starting!")
        print()
        
        # Check if PayGuard is running
        try:
            result = subprocess.run(["pgrep", "-f", "payguard_menubar.py"], capture_output=True)
            if result.returncode != 0:
                print("❌ PayGuard is not running!")
                print("   Start PayGuard first: python3 payguard_menubar.py")
                return
            else:
                print("✅ PayGuard is running - proceeding with tests")
        except:
            print("⚠️ Could not verify PayGuard status - proceeding anyway")
        
        print("\n📋 TEST CATEGORIES:")
        print("   🎨 Visual Detection Tests (5 tests)")
        print("   📝 Text Pattern Tests (8 tests)")
        print("   🌐 Complete Scam Page Tests (4 tests)")
        print("   🔧 System Feature Tests (2 tests)")
        print()
        
        input("Press Enter to start comprehensive testing...")
        
        try:
            # Visual Detection Tests
            print("\n" + "="*60)
            print("🎨 VISUAL DETECTION TESTS")
            print("="*60)
            
            self.test_visual_red_alert_detection()
            self.test_visual_orange_alert_detection()
            self.test_visual_yellow_alert_detection()
            
            # Text Pattern Tests
            print("\n" + "="*60)
            print("📝 TEXT PATTERN TESTS")
            print("="*60)
            
            self.test_phone_number_detection()
            self.test_urgency_tactics_detection()
            self.test_virus_warning_detection()
            self.test_company_impersonation_detection()
            self.test_scare_tactics_detection()
            self.test_account_threat_detection()
            self.test_phishing_detection()
            self.test_fake_error_code_detection()
            
            # Complete Scam Page Tests
            print("\n" + "="*60)
            print("🌐 COMPLETE SCAM PAGE TESTS")
            print("="*60)
            
            self.test_tech_support_scam_page()
            self.test_phishing_login_page()
            self.test_fake_invoice_scam()
            self.test_browser_hijack_attempt()
            
            # System Feature Tests
            print("\n" + "="*60)
            print("🔧 SYSTEM FEATURE TESTS")
            print("="*60)
            
            self.test_clipboard_duplicate_prevention()
            self.test_legitimate_content_no_alert()
            
        finally:
            # Cleanup
            print("\n🧹 Cleaning up test files...")
            self.cleanup_files()
        
        print("\n" + "="*80)
        print("✅ COMPREHENSIVE TEST COMPLETE!")
        print("="*80)
        print("📊 RESULTS SUMMARY:")
        print("   🎨 Visual Tests: 3 red/orange/yellow alert tests")
        print("   📝 Text Tests: 8 pattern detection tests")
        print("   🌐 Page Tests: 4 complete scam page tests")
        print("   🔧 System Tests: 2 feature validation tests")
        print("   📁 Files: All temporary files cleaned up")
        print()
        print("🛡️ PayGuard should have detected and alerted on:")
        print("   ✅ 14 different scam attempts")
        print("   ✅ Multiple visual scam indicators")
        print("   ✅ Various text-based scam patterns")
        print("   ✅ Complete scam page scenarios")
        print()
        print("🎯 PayGuard should NOT have alerted on:")
        print("   ✅ Legitimate business content")
        print("   ✅ Duplicate clipboard content (after first alert)")
        print()
        print("📱 Check your notifications to verify all alerts were received!")

def main():
    """Main test function"""
    tester = PayGuardComprehensiveTest()
    tester.run_all_tests()

if __name__ == "__main__":
    main()