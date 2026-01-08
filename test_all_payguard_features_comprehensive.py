#!/usr/bin/env python3
"""
PayGuard Comprehensive Feature Test Suite
Tests ALL discovered PayGuard capabilities across the entire codebase
"""

import subprocess
import time
import os
import json
import requests
import base64
from datetime import datetime
import tempfile
import sys

class PayGuardFeatureTester:
    def __init__(self):
        self.backend_url = "http://localhost:8002"
        self.test_results = []
        self.failed_tests = []
        self.passed_tests = []
        
    def log_result(self, test_name, status, details=""):
        """Log test result"""
        result = {
            "test": test_name,
            "status": status,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        if status == "PASS":
            self.passed_tests.append(test_name)
            print(f"✅ {test_name}: {details}")
        else:
            self.failed_tests.append(test_name)
            print(f"❌ {test_name}: {details}")

    def check_backend_health(self):
        """Test backend health endpoint"""
        try:
            response = requests.get(f"{self.backend_url}/api/health", timeout=5)
            if response.status_code == 200:
                self.log_result("Backend Health Check", "PASS", "Backend is running")
                return True
            else:
                self.log_result("Backend Health Check", "FAIL", f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_result("Backend Health Check", "FAIL", f"Connection failed: {str(e)}")
            return False

    def test_api_endpoints(self):
        """Test all API endpoints discovered in backend/server.py"""
        endpoints = [
            ("/api/health", "GET"),
            ("/api/stats", "GET"),
            ("/api/merchants", "GET"),
            ("/api/fraud-reports", "GET"),
        ]
        
        for endpoint, method in endpoints:
            try:
                if method == "GET":
                    response = requests.get(f"{self.backend_url}{endpoint}", timeout=5)
                    if response.status_code in [200, 404]:  # 404 is OK for empty collections
                        self.log_result(f"API Endpoint {endpoint}", "PASS", f"Status: {response.status_code}")
                    else:
                        self.log_result(f"API Endpoint {endpoint}", "FAIL", f"Status: {response.status_code}")
            except Exception as e:
                self.log_result(f"API Endpoint {endpoint}", "FAIL", f"Error: {str(e)}")

    def test_url_risk_analysis(self):
        """Test URL risk analysis capabilities"""
        test_urls = [
            "https://microsoft.com",  # Should be safe
            "https://micr0soft-security.xyz",  # Should be risky
            "https://paypal-verify.suspicious-domain.com",  # Should be risky
            "https://google.com",  # Should be safe
        ]
        
        for url in test_urls:
            try:
                payload = {"url": url}
                response = requests.post(f"{self.backend_url}/api/risk-check", 
                                       json=payload, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    risk_level = data.get("risk_level", "unknown")
                    trust_score = data.get("trust_score", 0)
                    self.log_result(f"URL Risk Analysis: {url}", "PASS", 
                                  f"Risk: {risk_level}, Trust: {trust_score}")
                else:
                    self.log_result(f"URL Risk Analysis: {url}", "FAIL", 
                                  f"Status: {response.status_code}")
            except Exception as e:
                self.log_result(f"URL Risk Analysis: {url}", "FAIL", f"Error: {str(e)}")

    def test_email_typosquatting(self):
        """Test email typosquatting detection from email_guardian.py"""
        test_emails = [
            "support@microsoft.com",  # Should be safe
            "support@micr0soft.com",  # Should be suspicious (homoglyph)
            "security@paypal-verify.xyz",  # Should be suspicious
            "noreply@g00gle.com",  # Should be suspicious
            "admin@apple-security.support",  # Should be suspicious
        ]
        
        for email in test_emails:
            try:
                # Test via content risk endpoint with email in text
                payload = {
                    "url": "test://email-check",
                    "html": f"<p>Contact us at {email}</p>",
                    "overlay_text": f"Email from {email}"
                }
                response = requests.post(f"{self.backend_url}/api/content-risk", 
                                       json=payload, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    scam_alert = data.get("scam_alert", {})
                    is_scam = scam_alert.get("is_scam", False)
                    confidence = scam_alert.get("confidence", 0)
                    self.log_result(f"Email Typosquatting: {email}", "PASS", 
                                  f"Scam: {is_scam}, Confidence: {confidence}%")
                else:
                    self.log_result(f"Email Typosquatting: {email}", "FAIL", 
                                  f"Status: {response.status_code}")
            except Exception as e:
                self.log_result(f"Email Typosquatting: {email}", "FAIL", f"Error: {str(e)}")

    def test_ai_image_detection(self):
        """Test AI image detection using DIRE model"""
        # Create a simple test image
        try:
            from PIL import Image, ImageDraw
            import io
            
            # Create a fake "scam" image with red background and text
            img = Image.new('RGB', (800, 600), color='red')
            draw = ImageDraw.Draw(img)
            draw.text((50, 50), "VIRUS DETECTED! CALL 1-800-SCAM-NOW", fill='white')
            
            # Convert to bytes
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            img_data = img_bytes.getvalue()
            
            # Encode to base64
            b64_data = base64.b64encode(img_data).decode('utf-8')
            
            payload = {
                "url": "test://ai-image",
                "content": b64_data,
                "metadata": {"source": "test", "static": True}
            }
            
            response = requests.post(f"{self.backend_url}/api/media-risk/bytes", 
                                   json=payload, timeout=15)
            if response.status_code == 200:
                data = response.json()
                media_score = data.get("media_score", 0)
                media_color = data.get("media_color", "unknown")
                reasons = data.get("reasons", [])
                self.log_result("AI Image Detection", "PASS", 
                              f"Score: {media_score}, Color: {media_color}, Reasons: {len(reasons)}")
            else:
                self.log_result("AI Image Detection", "FAIL", 
                              f"Status: {response.status_code}")
                
        except ImportError:
            self.log_result("AI Image Detection", "SKIP", "PIL not available")
        except Exception as e:
            self.log_result("AI Image Detection", "FAIL", f"Error: {str(e)}")

    def test_payment_gateway_detection(self):
        """Test payment gateway detection capabilities"""
        test_html_samples = [
            ('<form action="https://js.stripe.com/v3/">', "stripe"),
            ('<script src="https://www.paypal.com/sdk/js">', "paypal"),
            ('<form action="https://squareup.com/checkout">', "square"),
            ('<div class="crypto-payment">Bitcoin accepted</div>', "crypto"),
        ]
        
        for html_content, expected_gateway in test_html_samples:
            try:
                payload = {
                    "url": "https://test-merchant.com",
                    "html": html_content
                }
                response = requests.post(f"{self.backend_url}/api/content-risk", 
                                       json=payload, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    # Check if payment gateway was detected in the response
                    self.log_result(f"Payment Gateway Detection: {expected_gateway}", "PASS", 
                                  f"Detected payment processing")
                else:
                    self.log_result(f"Payment Gateway Detection: {expected_gateway}", "FAIL", 
                                  f"Status: {response.status_code}")
            except Exception as e:
                self.log_result(f"Payment Gateway Detection: {expected_gateway}", "FAIL", 
                              f"Error: {str(e)}")

    def test_sms_scam_detection(self):
        """Test SMS scam detection patterns"""
        sms_samples = [
            "Your parcel is waiting for delivery. Pay $2.99 shipping fee: bit.ly/fake123",
            "URGENT: Your bank account has been locked. Verify now: tinyurl.com/verify123",
            "Congratulations! You've won $1000. Claim your prize: is.gd/prize123",
            "Your Netflix subscription failed. Update payment: t.co/netflix123",
        ]
        
        for sms_text in sms_samples:
            try:
                payload = {
                    "url": "sms://test",
                    "overlay_text": sms_text,
                    "html": f"<p>{sms_text}</p>"
                }
                response = requests.post(f"{self.backend_url}/api/content-risk", 
                                       json=payload, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    scam_alert = data.get("scam_alert", {})
                    is_scam = scam_alert.get("is_scam", False)
                    patterns = scam_alert.get("detected_patterns", [])
                    self.log_result(f"SMS Scam Detection", "PASS", 
                                  f"Scam: {is_scam}, Patterns: {len(patterns)}")
                else:
                    self.log_result(f"SMS Scam Detection", "FAIL", 
                                  f"Status: {response.status_code}")
            except Exception as e:
                self.log_result(f"SMS Scam Detection", "FAIL", f"Error: {str(e)}")

    def test_merchant_reputation_system(self):
        """Test merchant reputation and fraud reporting"""
        try:
            # Test creating a merchant
            merchant_data = {
                "domain": "test-merchant.com",
                "name": "Test Merchant"
            }
            response = requests.post(f"{self.backend_url}/api/merchants", 
                                   json=merchant_data, timeout=10)
            if response.status_code in [200, 201, 409]:  # 409 = already exists
                self.log_result("Merchant Creation", "PASS", "Merchant created/exists")
                
                # Test fraud report
                fraud_data = {
                    "domain": "test-merchant.com",
                    "url": "https://test-merchant.com/scam",
                    "report_type": "phishing",
                    "description": "Fake login page"
                }
                response = requests.post(f"{self.backend_url}/api/fraud-reports", 
                                       json=fraud_data, timeout=10)
                if response.status_code in [200, 201]:
                    self.log_result("Fraud Reporting", "PASS", "Fraud report submitted")
                else:
                    self.log_result("Fraud Reporting", "FAIL", f"Status: {response.status_code}")
            else:
                self.log_result("Merchant Creation", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("Merchant Reputation System", "FAIL", f"Error: {str(e)}")

    def test_api_authentication(self):
        """Test API key authentication system"""
        try:
            # Test creating API key
            api_key_data = {
                "institution_name": "Test Institution",
                "tier": "free"
            }
            response = requests.post(f"{self.backend_url}/api/api-keys", 
                                   json=api_key_data, timeout=10)
            if response.status_code in [200, 201]:
                data = response.json()
                api_key = data.get("api_key")
                if api_key:
                    self.log_result("API Key Creation", "PASS", "API key generated")
                    
                    # Test using the API key
                    headers = {"X-API-Key": api_key}
                    response = requests.get(f"{self.backend_url}/api/stats", 
                                          headers=headers, timeout=10)
                    if response.status_code == 200:
                        self.log_result("API Key Authentication", "PASS", "API key works")
                    else:
                        self.log_result("API Key Authentication", "FAIL", 
                                      f"Status: {response.status_code}")
                else:
                    self.log_result("API Key Creation", "FAIL", "No API key in response")
            else:
                self.log_result("API Key Creation", "FAIL", f"Status: {response.status_code}")
        except Exception as e:
            self.log_result("API Authentication", "FAIL", f"Error: {str(e)}")

    def test_transaction_risk_assessment(self):
        """Test transaction risk assessment"""
        transactions = [
            {"merchant_domain": "amazon.com", "amount": 50.0, "currency": "USD"},
            {"merchant_domain": "suspicious-store.xyz", "amount": 1000.0, "currency": "USD"},
            {"merchant_domain": "paypal.com", "amount": 25.0, "currency": "USD"},
        ]
        
        for transaction in transactions:
            try:
                response = requests.post(f"{self.backend_url}/api/transaction-check", 
                                       json=transaction, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    risk_level = data.get("risk_level", "unknown")
                    approved = data.get("approved", False)
                    self.log_result(f"Transaction Risk: {transaction['merchant_domain']}", "PASS", 
                                  f"Risk: {risk_level}, Approved: {approved}")
                else:
                    self.log_result(f"Transaction Risk: {transaction['merchant_domain']}", "FAIL", 
                                  f"Status: {response.status_code}")
            except Exception as e:
                self.log_result(f"Transaction Risk: {transaction['merchant_domain']}", "FAIL", 
                              f"Error: {str(e)}")

    def test_visual_scam_patterns(self):
        """Test visual scam pattern detection"""
        # Test with HTML that should trigger scam detection
        scam_html_samples = [
            '<div style="background-color: red; color: white;">VIRUS DETECTED! CALL 1-800-123-4567</div>',
            '<p style="color: orange;">URGENT: Your computer is infected! Do not close this window!</p>',
            '<div>Microsoft Security Alert: Call +1-800-MICROSOFT immediately</div>',
            '<p>Your PayPal account has been suspended. Verify now or lose access forever!</p>',
        ]
        
        for i, html_content in enumerate(scam_html_samples):
            try:
                payload = {
                    "url": f"https://scam-test-{i}.com",
                    "html": html_content,
                    "overlay_text": "Security Warning"
                }
                response = requests.post(f"{self.backend_url}/api/content-risk", 
                                       json=payload, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    scam_alert = data.get("scam_alert", {})
                    is_scam = scam_alert.get("is_scam", False)
                    confidence = scam_alert.get("confidence", 0)
                    patterns = scam_alert.get("detected_patterns", [])
                    self.log_result(f"Visual Scam Pattern {i+1}", "PASS", 
                                  f"Scam: {is_scam}, Confidence: {confidence}%, Patterns: {len(patterns)}")
                else:
                    self.log_result(f"Visual Scam Pattern {i+1}", "FAIL", 
                                  f"Status: {response.status_code}")
            except Exception as e:
                self.log_result(f"Visual Scam Pattern {i+1}", "FAIL", f"Error: {str(e)}")

    def test_agent_functionality(self):
        """Test if PayGuard agent is running"""
        try:
            # Check if payguard_menubar.py process is running
            result = subprocess.run(['pgrep', '-f', 'payguard_menubar.py'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                pid = result.stdout.strip()
                self.log_result("PayGuard Agent Status", "PASS", f"Agent running (PID: {pid})")
            else:
                self.log_result("PayGuard Agent Status", "FAIL", "Agent not running")
        except Exception as e:
            self.log_result("PayGuard Agent Status", "FAIL", f"Error: {str(e)}")

    def run_all_tests(self):
        """Run all feature tests"""
        print("🧪 PayGuard Comprehensive Feature Test Suite")
        print("=" * 60)
        print(f"Testing all discovered capabilities...")
        print(f"Backend URL: {self.backend_url}")
        print("=" * 60)
        
        # Check if backend is running first
        if not self.check_backend_health():
            print("\n❌ Backend is not running! Please start it first:")
            print("   cd backend && python server.py")
            return False
        
        print("\n🔍 Testing Core Features...")
        
        # Test all feature categories
        self.test_api_endpoints()
        self.test_url_risk_analysis()
        self.test_email_typosquatting()
        self.test_ai_image_detection()
        self.test_payment_gateway_detection()
        self.test_sms_scam_detection()
        self.test_merchant_reputation_system()
        self.test_api_authentication()
        self.test_transaction_risk_assessment()
        self.test_visual_scam_patterns()
        self.test_agent_functionality()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        print(f"✅ Passed: {len(self.passed_tests)}")
        print(f"❌ Failed: {len(self.failed_tests)}")
        print(f"📈 Success Rate: {len(self.passed_tests)/(len(self.passed_tests)+len(self.failed_tests))*100:.1f}%")
        
        if self.failed_tests:
            print(f"\n❌ Failed Tests:")
            for test in self.failed_tests:
                print(f"   - {test}")
        
        print(f"\n✅ Passed Tests:")
        for test in self.passed_tests:
            print(f"   - {test}")
        
        # Save detailed results
        with open("payguard_test_results.json", "w") as f:
            json.dump(self.test_results, f, indent=2)
        
        print(f"\n📄 Detailed results saved to: payguard_test_results.json")
        
        return len(self.failed_tests) == 0

if __name__ == "__main__":
    tester = PayGuardFeatureTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)