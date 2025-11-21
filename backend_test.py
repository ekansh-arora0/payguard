#!/usr/bin/env python3
"""
PayGuard Backend API Test Suite
Tests all endpoints thoroughly including authentication, risk scoring, and data persistence.
"""

import asyncio
import aiohttp
import json
import time
from typing import Dict, Any, Optional
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/app/frontend/.env')

class PayGuardAPITester:
    def __init__(self):
        self.base_url = os.getenv('REACT_APP_BACKEND_URL', 'http://localhost:8001')
        self.api_url = f"{self.base_url}/api"
        self.api_key = None
        self.session = None
        self.test_results = []
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def log_test(self, test_name: str, success: bool, details: str = "", response_time: float = 0):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        result = {
            "test": test_name,
            "status": status,
            "success": success,
            "details": details,
            "response_time": f"{response_time:.3f}s" if response_time > 0 else "N/A"
        }
        self.test_results.append(result)
        print(f"{status} {test_name} ({response_time:.3f}s): {details}")
    
    async def make_request(self, method: str, endpoint: str, data: Dict = None, 
                          headers: Dict = None, params: Dict = None) -> tuple:
        """Make HTTP request and return response, status, and timing"""
        url = f"{self.api_url}{endpoint}"
        
        # Add API key to headers if available
        if self.api_key and headers is None:
            headers = {}
        if self.api_key:
            headers = headers or {}
            headers['X-API-Key'] = self.api_key
        
        start_time = time.time()
        try:
            async with self.session.request(
                method, url, json=data, headers=headers, params=params
            ) as response:
                response_time = time.time() - start_time
                try:
                    response_data = await response.json()
                except:
                    response_data = await response.text()
                
                return response_data, response.status, response_time
        except Exception as e:
            response_time = time.time() - start_time
            return {"error": str(e)}, 0, response_time
    
    async def test_basic_health_checks(self):
        """Test basic health check endpoints"""
        print("\n=== Testing Basic Health Checks ===")
        
        # Test root endpoint
        response, status, response_time = await self.make_request("GET", "/")
        success = status == 200 and "PayGuard API" in str(response)
        details = f"Status: {status}, Response: {response}"
        self.log_test("GET /api/ - API Info", success, details, response_time)
        
        # Test health endpoint
        response, status, response_time = await self.make_request("GET", "/health")
        success = status == 200 and response.get("status") == "healthy"
        details = f"Status: {status}, Health: {response.get('status', 'unknown')}"
        self.log_test("GET /api/health - Health Check", success, details, response_time)
    
    async def test_api_key_generation(self):
        """Test API key generation and management"""
        print("\n=== Testing API Key Generation ===")
        
        # Generate API key
        data = {
            "institution_name": "PayGuard Test Bank",
            "tier": "premium"
        }
        
        response, status, response_time = await self.make_request("POST", "/api-key/generate", data)
        success = status == 200 and "api_key" in response
        
        if success:
            self.api_key = response["api_key"]
            details = f"Status: {status}, Institution: {response.get('institution_name')}, Tier: {response.get('tier')}"
        else:
            details = f"Status: {status}, Error: {response}"
        
        self.log_test("POST /api/api-key/generate", success, details, response_time)
        
        return success
    
    async def test_risk_assessment(self):
        """Test risk assessment endpoints"""
        print("\n=== Testing Risk Assessment ===")
        
        # Test POST /api/risk with safe URL
        safe_url_data = {"url": "https://stripe.com/checkout"}
        response, status, response_time = await self.make_request("POST", "/risk", safe_url_data)
        
        success = (status == 200 and 
                  "trust_score" in response and 
                  "risk_level" in response and
                  response.get("risk_level") in ["low", "medium", "high"] and
                  0 <= response.get("trust_score", -1) <= 100)
        
        details = f"Status: {status}, Trust Score: {response.get('trust_score')}, Risk: {response.get('risk_level')}"
        self.log_test("POST /api/risk - Safe URL (Stripe)", success, details, response_time)
        
        # Verify response time is under 500ms
        if response_time > 0.5:
            self.log_test("Risk Assessment Response Time", False, f"Response time {response_time:.3f}s exceeds 500ms limit")
        else:
            self.log_test("Risk Assessment Response Time", True, f"Response time {response_time:.3f}s within 500ms limit")
        
        # Test POST /api/risk with suspicious URL
        suspicious_url_data = {"url": "https://suspicious-verify-account-123.com/payment"}
        response, status, response_time = await self.make_request("POST", "/risk", suspicious_url_data)
        
        success = (status == 200 and 
                  "trust_score" in response and 
                  "risk_level" in response and
                  len(response.get("risk_factors", [])) > 0)
        
        details = f"Status: {status}, Trust Score: {response.get('trust_score')}, Risk Factors: {len(response.get('risk_factors', []))}"
        self.log_test("POST /api/risk - Suspicious URL", success, details, response_time)
        
        # Test GET /api/risk
        params = {"url": "https://amazon.com"}
        response, status, response_time = await self.make_request("GET", "/risk", params=params)
        
        success = (status == 200 and 
                  "trust_score" in response and 
                  "ssl_valid" in response and
                  "education_message" in response)
        
        details = f"Status: {status}, SSL Valid: {response.get('ssl_valid')}, Has Education: {'education_message' in response}"
        self.log_test("GET /api/risk - Amazon URL", success, details, response_time)
    
    async def test_merchant_management(self):
        """Test merchant management endpoints"""
        print("\n=== Testing Merchant Management ===")
        
        # Test GET /api/merchant/history
        response, status, response_time = await self.make_request("GET", "/merchant/history")
        success = status == 200 and isinstance(response, list)
        details = f"Status: {status}, Merchants returned: {len(response) if isinstance(response, list) else 'N/A'}"
        self.log_test("GET /api/merchant/history", success, details, response_time)
        
        # Test POST /api/merchant - Create merchant
        merchant_data = {
            "domain": "testmerchant.com",
            "name": "Test Merchant Corp"
        }
        response, status, response_time = await self.make_request("POST", "/merchant", merchant_data)
        success = status == 200 and response.get("domain") == "testmerchant.com"
        details = f"Status: {status}, Domain: {response.get('domain')}, Name: {response.get('name')}"
        self.log_test("POST /api/merchant - Create Merchant", success, details, response_time)
        
        # Test GET /api/merchant/{domain}
        response, status, response_time = await self.make_request("GET", "/merchant/testmerchant.com")
        success = status == 200 and response.get("domain") == "testmerchant.com"
        details = f"Status: {status}, Found merchant: {response.get('domain') == 'testmerchant.com'}"
        self.log_test("GET /api/merchant/{domain}", success, details, response_time)
    
    async def test_transaction_checks(self):
        """Test transaction check endpoints"""
        print("\n=== Testing Transaction Checks ===")
        
        # Test low-risk transaction
        transaction_data = {
            "merchant_domain": "stripe.com",
            "amount": 50.00,
            "currency": "USD"
        }
        response, status, response_time = await self.make_request("POST", "/transaction/check", transaction_data)
        success = (status == 200 and 
                  "approved" in response and
                  "risk_score" in response and
                  "risk_level" in response)
        
        details = f"Status: {status}, Approved: {response.get('approved')}, Risk Score: {response.get('risk_score')}"
        self.log_test("POST /api/transaction/check - Low Risk", success, details, response_time)
        
        # Test high-risk transaction
        high_risk_data = {
            "merchant_domain": "suspicious-site.com",
            "amount": 5000.00,
            "currency": "USD"
        }
        response, status, response_time = await self.make_request("POST", "/transaction/check", high_risk_data)
        success = (status == 200 and 
                  "approved" in response and
                  "reasons" in response)
        
        approved = response.get("approved", True)
        details = f"Status: {status}, Approved: {approved}, Reasons: {len(response.get('reasons', []))}"
        self.log_test("POST /api/transaction/check - High Risk", success, details, response_time)
    
    async def test_fraud_reporting(self):
        """Test fraud reporting endpoints"""
        print("\n=== Testing Fraud Reporting ===")
        
        # Test POST /api/fraud/report
        fraud_data = {
            "domain": "scam-site.com",
            "url": "https://scam-site.com",
            "report_type": "phishing",
            "description": "Fake payment page mimicking legitimate bank"
        }
        response, status, response_time = await self.make_request("POST", "/fraud/report", fraud_data)
        success = (status == 200 and 
                  response.get("domain") == "scam-site.com" and
                  response.get("report_type") == "phishing")
        
        details = f"Status: {status}, Domain: {response.get('domain')}, Type: {response.get('report_type')}"
        self.log_test("POST /api/fraud/report", success, details, response_time)
        
        # Test GET /api/fraud/reports
        params = {"domain": "scam-site.com"}
        response, status, response_time = await self.make_request("GET", "/fraud/reports", params=params)
        success = status == 200 and isinstance(response, list) and len(response) > 0
        details = f"Status: {status}, Reports found: {len(response) if isinstance(response, list) else 0}"
        self.log_test("GET /api/fraud/reports", success, details, response_time)
    
    async def test_custom_rules(self):
        """Test custom rules for institutions"""
        print("\n=== Testing Custom Rules ===")
        
        # Test POST /api/institution/custom-rules
        rule_data = {
            "rule_name": "Block High Risk Transactions",
            "rule_type": "risk_threshold",
            "parameters": {"max_risk_score": 30}
        }
        response, status, response_time = await self.make_request("POST", "/institution/custom-rules", rule_data)
        success = (status == 200 and 
                  response.get("rule_name") == "Block High Risk Transactions" and
                  response.get("rule_type") == "risk_threshold")
        
        details = f"Status: {status}, Rule: {response.get('rule_name')}, Type: {response.get('rule_type')}"
        self.log_test("POST /api/institution/custom-rules", success, details, response_time)
        
        # Test GET /api/institution/custom-rules
        response, status, response_time = await self.make_request("GET", "/institution/custom-rules")
        success = status == 200 and isinstance(response, list)
        details = f"Status: {status}, Rules returned: {len(response) if isinstance(response, list) else 0}"
        self.log_test("GET /api/institution/custom-rules", success, details, response_time)
    
    async def test_statistics(self):
        """Test statistics endpoint"""
        print("\n=== Testing Statistics ===")
        
        response, status, response_time = await self.make_request("GET", "/stats")
        success = (status == 200 and 
                  "total_checks" in response and
                  "merchants_tracked" in response and
                  "avg_trust_score" in response)
        
        details = f"Status: {status}, Total Checks: {response.get('total_checks')}, Merchants: {response.get('merchants_tracked')}"
        self.log_test("GET /api/stats", success, details, response_time)
    
    async def test_authentication_errors(self):
        """Test authentication and error handling"""
        print("\n=== Testing Authentication & Error Handling ===")
        
        # Test protected endpoint without API key
        old_api_key = self.api_key
        self.api_key = None
        
        response, status, response_time = await self.make_request("POST", "/merchant", {"domain": "test.com"})
        success = status == 401 or status == 422  # Should require authentication
        details = f"Status: {status}, Properly rejected unauthenticated request"
        self.log_test("Authentication Required - POST /api/merchant", success, details, response_time)
        
        # Test with invalid API key
        self.api_key = "invalid-key-12345"
        response, status, response_time = await self.make_request("POST", "/merchant", {"domain": "test.com"})
        success = status == 401  # Should reject invalid key
        details = f"Status: {status}, Properly rejected invalid API key"
        self.log_test("Invalid API Key Rejection", success, details, response_time)
        
        # Restore valid API key
        self.api_key = old_api_key
        
        # Test invalid input data
        response, status, response_time = await self.make_request("POST", "/risk", {"invalid_field": "test"})
        success = status == 422  # Should validate input
        details = f"Status: {status}, Properly validated input data"
        self.log_test("Input Validation", success, details, response_time)
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*60)
        print("PAYGUARD API TEST SUMMARY")
        print("="*60)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result["success"])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print(f"\n❌ FAILED TESTS ({failed_tests}):")
            for result in self.test_results:
                if not result["success"]:
                    print(f"  • {result['test']}: {result['details']}")
        
        print(f"\n✅ PASSED TESTS ({passed_tests}):")
        for result in self.test_results:
            if result["success"]:
                print(f"  • {result['test']}")
        
        return failed_tests == 0
    
    async def run_all_tests(self):
        """Run all test suites"""
        print("Starting PayGuard API Test Suite...")
        print(f"Testing API at: {self.api_url}")
        
        # Basic health checks (no auth required)
        await self.test_basic_health_checks()
        
        # Generate API key for authenticated tests
        api_key_success = await self.test_api_key_generation()
        
        if not api_key_success:
            print("❌ API key generation failed - skipping authenticated tests")
            return False
        
        # Run all authenticated tests
        await self.test_risk_assessment()
        await self.test_merchant_management()
        await self.test_transaction_checks()
        await self.test_fraud_reporting()
        await self.test_custom_rules()
        await self.test_statistics()
        await self.test_authentication_errors()
        
        # Print summary
        return self.print_summary()

async def main():
    """Main test runner"""
    async with PayGuardAPITester() as tester:
        success = await tester.run_all_tests()
        return success

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)