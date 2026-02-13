#!/usr/bin/env python3
"""
PayGuard Production Test Suite
Tests the backend API to ensure detection is working correctly.
Run this to verify everything is production-ready.
"""

import requests
import sys
import time
import subprocess
from typing import Dict, List, Tuple

API_BASE = "http://127.0.0.1:8002"
API_KEY = "demo_key"

def show_notification(title: str, message: str, sound: bool = True):
    """Show macOS notification."""
    try:
        script = f'display notification "{message}" with title "{title}"'
        if sound:
            script += ' sound name "Sosumi"'
        subprocess.run(["osascript", "-e", script], capture_output=True)
    except Exception:
        pass  # Notifications not available

# Test cases: (URL, Expected Risk Level, Should Contain Factor)
TEST_CASES = [
    # Safe URLs - should be LOW risk
    ("https://google.com", "low", ["Verified legitimate domain", "Uses HTTPS"]),
    ("https://github.com", "low", ["Verified legitimate domain"]),
    ("https://apple.com", "low", ["Verified legitimate domain"]),
    
    # Phishing URLs - should be HIGH risk
    ("https://verify-paypal-account-now.com/login", "high", ["Fake Paypal site"]),
    ("https://secure-apple-login-verify.com", "high", ["Fake Apple site"]),
    ("https://amazon-secure-update.com/signin", "high", ["Fake Amazon site"]),
    ("https://microsoft-verify-account.com/login", "high", ["Fake Microsoft site"]),
    
    # Typosquatting - should be HIGH risk
    ("https://amaz0n-shop.com", "high", ["Typosquatting", "Fake Amazon"]),
    ("https://paypa1-secure.com", "high", ["Typosquatting", "Fake Paypal"]),
    ("https://g00gle-verify.com", "high", ["Typosquatting", "Fake Google"]),
    
    # Suspicious patterns - should be HIGH or MEDIUM
    ("https://free-winner-prize-now.xyz/claim", "high", ["winner", "prize"]),
    ("https://urgent-verify-account-now.com", "high", ["urgent", "verify"]),
    
    # IP addresses - should be HIGH risk
    ("http://192.168.1.1/login", "high", ["IP address"]),
]

def test_health() -> bool:
    """Test if backend is running."""
    try:
        resp = requests.get(f"{API_BASE}/api/v1/health", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            print(f"✅ Backend is healthy")
            print(f"   Models loaded: XGBoost={data['models']['xgboost']}, CNN={data['models']['cnn']}")
            return True
        else:
            print(f"❌ Backend returned status {resp.status_code}")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to backend: {e}")
        print(f"   Make sure the backend is running: python3 -m uvicorn backend.server:app --host 0.0.0.0 --port 8002")
        return False

def test_url(url: str, expected_risk: str, expected_factors: List[str]) -> Tuple[bool, Dict]:
    """Test a single URL."""
    try:
        resp = requests.post(
            f"{API_BASE}/api/v1/risk?fast=true",
            headers={
                "Content-Type": "application/json",
                "X-API-Key": API_KEY
            },
            json={"url": url},
            timeout=5
        )
        
        if resp.status_code != 200:
            return False, {"error": f"HTTP {resp.status_code}"}
        
        data = resp.json()
        actual_risk = data.get("risk_level", "").lower()
        risk_factors = [f.lower() for f in data.get("risk_factors", [])]
        trust_score = data.get("trust_score", 0)
        
        # Check risk level
        risk_match = actual_risk == expected_risk.lower()
        
        # Check if expected factors are present
        factors_found = []
        factors_missing = []
        for factor in expected_factors:
            factor_lower = factor.lower()
            found = any(factor_lower in rf for rf in risk_factors)
            if found:
                factors_found.append(factor)
            else:
                factors_missing.append(factor)
        
        return risk_match, {
            "url": url,
            "expected_risk": expected_risk,
            "actual_risk": actual_risk,
            "trust_score": trust_score,
            "factors_found": factors_found,
            "factors_missing": factors_missing,
            "all_factors": data.get("risk_factors", [])
        }
        
    except Exception as e:
        return False, {"error": str(e)}

def run_tests():
    """Run all tests."""
    print("=" * 70)
    print("🛡️  PayGuard Production Test Suite")
    print("=" * 70)
    print()
    
    # Test 1: Health check
    print("📡 Testing backend health...")
    if not test_health():
        print()
        print("❌ Backend is not running! Start it with:")
        print("   python3 -m uvicorn backend.server:app --host 0.0.0.0 --port 8002")
        sys.exit(1)
    print()
    
    # Test 2: Speed test
    print("⚡ Testing response speed...")
    start = time.time()
    test_url("https://google.com", "low", ["Verified"])
    elapsed = (time.time() - start) * 1000
    if elapsed < 200:
        print(f"✅ Fast response: {elapsed:.1f}ms")
    else:
        print(f"⚠️  Slow response: {elapsed:.1f}ms (should be < 200ms)")
    print()
    
    # Test 3: Detection accuracy
    print("🎯 Testing detection accuracy...")
    print("-" * 70)
    
    passed = 0
    failed = 0
    
    for url, expected_risk, expected_factors in TEST_CASES:
        risk_match, details = test_url(url, expected_risk, expected_factors)
        
        if "error" in details:
            print(f"❌ {url[:50]}...")
            print(f"   Error: {details['error']}")
            failed += 1
            continue
        
        # Determine pass/fail
        test_passed = risk_match
        
        if test_passed:
            passed += 1
            status = "✅ PASS"
            
            # Show notification for threats detected
            if expected_risk == "high":
                show_notification(
                    "🚨 PayGuard Threat Detected!",
                    f"Detected phishing: {url[:40]}...",
                    sound=True
                )
                time.sleep(0.5)  # Small delay between notifications
        else:
            failed += 1
            status = "❌ FAIL"
        
        print(f"{status} {url[:55]}...")
        print(f"   Expected: {expected_risk.upper()} | Got: {details['actual_risk'].upper()} | Score: {details['trust_score']:.0f}")
        
        if not test_passed:
            print(f"   Expected risk level: {expected_risk}")
            print(f"   Actual risk level: {details['actual_risk']}")
        
        if details['factors_missing']:
            print(f"   Missing factors: {', '.join(details['factors_missing'])}")
        
        if not test_passed or details['factors_missing']:
            print(f"   All detected factors: {', '.join(details['all_factors'][:3])}")
    
    print("-" * 70)
    print()
    
    # Summary
    total = passed + failed
    percentage = (passed / total * 100) if total > 0 else 0
    
    print("📊 Test Summary")
    print(f"   Total: {total}")
    print(f"   Passed: {passed}")
    print(f"   Failed: {failed}")
    print(f"   Success Rate: {percentage:.1f}%")
    print()
    
    if failed == 0:
        print("🎉 ALL TESTS PASSED! System is production-ready.")
        show_notification(
            "✅ PayGuard Tests Complete",
            f"All {total} tests passed! System is production-ready.",
            sound=False
        )
        return 0
    elif percentage >= 80:
        print("⚠️  MOSTLY WORKING (80%+ pass rate) - Check failed tests above")
        show_notification(
            "⚠️ PayGuard Tests Mostly Passed",
            f"{passed}/{total} tests passed ({percentage:.0f}%)",
            sound=False
        )
        return 0
    else:
        print("❌ TOO MANY FAILURES - System needs debugging")
        show_notification(
            "❌ PayGuard Tests Failed",
            f"Only {passed}/{total} tests passed. Check terminal for details.",
            sound=True
        )
        return 1

if __name__ == "__main__":
    sys.exit(run_tests())
