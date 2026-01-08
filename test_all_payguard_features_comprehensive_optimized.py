#!/usr/bin/env python3
"""
PayGuard Comprehensive Feature Test Suite - Optimized Version
Tests ALL discovered PayGuard capabilities with performance optimizations and better error handling
"""

import asyncio
import aiohttp
import concurrent.futures
import time
import os
import json
import base64
from datetime import datetime
import tempfile
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from contextlib import asynccontextmanager
import subprocess
from functools import wraps
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TestStatus(Enum):
    """Test result status enumeration"""
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"

@dataclass
class TestResult:
    """Structured test result"""
    test_name: str
    status: TestStatus
    details: str
    duration: float
    timestamp: str
    error_details: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class TestConfig:
    """Test configuration"""
    backend_url: str = "http://localhost:8002"
    timeout: int = 30
    max_concurrent: int = 5
    retry_attempts: int = 3
    retry_delay: float = 1.0

class PayGuardFeatureTesterOptimized:
    """Optimized PayGuard feature tester with async operations and connection pooling"""
    
    def __init__(self, config: TestConfig = None):
        self.config = config or TestConfig()
        self.test_results: List[TestResult] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self._temp_files: List[Path] = []
        
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            limit=self.config.max_concurrent,
            limit_per_host=self.config.max_concurrent,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "PayGuard-Tester/1.0"}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
        self._cleanup_temp_files()
    
    def _cleanup_temp_files(self):
        """Clean up temporary files"""
        for temp_file in self._temp_files:
            try:
                if temp_file.exists():
                    temp_file.unlink()
            except Exception as e:
                logger.warning(f"Failed to cleanup {temp_file}: {e}")
        self._temp_files.clear()
    
    def _log_result(self, test_name: str, status: TestStatus, details: str = "", 
                   duration: float = 0.0, error_details: str = None, 
                   metadata: Dict[str, Any] = None):
        """Log test result with structured data"""
        result = TestResult(
            test_name=test_name,
            status=status,
            details=details,
            duration=duration,
            timestamp=datetime.now().isoformat(),
            error_details=error_details,
            metadata=metadata or {}
        )
        
        self.test_results.append(result)
        
        # Console output with color coding
        status_icon = {
            TestStatus.PASS: "✅",
            TestStatus.FAIL: "❌", 
            TestStatus.SKIP: "⏭️",
            TestStatus.ERROR: "🚨"
        }
        
        print(f"{status_icon[status]} {test_name}: {details} ({duration:.3f}s)")
        if error_details:
            print(f"   Error: {error_details}")
    
    async def _make_request_with_retry(self, method: str, url: str, 
                                     **kwargs) -> Tuple[int, Dict[str, Any]]:
        """Make HTTP request with retry logic and exponential backoff"""
        for attempt in range(self.config.retry_attempts):
            try:
                async with self.session.request(method, url, **kwargs) as response:
                    if response.content_type == 'application/json':
                        data = await response.json()
                    else:
                        text = await response.text()
                        data = {"response": text}
                    
                    return response.status, data
                    
            except asyncio.TimeoutError:
                if attempt == self.config.retry_attempts - 1:
                    raise
                await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
            except Exception as e:
                if attempt == self.config.retry_attempts - 1:
                    raise
                await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
        
        raise Exception("Max retry attempts exceeded")
    
    def _performance_monitor(func):
        """Decorator to monitor test performance"""
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            start_time = time.time()
            try:
                result = await func(self, *args, **kwargs)
                duration = time.time() - start_time
                return result, duration
            except Exception as e:
                duration = time.time() - start_time
                raise e
        return wrapper
    
    async def check_backend_health(self) -> bool:
        """Test backend health endpoint with detailed diagnostics"""
        start_time = time.time()
        try:
            status, data = await self._make_request_with_retry(
                "GET", f"{self.config.backend_url}/api/health"
            )
            duration = time.time() - start_time
            
            if status == 200:
                health_status = data.get("status", "unknown")
                uptime = data.get("uptime", "unknown")
                self._log_result(
                    "Backend Health Check", 
                    TestStatus.PASS, 
                    f"Status: {health_status}, Uptime: {uptime}",
                    duration,
                    metadata={"health_data": data}
                )
                return True
            else:
                self._log_result(
                    "Backend Health Check", 
                    TestStatus.FAIL, 
                    f"HTTP {status}",
                    duration
                )
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self._log_result(
                "Backend Health Check", 
                TestStatus.ERROR, 
                "Connection failed",
                duration,
                error_details=str(e)
            )
            return False
    
    async def test_api_endpoints_batch(self):
        """Test multiple API endpoints concurrently"""
        endpoints = [
            ("/api/health", "GET", "Health endpoint"),
            ("/api/stats", "GET", "Statistics endpoint"),
            ("/api/merchants", "GET", "Merchants endpoint"),
            ("/api/fraud-reports", "GET", "Fraud reports endpoint"),
            ("/api/", "GET", "Root API endpoint"),
        ]
        
        async def test_single_endpoint(endpoint_info):
            path, method, description = endpoint_info
            start_time = time.time()
            
            try:
                status, data = await self._make_request_with_retry(
                    method, f"{self.config.backend_url}{path}"
                )
                duration = time.time() - start_time
                
                # Accept 200, 404 (empty collections), and 401 (auth required)
                if status in [200, 404, 401]:
                    self._log_result(
                        f"API Endpoint {path}",
                        TestStatus.PASS,
                        f"{description} - HTTP {status}",
                        duration,
                        metadata={"endpoint": path, "method": method, "status": status}
                    )
                else:
                    self._log_result(
                        f"API Endpoint {path}",
                        TestStatus.FAIL,
                        f"{description} - HTTP {status}",
                        duration
                    )
                    
            except Exception as e:
                duration = time.time() - start_time
                self._log_result(
                    f"API Endpoint {path}",
                    TestStatus.ERROR,
                    f"{description} - Request failed",
                    duration,
                    error_details=str(e)
                )
        
        # Run endpoint tests concurrently
        await asyncio.gather(*[test_single_endpoint(ep) for ep in endpoints])
    
    async def test_url_risk_analysis_batch(self):
        """Test URL risk analysis with batch processing"""
        test_urls = [
            ("https://microsoft.com", "legitimate", "Should be safe"),
            ("https://micr0soft-security.xyz", "suspicious", "Typosquatting domain"),
            ("https://paypal-verify.suspicious-domain.com", "suspicious", "Phishing domain"),
            ("https://google.com", "legitimate", "Should be safe"),
            ("javascript:alert('xss')", "malicious", "XSS attempt"),
            ("data:text/html,<script>alert('xss')</script>", "malicious", "Data URL XSS"),
        ]
        
        async def analyze_single_url(url_info):
            url, expected_category, description = url_info
            start_time = time.time()
            
            try:
                payload = {"url": url}
                status, data = await self._make_request_with_retry(
                    "POST", f"{self.config.backend_url}/api/risk-check",
                    json=payload
                )
                duration = time.time() - start_time
                
                if status == 200:
                    risk_level = data.get("risk_level", "unknown")
                    trust_score = data.get("trust_score", 0)
                    
                    # Validate expected behavior
                    is_expected = self._validate_risk_assessment(
                        expected_category, risk_level, trust_score
                    )
                    
                    result_status = TestStatus.PASS if is_expected else TestStatus.FAIL
                    self._log_result(
                        f"URL Risk Analysis: {url[:50]}...",
                        result_status,
                        f"{description} - Risk: {risk_level}, Trust: {trust_score}",
                        duration,
                        metadata={
                            "url": url,
                            "expected": expected_category,
                            "actual_risk": risk_level,
                            "trust_score": trust_score
                        }
                    )
                else:
                    self._log_result(
                        f"URL Risk Analysis: {url[:50]}...",
                        TestStatus.FAIL,
                        f"{description} - HTTP {status}",
                        duration
                    )
                    
            except Exception as e:
                duration = time.time() - start_time
                self._log_result(
                    f"URL Risk Analysis: {url[:50]}...",
                    TestStatus.ERROR,
                    f"{description} - Request failed",
                    duration,
                    error_details=str(e)
                )
        
        # Process URLs concurrently with semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        
        async def limited_analyze(url_info):
            async with semaphore:
                await analyze_single_url(url_info)
        
        await asyncio.gather(*[limited_analyze(url_info) for url_info in test_urls])
    
    def _validate_risk_assessment(self, expected_category: str, 
                                risk_level: str, trust_score: int) -> bool:
        """Validate risk assessment results against expectations"""
        if expected_category == "legitimate":
            return risk_level.lower() in ["low", "medium"] and trust_score >= 50
        elif expected_category == "suspicious":
            return risk_level.lower() in ["medium", "high"] and trust_score <= 70
        elif expected_category == "malicious":
            return risk_level.lower() == "high" and trust_score <= 30
        return True  # Unknown category, accept any result
    
    async def test_ai_image_detection_optimized(self):
        """Test AI image detection with optimized image generation"""
        start_time = time.time()
        
        try:
            # Generate test image more efficiently
            image_data = self._generate_test_scam_image()
            if not image_data:
                self._log_result(
                    "AI Image Detection",
                    TestStatus.SKIP,
                    "PIL not available",
                    time.time() - start_time
                )
                return
            
            b64_data = base64.b64encode(image_data).decode('utf-8')
            
            payload = {
                "url": "test://ai-image",
                "content": b64_data,
                "metadata": {"source": "test", "static": True}
            }
            
            status, data = await self._make_request_with_retry(
                "POST", f"{self.config.backend_url}/api/media-risk/bytes",
                json=payload
            )
            duration = time.time() - start_time
            
            if status == 200:
                media_score = data.get("media_score", 0)
                media_color = data.get("media_color", "unknown")
                reasons = data.get("reasons", [])
                scam_alert = data.get("scam_alert", {})
                
                self._log_result(
                    "AI Image Detection",
                    TestStatus.PASS,
                    f"Score: {media_score}, Color: {media_color}, Reasons: {len(reasons)}",
                    duration,
                    metadata={
                        "media_score": media_score,
                        "media_color": media_color,
                        "reasons_count": len(reasons),
                        "scam_detected": scam_alert.get("is_scam", False)
                    }
                )
            else:
                self._log_result(
                    "AI Image Detection",
                    TestStatus.FAIL,
                    f"HTTP {status}",
                    duration
                )
                
        except Exception as e:
            duration = time.time() - start_time
            self._log_result(
                "AI Image Detection",
                TestStatus.ERROR,
                "Processing failed",
                duration,
                error_details=str(e)
            )
    
    def _generate_test_scam_image(self) -> Optional[bytes]:
        """Generate test scam image efficiently"""
        try:
            from PIL import Image, ImageDraw, ImageFont
            import io
            
            # Create image with scam characteristics
            img = Image.new('RGB', (800, 600), color='red')
            draw = ImageDraw.Draw(img)
            
            # Add scam text
            try:
                # Try to use system font
                font = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 36)
            except:
                font = ImageFont.load_default()
            
            scam_text = [
                "⚠️ VIRUS DETECTED! ⚠️",
                "CALL 1-800-SCAM-NOW",
                "DO NOT CLOSE WINDOW"
            ]
            
            y_pos = 100
            for text in scam_text:
                draw.text((50, y_pos), text, fill='white', font=font)
                y_pos += 80
            
            # Convert to bytes
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG', optimize=True)
            return img_bytes.getvalue()
            
        except ImportError:
            return None
        except Exception as e:
            logger.warning(f"Failed to generate test image: {e}")
            return None
    
    async def test_comprehensive_scam_patterns(self):
        """Test comprehensive scam pattern detection"""
        scam_patterns = [
            {
                "name": "Tech Support Scam",
                "html": '<div style="background:red;color:white;">VIRUS DETECTED! CALL 1-800-123-4567</div>',
                "overlay": "Microsoft Security Alert",
                "expected_patterns": ["virus_warning", "phone_number", "urgency"]
            },
            {
                "name": "Phishing Email",
                "html": '<p>Your PayPal account suspended. Verify now: paypal-verify.xyz</p>',
                "overlay": "Account Security Notice",
                "expected_patterns": ["account_threat", "phishing"]
            },
            {
                "name": "SMS Scam",
                "html": '<p>Parcel delivery failed. Pay $2.99: bit.ly/fake123</p>',
                "overlay": "Delivery Notice",
                "expected_patterns": ["payment_request", "url_shortener"]
            },
            {
                "name": "Fake Prize",
                "html": '<p>Congratulations! You won $1000. Claim: winner-claim.com</p>',
                "overlay": "Prize Notification",
                "expected_patterns": ["fake_prize", "suspicious_domain"]
            }
        ]
        
        async def test_single_pattern(pattern_info):
            start_time = time.time()
            
            try:
                payload = {
                    "url": f"https://scam-test-{hash(pattern_info['name'])}.com",
                    "html": pattern_info["html"],
                    "overlay_text": pattern_info["overlay"]
                }
                
                status, data = await self._make_request_with_retry(
                    "POST", f"{self.config.backend_url}/api/content-risk",
                    json=payload
                )
                duration = time.time() - start_time
                
                if status == 200:
                    scam_alert = data.get("scam_alert", {})
                    is_scam = scam_alert.get("is_scam", False)
                    confidence = scam_alert.get("confidence", 0)
                    detected_patterns = scam_alert.get("detected_patterns", [])
                    
                    # Check if expected patterns were detected
                    expected_found = sum(1 for pattern in pattern_info["expected_patterns"] 
                                       if pattern in detected_patterns)
                    
                    result_status = TestStatus.PASS if is_scam and expected_found > 0 else TestStatus.FAIL
                    
                    self._log_result(
                        f"Scam Pattern: {pattern_info['name']}",
                        result_status,
                        f"Scam: {is_scam}, Confidence: {confidence}%, Patterns: {len(detected_patterns)}",
                        duration,
                        metadata={
                            "is_scam": is_scam,
                            "confidence": confidence,
                            "detected_patterns": detected_patterns,
                            "expected_patterns": pattern_info["expected_patterns"],
                            "patterns_found": expected_found
                        }
                    )
                else:
                    self._log_result(
                        f"Scam Pattern: {pattern_info['name']}",
                        TestStatus.FAIL,
                        f"HTTP {status}",
                        duration
                    )
                    
            except Exception as e:
                duration = time.time() - start_time
                self._log_result(
                    f"Scam Pattern: {pattern_info['name']}",
                    TestStatus.ERROR,
                    "Request failed",
                    duration,
                    error_details=str(e)
                )
        
        await asyncio.gather(*[test_single_pattern(pattern) for pattern in scam_patterns])
    
    async def test_performance_benchmarks(self):
        """Test system performance under load"""
        start_time = time.time()
        
        # Test concurrent requests
        concurrent_requests = 20
        request_tasks = []
        
        for i in range(concurrent_requests):
            task = self._make_request_with_retry(
                "GET", f"{self.config.backend_url}/api/health"
            )
            request_tasks.append(task)
        
        try:
            results = await asyncio.gather(*request_tasks, return_exceptions=True)
            duration = time.time() - start_time
            
            successful_requests = sum(1 for result in results 
                                    if not isinstance(result, Exception) and result[0] == 200)
            
            requests_per_second = concurrent_requests / duration if duration > 0 else 0
            
            # Performance thresholds
            min_success_rate = 0.8  # 80% success rate
            min_rps = 10  # 10 requests per second
            
            success_rate = successful_requests / concurrent_requests
            performance_ok = success_rate >= min_success_rate and requests_per_second >= min_rps
            
            result_status = TestStatus.PASS if performance_ok else TestStatus.FAIL
            
            self._log_result(
                "Performance Benchmark",
                result_status,
                f"RPS: {requests_per_second:.2f}, Success: {success_rate:.1%}",
                duration,
                metadata={
                    "concurrent_requests": concurrent_requests,
                    "successful_requests": successful_requests,
                    "requests_per_second": requests_per_second,
                    "success_rate": success_rate
                }
            )
            
        except Exception as e:
            duration = time.time() - start_time
            self._log_result(
                "Performance Benchmark",
                TestStatus.ERROR,
                "Benchmark failed",
                duration,
                error_details=str(e)
            )
    
    def check_agent_status(self) -> bool:
        """Check if PayGuard agent is running"""
        try:
            result = subprocess.run(
                ['pgrep', '-f', 'payguard_menubar.py'], 
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    async def run_all_tests(self) -> bool:
        """Run all feature tests with optimized execution"""
        print("🧪 PayGuard Comprehensive Feature Test Suite - Optimized")
        print("=" * 70)
        print(f"Backend URL: {self.config.backend_url}")
        print(f"Max Concurrent: {self.config.max_concurrent}")
        print(f"Timeout: {self.config.timeout}s")
        print("=" * 70)
        
        overall_start = time.time()
        
        # Check backend health first
        if not await self.check_backend_health():
            print("\n❌ Backend is not running! Please start it first:")
            print("   cd backend && python server.py")
            return False
        
        print("\n🔍 Running Comprehensive Tests...")
        
        # Run test suites
        test_suites = [
            ("API Endpoints", self.test_api_endpoints_batch),
            ("URL Risk Analysis", self.test_url_risk_analysis_batch),
            ("AI Image Detection", self.test_ai_image_detection_optimized),
            ("Scam Patterns", self.test_comprehensive_scam_patterns),
            ("Performance", self.test_performance_benchmarks),
        ]
        
        for suite_name, test_func in test_suites:
            print(f"\n📋 {suite_name}...")
            try:
                await test_func()
            except Exception as e:
                logger.error(f"Test suite {suite_name} failed: {e}")
        
        # Check agent status
        agent_running = self.check_agent_status()
        self._log_result(
            "PayGuard Agent Status",
            TestStatus.PASS if agent_running else TestStatus.FAIL,
            "Agent running" if agent_running else "Agent not detected",
            0.0
        )
        
        total_duration = time.time() - overall_start
        
        # Generate comprehensive report
        return self._generate_final_report(total_duration)
    
    def _generate_final_report(self, total_duration: float) -> bool:
        """Generate comprehensive test report"""
        passed = [r for r in self.test_results if r.status == TestStatus.PASS]
        failed = [r for r in self.test_results if r.status == TestStatus.FAIL]
        errors = [r for r in self.test_results if r.status == TestStatus.ERROR]
        skipped = [r for r in self.test_results if r.status == TestStatus.SKIP]
        
        print("\n" + "=" * 70)
        print("📊 COMPREHENSIVE TEST REPORT")
        print("=" * 70)
        print(f"⏱️  Total Duration: {total_duration:.2f}s")
        print(f"📊 Total Tests: {len(self.test_results)}")
        print(f"✅ Passed: {len(passed)}")
        print(f"❌ Failed: {len(failed)}")
        print(f"🚨 Errors: {len(errors)}")
        print(f"⏭️ Skipped: {len(skipped)}")
        
        if self.test_results:
            success_rate = len(passed) / len(self.test_results) * 100
            print(f"📈 Success Rate: {success_rate:.1f}%")
        
        # Performance metrics
        avg_duration = sum(r.duration for r in self.test_results) / len(self.test_results)
        print(f"⚡ Average Test Duration: {avg_duration:.3f}s")
        
        # Show failed tests
        if failed or errors:
            print(f"\n❌ Issues Found:")
            for result in failed + errors:
                print(f"   • {result.test_name}: {result.details}")
                if result.error_details:
                    print(f"     Error: {result.error_details}")
        
        # Save detailed results
        report_data = {
            "summary": {
                "total_tests": len(self.test_results),
                "passed": len(passed),
                "failed": len(failed),
                "errors": len(errors),
                "skipped": len(skipped),
                "success_rate": len(passed) / len(self.test_results) * 100 if self.test_results else 0,
                "total_duration": total_duration,
                "average_duration": avg_duration
            },
            "config": asdict(self.config),
            "results": [asdict(result) for result in self.test_results],
            "timestamp": datetime.now().isoformat()
        }
        
        report_file = Path("payguard_comprehensive_test_results.json")
        with open(report_file, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        
        print(f"\n📄 Detailed results saved to: {report_file}")
        
        return len(failed) + len(errors) == 0

async def main():
    """Main async entry point"""
    config = TestConfig(
        backend_url=os.getenv("PAYGUARD_BACKEND_URL", "http://localhost:8002"),
        timeout=int(os.getenv("PAYGUARD_TEST_TIMEOUT", "30")),
        max_concurrent=int(os.getenv("PAYGUARD_MAX_CONCURRENT", "5"))
    )
    
    async with PayGuardFeatureTesterOptimized(config) as tester:
        success = await tester.run_all_tests()
        return success

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Test runner failed: {e}")
        sys.exit(1)