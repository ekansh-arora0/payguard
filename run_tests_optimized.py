#!/usr/bin/env python3
"""
PayGuard Optimized Test Runner
Comprehensive testing suite with performance optimizations and better error handling
"""

import subprocess
import time
import os
import sys
import json
import http.client
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import logging
from contextlib import contextmanager
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TestResult(Enum):
    PASS = "✅ PASS"
    FAIL = "❌ FAIL"
    SKIP = "⏭️ SKIP"
    ERROR = "🚨 ERROR"

@dataclass
class TestCase:
    name: str
    description: str
    test_func: callable
    timeout: int = 30
    depends_on: List[str] = None
    cleanup_func: callable = None

@dataclass
class TestReport:
    test_name: str
    result: TestResult
    duration: float
    message: str = ""
    details: Dict[str, Any] = None

class PayGuardTestRunner:
    """Optimized test runner with dependency management and parallel execution"""
    
    def __init__(self, backend_host: str = "localhost", backend_port: int = 8002):
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.test_cases: List[TestCase] = []
        self.results: List[TestReport] = []
        self.temp_files: List[Path] = []
        self.backend_available = False
        self.agent_available = False
        
    def add_test(self, test_case: TestCase):
        """Add a test case to the runner"""
        self.test_cases.append(test_case)
    
    @contextmanager
    def temp_html_file(self, content: str, filename: str = None) -> Path:
        """Context manager for temporary HTML files"""
        if filename is None:
            filename = f"test_{int(time.time())}.html"
        
        temp_path = Path(tempfile.gettempdir()) / filename
        try:
            temp_path.write_text(content, encoding='utf-8')
            self.temp_files.append(temp_path)
            yield temp_path
        finally:
            if temp_path.exists():
                temp_path.unlink()
                if temp_path in self.temp_files:
                    self.temp_files.remove(temp_path)
    
    def check_backend_health(self) -> bool:
        """Check if backend is running and healthy"""
        try:
            conn = http.client.HTTPConnection(self.backend_host, self.backend_port, timeout=5)
            conn.request("GET", "/api/health")
            resp = conn.getresponse()
            self.backend_available = resp.status == 200
            conn.close()
            return self.backend_available
        except Exception as e:
            logger.error(f"Backend health check failed: {e}")
            self.backend_available = False
            return False
    
    def check_agent_status(self) -> bool:
        """Check if agent is likely running by looking for process"""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "agent.py"], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            self.agent_available = result.returncode == 0
            return self.agent_available
        except Exception:
            self.agent_available = False
            return False
    
    def run_test_case(self, test_case: TestCase) -> TestReport:
        """Execute a single test case with timeout and error handling"""
        start_time = time.time()
        
        try:
            logger.info(f"Running test: {test_case.name}")
            
            # Check dependencies
            if test_case.depends_on:
                for dep in test_case.depends_on:
                    if not self._check_dependency(dep):
                        return TestReport(
                            test_name=test_case.name,
                            result=TestResult.SKIP,
                            duration=time.time() - start_time,
                            message=f"Dependency not met: {dep}"
                        )
            
            # Run the test with timeout
            result = self._run_with_timeout(test_case.test_func, test_case.timeout)
            
            duration = time.time() - start_time
            
            if result is True:
                return TestReport(
                    test_name=test_case.name,
                    result=TestResult.PASS,
                    duration=duration,
                    message="Test completed successfully"
                )
            elif result is False:
                return TestReport(
                    test_name=test_case.name,
                    result=TestResult.FAIL,
                    duration=duration,
                    message="Test assertion failed"
                )
            else:
                return TestReport(
                    test_name=test_case.name,
                    result=TestResult.PASS,
                    duration=duration,
                    message=str(result) if result else "Test completed"
                )
                
        except TimeoutError:
            return TestReport(
                test_name=test_case.name,
                result=TestResult.ERROR,
                duration=time.time() - start_time,
                message=f"Test timed out after {test_case.timeout}s"
            )
        except Exception as e:
            return TestReport(
                test_name=test_case.name,
                result=TestResult.ERROR,
                duration=time.time() - start_time,
                message=f"Test error: {str(e)}"
            )
        finally:
            # Run cleanup if provided
            if test_case.cleanup_func:
                try:
                    test_case.cleanup_func()
                except Exception as e:
                    logger.warning(f"Cleanup failed for {test_case.name}: {e}")
    
    def _run_with_timeout(self, func: callable, timeout: int):
        """Run function with timeout"""
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Function timed out after {timeout} seconds")
        
        # Set up timeout
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        
        try:
            result = func()
            signal.alarm(0)  # Cancel timeout
            return result
        finally:
            signal.signal(signal.SIGALRM, old_handler)
    
    def _check_dependency(self, dependency: str) -> bool:
        """Check if a dependency is satisfied"""
        if dependency == "backend":
            return self.backend_available
        elif dependency == "agent":
            return self.agent_available
        return True
    
    def run_all_tests(self, parallel: bool = False) -> List[TestReport]:
        """Run all test cases"""
        print("🧪 PayGuard Optimized Test Suite")
        print("=" * 60)
        
        # Pre-flight checks
        print("🔍 Pre-flight checks...")
        backend_ok = self.check_backend_health()
        agent_ok = self.check_agent_status()
        
        print(f"   Backend: {'✅' if backend_ok else '❌'}")
        print(f"   Agent: {'✅' if agent_ok else '❌'}")
        
        if not backend_ok:
            print("\n❌ Backend not running! Please start it first:")
            print("   cd backend && python server.py")
            return []
        
        if not agent_ok:
            print("\n⚠️ Agent not detected. Some tests may fail.")
            print("   cd agent && python agent.py")
        
        print(f"\n📋 Running {len(self.test_cases)} test cases...")
        
        if parallel and len(self.test_cases) > 1:
            self.results = self._run_parallel()
        else:
            self.results = self._run_sequential()
        
        self._print_summary()
        return self.results
    
    def _run_sequential(self) -> List[TestReport]:
        """Run tests sequentially"""
        results = []
        for i, test_case in enumerate(self.test_cases, 1):
            print(f"\n[{i}/{len(self.test_cases)}] {test_case.name}")
            result = self.run_test_case(test_case)
            results.append(result)
            print(f"   {result.result.value} ({result.duration:.2f}s)")
            if result.message:
                print(f"   {result.message}")
        return results
    
    def _run_parallel(self) -> List[TestReport]:
        """Run tests in parallel where possible"""
        results = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_test = {
                executor.submit(self.run_test_case, test): test 
                for test in self.test_cases
            }
            
            for future in as_completed(future_to_test):
                test_case = future_to_test[future]
                try:
                    result = future.result()
                    results.append(result)
                    print(f"   {result.result.value} {test_case.name} ({result.duration:.2f}s)")
                except Exception as e:
                    logger.error(f"Test {test_case.name} failed with exception: {e}")
        
        return sorted(results, key=lambda x: x.test_name)
    
    def _print_summary(self):
        """Print test results summary"""
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r.result == TestResult.PASS)
        failed = sum(1 for r in self.results if r.result == TestResult.FAIL)
        errors = sum(1 for r in self.results if r.result == TestResult.ERROR)
        skipped = sum(1 for r in self.results if r.result == TestResult.SKIP)
        
        print(f"Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"🚨 Errors: {errors}")
        print(f"⏭️ Skipped: {skipped}")
        
        total_time = sum(r.duration for r in self.results)
        print(f"⏱️ Total Time: {total_time:.2f}s")
        
        if failed > 0 or errors > 0:
            print("\n🔍 Failed/Error Details:")
            for result in self.results:
                if result.result in [TestResult.FAIL, TestResult.ERROR]:
                    print(f"   {result.result.value} {result.test_name}: {result.message}")
    
    def cleanup(self):
        """Clean up temporary files"""
        for temp_file in self.temp_files:
            try:
                if temp_file.exists():
                    temp_file.unlink()
            except Exception as e:
                logger.warning(f"Failed to cleanup {temp_file}: {e}")
        self.temp_files.clear()

# Test implementations
def create_test_runner() -> PayGuardTestRunner:
    """Create and configure the test runner with all test cases"""
    runner = PayGuardTestRunner()
    
    # Test case definitions
    def test_backend_health():
        """Test backend health endpoint"""
        conn = http.client.HTTPConnection(runner.backend_host, runner.backend_port, timeout=5)
        conn.request("GET", "/api/health")
        resp = conn.getresponse()
        conn.close()
        return resp.status == 200
    
    def test_tech_support_scam():
        """Test tech support scam detection"""
        scam_html = """
        <!DOCTYPE html>
        <html>
        <head><title>CRITICAL ERROR</title></head>
        <body style="background: red; color: white; text-align: center; padding: 50px;">
            <h1>⚠️ CRITICAL SYSTEM ERROR ⚠️</h1>
            <p style="font-size: 24px;">YOUR COMPUTER IS INFECTED!</p>
            <p style="font-size: 20px;">CALL MICROSOFT: 1-800-555-0199</p>
            <p>DO NOT CLOSE THIS WINDOW</p>
        </body>
        </html>
        """
        
        with runner.temp_html_file(scam_html, "tech_support_scam.html") as temp_path:
            subprocess.run(["open", str(temp_path)], check=True)
            time.sleep(5)  # Wait for detection
            return True
    
    def test_phishing_scam():
        """Test phishing scam detection"""
        phishing_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Amazon Security Notice</title></head>
        <body style="background: #232f3e; color: white; padding: 30px;">
            <h2 style="color: #ff9900;">Amazon Security Alert</h2>
            <p>Your account has been suspended due to suspicious activity.</p>
            <p style="color: red; font-weight: bold;">Action required within 24 hours!</p>
            <button style="background: #ff9900; padding: 10px;">Verify Account</button>
        </body>
        </html>
        """
        
        with runner.temp_html_file(phishing_html, "phishing_scam.html") as temp_path:
            subprocess.run(["open", str(temp_path)], check=True)
            time.sleep(5)
            return True
    
    def test_api_risk_endpoint():
        """Test API risk assessment endpoint"""
        test_url = "https://example.com"
        
        conn = http.client.HTTPConnection(runner.backend_host, runner.backend_port, timeout=10)
        params = urllib.parse.urlencode({"url": test_url})
        conn.request("GET", f"/api/risk?{params}")
        resp = conn.getresponse()
        
        if resp.status != 200:
            return False
            
        data = json.loads(resp.read().decode())
        conn.close()
        
        # Validate response structure
        required_fields = ["url", "trust_score", "risk_level", "checked_at"]
        return all(field in data for field in required_fields)
    
    # Add test cases
    runner.add_test(TestCase(
        name="backend_health",
        description="Verify backend is running and healthy",
        test_func=test_backend_health,
        timeout=10
    ))
    
    runner.add_test(TestCase(
        name="api_risk_endpoint",
        description="Test risk assessment API endpoint",
        test_func=test_api_risk_endpoint,
        depends_on=["backend"],
        timeout=15
    ))
    
    runner.add_test(TestCase(
        name="tech_support_scam",
        description="Test tech support scam detection",
        test_func=test_tech_support_scam,
        depends_on=["backend", "agent"],
        timeout=20
    ))
    
    runner.add_test(TestCase(
        name="phishing_scam",
        description="Test phishing scam detection",
        test_func=test_phishing_scam,
        depends_on=["backend", "agent"],
        timeout=20
    ))
    
    return runner

def main():
    """Main test execution"""
    runner = create_test_runner()
    
    try:
        # Run tests
        results = runner.run_all_tests(parallel=False)
        
        # Exit with appropriate code
        failed_count = sum(1 for r in results if r.result in [TestResult.FAIL, TestResult.ERROR])
        sys.exit(failed_count)
        
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        sys.exit(1)
    finally:
        runner.cleanup()

if __name__ == "__main__":
    main()