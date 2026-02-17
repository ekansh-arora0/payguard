#!/usr/bin/env python3
"""
PayGuard Comprehensive Test Runner
Orchestrates all test suites for the PayGuard feature tester
"""

import subprocess
import sys
import os
import time
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TestSuite(Enum):
    """Available test suites"""
    UNIT = "unit"
    INTEGRATION = "integration"
    PERFORMANCE = "performance"
    PROPERTY = "property"
    FEATURES = "features"
    ALL = "all"

@dataclass
class TestSuiteResult:
    """Test suite execution result"""
    suite_name: str
    success: bool
    duration: float
    test_count: int
    passed: int
    failed: int
    skipped: int
    errors: int
    output: str
    error_output: str

class PayGuardComprehensiveTestRunner:
    """Comprehensive test runner for PayGuard feature tester"""
    
    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path(__file__).parent
        self.results: List[TestSuiteResult] = []
        self.start_time = time.time()
        
    def check_dependencies(self) -> bool:
        """Check if all test dependencies are installed"""
        logger.info("🔍 Checking test dependencies...")
        
        required_packages = [
            'pytest', 'pytest_asyncio', 'pytest_cov', 'aiohttp',
            'hypothesis', 'psutil', 'PIL'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                # Map PIL back to pillow for error message
                display_name = 'pillow' if package == 'PIL' else package.replace('_', '-')
                missing_packages.append(display_name)
        
        if missing_packages:
            logger.error(f"❌ Missing packages: {', '.join(missing_packages)}")
            logger.info("Install with: pip install pytest pytest-asyncio pytest-cov aiohttp hypothesis psutil pillow")
            return False
        
        logger.info("✅ All test dependencies available")
        return True
    
    def check_backend_status(self) -> bool:
        """Check if backend is running"""
        try:
            import requests
            response = requests.get("http://localhost:8002/api/health", timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    def run_unit_tests(self) -> TestSuiteResult:
        """Run unit tests"""
        logger.info("🧪 Running unit tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            "tests/test_payguard_comprehensive_features.py",
            "-v",
            "--tb=short",
            "--cov=test_all_payguard_features_comprehensive_optimized",
            "--cov-report=term-missing",
            "--junit-xml=test_results_unit.xml"
        ]
        
        return self._run_test_command("Unit Tests", cmd)
    
    def run_integration_tests(self) -> TestSuiteResult:
        """Run integration tests"""
        logger.info("🔗 Running integration tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            "tests/test_payguard_features_integration.py",
            "-v",
            "--tb=short",
            "--junit-xml=test_results_integration.xml"
        ]
        
        return self._run_test_command("Integration Tests", cmd)
    
    def run_performance_tests(self) -> TestSuiteResult:
        """Run performance tests"""
        logger.info("⚡ Running performance tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            "tests/test_payguard_features_performance.py",
            "-v",
            "--tb=short",
            "-s",  # Don't capture output for performance tests
            "--junit-xml=test_results_performance.xml"
        ]
        
        return self._run_test_command("Performance Tests", cmd)
    
    def run_property_tests(self) -> TestSuiteResult:
        """Run property-based tests"""
        logger.info("🎲 Running property-based tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            "tests/test_payguard_features_property.py",
            "-v",
            "--tb=short",
            "--hypothesis-show-statistics",
            "--junit-xml=test_results_property.xml"
        ]
        
        return self._run_test_command("Property-Based Tests", cmd)
    
    def run_feature_tests(self) -> TestSuiteResult:
        """Run the optimized feature tests"""
        logger.info("🚀 Running optimized feature tests...")
        
        cmd = [
            sys.executable,
            "test_all_payguard_features_comprehensive_optimized.py"
        ]
        
        return self._run_test_command("Feature Tests", cmd)
    
    def _run_test_command(self, suite_name: str, cmd: List[str]) -> TestSuiteResult:
        """Execute a test command and parse results"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            duration = time.time() - start_time
            
            # Parse pytest output for test counts
            test_count, passed, failed, skipped, errors = self._parse_pytest_output(result.stdout)
            
            suite_result = TestSuiteResult(
                suite_name=suite_name,
                success=result.returncode == 0,
                duration=duration,
                test_count=test_count,
                passed=passed,
                failed=failed,
                skipped=skipped,
                errors=errors,
                output=result.stdout,
                error_output=result.stderr
            )
            
            self.results.append(suite_result)
            
            # Print immediate feedback
            status = "✅ PASSED" if suite_result.success else "❌ FAILED"
            print(f"{status} {suite_name} ({duration:.2f}s) - {passed}/{test_count} passed")
            
            if not suite_result.success and result.stderr:
                print(f"   Error: {result.stderr[:200]}...")
            
            return suite_result
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            suite_result = TestSuiteResult(
                suite_name=suite_name,
                success=False,
                duration=duration,
                test_count=0,
                passed=0,
                failed=0,
                skipped=0,
                errors=1,
                output="",
                error_output=f"Test suite timed out after 5 minutes"
            )
            
            self.results.append(suite_result)
            print(f"⏰ TIMEOUT {suite_name} ({duration:.2f}s)")
            return suite_result
            
        except Exception as e:
            duration = time.time() - start_time
            suite_result = TestSuiteResult(
                suite_name=suite_name,
                success=False,
                duration=duration,
                test_count=0,
                passed=0,
                failed=0,
                skipped=0,
                errors=1,
                output="",
                error_output=str(e)
            )
            
            self.results.append(suite_result)
            print(f"🚨 ERROR {suite_name}: {e}")
            return suite_result
    
    def _parse_pytest_output(self, output: str) -> tuple:
        """Parse pytest output to extract test counts"""
        import re
        
        # Look for pytest summary line
        # Example: "5 passed, 2 failed, 1 skipped in 10.23s"
        summary_pattern = r'(\d+)\s+passed(?:,\s+(\d+)\s+failed)?(?:,\s+(\d+)\s+skipped)?(?:,\s+(\d+)\s+error)?'
        
        match = re.search(summary_pattern, output)
        if match:
            passed = int(match.group(1)) if match.group(1) else 0
            failed = int(match.group(2)) if match.group(2) else 0
            skipped = int(match.group(3)) if match.group(3) else 0
            errors = int(match.group(4)) if match.group(4) else 0
            total = passed + failed + skipped + errors
            return total, passed, failed, skipped, errors
        
        # Fallback: count test function calls
        test_functions = re.findall(r'test_\w+', output)
        test_count = len(set(test_functions))  # Remove duplicates
        
        # If no clear success/failure info, check for FAILED/ERROR keywords
        if "FAILED" in output or "ERROR" in output:
            return test_count, 0, test_count, 0, 0
        else:
            return test_count, test_count, 0, 0, 0
    
    def run_code_quality_checks(self) -> TestSuiteResult:
        """Run code quality checks"""
        logger.info("🔍 Running code quality checks...")
        
        checks = []
        start_time = time.time()
        
        # Flake8 check
        try:
            result = subprocess.run([
                sys.executable, "-m", "flake8", 
                "test_all_payguard_features_comprehensive_optimized.py",
                "--max-line-length=100",
                "--ignore=E203,W503"
            ], capture_output=True, text=True, cwd=self.project_root)
            
            checks.append(("Flake8", result.returncode == 0, result.stdout + result.stderr))
        except FileNotFoundError:
            checks.append(("Flake8", False, "flake8 not installed"))
        
        # MyPy check
        try:
            result = subprocess.run([
                sys.executable, "-m", "mypy", 
                "test_all_payguard_features_comprehensive_optimized.py",
                "--ignore-missing-imports"
            ], capture_output=True, text=True, cwd=self.project_root)
            
            checks.append(("MyPy", result.returncode == 0, result.stdout + result.stderr))
        except FileNotFoundError:
            checks.append(("MyPy", False, "mypy not installed"))
        
        duration = time.time() - start_time
        
        # Aggregate results
        passed_checks = sum(1 for _, success, _ in checks if success)
        failed_checks = len(checks) - passed_checks
        overall_success = failed_checks == 0
        
        output = "\n".join(f"{name}: {'PASS' if success else 'FAIL'}\n{output}" 
                          for name, success, output in checks)
        
        result = TestSuiteResult(
            suite_name="Code Quality",
            success=overall_success,
            duration=duration,
            test_count=len(checks),
            passed=passed_checks,
            failed=failed_checks,
            skipped=0,
            errors=0,
            output=output,
            error_output=""
        )
        
        self.results.append(result)
        
        status = "✅ PASSED" if overall_success else "❌ FAILED"
        print(f"{status} Code Quality Checks ({duration:.2f}s)")
        
        return result
    
    def run_security_checks(self) -> TestSuiteResult:
        """Run security checks"""
        logger.info("🔒 Running security checks...")
        
        start_time = time.time()
        
        # Bandit security check
        try:
            result = subprocess.run([
                sys.executable, "-m", "bandit", 
                "test_all_payguard_features_comprehensive_optimized.py",
                "-f", "json"
            ], capture_output=True, text=True, cwd=self.project_root)
            
            # Parse bandit output
            if result.stdout:
                try:
                    bandit_data = json.loads(result.stdout)
                    issues = len(bandit_data.get('results', []))
                    high_severity = sum(1 for r in bandit_data.get('results', []) 
                                      if r.get('issue_severity') == 'HIGH')
                    
                    success = high_severity == 0  # Allow low/medium issues
                    output = f"Security issues found: {issues} (High severity: {high_severity})"
                    
                except json.JSONDecodeError:
                    success = result.returncode == 0
                    output = result.stdout + result.stderr
            else:
                success = result.returncode == 0
                output = "No security issues found"
                
        except FileNotFoundError:
            success = False
            output = "bandit not installed"
        
        duration = time.time() - start_time
        
        result = TestSuiteResult(
            suite_name="Security",
            success=success,
            duration=duration,
            test_count=1,
            passed=1 if success else 0,
            failed=0 if success else 1,
            skipped=0,
            errors=0,
            output=output,
            error_output=""
        )
        
        self.results.append(result)
        
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{status} Security Checks ({duration:.2f}s)")
        
        return result
    
    def run_all_tests(self, suites: List[TestSuite] = None) -> bool:
        """Run all or specified test suites"""
        if suites is None:
            suites = [TestSuite.ALL]
        
        print("🧪 PayGuard Comprehensive Test Suite")
        print("=" * 70)
        
        # Check dependencies
        if not self.check_dependencies():
            return False
        
        # Check backend status
        backend_status = "✅" if self.check_backend_status() else "❌"
        print(f"Backend Status: {backend_status}")
        
        if TestSuite.ALL in suites:
            suites = [TestSuite.UNIT, TestSuite.INTEGRATION, TestSuite.PERFORMANCE, 
                     TestSuite.PROPERTY, TestSuite.FEATURES]
        
        # Run test suites
        suite_functions = {
            TestSuite.UNIT: self.run_unit_tests,
            TestSuite.INTEGRATION: self.run_integration_tests,
            TestSuite.PERFORMANCE: self.run_performance_tests,
            TestSuite.PROPERTY: self.run_property_tests,
            TestSuite.FEATURES: self.run_feature_tests,
        }
        
        for suite in suites:
            if suite in suite_functions:
                try:
                    suite_functions[suite]()
                except Exception as e:
                    logger.error(f"Error running {suite.value} tests: {e}")
        
        # Run additional checks
        self.run_code_quality_checks()
        self.run_security_checks()
        
        # Generate final report
        return self._generate_final_report()
    
    def _generate_final_report(self) -> bool:
        """Generate comprehensive test report"""
        total_duration = time.time() - self.start_time
        
        # Aggregate statistics
        total_tests = sum(r.test_count for r in self.results)
        total_passed = sum(r.passed for r in self.results)
        total_failed = sum(r.failed for r in self.results)
        total_skipped = sum(r.skipped for r in self.results)
        total_errors = sum(r.errors for r in self.results)
        
        overall_success = all(r.success for r in self.results)
        success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
        
        # Generate report
        report = {
            "timestamp": time.time(),
            "total_duration": total_duration,
            "overall_success": overall_success,
            "summary": {
                "total_test_suites": len(self.results),
                "total_tests": total_tests,
                "passed": total_passed,
                "failed": total_failed,
                "skipped": total_skipped,
                "errors": total_errors,
                "success_rate": success_rate
            },
            "test_suites": [
                {
                    "name": r.suite_name,
                    "success": r.success,
                    "duration": r.duration,
                    "test_count": r.test_count,
                    "passed": r.passed,
                    "failed": r.failed,
                    "skipped": r.skipped,
                    "errors": r.errors,
                    "success_rate": (r.passed / r.test_count * 100) if r.test_count > 0 else 0
                }
                for r in self.results
            ],
            "environment": {
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "platform": sys.platform,
                "working_directory": str(self.project_root),
                "backend_available": self.check_backend_status()
            }
        }
        
        # Print summary
        print("\n" + "=" * 70)
        print("📊 COMPREHENSIVE TEST REPORT")
        print("=" * 70)
        print(f"Total Duration: {total_duration:.2f}s")
        print(f"Overall Result: {'✅ SUCCESS' if overall_success else '❌ FAILURE'}")
        
        print(f"\n📈 Summary:")
        print(f"   Test Suites: {len(self.results)}")
        print(f"   Total Tests: {total_tests}")
        print(f"   ✅ Passed: {total_passed}")
        print(f"   ❌ Failed: {total_failed}")
        print(f"   ⏭️ Skipped: {total_skipped}")
        print(f"   🚨 Errors: {total_errors}")
        print(f"   📊 Success Rate: {success_rate:.1f}%")
        
        print(f"\n🧪 Test Suite Results:")
        for suite in report['test_suites']:
            status = "✅" if suite['success'] else "❌"
            print(f"   {status} {suite['name']}: {suite['passed']}/{suite['test_count']} "
                  f"({suite['success_rate']:.1f}%) in {suite['duration']:.2f}s")
        
        # Show failed suites
        failed_suites = [s for s in report['test_suites'] if not s['success']]
        if failed_suites:
            print(f"\n❌ Failed Test Suites:")
            for suite in failed_suites:
                print(f"   • {suite['name']}: {suite['failed']} failed, {suite['errors']} errors")
        
        # Save report
        report_path = self.project_root / "payguard_comprehensive_test_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_path}")
        
        return overall_success

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="PayGuard Comprehensive Test Runner")
    parser.add_argument("--suite", "-s", 
                       choices=[s.value for s in TestSuite],
                       action='append',
                       help="Test suite(s) to run (can be specified multiple times)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")
    parser.add_argument("--no-quality", action="store_true",
                       help="Skip code quality checks")
    parser.add_argument("--no-security", action="store_true", 
                       help="Skip security checks")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Determine which suites to run
    if args.suite:
        suites = [TestSuite(s) for s in args.suite]
    else:
        suites = [TestSuite.ALL]
    
    runner = PayGuardComprehensiveTestRunner()
    
    try:
        success = runner.run_all_tests(suites)
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Test runner failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()