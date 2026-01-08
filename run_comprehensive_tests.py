#!/usr/bin/env python3
"""
Comprehensive Test Runner for PayGuard Simple Test Runner
Orchestrates all test suites with detailed reporting and analysis
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
    PROPERTY = "property"
    PERFORMANCE = "performance"
    ALL = "all"

@dataclass
class TestResult:
    """Test execution result"""
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

class ComprehensiveTestRunner:
    """Comprehensive test runner for all PayGuard Simple Test Runner tests"""
    
    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path(__file__).parent
        self.results: List[TestResult] = []
        self.start_time = time.time()
        
    def run_test_suite(self, suite: TestSuite, verbose: bool = False) -> TestResult:
        """Run a specific test suite"""
        logger.info(f"🧪 Running {suite.value} tests...")
        
        # Map test suites to their files
        suite_files = {
            TestSuite.UNIT: "tests/test_simple_runner_unit.py",
            TestSuite.INTEGRATION: "tests/test_simple_runner_integration.py", 
            TestSuite.PROPERTY: "tests/test_simple_runner_property.py",
            TestSuite.PERFORMANCE: "tests/test_simple_runner_performance.py",
        }
        
        if suite == TestSuite.ALL:
            # Run all suites
            all_results = []
            for test_suite in [TestSuite.UNIT, TestSuite.INTEGRATION, TestSuite.PROPERTY, TestSuite.PERFORMANCE]:
                result = self.run_test_suite(test_suite, verbose)
                all_results.append(result)
            
            # Aggregate results
            total_duration = sum(r.duration for r in all_results)
            total_tests = sum(r.test_count for r in all_results)
            total_passed = sum(r.passed for r in all_results)
            total_failed = sum(r.failed for r in all_results)
            total_skipped = sum(r.skipped for r in all_results)
            total_errors = sum(r.errors for r in all_results)
            overall_success = all(r.success for r in all_results)
            
            return TestResult(
                suite_name="All Tests",
                success=overall_success,
                duration=total_duration,
                test_count=total_tests,
                passed=total_passed,
                failed=total_failed,
                skipped=total_skipped,
                errors=total_errors,
                output="\n".join(r.output for r in all_results),
                error_output="\n".join(r.error_output for r in all_results if r.error_output)
            )
        
        test_file = suite_files.get(suite)
        if not test_file:
            raise ValueError(f"Unknown test suite: {suite}")
        
        # Build pytest command
        cmd = [
            sys.executable, "-m", "pytest",
            test_file,
            "-v" if verbose else "-q",
            "--tb=short",
            "--junit-xml=test_results.xml",
            "--cov=run_simple_tests_optimized" if suite == TestSuite.UNIT else "",
            "--cov-report=term-missing" if suite == TestSuite.UNIT else "",
        ]
        
        # Remove empty strings
        cmd = [c for c in cmd if c]
        
        # Add suite-specific options
        if suite == TestSuite.PROPERTY:
            cmd.extend(["--hypothesis-show-statistics"])
        elif suite == TestSuite.PERFORMANCE:
            cmd.extend(["-s"])  # Don't capture output for performance tests
        
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
            
            test_result = TestResult(
                suite_name=suite.value.title(),
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
            
            self.results.append(test_result)
            
            # Print immediate feedback
            status = "✅ PASSED" if test_result.success else "❌ FAILED"
            print(f"{status} {suite.value.title()} Tests ({duration:.2f}s)")
            if not test_result.success and verbose:
                print(f"Error output: {result.stderr}")
            
            return test_result
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            test_result = TestResult(
                suite_name=suite.value.title(),
                success=False,
                duration=duration,
                test_count=0,
                passed=0,
                failed=0,
                skipped=0,
                errors=1,
                output="",
                error_output="Test suite timed out after 5 minutes"
            )
            
            self.results.append(test_result)
            print(f"⏰ TIMEOUT {suite.value.title()} Tests ({duration:.2f}s)")
            return test_result
            
        except Exception as e:
            duration = time.time() - start_time
            test_result = TestResult(
                suite_name=suite.value.title(),
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
            
            self.results.append(test_result)
            print(f"🚨 ERROR {suite.value.title()} Tests: {e}")
            return test_result
    
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
        
        # If no clear success/failure info, assume all passed if no errors
        if "FAILED" in output or "ERROR" in output:
            return test_count, 0, test_count, 0, 0
        else:
            return test_count, test_count, 0, 0, 0
    
    def run_code_quality_checks(self) -> TestResult:
        """Run code quality checks"""
        logger.info("🔍 Running code quality checks...")
        
        checks = []
        start_time = time.time()
        
        # Flake8 check
        try:
            result = subprocess.run([
                sys.executable, "-m", "flake8", 
                "run_simple_tests_optimized.py",
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
                "run_simple_tests_optimized.py",
                "--ignore-missing-imports"
            ], capture_output=True, text=True, cwd=self.project_root)
            
            checks.append(("MyPy", result.returncode == 0, result.stdout + result.stderr))
        except FileNotFoundError:
            checks.append(("MyPy", False, "mypy not installed"))
        
        # Black check (format checking)
        try:
            result = subprocess.run([
                sys.executable, "-m", "black", 
                "run_simple_tests_optimized.py",
                "--check", "--diff"
            ], capture_output=True, text=True, cwd=self.project_root)
            
            checks.append(("Black", result.returncode == 0, result.stdout + result.stderr))
        except FileNotFoundError:
            checks.append(("Black", False, "black not installed"))
        
        duration = time.time() - start_time
        
        # Aggregate results
        passed_checks = sum(1 for _, success, _ in checks if success)
        failed_checks = len(checks) - passed_checks
        overall_success = failed_checks == 0
        
        output = "\n".join(f"{name}: {'PASS' if success else 'FAIL'}\n{output}" 
                          for name, success, output in checks)
        
        result = TestResult(
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
    
    def run_security_checks(self) -> TestResult:
        """Run security checks"""
        logger.info("🔒 Running security checks...")
        
        start_time = time.time()
        
        # Bandit security check
        try:
            result = subprocess.run([
                sys.executable, "-m", "bandit", 
                "run_simple_tests_optimized.py",
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
        
        result = TestResult(
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
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
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
                "working_directory": str(self.project_root)
            }
        }
        
        return report
    
    def print_summary(self):
        """Print comprehensive test summary"""
        report = self.generate_comprehensive_report()
        
        print("\n" + "=" * 80)
        print("📊 COMPREHENSIVE TEST REPORT")
        print("=" * 80)
        
        print(f"Total Duration: {report['total_duration']:.2f}s")
        print(f"Overall Result: {'✅ SUCCESS' if report['overall_success'] else '❌ FAILURE'}")
        
        print(f"\n📈 Summary:")
        summary = report['summary']
        print(f"   Test Suites: {summary['total_test_suites']}")
        print(f"   Total Tests: {summary['total_tests']}")
        print(f"   ✅ Passed: {summary['passed']}")
        print(f"   ❌ Failed: {summary['failed']}")
        print(f"   ⏭️ Skipped: {summary['skipped']}")
        print(f"   🚨 Errors: {summary['errors']}")
        print(f"   📊 Success Rate: {summary['success_rate']:.1f}%")
        
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
        
        print(f"\n🌍 Environment:")
        env = report['environment']
        print(f"   Python: {env['python_version']}")
        print(f"   Platform: {env['platform']}")
        print(f"   Directory: {env['working_directory']}")
    
    def save_report(self, filename: str = "comprehensive_test_report.json"):
        """Save comprehensive report to file"""
        report = self.generate_comprehensive_report()
        
        report_path = self.project_root / filename
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_path}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Comprehensive PayGuard Simple Test Runner")
    parser.add_argument("--suite", "-s", 
                       choices=[s.value for s in TestSuite],
                       default=TestSuite.ALL.value,
                       help="Test suite to run")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")
    parser.add_argument("--no-quality", action="store_true",
                       help="Skip code quality checks")
    parser.add_argument("--no-security", action="store_true", 
                       help="Skip security checks")
    parser.add_argument("--report", "-r", 
                       default="comprehensive_test_report.json",
                       help="Report output file")
    
    args = parser.parse_args()
    
    print("🚀 PayGuard Simple Test Runner - Comprehensive Test Suite")
    print("=" * 80)
    
    runner = ComprehensiveTestRunner()
    
    try:
        # Run main test suite
        suite = TestSuite(args.suite)
        runner.run_test_suite(suite, args.verbose)
        
        # Run additional checks if requested
        if not args.no_quality:
            runner.run_code_quality_checks()
        
        if not args.no_security:
            runner.run_security_checks()
        
        # Generate and display results
        runner.print_summary()
        runner.save_report(args.report)
        
        # Exit with appropriate code
        overall_success = all(r.success for r in runner.results)
        sys.exit(0 if overall_success else 1)
        
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Test runner failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()