#!/usr/bin/env python3
"""
PayGuard Comprehensive Test Runner
Runs all test suites with proper setup and reporting
"""

import subprocess
import sys
import os
import time
import json
from pathlib import Path
from typing import Dict, List, Any
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TestSuiteRunner:
    """Comprehensive test suite runner for PayGuard"""
    
    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path(__file__).parent
        self.test_results = {}
        self.start_time = time.time()
        
    def check_dependencies(self) -> bool:
        """Check if all test dependencies are installed"""
        logger.info("🔍 Checking test dependencies...")
        
        required_packages = [
            'pytest', 'pytest-asyncio', 'pytest-cov', 'hypothesis',
            'httpx', 'psutil', 'pillow'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            logger.error(f"❌ Missing packages: {', '.join(missing_packages)}")
            logger.info("Install with: pip install -r tests/requirements.txt")
            return False
        
        logger.info("✅ All test dependencies available")
        return True
    
    def check_backend_status(self) -> bool:
        """Check if backend is running"""
        try:
            import httpx
            response = httpx.get("http://localhost:8002/api/health", timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    def check_agent_status(self) -> bool:
        """Check if agent is running"""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "agent.py"], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def run_unit_tests(self) -> Dict[str, Any]:
        """Run unit tests"""
        logger.info("🧪 Running unit tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            "tests/test_payguard_comprehensive.py",
            "-v",
            "--tb=short",
            "--cov=backend",
            "--cov=agent",
            "--cov-report=term-missing",
            "--junit-xml=tests/unit_results.xml",
            "-m", "not slow and not integration and not performance"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
        
        return {
            "name": "Unit Tests",
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr,
            "duration": time.time() - self.start_time
        }
    
    def run_integration_tests(self) -> Dict[str, Any]:
        """Run integration tests"""
        logger.info("🔗 Running integration tests...")
        
        # Check if backend is available
        if not self.check_backend_status():
            logger.warning("⚠️ Backend not running - skipping integration tests")
            return {
                "name": "Integration Tests",
                "success": False,
                "output": "",
                "error": "Backend not available",
                "duration": 0,
                "skipped": True
            }
        
        cmd = [
            sys.executable, "-m", "pytest",
            "tests/test_payguard_comprehensive.py::TestPayGuardIntegration",
            "-v",
            "--tb=short",
            "--junit-xml=tests/integration_results.xml"
        ]
        
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
        
        return {
            "name": "Integration Tests",
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr,
            "duration": time.time() - start_time
        }
    
    def run_performance_tests(self) -> Dict[str, Any]:
        """Run performance tests"""
        logger.info("⚡ Running performance tests...")
        
        if not self.check_backend_status():
            logger.warning("⚠️ Backend not running - skipping performance tests")
            return {
                "name": "Performance Tests",
                "success": False,
                "output": "",
                "error": "Backend not available",
                "duration": 0,
                "skipped": True
            }
        
        cmd = [
            sys.executable, "-m", "pytest",
            "tests/test_performance.py",
            "-v",
            "--tb=short",
            "--junit-xml=tests/performance_results.xml",
            "-s"  # Don't capture output for performance tests
        ]
        
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
        
        return {
            "name": "Performance Tests",
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr,
            "duration": time.time() - start_time
        }
    
    def run_property_tests(self) -> Dict[str, Any]:
        """Run property-based tests"""
        logger.info("🎲 Running property-based tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            "tests/test_property_based.py",
            "-v",
            "--tb=short",
            "--hypothesis-show-statistics",
            "--junit-xml=tests/property_results.xml"
        ]
        
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
        
        return {
            "name": "Property-Based Tests",
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr,
            "duration": time.time() - start_time
        }
    
    def run_optimized_tests(self) -> Dict[str, Any]:
        """Run the optimized test runner"""
        logger.info("🚀 Running optimized test suite...")
        
        cmd = [sys.executable, "run_tests_optimized.py"]
        
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
        
        return {
            "name": "Optimized Test Suite",
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr,
            "duration": time.time() - start_time
        }
    
    def run_code_quality_checks(self) -> Dict[str, Any]:
        """Run code quality checks"""
        logger.info("🔍 Running code quality checks...")
        
        results = {}
        
        # Run flake8
        try:
            result = subprocess.run(
                [sys.executable, "-m", "flake8", "backend", "agent", "--max-line-length=100"],
                capture_output=True, text=True, cwd=self.project_root
            )
            results["flake8"] = {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
        except FileNotFoundError:
            results["flake8"] = {"success": False, "error": "flake8 not installed"}
        
        # Run mypy
        try:
            result = subprocess.run(
                [sys.executable, "-m", "mypy", "backend", "--ignore-missing-imports"],
                capture_output=True, text=True, cwd=self.project_root
            )
            results["mypy"] = {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
        except FileNotFoundError:
            results["mypy"] = {"success": False, "error": "mypy not installed"}
        
        overall_success = all(r.get("success", False) for r in results.values())
        
        return {
            "name": "Code Quality Checks",
            "success": overall_success,
            "details": results,
            "duration": 0
        }
    
    def generate_report(self) -> None:
        """Generate comprehensive test report"""
        total_duration = time.time() - self.start_time
        
        # Count results
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results.values() if r.get("success", False))
        failed_tests = total_tests - passed_tests
        skipped_tests = sum(1 for r in self.test_results.values() if r.get("skipped", False))
        
        # Generate report
        report = {
            "timestamp": time.time(),
            "total_duration": total_duration,
            "summary": {
                "total_test_suites": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "skipped": skipped_tests,
                "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0
            },
            "environment": {
                "backend_available": self.check_backend_status(),
                "agent_available": self.check_agent_status(),
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            },
            "test_results": self.test_results
        }
        
        # Save report
        report_path = self.project_root / "tests" / "comprehensive_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n" + "="*80)
        print("📊 COMPREHENSIVE TEST REPORT")
        print("="*80)
        print(f"Total Duration: {total_duration:.2f}s")
        print(f"Test Suites: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"⏭️ Skipped: {skipped_tests}")
        print(f"Success Rate: {report['summary']['success_rate']:.1f}%")
        
        print(f"\n🌍 Environment:")
        print(f"   Backend: {'✅' if report['environment']['backend_available'] else '❌'}")
        print(f"   Agent: {'✅' if report['environment']['agent_available'] else '❌'}")
        print(f"   Python: {report['environment']['python_version']}")
        
        print(f"\n📄 Detailed report saved to: {report_path}")
        
        # Print failed tests
        if failed_tests > 0:
            print(f"\n❌ Failed Test Suites:")
            for name, result in self.test_results.items():
                if not result.get("success", False) and not result.get("skipped", False):
                    print(f"   • {name}")
                    if result.get("error"):
                        print(f"     Error: {result['error'][:100]}...")
    
    def run_all(self, include_performance: bool = True, include_property: bool = True) -> bool:
        """Run all test suites"""
        logger.info("🚀 Starting comprehensive PayGuard test suite")
        
        # Check dependencies
        if not self.check_dependencies():
            return False
        
        # Print environment status
        backend_status = "✅" if self.check_backend_status() else "❌"
        agent_status = "✅" if self.check_agent_status() else "❌"
        
        print(f"\n🌍 Environment Status:")
        print(f"   Backend: {backend_status}")
        print(f"   Agent: {agent_status}")
        
        # Run test suites
        test_suites = [
            ("unit", self.run_unit_tests),
            ("integration", self.run_integration_tests),
            ("optimized", self.run_optimized_tests),
            ("quality", self.run_code_quality_checks)
        ]
        
        if include_performance:
            test_suites.append(("performance", self.run_performance_tests))
        
        if include_property:
            test_suites.append(("property", self.run_property_tests))
        
        # Execute test suites
        for suite_name, suite_func in test_suites:
            try:
                result = suite_func()
                self.test_results[result["name"]] = result
                
                status = "✅" if result.get("success", False) else ("⏭️" if result.get("skipped", False) else "❌")
                duration = result.get("duration", 0)
                print(f"{status} {result['name']} ({duration:.2f}s)")
                
            except Exception as e:
                logger.error(f"Error running {suite_name} tests: {e}")
                self.test_results[f"{suite_name.title()} Tests"] = {
                    "name": f"{suite_name.title()} Tests",
                    "success": False,
                    "error": str(e),
                    "duration": 0
                }
        
        # Generate report
        self.generate_report()
        
        # Return overall success
        return all(r.get("success", False) or r.get("skipped", False) for r in self.test_results.values())

def main():
    """Main test runner entry point"""
    parser = argparse.ArgumentParser(description="PayGuard Comprehensive Test Runner")
    parser.add_argument("--no-performance", action="store_true", help="Skip performance tests")
    parser.add_argument("--no-property", action="store_true", help="Skip property-based tests")
    parser.add_argument("--unit-only", action="store_true", help="Run only unit tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    runner = TestSuiteRunner()
    
    if args.unit_only:
        result = runner.run_unit_tests()
        success = result["success"]
        print(f"Unit tests: {'✅ PASSED' if success else '❌ FAILED'}")
    else:
        success = runner.run_all(
            include_performance=not args.no_performance,
            include_property=not args.no_property
        )
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()