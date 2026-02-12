#!/usr/bin/env python3
"""
Performance Test Suite for PayGuard Feature Tester
Load testing, stress testing, and performance benchmarks
"""

import pytest
import asyncio
import aiohttp
import time
import statistics
import psutil
import os
from typing import List, Dict, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

# Import test modules
import sys
sys.path.append(str(Path(__file__).parent.parent))

from test_all_payguard_features_comprehensive_optimized import (
    PayGuardFeatureTesterOptimized, TestConfig, TestStatus
)

@dataclass
class PerformanceMetrics:
    """Performance test metrics"""
    test_name: str
    total_operations: int
    successful_operations: int
    failed_operations: int
    total_duration: float
    avg_duration: float
    min_duration: float
    max_duration: float
    p95_duration: float
    operations_per_second: float
    memory_usage_mb: float
    cpu_usage_percent: float

class PayGuardPerformanceTester:
    """Performance tester for PayGuard features"""
    
    def __init__(self, backend_url: str = "http://localhost:8002"):
        self.backend_url = backend_url
        self.metrics: List[PerformanceMetrics] = []
        self.process = psutil.Process()
    
    async def measure_performance(self, test_name: str, operation_func, 
                                iterations: int = 100) -> PerformanceMetrics:
        """Measure performance of an async operation"""
        print(f"🚀 Performance test: {test_name} ({iterations} iterations)")
        
        # Warm up
        for _ in range(min(5, iterations // 10)):
            try:
                await operation_func()
            except:
                pass
        
        # Measure baseline memory
        initial_memory = self.process.memory_info().rss / 1024 / 1024
        
        # Measure performance
        durations = []
        successful_ops = 0
        failed_ops = 0
        
        start_time = time.time()
        
        for _ in range(iterations):
            op_start = time.time()
            try:
                await operation_func()
                successful_ops += 1
            except Exception:
                failed_ops += 1
            
            op_duration = time.time() - op_start
            durations.append(op_duration)
        
        total_duration = time.time() - start_time
        
        # Calculate metrics
        if durations:
            avg_duration = statistics.mean(durations)
            min_duration = min(durations)
            max_duration = max(durations)
            p95_duration = statistics.quantiles(durations, n=20)[18] if len(durations) >= 20 else max_duration
        else:
            avg_duration = min_duration = max_duration = p95_duration = 0
        
        operations_per_second = iterations / total_duration if total_duration > 0 else 0
        
        # Memory usage
        final_memory = self.process.memory_info().rss / 1024 / 1024
        memory_usage = final_memory - initial_memory
        
        # CPU usage
        cpu_usage = self.process.cpu_percent()
        
        metrics = PerformanceMetrics(
            test_name=test_name,
            total_operations=iterations,
            successful_operations=successful_ops,
            failed_operations=failed_ops,
            total_duration=total_duration,
            avg_duration=avg_duration,
            min_duration=min_duration,
            max_duration=max_duration,
            p95_duration=p95_duration,
            operations_per_second=operations_per_second,
            memory_usage_mb=memory_usage,
            cpu_usage_percent=cpu_usage
        )
        
        self.metrics.append(metrics)
        self._print_metrics(metrics)
        return metrics
    
    def _print_metrics(self, metrics: PerformanceMetrics):
        """Print performance metrics"""
        print(f"📊 {metrics.test_name}:")
        print(f"   Operations: {metrics.total_operations}")
        print(f"   ✅ Successful: {metrics.successful_operations}")
        print(f"   ❌ Failed: {metrics.failed_operations}")
        print(f"   ⚡ Ops/sec: {metrics.operations_per_second:.2f}")
        print(f"   ⏱️  Avg Time: {metrics.avg_duration*1000:.2f}ms")
        print(f"   📊 95th Percentile: {metrics.p95_duration*1000:.2f}ms")
        print(f"   💾 Memory: {metrics.memory_usage_mb:.2f}MB")
        print(f"   🖥️  CPU: {metrics.cpu_usage_percent:.1f}%")
    
    def generate_report(self, output_file: str = "performance_report.json"):
        """Generate performance report"""
        report = {
            "timestamp": time.time(),
            "system_info": {
                "cpu_count": psutil.cpu_count(),
                "memory_total_gb": psutil.virtual_memory().total / 1024 / 1024 / 1024,
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            },
            "performance_results": [
                {
                    "test_name": m.test_name,
                    "total_operations": m.total_operations,
                    "successful_operations": m.successful_operations,
                    "failed_operations": m.failed_operations,
                    "success_rate_percent": (m.successful_operations / m.total_operations * 100) if m.total_operations > 0 else 0,
                    "avg_duration_ms": m.avg_duration * 1000,
                    "p95_duration_ms": m.p95_duration * 1000,
                    "operations_per_second": m.operations_per_second,
                    "memory_usage_mb": m.memory_usage_mb,
                    "cpu_usage_percent": m.cpu_usage_percent
                }
                for m in self.metrics
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Performance report saved to: {output_file}")

class TestPayGuardFeaturePerformance:
    """Performance tests for PayGuard feature tester"""
    
    @pytest.fixture
    def perf_tester(self):
        """Performance tester instance"""
        return PayGuardPerformanceTester()
    
    @pytest.fixture
    def test_config(self):
        """Optimized test configuration for performance"""
        return TestConfig(
            backend_url="http://localhost:8002",
            timeout=5,
            max_concurrent=10,
            retry_attempts=1,
            retry_delay=0.1
        )
    
    @pytest.mark.asyncio
    async def test_health_check_performance(self, perf_tester, test_config):
        """Test health check endpoint performance"""
        async def health_check_operation():
            async with PayGuardFeatureTesterOptimized(test_config) as tester:
                # Mock successful health check
                async def mock_request(*args, **kwargs):
                    await asyncio.sleep(0.001)  # Simulate 1ms response
                    return 200, {"status": "healthy"}
                
                tester._make_request_with_retry = mock_request
                await tester.check_backend_health()
        
        metrics = await perf_tester.measure_performance(
            "Health Check Performance", 
            health_check_operation, 
            iterations=100
        )
        
        # Performance assertions
        assert metrics.operations_per_second > 50  # At least 50 ops/sec
        assert metrics.avg_duration < 0.1  # Less than 100ms average
        assert metrics.successful_operations > 90  # 90%+ success rate
    
    @pytest.mark.asyncio
    async def test_url_analysis_performance(self, perf_tester, test_config):
        """Test URL analysis performance"""
        test_urls = [
            "https://microsoft.com",
            "https://google.com", 
            "https://suspicious-site.xyz",
            "https://phishing-example.com"
        ]
        
        url_index = 0
        
        async def url_analysis_operation():
            nonlocal url_index
            async with PayGuardFeatureTesterOptimized(test_config) as tester:
                # Mock URL analysis
                async def mock_request(method, url, **kwargs):
                    await asyncio.sleep(0.005)  # Simulate 5ms response
                    return 200, {
                        "risk_level": "medium",
                        "trust_score": 60
                    }
                
                tester._make_request_with_retry = mock_request
                
                # Simulate analyzing different URLs
                current_url = test_urls[url_index % len(test_urls)]
                url_index += 1
                
                # Mock the URL analysis method
                await tester._make_request_with_retry(
                    "POST", f"{test_config.backend_url}/api/risk-check",
                    json={"url": current_url}
                )
        
        metrics = await perf_tester.measure_performance(
            "URL Analysis Performance",
            url_analysis_operation,
            iterations=50
        )
        
        # Performance assertions
        assert metrics.operations_per_second > 20  # At least 20 ops/sec
        assert metrics.avg_duration < 0.2  # Less than 200ms average
        assert metrics.successful_operations > 45  # 90%+ success rate
    
    @pytest.mark.asyncio
    async def test_concurrent_operations_performance(self, perf_tester, test_config):
        """Test concurrent operations performance"""
        async def concurrent_operation():
            async with PayGuardFeatureTesterOptimized(test_config) as tester:
                # Mock fast responses
                async def mock_request(*args, **kwargs):
                    await asyncio.sleep(0.002)  # Simulate 2ms response
                    return 200, {"status": "ok"}
                
                tester._make_request_with_retry = mock_request
                
                # Run multiple concurrent requests
                tasks = []
                for _ in range(5):  # 5 concurrent requests
                    task = tester._make_request_with_retry("GET", f"{test_config.backend_url}/api/health")
                    tasks.append(task)
                
                await asyncio.gather(*tasks)
        
        metrics = await perf_tester.measure_performance(
            "Concurrent Operations Performance",
            concurrent_operation,
            iterations=20
        )
        
        # Performance assertions
        assert metrics.operations_per_second > 10  # At least 10 ops/sec
        assert metrics.avg_duration < 0.5  # Less than 500ms average
        assert metrics.successful_operations > 18  # 90%+ success rate
    
    @pytest.mark.asyncio
    async def test_image_generation_performance(self, perf_tester):
        """Test image generation performance"""
        async def image_generation_operation():
            tester = PayGuardFeatureTesterOptimized()
            
            # Mock PIL to simulate image generation
            with pytest.mock.patch('test_all_payguard_features_comprehensive_optimized.Image') as mock_image:
                with pytest.mock.patch('test_all_payguard_features_comprehensive_optimized.ImageDraw'):
                    with pytest.mock.patch('test_all_payguard_features_comprehensive_optimized.ImageFont'):
                        with pytest.mock.patch('test_all_payguard_features_comprehensive_optimized.io.BytesIO') as mock_bytesio:
                            mock_bytes = pytest.mock.Mock()
                            mock_bytes.getvalue.return_value = b'fake_image_data'
                            mock_bytesio.return_value = mock_bytes
                            
                            # Simulate some processing time
                            await asyncio.sleep(0.01)
                            
                            result = tester._generate_test_scam_image()
                            assert result == b'fake_image_data'
        
        metrics = await perf_tester.measure_performance(
            "Image Generation Performance",
            image_generation_operation,
            iterations=30
        )
        
        # Performance assertions
        assert metrics.operations_per_second > 5  # At least 5 ops/sec
        assert metrics.avg_duration < 1.0  # Less than 1s average
        assert metrics.successful_operations > 25  # 85%+ success rate
    
    @pytest.mark.asyncio
    async def test_memory_usage_stability(self, perf_tester, test_config):
        """Test memory usage stability during extended operation"""
        async def memory_test_operation():
            async with PayGuardFeatureTesterOptimized(test_config) as tester:
                # Mock various operations
                async def mock_request(*args, **kwargs):
                    await asyncio.sleep(0.001)
                    return 200, {"status": "ok"}
                
                tester._make_request_with_retry = mock_request
                
                # Perform multiple operations
                await tester.check_backend_health()
                
                # Generate some test data
                test_data = {"large_data": "x" * 1000}  # 1KB of data
                
                # Simulate processing
                await asyncio.sleep(0.001)
        
        metrics = await perf_tester.measure_performance(
            "Memory Usage Stability",
            memory_test_operation,
            iterations=100
        )
        
        # Memory assertions
        assert metrics.memory_usage_mb < 50  # Less than 50MB growth
        assert metrics.successful_operations > 95  # 95%+ success rate
    
    @pytest.mark.asyncio
    async def test_error_handling_performance(self, perf_tester, test_config):
        """Test performance when handling errors"""
        error_count = 0
        
        async def error_prone_operation():
            nonlocal error_count
            async with PayGuardFeatureTesterOptimized(test_config) as tester:
                # Mock operations that sometimes fail
                async def mock_request(*args, **kwargs):
                    nonlocal error_count
                    await asyncio.sleep(0.002)
                    
                    # Fail 20% of the time
                    if error_count % 5 == 0:
                        error_count += 1
                        raise aiohttp.ClientError("Simulated error")
                    
                    error_count += 1
                    return 200, {"status": "ok"}
                
                tester._make_request_with_retry = mock_request
                
                try:
                    await tester.check_backend_health()
                except:
                    pass  # Expected to fail sometimes
        
        metrics = await perf_tester.measure_performance(
            "Error Handling Performance",
            error_prone_operation,
            iterations=50
        )
        
        # Performance assertions with error tolerance
        assert metrics.operations_per_second > 10  # At least 10 ops/sec
        assert metrics.avg_duration < 0.5  # Less than 500ms average
        # Allow for some failures due to simulated errors
        assert metrics.successful_operations > 30  # 60%+ success rate
    
    def test_generate_performance_report(self, perf_tester):
        """Test performance report generation"""
        # Add some mock metrics
        perf_tester.metrics = [
            PerformanceMetrics(
                test_name="Test 1",
                total_operations=100,
                successful_operations=95,
                failed_operations=5,
                total_duration=10.0,
                avg_duration=0.1,
                min_duration=0.05,
                max_duration=0.5,
                p95_duration=0.2,
                operations_per_second=10.0,
                memory_usage_mb=5.0,
                cpu_usage_percent=25.0
            )
        ]
        
        # Generate report
        report_file = "test_performance_report.json"
        perf_tester.generate_report(report_file)
        
        # Verify report was created
        assert Path(report_file).exists()
        
        # Verify report content
        with open(report_file, 'r') as f:
            report_data = json.load(f)
        
        assert "timestamp" in report_data
        assert "system_info" in report_data
        assert "performance_results" in report_data
        assert len(report_data["performance_results"]) == 1
        
        result = report_data["performance_results"][0]
        assert result["test_name"] == "Test 1"
        assert result["total_operations"] == 100
        assert result["success_rate_percent"] == 95.0
        
        # Cleanup
        Path(report_file).unlink()

class TestPayGuardFeatureStressTest:
    """Stress tests for PayGuard features"""
    
    @pytest.mark.asyncio
    async def test_high_concurrency_stress(self):
        """Test system under high concurrency"""
        config = TestConfig(
            backend_url="http://localhost:8002",
            timeout=10,
            max_concurrent=50,  # High concurrency
            retry_attempts=1
        )
        
        async def stress_operation():
            async with PayGuardFeatureTesterOptimized(config) as tester:
                # Mock fast responses
                async def mock_request(*args, **kwargs):
                    await asyncio.sleep(0.001)  # Very fast response
                    return 200, {"status": "ok"}
                
                tester._make_request_with_retry = mock_request
                
                # Create many concurrent tasks
                tasks = []
                for _ in range(20):  # 20 concurrent requests
                    task = tester._make_request_with_retry("GET", f"{config.backend_url}/api/health")
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Count successful operations
                successful = sum(1 for result in results 
                               if not isinstance(result, Exception) and result[0] == 200)
                
                return successful >= 15  # At least 75% success rate
        
        # Run stress test
        start_time = time.time()
        success = await stress_operation()
        duration = time.time() - start_time
        
        assert success, "Stress test failed - too many operations failed"
        assert duration < 5.0, f"Stress test too slow: {duration:.2f}s"
    
    @pytest.mark.asyncio
    async def test_memory_pressure_stress(self):
        """Test system under memory pressure"""
        config = TestConfig(timeout=5, max_concurrent=5)
        
        async def memory_intensive_operation():
            async with PayGuardFeatureTesterOptimized(config) as tester:
                # Create large data structures
                large_data = []
                for i in range(1000):
                    large_data.append({
                        "id": i,
                        "data": "x" * 1000,  # 1KB per item
                        "metadata": {"timestamp": time.time()}
                    })
                
                # Mock operation that processes the data
                async def mock_request(*args, **kwargs):
                    # Simulate processing large data
                    processed = len([item for item in large_data if item["id"] % 2 == 0])
                    await asyncio.sleep(0.01)
                    return 200, {"processed": processed}
                
                tester._make_request_with_retry = mock_request
                
                # Perform operation
                result = await tester._make_request_with_retry("POST", f"{config.backend_url}/api/process")
                
                # Clean up large data
                del large_data
                
                return result[0] == 200
        
        # Monitor memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        
        success = await memory_intensive_operation()
        
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_growth = final_memory - initial_memory
        
        assert success, "Memory intensive operation failed"
        assert memory_growth < 100, f"Excessive memory growth: {memory_growth:.2f}MB"

class TestPayGuardFeatureBenchmarks:
    """Benchmark tests for specific operations"""
    
    def test_config_initialization_benchmark(self):
        """Benchmark configuration initialization"""
        iterations = 1000
        
        start_time = time.time()
        for _ in range(iterations):
            config = TestConfig(
                backend_url="http://localhost:8002",
                timeout=30,
                max_concurrent=5
            )
        duration = time.time() - start_time
        
        avg_time = duration / iterations
        assert avg_time < 0.001, f"Config initialization too slow: {avg_time:.6f}s"
    
    def test_test_result_creation_benchmark(self):
        """Benchmark test result creation"""
        from test_all_payguard_features_comprehensive_optimized import TestResult
        
        iterations = 1000
        
        start_time = time.time()
        for i in range(iterations):
            result = TestResult(
                test_name=f"Test {i}",
                status=TestStatus.PASS,
                details="Test completed successfully",
                duration=1.5,
                timestamp="2024-01-01T00:00:00",
                metadata={"iteration": i}
            )
        duration = time.time() - start_time
        
        avg_time = duration / iterations
        assert avg_time < 0.001, f"TestResult creation too slow: {avg_time:.6f}s"
    
    @pytest.mark.asyncio
    async def test_session_creation_benchmark(self):
        """Benchmark aiohttp session creation"""
        iterations = 10  # Fewer iterations for session creation
        
        start_time = time.time()
        for _ in range(iterations):
            config = TestConfig()
            async with PayGuardFeatureTesterOptimized(config) as tester:
                assert tester.session is not None
        duration = time.time() - start_time
        
        avg_time = duration / iterations
        assert avg_time < 1.0, f"Session creation too slow: {avg_time:.3f}s"

if __name__ == "__main__":
    # Run performance tests
    pytest.main([__file__, "-v", "-s", "--tb=short"])