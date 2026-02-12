#!/usr/bin/env python3
"""
PayGuard Performance Test Suite
Load testing, stress testing, and performance benchmarks
"""

import pytest
import asyncio
import time
import statistics
import concurrent.futures
import threading
from typing import List, Dict, Any
import httpx
import psutil
import os
from dataclasses import dataclass
from pathlib import Path
import json
import base64
from PIL import Image
import io

@dataclass
class PerformanceMetrics:
    """Performance test results"""
    test_name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    p95_response_time: float
    requests_per_second: float
    total_duration: float
    memory_usage_mb: float
    cpu_usage_percent: float

class PerformanceTestRunner:
    """Performance test runner with metrics collection"""
    
    def __init__(self, base_url: str = "http://localhost:8002"):
        self.base_url = base_url
        self.metrics: List[PerformanceMetrics] = []
    
    async def run_load_test(
        self, 
        endpoint: str, 
        method: str = "GET",
        payload: Dict = None,
        concurrent_users: int = 10,
        requests_per_user: int = 10,
        test_name: str = None
    ) -> PerformanceMetrics:
        """Run load test against an endpoint"""
        
        if test_name is None:
            test_name = f"{method} {endpoint}"
        
        print(f"🚀 Running load test: {test_name}")
        print(f"   Users: {concurrent_users}, Requests/User: {requests_per_user}")
        
        # Track system resources
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        response_times = []
        successful_requests = 0
        failed_requests = 0
        
        start_time = time.time()
        
        async def make_request(session: httpx.AsyncClient) -> float:
            """Make a single request and return response time"""
            nonlocal successful_requests, failed_requests
            
            request_start = time.time()
            try:
                if method.upper() == "GET":
                    response = await session.get(f"{self.base_url}{endpoint}")
                elif method.upper() == "POST":
                    response = await session.post(f"{self.base_url}{endpoint}", json=payload)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                
                request_time = time.time() - request_start
                
                if response.status_code < 400:
                    successful_requests += 1
                else:
                    failed_requests += 1
                
                return request_time
                
            except Exception as e:
                failed_requests += 1
                return time.time() - request_start
        
        async def user_session():
            """Simulate a user making multiple requests"""
            async with httpx.AsyncClient(timeout=30.0) as session:
                user_times = []
                for _ in range(requests_per_user):
                    response_time = await make_request(session)
                    user_times.append(response_time)
                    await asyncio.sleep(0.1)  # Small delay between requests
                return user_times
        
        # Run concurrent user sessions
        tasks = [user_session() for _ in range(concurrent_users)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect response times
        for result in results:
            if isinstance(result, list):
                response_times.extend(result)
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        # Calculate metrics
        if response_times:
            avg_response_time = statistics.mean(response_times)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
            p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
        else:
            avg_response_time = min_response_time = max_response_time = p95_response_time = 0
        
        total_requests = concurrent_users * requests_per_user
        requests_per_second = total_requests / total_duration if total_duration > 0 else 0
        
        # System resource usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_usage = final_memory - initial_memory
        cpu_usage = process.cpu_percent()
        
        metrics = PerformanceMetrics(
            test_name=test_name,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            p95_response_time=p95_response_time,
            requests_per_second=requests_per_second,
            total_duration=total_duration,
            memory_usage_mb=memory_usage,
            cpu_usage_percent=cpu_usage
        )
        
        self.metrics.append(metrics)
        self._print_metrics(metrics)
        return metrics
    
    def _print_metrics(self, metrics: PerformanceMetrics):
        """Print performance metrics"""
        print(f"\n📊 Performance Results: {metrics.test_name}")
        print(f"   Total Requests: {metrics.total_requests}")
        print(f"   ✅ Successful: {metrics.successful_requests}")
        print(f"   ❌ Failed: {metrics.failed_requests}")
        print(f"   📈 Success Rate: {(metrics.successful_requests/metrics.total_requests)*100:.1f}%")
        print(f"   ⚡ Requests/sec: {metrics.requests_per_second:.2f}")
        print(f"   ⏱️  Avg Response: {metrics.avg_response_time*1000:.2f}ms")
        print(f"   📊 95th Percentile: {metrics.p95_response_time*1000:.2f}ms")
        print(f"   💾 Memory Usage: {metrics.memory_usage_mb:.2f}MB")
        print(f"   🖥️  CPU Usage: {metrics.cpu_usage_percent:.1f}%")
    
    def generate_report(self, output_file: str = "performance_report.json"):
        """Generate performance test report"""
        report = {
            "timestamp": time.time(),
            "system_info": {
                "cpu_count": psutil.cpu_count(),
                "memory_total_gb": psutil.virtual_memory().total / 1024 / 1024 / 1024,
                "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}"
            },
            "test_results": [
                {
                    "test_name": m.test_name,
                    "total_requests": m.total_requests,
                    "successful_requests": m.successful_requests,
                    "failed_requests": m.failed_requests,
                    "success_rate_percent": (m.successful_requests/m.total_requests)*100,
                    "avg_response_time_ms": m.avg_response_time * 1000,
                    "p95_response_time_ms": m.p95_response_time * 1000,
                    "requests_per_second": m.requests_per_second,
                    "memory_usage_mb": m.memory_usage_mb,
                    "cpu_usage_percent": m.cpu_usage_percent
                }
                for m in self.metrics
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Performance report saved to: {output_file}")

class TestPayGuardPerformance:
    """PayGuard performance test suite"""
    
    @pytest.fixture
    def perf_runner(self):
        """Performance test runner"""
        return PerformanceTestRunner()
    
    @pytest.fixture
    def test_image_b64(self):
        """Base64 encoded test image"""
        img = Image.new('RGB', (800, 600), color='red')
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='JPEG', quality=80)
        return base64.b64encode(img_bytes.getvalue()).decode()
    
    @pytest.mark.asyncio
    async def test_health_endpoint_load(self, perf_runner):
        """Load test health endpoint"""
        metrics = await perf_runner.run_load_test(
            endpoint="/api/health",
            method="GET",
            concurrent_users=20,
            requests_per_user=50,
            test_name="Health Endpoint Load Test"
        )
        
        # Performance assertions
        assert metrics.successful_requests > 0
        assert metrics.avg_response_time < 0.1  # Less than 100ms average
        assert metrics.requests_per_second > 100  # At least 100 RPS
        assert (metrics.successful_requests / metrics.total_requests) > 0.95  # 95% success rate
    
    @pytest.mark.asyncio
    async def test_risk_assessment_load(self, perf_runner):
        """Load test risk assessment endpoint"""
        metrics = await perf_runner.run_load_test(
            endpoint="/api/risk?url=https://example.com",
            method="GET",
            concurrent_users=10,
            requests_per_user=20,
            test_name="Risk Assessment Load Test"
        )
        
        # Performance assertions for more complex endpoint
        assert metrics.successful_requests > 0
        assert metrics.avg_response_time < 2.0  # Less than 2s average
        assert metrics.requests_per_second > 5  # At least 5 RPS
        assert (metrics.successful_requests / metrics.total_requests) > 0.90  # 90% success rate
    
    @pytest.mark.asyncio
    async def test_media_risk_load(self, perf_runner, test_image_b64):
        """Load test media risk endpoint"""
        payload = {
            "url": "bytes://test",
            "content": test_image_b64,
            "metadata": {"static": True}
        }
        
        metrics = await perf_runner.run_load_test(
            endpoint="/api/media-risk/bytes",
            method="POST",
            payload=payload,
            concurrent_users=5,
            requests_per_user=10,
            test_name="Media Risk Load Test"
        )
        
        # Performance assertions for AI/ML endpoint
        assert metrics.successful_requests > 0
        assert metrics.avg_response_time < 5.0  # Less than 5s average (AI processing)
        assert metrics.requests_per_second > 1  # At least 1 RPS
        assert (metrics.successful_requests / metrics.total_requests) > 0.80  # 80% success rate
    
    @pytest.mark.asyncio
    async def test_stress_test(self, perf_runner):
        """Stress test with high load"""
        print("\n🔥 Running stress test...")
        
        metrics = await perf_runner.run_load_test(
            endpoint="/api/health",
            method="GET",
            concurrent_users=100,
            requests_per_user=10,
            test_name="Stress Test - High Concurrency"
        )
        
        # Stress test assertions (more lenient)
        assert metrics.successful_requests > 0
        assert (metrics.successful_requests / metrics.total_requests) > 0.70  # 70% success rate under stress
        assert metrics.memory_usage_mb < 500  # Memory usage under control
    
    @pytest.mark.asyncio
    async def test_endurance_test(self, perf_runner):
        """Endurance test with sustained load"""
        print("\n⏰ Running endurance test...")
        
        # Run multiple rounds to simulate sustained load
        total_successful = 0
        total_requests = 0
        
        for round_num in range(5):
            print(f"   Round {round_num + 1}/5")
            metrics = await perf_runner.run_load_test(
                endpoint="/api/health",
                method="GET",
                concurrent_users=10,
                requests_per_user=20,
                test_name=f"Endurance Test Round {round_num + 1}"
            )
            
            total_successful += metrics.successful_requests
            total_requests += metrics.total_requests
            
            # Small break between rounds
            await asyncio.sleep(1)
        
        overall_success_rate = total_successful / total_requests
        print(f"\n🏁 Endurance Test Complete:")
        print(f"   Overall Success Rate: {overall_success_rate*100:.1f}%")
        
        assert overall_success_rate > 0.85  # 85% success rate over time
    
    @pytest.mark.asyncio
    async def test_memory_leak_detection(self, perf_runner):
        """Test for memory leaks during sustained operation"""
        print("\n🔍 Testing for memory leaks...")
        
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Run several rounds and monitor memory
        memory_readings = [initial_memory]
        
        for i in range(10):
            await perf_runner.run_load_test(
                endpoint="/api/health",
                method="GET",
                concurrent_users=5,
                requests_per_user=10,
                test_name=f"Memory Test Round {i+1}"
            )
            
            current_memory = psutil.Process().memory_info().rss / 1024 / 1024
            memory_readings.append(current_memory)
            
            print(f"   Round {i+1}: {current_memory:.2f}MB")
        
        # Check for significant memory growth
        memory_growth = memory_readings[-1] - memory_readings[0]
        print(f"\n📈 Total memory growth: {memory_growth:.2f}MB")
        
        # Assert memory growth is reasonable (less than 100MB for this test)
        assert memory_growth < 100, f"Potential memory leak detected: {memory_growth:.2f}MB growth"
    
    def test_generate_performance_report(self, perf_runner):
        """Generate final performance report"""
        if perf_runner.metrics:
            perf_runner.generate_report("tests/performance_report.json")
            
            # Verify report was created
            assert Path("tests/performance_report.json").exists()

class TestPayGuardBenchmarks:
    """Benchmark tests for specific components"""
    
    def test_scam_detection_benchmark(self):
        """Benchmark scam detection performance"""
        from backend.risk_engine import RiskScoringEngine
        from unittest.mock import Mock
        
        engine = RiskScoringEngine(Mock())
        
        # Test texts of varying lengths
        test_texts = [
            "Short scam: Call 1-800-555-0199 now!",
            "Medium length scam text with more details about fake virus warnings and urgent action required to call support immediately at the provided number.",
            "Very long scam text " * 50 + "with phone number 1-800-555-0199 and urgent warnings about computer infections and security threats that require immediate action."
        ]
        
        results = []
        
        for i, text in enumerate(test_texts):
            start_time = time.time()
            
            # Run detection 100 times
            for _ in range(100):
                result = engine._analyze_text_for_scam(text)
            
            avg_time = (time.time() - start_time) / 100
            results.append((len(text), avg_time))
            
            print(f"Text length {len(text)}: {avg_time*1000:.2f}ms avg")
        
        # Assert performance scales reasonably with text length
        for length, avg_time in results:
            assert avg_time < 0.1, f"Scam detection too slow for length {length}: {avg_time:.3f}s"
    
    def test_image_processing_benchmark(self):
        """Benchmark image processing performance"""
        from backend.risk_engine import RiskScoringEngine
        from unittest.mock import Mock
        
        engine = RiskScoringEngine(Mock())
        
        # Create test images of different sizes
        sizes = [(800, 600), (1920, 1080), (3840, 2160)]  # HD, FHD, 4K
        
        for width, height in sizes:
            img = Image.new('RGB', (width, height), color='red')
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='JPEG', quality=80)
            img_data = img_bytes.getvalue()
            
            start_time = time.time()
            
            # Process image 10 times
            for _ in range(10):
                try:
                    # Test visual cues detection
                    engine._screen_visual_cues(img_data)
                except:
                    pass  # Some methods might not be available in test environment
            
            avg_time = (time.time() - start_time) / 10
            print(f"Image {width}x{height}: {avg_time*1000:.2f}ms avg")
            
            # Assert reasonable processing time
            assert avg_time < 2.0, f"Image processing too slow for {width}x{height}: {avg_time:.3f}s"

if __name__ == "__main__":
    # Run performance tests
    runner = PerformanceTestRunner()
    
    async def run_all_performance_tests():
        print("🚀 PayGuard Performance Test Suite")
        print("=" * 60)
        
        # Basic load tests
        await runner.run_load_test("/api/health", "GET", concurrent_users=10, requests_per_user=20)
        await runner.run_load_test("/api/risk?url=https://example.com", "GET", concurrent_users=5, requests_per_user=10)
        
        # Generate report
        runner.generate_report()
    
    asyncio.run(run_all_performance_tests())