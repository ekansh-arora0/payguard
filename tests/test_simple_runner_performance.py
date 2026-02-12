#!/usr/bin/env python3
"""
Performance Tests for PayGuard Simple Test Runner
Benchmarking, load testing, and performance regression detection
"""

import pytest
import time
import statistics
import threading
import concurrent.futures
import psutil
import os
import sys
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass
import json
from PIL import Image
import io

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from run_simple_tests_optimized import SimpleTestRunner

@dataclass
class PerformanceMetrics:
    """Performance test results"""
    test_name: str
    operation_count: int
    total_duration: float
    avg_duration: float
    min_duration: float
    max_duration: float
    p95_duration: float
    operations_per_second: float
    memory_usage_mb: float
    cpu_usage_percent: float

class PerformanceTestRunner:
    """Performance test runner with metrics collection"""
    
    def __init__(self):
        self.runner = SimpleTestRunner()
        self.metrics: List[PerformanceMetrics] = []
        self.process = psutil.Process()
    
    def measure_performance(self, test_name: str, operation_func, iterations: int = 100) -> PerformanceMetrics:
        """Measure performance of an operation"""
        print(f"🚀 Running performance test: {test_name} ({iterations} iterations)")
        
        # Warm up
        for _ in range(min(10, iterations // 10)):
            operation_func()
        
        # Measure baseline memory
        initial_memory = self.process.memory_info().rss / 1024 / 1024
        
        # Measure performance
        durations = []
        start_time = time.time()
        
        for _ in range(iterations):
            op_start = time.time()
            operation_func()
            op_duration = time.time() - op_start
            durations.append(op_duration)
        
        total_duration = time.time() - start_time
        
        # Calculate metrics
        avg_duration = statistics.mean(durations)
        min_duration = min(durations)
        max_duration = max(durations)
        p95_duration = statistics.quantiles(durations, n=20)[18] if len(durations) > 20 else max_duration
        operations_per_second = iterations / total_duration
        
        # Memory usage
        final_memory = self.process.memory_info().rss / 1024 / 1024
        memory_usage = final_memory - initial_memory
        
        # CPU usage (approximate)
        cpu_usage = self.process.cpu_percent()
        
        metrics = PerformanceMetrics(
            test_name=test_name,
            operation_count=iterations,
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
        print(f"   Operations: {metrics.operation_count}")
        print(f"   Total Time: {metrics.total_duration:.3f}s")
        print(f"   Avg Time: {metrics.avg_duration*1000:.2f}ms")
        print(f"   95th Percentile: {metrics.p95_duration*1000:.2f}ms")
        print(f"   Ops/sec: {metrics.operations_per_second:.1f}")
        print(f"   Memory: {metrics.memory_usage_mb:.2f}MB")
        print(f"   CPU: {metrics.cpu_usage_percent:.1f}%")
    
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
                    "operation_count": m.operation_count,
                    "total_duration": m.total_duration,
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

class TestTextAnalysisPerformance:
    """Performance tests for text analysis"""
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_short_text_performance(self, perf_runner):
        """Test performance with short texts"""
        short_texts = [
            "URGENT: Call now!",
            "Your account is suspended",
            "Virus detected!",
            "Click here to verify",
            "Normal business email"
        ]
        
        def operation():
            text = short_texts[hash(time.time()) % len(short_texts)]
            perf_runner.runner.analyze_text_for_scam(text)
        
        metrics = perf_runner.measure_performance("Short Text Analysis", operation, 1000)
        
        # Performance assertions
        assert metrics.avg_duration < 0.001, f"Short text analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 1000, f"Short text throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_medium_text_performance(self, perf_runner):
        """Test performance with medium-length texts"""
        medium_text = """
        URGENT SECURITY ALERT: Your computer has been infected with malware!
        This is a critical security warning from Microsoft Windows Security.
        Your personal files and data are at risk of being permanently deleted.
        Call our certified technicians immediately at 1-800-555-0199 to resolve this issue.
        Do not ignore this warning or your computer will be permanently damaged.
        """
        
        def operation():
            perf_runner.runner.analyze_text_for_scam(medium_text)
        
        metrics = perf_runner.measure_performance("Medium Text Analysis", operation, 500)
        
        # Performance assertions
        assert metrics.avg_duration < 0.005, f"Medium text analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 200, f"Medium text throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_long_text_performance(self, perf_runner):
        """Test performance with long texts"""
        long_text = """
        URGENT SECURITY ALERT: Your computer has been infected with malware!
        """ * 100  # Very long text
        
        def operation():
            perf_runner.runner.analyze_text_for_scam(long_text)
        
        metrics = perf_runner.measure_performance("Long Text Analysis", operation, 100)
        
        # Performance assertions
        assert metrics.avg_duration < 0.02, f"Long text analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 50, f"Long text throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_pattern_compilation_performance(self, perf_runner):
        """Test that pre-compiled patterns improve performance"""
        test_text = "URGENT: Your computer is infected! Call 1-800-555-0199 immediately!"
        
        # Test with compiled patterns (current implementation)
        def compiled_operation():
            perf_runner.runner.analyze_text_for_scam(test_text)
        
        compiled_metrics = perf_runner.measure_performance("Compiled Patterns", compiled_operation, 1000)
        
        # Test with re-compilation each time (simulated)
        import re
        def uncompiled_operation():
            patterns = perf_runner.runner.SCAM_PATTERNS
            score = 0
            for pattern, pattern_score, name in patterns:
                if re.search(pattern, test_text):
                    score += pattern_score
        
        uncompiled_metrics = perf_runner.measure_performance("Uncompiled Patterns", uncompiled_operation, 1000)
        
        # Compiled patterns should be faster
        improvement_ratio = uncompiled_metrics.avg_duration / compiled_metrics.avg_duration
        print(f"Pattern compilation improvement: {improvement_ratio:.2f}x faster")
        assert improvement_ratio > 1.5, f"Pattern compilation not providing expected speedup: {improvement_ratio:.2f}x"
    
    def test_text_analysis_scaling(self, perf_runner):
        """Test how text analysis scales with input size"""
        text_sizes = [10, 50, 100, 500, 1000, 5000]
        base_text = "URGENT: Your computer is infected! Call 1-800-555-0199 "
        
        scaling_results = []
        
        for size in text_sizes:
            # Create text of specified size
            test_text = (base_text * (size // len(base_text) + 1))[:size]
            
            def operation():
                perf_runner.runner.analyze_text_for_scam(test_text)
            
            metrics = perf_runner.measure_performance(f"Text Size {size}", operation, 100)
            scaling_results.append((size, metrics.avg_duration))
        
        # Check that scaling is reasonable (should be roughly linear or better)
        for i in range(1, len(scaling_results)):
            prev_size, prev_time = scaling_results[i-1]
            curr_size, curr_time = scaling_results[i]
            
            size_ratio = curr_size / prev_size
            time_ratio = curr_time / prev_time
            
            # Time should not increase faster than size squared
            assert time_ratio < size_ratio ** 2, f"Poor scaling: {size_ratio:.1f}x size -> {time_ratio:.1f}x time"

class TestUrlAnalysisPerformance:
    """Performance tests for URL analysis"""
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_url_analysis_performance(self, perf_runner):
        """Test URL analysis performance"""
        test_urls = [
            "https://google.com",
            "http://suspicious-site.tk",
            "https://phishing-example.com",
            "javascript:alert('xss')",
            "https://192.168.1.1",
            "ftp://example.com",
            "not-a-url",
            ""
        ]
        
        def operation():
            url = test_urls[hash(time.time()) % len(test_urls)]
            perf_runner.runner.analyze_url(url)
        
        metrics = perf_runner.measure_performance("URL Analysis", operation, 1000)
        
        # Performance assertions
        assert metrics.avg_duration < 0.001, f"URL analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 1000, f"URL throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_batch_url_performance(self, perf_runner):
        """Test batch URL processing performance"""
        urls = [f"https://example{i}.com" for i in range(100)]
        
        def operation():
            for url in urls:
                perf_runner.runner.analyze_url(url)
        
        metrics = perf_runner.measure_performance("Batch URL Analysis", operation, 10)
        
        # Calculate per-URL performance
        per_url_time = metrics.avg_duration / len(urls)
        per_url_ops = metrics.operations_per_second * len(urls)
        
        print(f"Per-URL performance: {per_url_time*1000:.2f}ms, {per_url_ops:.1f} URLs/s")
        
        assert per_url_time < 0.001, f"Per-URL analysis too slow: {per_url_time:.3f}s"

class TestHtmlAnalysisPerformance:
    """Performance tests for HTML analysis"""
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_html_analysis_performance(self, perf_runner):
        """Test HTML analysis performance"""
        test_html = """
        <html>
        <head><title>URGENT SECURITY ALERT</title></head>
        <body style="background-color: red;">
            <h1>Your computer is infected!</h1>
            <p>Call Microsoft at 1-800-555-0199 immediately!</p>
            <p>Do not close this window or your files will be deleted!</p>
        </body>
        </html>
        """
        
        def operation():
            perf_runner.runner.analyze_html_content(test_html)
        
        metrics = perf_runner.measure_performance("HTML Analysis", operation, 1000)
        
        # Performance assertions
        assert metrics.avg_duration < 0.002, f"HTML analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 500, f"HTML throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_large_html_performance(self, perf_runner):
        """Test performance with large HTML documents"""
        # Create large HTML document
        large_html = "<html><body>"
        for i in range(1000):
            large_html += f"<p>Content block {i} with some text</p>"
        large_html += "</body></html>"
        
        def operation():
            perf_runner.runner.analyze_html_content(large_html)
        
        metrics = perf_runner.measure_performance("Large HTML Analysis", operation, 100)
        
        # Performance assertions
        assert metrics.avg_duration < 0.01, f"Large HTML analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 100, f"Large HTML throughput too low: {metrics.operations_per_second:.1f} ops/s"

class TestImageAnalysisPerformance:
    """Performance tests for image analysis"""
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    @pytest.fixture
    def test_images(self):
        """Create test images of different sizes"""
        images = {}
        
        sizes = [(100, 100), (500, 500), (1000, 1000)]
        
        for width, height in sizes:
            img = Image.new('RGB', (width, height), color='red')
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            images[f'{width}x{height}'] = (img, img_bytes.getvalue())
        
        return images
    
    def test_small_image_performance(self, perf_runner, test_images):
        """Test performance with small images"""
        img, img_data = test_images['100x100']
        
        def operation():
            perf_runner.runner._analyze_image_risk(img, img_data)
        
        metrics = perf_runner.measure_performance("Small Image Analysis", operation, 500)
        
        # Performance assertions
        assert metrics.avg_duration < 0.01, f"Small image analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 100, f"Small image throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_medium_image_performance(self, perf_runner, test_images):
        """Test performance with medium images"""
        img, img_data = test_images['500x500']
        
        def operation():
            perf_runner.runner._analyze_image_risk(img, img_data)
        
        metrics = perf_runner.measure_performance("Medium Image Analysis", operation, 100)
        
        # Performance assertions
        assert metrics.avg_duration < 0.05, f"Medium image analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 20, f"Medium image throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_large_image_performance(self, perf_runner, test_images):
        """Test performance with large images"""
        img, img_data = test_images['1000x1000']
        
        def operation():
            perf_runner.runner._analyze_image_risk(img, img_data)
        
        metrics = perf_runner.measure_performance("Large Image Analysis", operation, 50)
        
        # Performance assertions
        assert metrics.avg_duration < 0.1, f"Large image analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 10, f"Large image throughput too low: {metrics.operations_per_second:.1f} ops/s"

class TestFileOperationsPerformance:
    """Performance tests for file operations"""
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_temp_file_creation_performance(self, perf_runner):
        """Test temporary file creation performance"""
        test_content = "Test content for performance testing"
        
        def operation():
            with perf_runner.runner._temp_file_manager(test_content, '.txt') as temp_file:
                temp_file.read_text()
        
        metrics = perf_runner.measure_performance("Temp File Operations", operation, 200)
        
        # Performance assertions
        assert metrics.avg_duration < 0.01, f"Temp file operations too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 100, f"Temp file throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_large_file_performance(self, perf_runner):
        """Test performance with large file content"""
        large_content = "Large file content " * 1000
        
        def operation():
            with perf_runner.runner._temp_file_manager(large_content, '.txt') as temp_file:
                temp_file.read_text()
        
        metrics = perf_runner.measure_performance("Large File Operations", operation, 50)
        
        # Performance assertions
        assert metrics.avg_duration < 0.05, f"Large file operations too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 20, f"Large file throughput too low: {metrics.operations_per_second:.1f} ops/s"

class TestConcurrencyPerformance:
    """Performance tests for concurrent operations"""
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_concurrent_text_analysis(self, perf_runner):
        """Test concurrent text analysis performance"""
        test_texts = [
            "URGENT: Your computer is infected! Call 1-800-555-0199",
            "Your account has been suspended. Verify immediately.",
            "Congratulations! You've won $1000.",
            "Normal business email about our services."
        ] * 25  # 100 texts total
        
        def sequential_operation():
            for text in test_texts:
                perf_runner.runner.analyze_text_for_scam(text)
        
        def concurrent_operation():
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(perf_runner.runner.analyze_text_for_scam, text) for text in test_texts]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
        
        # Measure sequential performance
        sequential_metrics = perf_runner.measure_performance("Sequential Text Analysis", sequential_operation, 5)
        
        # Measure concurrent performance
        concurrent_metrics = perf_runner.measure_performance("Concurrent Text Analysis", concurrent_operation, 5)
        
        # Concurrent should be faster (or at least not much slower due to GIL)
        speedup = sequential_metrics.avg_duration / concurrent_metrics.avg_duration
        print(f"Concurrency speedup: {speedup:.2f}x")
        
        # Should at least not be significantly slower
        assert speedup > 0.5, f"Concurrency causing significant slowdown: {speedup:.2f}x"
    
    def test_thread_safety_performance(self, perf_runner):
        """Test thread safety doesn't impact performance significantly"""
        test_text = "URGENT: Your computer is infected! Call 1-800-555-0199"
        
        def single_thread_operation():
            for _ in range(100):
                perf_runner.runner.analyze_text_for_scam(test_text)
        
        def multi_thread_operation():
            def worker():
                for _ in range(25):
                    perf_runner.runner.analyze_text_for_scam(test_text)
            
            threads = [threading.Thread(target=worker) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        
        single_metrics = perf_runner.measure_performance("Single Thread", single_thread_operation, 10)
        multi_metrics = perf_runner.measure_performance("Multi Thread", multi_thread_operation, 10)
        
        # Multi-threading shouldn't be significantly slower
        slowdown = multi_metrics.avg_duration / single_metrics.avg_duration
        print(f"Multi-threading overhead: {slowdown:.2f}x")
        
        assert slowdown < 2.0, f"Excessive multi-threading overhead: {slowdown:.2f}x"

class TestMemoryPerformance:
    """Memory usage and leak detection tests"""
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_memory_usage_stability(self, perf_runner):
        """Test that memory usage remains stable during extended operation"""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        
        memory_readings = [initial_memory]
        
        # Perform many operations
        for i in range(1000):
            # Mix of different operations
            perf_runner.runner.analyze_text_for_scam(f"URGENT: Test {i}")
            perf_runner.runner.analyze_url(f"https://test{i}.com")
            perf_runner.runner.analyze_html_content(f"<html><body>Test {i}</body></html>")
            
            # Record memory every 100 operations
            if i % 100 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                memory_readings.append(current_memory)
        
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_growth = final_memory - initial_memory
        
        print(f"Memory usage: {initial_memory:.2f}MB -> {final_memory:.2f}MB (growth: {memory_growth:.2f}MB)")
        
        # Memory growth should be reasonable
        assert memory_growth < 50, f"Excessive memory growth: {memory_growth:.2f}MB"
        
        # Memory should not grow continuously
        max_memory = max(memory_readings)
        assert max_memory - initial_memory < 100, f"Peak memory usage too high: {max_memory - initial_memory:.2f}MB"
    
    def test_temp_file_memory_cleanup(self, perf_runner):
        """Test that temporary files don't cause memory leaks"""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        
        # Create and cleanup many temp files
        for i in range(100):
            content = f"Test content {i} " * 100  # Larger content
            with perf_runner.runner._temp_file_manager(content, '.txt') as temp_file:
                temp_file.read_text()
        
        # Force cleanup
        perf_runner.runner.cleanup()
        
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_growth = final_memory - initial_memory
        
        print(f"Temp file memory impact: {memory_growth:.2f}MB")
        
        # Should not cause significant memory growth
        assert memory_growth < 10, f"Temp files causing memory growth: {memory_growth:.2f}MB"

class TestRegressionDetection:
    """Performance regression detection tests"""
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_performance_baselines(self, perf_runner):
        """Test against performance baselines"""
        # Define performance baselines (these would be updated as optimizations are made)
        baselines = {
            "text_analysis_ms": 1.0,  # 1ms for typical text
            "url_analysis_ms": 0.5,   # 0.5ms for typical URL
            "html_analysis_ms": 2.0,  # 2ms for typical HTML
        }
        
        # Test text analysis
        def text_op():
            perf_runner.runner.analyze_text_for_scam("URGENT: Your computer is infected! Call 1-800-555-0199")
        
        text_metrics = perf_runner.measure_performance("Text Baseline", text_op, 1000)
        text_ms = text_metrics.avg_duration * 1000
        
        # Test URL analysis
        def url_op():
            perf_runner.runner.analyze_url("https://suspicious-site.tk")
        
        url_metrics = perf_runner.measure_performance("URL Baseline", url_op, 1000)
        url_ms = url_metrics.avg_duration * 1000
        
        # Test HTML analysis
        def html_op():
            perf_runner.runner.analyze_html_content("<html><body>URGENT ALERT</body></html>")
        
        html_metrics = perf_runner.measure_performance("HTML Baseline", html_op, 1000)
        html_ms = html_metrics.avg_duration * 1000
        
        # Check against baselines (allow 50% tolerance for CI environment variations)
        tolerance = 1.5
        
        assert text_ms < baselines["text_analysis_ms"] * tolerance, \
            f"Text analysis regression: {text_ms:.2f}ms > {baselines['text_analysis_ms'] * tolerance:.2f}ms"
        
        assert url_ms < baselines["url_analysis_ms"] * tolerance, \
            f"URL analysis regression: {url_ms:.2f}ms > {baselines['url_analysis_ms'] * tolerance:.2f}ms"
        
        assert html_ms < baselines["html_analysis_ms"] * tolerance, \
            f"HTML analysis regression: {html_ms:.2f}ms > {baselines['html_analysis_ms'] * tolerance:.2f}ms"
        
        print(f"✅ Performance baselines met:")
        print(f"   Text: {text_ms:.2f}ms (baseline: {baselines['text_analysis_ms']}ms)")
        print(f"   URL: {url_ms:.2f}ms (baseline: {baselines['url_analysis_ms']}ms)")
        print(f"   HTML: {html_ms:.2f}ms (baseline: {baselines['html_analysis_ms']}ms)")

if __name__ == "__main__":
    # Run performance tests
    runner = PerformanceTestRunner()
    
    print("🚀 PayGuard Simple Test Runner Performance Suite")
    print("=" * 60)
    
    # Run key performance tests
    test_text = "URGENT: Your computer is infected! Call 1-800-555-0199"
    runner.measure_performance("Text Analysis", 
                             lambda: runner.runner.analyze_text_for_scam(test_text), 1000)
    
    runner.measure_performance("URL Analysis", 
                             lambda: runner.runner.analyze_url("https://suspicious-site.tk"), 1000)
    
    runner.measure_performance("HTML Analysis", 
                             lambda: runner.runner.analyze_html_content("<html><body>URGENT</body></html>"), 1000)
    
    # Generate report
    runner.generate_report("tests/performance_report.json")
    
    pytest.main([__file__, "-v"])