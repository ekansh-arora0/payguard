#!/usr/bin/env python3
"""
Performance Tests for PayGuard Menu Bar
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
import gc

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from payguard_menubar_optimized import (
    PayGuardMenuBarOptimized, ScamDetector, NotificationManager,
    PerformanceMonitor, DetectionResult
)

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
        self.metrics: List[PerformanceMetrics] = []
        self.process = psutil.Process()
    
    def measure_performance(self, test_name: str, operation_func, iterations: int = 100) -> PerformanceMetrics:
        """Measure performance of an operation"""
        print(f"🚀 Running performance test: {test_name} ({iterations} iterations)")
        
        # Warm up
        for _ in range(min(10, iterations // 10)):
            operation_func()
        
        # Force garbage collection before measurement
        gc.collect()
        
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
    
    def generate_report(self, output_file: str = "payguard_performance_report.json"):
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

class TestScamDetectorPerformance:
    """Performance tests for ScamDetector"""
    
    @pytest.fixture
    def detector(self):
        return ScamDetector()
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_text_analysis_performance_short(self, detector, perf_runner):
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
            detector.analyze_text(text)
        
        metrics = perf_runner.measure_performance("Short Text Analysis", operation, 1000)
        
        # Performance assertions
        assert metrics.avg_duration < 0.001, f"Short text analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 1000, f"Short text throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_text_analysis_performance_medium(self, detector, perf_runner):
        """Test performance with medium-length texts"""
        medium_text = """
        URGENT SECURITY ALERT: Your computer has been infected with malware!
        This is a critical security warning from Microsoft Windows Security.
        Your personal files and data are at risk of being permanently deleted.
        Call our certified technicians immediately at 1-800-555-0199 to resolve this issue.
        Do not ignore this warning or your computer will be permanently damaged.
        """
        
        def operation():
            detector.analyze_text(medium_text)
        
        metrics = perf_runner.measure_performance("Medium Text Analysis", operation, 500)
        
        # Performance assertions
        assert metrics.avg_duration < 0.005, f"Medium text analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 200, f"Medium text throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_text_analysis_performance_long(self, detector, perf_runner):
        """Test performance with long texts"""
        long_text = """
        URGENT SECURITY ALERT: Your computer has been infected with malware!
        """ * 100  # Very long text
        
        def operation():
            detector.analyze_text(long_text)
        
        metrics = perf_runner.measure_performance("Long Text Analysis", operation, 100)
        
        # Performance assertions
        assert metrics.avg_duration < 0.02, f"Long text analysis too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 50, f"Long text throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_pattern_compilation_performance(self, detector, perf_runner):
        """Test that pre-compiled patterns improve performance"""
        test_text = "URGENT: Your computer is infected! Call 1-800-555-0199 immediately!"
        
        # Test with compiled patterns (current implementation)
        def compiled_operation():
            detector.analyze_text(test_text)
        
        compiled_metrics = perf_runner.measure_performance("Compiled Patterns", compiled_operation, 1000)
        
        # Test with re-compilation each time (simulated)
        import re
        def uncompiled_operation():
            patterns = [
                (r'\b1-\d{3}-\d{3}-\d{4}\b', 30, 'phone_number'),
                (r'(?i)\b(urgent|immediate|act now|call now)\b', 25, 'urgency'),
                (r'(?i)\b(virus|infected|malware|trojan)\b', 30, 'virus_warning'),
            ]
            score = 0
            for pattern, pattern_score, name in patterns:
                if re.search(pattern, test_text):
                    score += pattern_score
        
        uncompiled_metrics = perf_runner.measure_performance("Uncompiled Patterns", uncompiled_operation, 1000)
        
        # Compiled patterns should be faster
        improvement_ratio = uncompiled_metrics.avg_duration / compiled_metrics.avg_duration
        print(f"Pattern compilation improvement: {improvement_ratio:.2f}x faster")
        assert improvement_ratio > 1.2, f"Pattern compilation not providing expected speedup: {improvement_ratio:.2f}x"
    
    def test_text_caching_performance(self, detector, perf_runner):
        """Test performance improvement from text caching"""
        test_texts = [
            "URGENT: Your computer is infected! Call 1-800-555-0199",
            "Your account has been suspended. Verify immediately.",
            "Congratulations! You've won $1000.",
        ]
        
        # First run - populate cache
        def first_run():
            for text in test_texts:
                detector.analyze_text(text)
        
        first_metrics = perf_runner.measure_performance("First Run (No Cache)", first_run, 100)
        
        # Second run - use cache
        def cached_run():
            for text in test_texts:
                detector.analyze_text(text)
        
        cached_metrics = perf_runner.measure_performance("Cached Run", cached_run, 100)
        
        # Cached run should be faster
        speedup = first_metrics.avg_duration / cached_metrics.avg_duration
        print(f"Caching speedup: {speedup:.2f}x faster")
        assert speedup > 1.5, f"Caching not providing expected speedup: {speedup:.2f}x"
    
    def test_text_scaling_performance(self, detector, perf_runner):
        """Test how text analysis scales with input size"""
        text_sizes = [10, 50, 100, 500, 1000, 5000]
        base_text = "URGENT: Your computer is infected! Call 1-800-555-0199 "
        
        scaling_results = []
        
        for size in text_sizes:
            # Create text of specified size
            test_text = (base_text * (size // len(base_text) + 1))[:size]
            
            def operation():
                detector.analyze_text(test_text)
            
            metrics = perf_runner.measure_performance(f"Text Size {size}", operation, 50)
            scaling_results.append((size, metrics.avg_duration))
        
        # Check that scaling is reasonable (should be roughly linear or better)
        for i in range(1, len(scaling_results)):
            prev_size, prev_time = scaling_results[i-1]
            curr_size, curr_time = scaling_results[i]
            
            size_ratio = curr_size / prev_size
            time_ratio = curr_time / prev_time
            
            # Time should not increase faster than size squared
            assert time_ratio < size_ratio ** 2, f"Poor scaling: {size_ratio:.1f}x size -> {time_ratio:.1f}x time"
    
    def test_image_analysis_performance(self, detector, perf_runner):
        """Test image analysis performance"""
        # Create test images of different sizes
        test_images = []
        
        sizes = [(400, 300), (800, 600), (1920, 1080)]
        
        for width, height in sizes:
            img = Image.new('RGB', (width, height), color='red')
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            test_images.append((f'{width}x{height}', img_bytes.getvalue()))
        
        for img_name, img_data in test_images:
            def operation():
                detector.analyze_image_colors(img_data)
            
            metrics = perf_runner.measure_performance(f"Image Analysis {img_name}", operation, 50)
            
            # Performance should be reasonable
            assert metrics.avg_duration < 0.1, f"Image analysis too slow for {img_name}: {metrics.avg_duration:.3f}s"

class TestNotificationManagerPerformance:
    """Performance tests for NotificationManager"""
    
    @pytest.fixture
    def notification_manager(self):
        manager = NotificationManager(cooldown_seconds=0.1)
        yield manager
        manager.shutdown()
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_notification_queuing_performance(self, notification_manager, perf_runner):
        """Test notification queuing performance"""
        def operation():
            notification_manager.notify_user("Test", "Message", critical=False)
        
        metrics = perf_runner.measure_performance("Notification Queuing", operation, 1000)
        
        # Queuing should be very fast
        assert metrics.avg_duration < 0.001, f"Notification queuing too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 1000, f"Notification queuing throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_text_sanitization_performance(self, notification_manager, perf_runner):
        """Test text sanitization performance"""
        test_texts = [
            'Simple text',
            'Text with "quotes" and \\backslashes',
            'Complex text with "multiple" \\escape\\ "sequences" and \\more\\',
            'Very long text with quotes and backslashes ' * 100
        ]
        
        def operation():
            text = test_texts[hash(time.time()) % len(test_texts)]
            notification_manager._sanitize_text(text)
        
        metrics = perf_runner.measure_performance("Text Sanitization", operation, 1000)
        
        # Sanitization should be fast
        assert metrics.avg_duration < 0.0001, f"Text sanitization too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 10000, f"Text sanitization throughput too low: {metrics.operations_per_second:.1f} ops/s"

class TestPayGuardPerformance:
    """Performance tests for PayGuardMenuBarOptimized"""
    
    @pytest.fixture
    def payguard(self):
        config = {
            "alert_cooldown": 0.1,
            "enable_performance_monitoring": True
        }
        guard = PayGuardMenuBarOptimized(config)
        yield guard
        guard.shutdown()
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_screen_capture_performance(self, payguard, perf_runner):
        """Test screen capture performance"""
        from unittest.mock import patch, Mock
        
        with patch('subprocess.run') as mock_subprocess, \
             patch('tempfile.mkstemp') as mock_mkstemp, \
             patch('os.close'), \
             patch.object(Path, 'exists', return_value=True), \
             patch.object(Path, 'read_bytes', return_value=b"fake_image_data"), \
             patch.object(Path, 'unlink'):
            
            mock_subprocess.return_value = Mock(returncode=0)
            mock_mkstemp.return_value = (1, "/tmp/test.png")
            
            def operation():
                payguard.capture_screen()
            
            metrics = perf_runner.measure_performance("Screen Capture", operation, 100)
            
            # Screen capture should be reasonably fast
            assert metrics.avg_duration < 0.1, f"Screen capture too slow: {metrics.avg_duration:.3f}s"
            assert metrics.operations_per_second > 10, f"Screen capture throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_clipboard_check_performance(self, payguard, perf_runner):
        """Test clipboard checking performance"""
        from unittest.mock import patch, Mock
        
        test_contents = [
            "Normal clipboard content",
            "URGENT: Call 1-800-555-0199",
            "Your account has been suspended",
            "Virus detected on your computer"
        ]
        
        with patch('subprocess.run') as mock_subprocess:
            def mock_pbpaste(*args, **kwargs):
                content = test_contents[hash(time.time()) % len(test_contents)]
                return Mock(returncode=0, stdout=content)
            
            mock_subprocess.side_effect = mock_pbpaste
            
            def operation():
                # Reset clipboard content to ensure analysis
                payguard.last_clipboard_content = ""
                payguard.check_clipboard()
            
            metrics = perf_runner.measure_performance("Clipboard Check", operation, 500)
            
            # Clipboard checking should be fast
            assert metrics.avg_duration < 0.01, f"Clipboard check too slow: {metrics.avg_duration:.3f}s"
            assert metrics.operations_per_second > 100, f"Clipboard check throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_detection_handling_performance(self, payguard, perf_runner):
        """Test detection handling performance"""
        from unittest.mock import patch
        
        test_results = [
            DetectionResult(is_scam=False),
            DetectionResult(is_scam=True, confidence=85, message="Scam detected"),
            DetectionResult(is_scam=True, confidence=95, message="High confidence scam"),
        ]
        
        with patch.object(payguard.notification_manager, 'notify_user', return_value=True):
            def operation():
                result = test_results[hash(time.time()) % len(test_results)]
                payguard.handle_detection(result, "performance_test")
            
            metrics = perf_runner.measure_performance("Detection Handling", operation, 1000)
            
            # Detection handling should be very fast
            assert metrics.avg_duration < 0.001, f"Detection handling too slow: {metrics.avg_duration:.3f}s"
            assert metrics.operations_per_second > 1000, f"Detection handling throughput too low: {metrics.operations_per_second:.1f} ops/s"
    
    def test_temp_file_management_performance(self, payguard, perf_runner):
        """Test temporary file management performance"""
        def operation():
            with payguard._temp_file_manager(".test") as temp_path:
                temp_path.write_text("test data")
                temp_path.read_text()
        
        metrics = perf_runner.measure_performance("Temp File Management", operation, 200)
        
        # File operations should be reasonably fast
        assert metrics.avg_duration < 0.01, f"Temp file management too slow: {metrics.avg_duration:.3f}s"
        assert metrics.operations_per_second > 100, f"Temp file management throughput too low: {metrics.operations_per_second:.1f} ops/s"

class TestConcurrencyPerformance:
    """Performance tests for concurrent operations"""
    
    @pytest.fixture
    def payguard(self):
        config = {"enable_performance_monitoring": True}
        guard = PayGuardMenuBarOptimized(config)
        yield guard
        guard.shutdown()
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_concurrent_text_analysis(self, payguard, perf_runner):
        """Test concurrent text analysis performance"""
        test_texts = [
            "URGENT: Your computer is infected! Call 1-800-555-0199",
            "Your account has been suspended. Verify immediately.",
            "Congratulations! You've won $1000.",
            "Normal business email about our services."
        ] * 25  # 100 texts total
        
        def sequential_operation():
            for text in test_texts:
                payguard.detector.analyze_text(text)
        
        def concurrent_operation():
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(payguard.detector.analyze_text, text) for text in test_texts]
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
    
    def test_thread_safety_performance(self, payguard, perf_runner):
        """Test thread safety doesn't impact performance significantly"""
        test_text = "URGENT: Your computer is infected! Call 1-800-555-0199"
        
        def single_thread_operation():
            for _ in range(100):
                payguard.detector.analyze_text(test_text)
        
        def multi_thread_operation():
            def worker():
                for _ in range(25):
                    payguard.detector.analyze_text(test_text)
            
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
    def payguard(self):
        config = {"enable_performance_monitoring": True}
        guard = PayGuardMenuBarOptimized(config)
        yield guard
        guard.shutdown()
    
    def test_memory_usage_stability(self, payguard):
        """Test that memory usage remains stable during extended operation"""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        
        memory_readings = [initial_memory]
        
        # Perform many operations
        for i in range(1000):
            # Mix of different operations
            payguard.detector.analyze_text(f"URGENT: Test {i}")
            
            # Vary content to test caching
            if i % 10 == 0:
                payguard.last_clipboard_content = f"clipboard_{i}"
            
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
    
    def test_cache_memory_management(self, payguard):
        """Test that caching doesn't cause excessive memory usage"""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        
        # Create many unique texts to fill cache
        unique_texts = [f"URGENT: Test message {i} with phone 1-800-555-{i:04d}" for i in range(1000)]
        
        # Analyze all texts (should populate cache)
        for text in unique_texts:
            payguard.detector.analyze_text(text)
        
        cache_filled_memory = process.memory_info().rss / 1024 / 1024
        cache_memory_usage = cache_filled_memory - initial_memory
        
        print(f"Cache memory usage: {cache_memory_usage:.2f}MB for {len(unique_texts)} cached items")
        
        # Cache should not use excessive memory
        assert cache_memory_usage < 100, f"Cache using too much memory: {cache_memory_usage:.2f}MB"
        
        # Average memory per cached item should be reasonable
        avg_memory_per_item = cache_memory_usage / len(unique_texts)
        assert avg_memory_per_item < 0.1, f"Too much memory per cached item: {avg_memory_per_item:.3f}MB"

class TestRegressionDetection:
    """Performance regression detection tests"""
    
    @pytest.fixture
    def payguard(self):
        config = {"enable_performance_monitoring": True}
        guard = PayGuardMenuBarOptimized(config)
        yield guard
        guard.shutdown()
    
    @pytest.fixture
    def perf_runner(self):
        return PerformanceTestRunner()
    
    def test_performance_baselines(self, payguard, perf_runner):
        """Test against performance baselines"""
        # Define performance baselines (these would be updated as optimizations are made)
        baselines = {
            "text_analysis_ms": 1.0,  # 1ms for typical text
            "image_analysis_ms": 50.0,  # 50ms for typical image
            "clipboard_check_ms": 5.0,  # 5ms for clipboard check
        }
        
        # Test text analysis
        def text_op():
            payguard.detector.analyze_text("URGENT: Your computer is infected! Call 1-800-555-0199")
        
        text_metrics = perf_runner.measure_performance("Text Baseline", text_op, 1000)
        text_ms = text_metrics.avg_duration * 1000
        
        # Test image analysis
        img = Image.new('RGB', (800, 600), color='red')
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        img_data = img_bytes.getvalue()
        
        def image_op():
            payguard.detector.analyze_image_colors(img_data)
        
        image_metrics = perf_runner.measure_performance("Image Baseline", image_op, 100)
        image_ms = image_metrics.avg_duration * 1000
        
        # Test clipboard check
        from unittest.mock import patch, Mock
        with patch('subprocess.run') as mock_subprocess:
            mock_subprocess.return_value = Mock(returncode=0, stdout="test content")
            
            def clipboard_op():
                payguard.last_clipboard_content = ""  # Reset to ensure analysis
                payguard.check_clipboard()
            
            clipboard_metrics = perf_runner.measure_performance("Clipboard Baseline", clipboard_op, 500)
            clipboard_ms = clipboard_metrics.avg_duration * 1000
        
        # Check against baselines (allow 50% tolerance for CI environment variations)
        tolerance = 1.5
        
        assert text_ms < baselines["text_analysis_ms"] * tolerance, \
            f"Text analysis regression: {text_ms:.2f}ms > {baselines['text_analysis_ms'] * tolerance:.2f}ms"
        
        assert image_ms < baselines["image_analysis_ms"] * tolerance, \
            f"Image analysis regression: {image_ms:.2f}ms > {baselines['image_analysis_ms'] * tolerance:.2f}ms"
        
        assert clipboard_ms < baselines["clipboard_check_ms"] * tolerance, \
            f"Clipboard check regression: {clipboard_ms:.2f}ms > {baselines['clipboard_check_ms'] * tolerance:.2f}ms"
        
        print(f"✅ Performance baselines met:")
        print(f"   Text: {text_ms:.2f}ms (baseline: {baselines['text_analysis_ms']}ms)")
        print(f"   Image: {image_ms:.2f}ms (baseline: {baselines['image_analysis_ms']}ms)")
        print(f"   Clipboard: {clipboard_ms:.2f}ms (baseline: {baselines['clipboard_check_ms']}ms)")

if __name__ == "__main__":
    # Run performance tests
    runner = PerformanceTestRunner()
    
    print("🚀 PayGuard Menu Bar Performance Suite")
    print("=" * 60)
    
    # Create test instances
    detector = ScamDetector()
    
    # Run key performance tests
    test_text = "URGENT: Your computer is infected! Call 1-800-555-0199"
    runner.measure_performance("Text Analysis", 
                             lambda: detector.analyze_text(test_text), 1000)
    
    # Create test image
    img = Image.new('RGB', (800, 600), color='red')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    img_data = img_bytes.getvalue()
    
    runner.measure_performance("Image Analysis", 
                             lambda: detector.analyze_image_colors(img_data), 100)
    
    # Generate report
    runner.generate_report("tests/payguard_menubar_performance_report.json")
    
    pytest.main([__file__, "-v"])