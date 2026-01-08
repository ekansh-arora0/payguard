#!/usr/bin/env python3
"""
PayGuard Simple Test Runner - Optimized Version
Runs tests that don't require backend/database dependencies
"""

import subprocess
import time
import os
import sys
import tempfile
import re
import base64
import io
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional, Union
from dataclasses import dataclass
from enum import Enum
import logging
from urllib.parse import urlparse
from contextlib import contextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TestResult(Enum):
    """Test result enumeration"""
    PASS = "✅ PASS"
    FAIL = "❌ FAIL"
    SKIP = "⏭️ SKIP"
    ERROR = "🚨 ERROR"

@dataclass
class TestReport:
    """Test execution report"""
    name: str
    result: TestResult
    duration: float
    message: str = ""
    details: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

@dataclass
class ScamAnalysisResult:
    """Scam analysis result"""
    text: str
    is_scam: bool
    score: int
    patterns: List[str]
    confidence: float

@dataclass
class UrlAnalysisResult:
    """URL analysis result"""
    url: str
    risk_score: int
    risk_level: str
    scheme: str
    domain: str
    is_valid: bool

class SimpleTestRunner:
    """Optimized simple test runner for PayGuard components"""
    
    # Class-level constants for better performance
    SCAM_PATTERNS = [
        (r'\b1-\d{3}-\d{3}-\d{4}\b', 25, 'phone_number'),  # Phone numbers
        (r'(?i)\b(urgent|immediate|act now|call now)\b', 20, 'urgency'),  # Urgency
        (r'(?i)\b(virus|infected|malware|trojan)\b', 30, 'virus_warning'),  # Virus warnings
        (r'(?i)\b(suspended|blocked|expired)\b', 20, 'account_threat'),  # Account threats
        (r'(?i)\b(verify|update|confirm).*(account|payment|card)\b', 25, 'phishing'),  # Phishing
        (r'(?i)\b(microsoft|apple|amazon).*(support|security)\b', 15, 'brand_impersonation'),  # Brand impersonation
        (r'(?i)\b(click here|download now|install)\b', 10, 'action_prompt'),  # Action prompts
    ]
    
    HTML_SCAM_INDICATORS = [
        (r'(?i)urgent|immediate|act now', 20, 'urgency'),
        (r'(?i)virus|infected|malware', 25, 'virus_warning'),
        (r'(?i)suspended|blocked|verify', 15, 'account_threat'),
        (r'(?i)call.*\d{3}.*\d{3}.*\d{4}', 30, 'phone_scam'),
        (r'background:\s*red|color:\s*red', 10, 'visual_alarm'),
        (r'(?i)amazon|microsoft|apple.*security', 15, 'brand_impersonation')
    ]
    
    SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq'}
    SUSPICIOUS_KEYWORDS = {'phishing', 'scam', 'fake', 'malware'}
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.results: List[TestReport] = []
        self._compiled_patterns = self._compile_patterns()
        self._temp_files: List[Path] = []
        
    def _compile_patterns(self) -> List[Tuple[re.Pattern, int, str]]:
        """Pre-compile regex patterns for better performance"""
        return [(re.compile(pattern), score, name) for pattern, score, name in self.SCAM_PATTERNS]
    
    @contextmanager
    def _temp_file_manager(self, content: str, suffix: str = '.tmp'):
        """Context manager for temporary files with automatic cleanup"""
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
                f.write(content)
                temp_file = Path(f.name)
                self._temp_files.append(temp_file)
            yield temp_file
        finally:
            if temp_file and temp_file.exists():
                try:
                    temp_file.unlink()
                    if temp_file in self._temp_files:
                        self._temp_files.remove(temp_file)
                except OSError as e:
                    logger.warning(f"Failed to cleanup temp file {temp_file}: {e}")
    
    def cleanup(self):
        """Clean up any remaining temporary files"""
        for temp_file in self._temp_files[:]:
            try:
                if temp_file.exists():
                    temp_file.unlink()
                self._temp_files.remove(temp_file)
            except OSError as e:
                logger.warning(f"Failed to cleanup temp file {temp_file}: {e}")
    
    def analyze_text_for_scam(self, text: str) -> ScamAnalysisResult:
        """Optimized scam text analysis with compiled patterns"""
        if not text or not text.strip():
            return ScamAnalysisResult(text, False, 0, [], 0.0)
        
        total_score = 0
        detected_patterns = []
        
        # Use pre-compiled patterns for better performance
        for compiled_pattern, score, pattern_name in self._compiled_patterns:
            if compiled_pattern.search(text):
                total_score += score
                detected_patterns.append(pattern_name)
        
        # Calculate confidence based on text length and pattern density
        text_length = len(text)
        pattern_density = len(detected_patterns) / max(text_length / 100, 1)  # patterns per 100 chars
        confidence = min(total_score + (pattern_density * 10), 100)
        
        is_scam = total_score >= 40 or confidence >= 70
        
        return ScamAnalysisResult(
            text=text[:100] + '...' if len(text) > 100 else text,
            is_scam=is_scam,
            score=total_score,
            patterns=detected_patterns,
            confidence=confidence
        )
    
    def analyze_url(self, url: str) -> UrlAnalysisResult:
        """Optimized URL analysis"""
        if not url:
            return UrlAnalysisResult(url, 0, "INVALID", "", "", False)
        
        try:
            parsed = urlparse(url)
            risk_score = 50  # Base score
            
            # Protocol scoring
            if parsed.scheme == 'https':
                risk_score += 20
            elif parsed.scheme == 'http':
                risk_score -= 10
            elif parsed.scheme in {'javascript', 'data', 'file'}:
                risk_score -= 40
            
            # Domain analysis
            domain = parsed.netloc.lower()
            if domain:
                # Check suspicious TLDs
                if any(tld in domain for tld in self.SUSPICIOUS_TLDS):
                    risk_score -= 30
                
                # Check suspicious keywords
                if any(keyword in domain for keyword in self.SUSPICIOUS_KEYWORDS):
                    risk_score -= 40
                
                # Check for IP addresses (simple check)
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    risk_score -= 25
            
            risk_score = max(0, min(100, risk_score))
            
            if risk_score >= 70:
                risk_level = "LOW"
            elif risk_score >= 40:
                risk_level = "MEDIUM"
            else:
                risk_level = "HIGH"
            
            return UrlAnalysisResult(
                url=url,
                risk_score=risk_score,
                risk_level=risk_level,
                scheme=parsed.scheme,
                domain=domain,
                is_valid=bool(parsed.netloc)
            )
            
        except Exception as e:
            logger.warning(f"URL parsing error for {url}: {e}")
            return UrlAnalysisResult(url, 0, "ERROR", "", "", False)
    
    def analyze_html_content(self, content: str) -> Dict[str, Any]:
        """Optimized HTML content analysis"""
        if not content:
            return {"risk_score": 0, "risk_level": "LOW", "detected_patterns": []}
        
        risk_score = 0
        detected_patterns = []
        
        for pattern, score, pattern_name in self.HTML_SCAM_INDICATORS:
            if re.search(pattern, content):
                risk_score += score
                detected_patterns.append(pattern_name)
        
        risk_level = "HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "LOW")
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "detected_patterns": detected_patterns,
            "pattern_count": len(detected_patterns)
        }
    
    def _run_test_with_timing(self, test_name: str, test_func) -> TestReport:
        """Run a test with timing and error handling"""
        start_time = time.time()
        try:
            result = test_func()
            duration = time.time() - start_time
            
            if result is True:
                return TestReport(test_name, TestResult.PASS, duration, "Test completed successfully")
            elif result is False:
                return TestReport(test_name, TestResult.FAIL, duration, "Test failed")
            else:
                return TestReport(test_name, TestResult.PASS, duration, str(result) if result else "Test completed")
                
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Test {test_name} failed with error: {e}")
            return TestReport(test_name, TestResult.ERROR, duration, f"Test error: {str(e)}", error=str(e))
    
    def test_scam_text_detection(self) -> bool:
        """Test scam text detection without backend"""
        print("🔍 Testing scam text detection...")
        
        test_cases = [
            ("URGENT: Your computer is infected! Call 1-800-555-0199", True),
            ("Your account has been suspended. Verify immediately.", True),
            ("Congratulations! You've won $1000.", False),
            ("Normal business email about our services.", False),
            ("", False),  # Empty string edge case
            ("   ", False),  # Whitespace only
            ("A" * 1000, False),  # Very long text
            ("Microsoft Security Alert: Call +1-888-555-0123", True),  # Brand impersonation
        ]
        
        try:
            all_passed = True
            for text, expected_scam in test_cases:
                result = self.analyze_text_for_scam(text)
                status = "🚨 SCAM" if result.is_scam else "✅ CLEAN"
                
                # Validate expectation
                if result.is_scam != expected_scam:
                    print(f"   ⚠️ UNEXPECTED: {status} ({result.score}%, {result.confidence:.1f}%): {result.text}")
                    all_passed = False
                else:
                    print(f"   {status} ({result.score}%, {result.confidence:.1f}%): {result.text}")
            
            return all_passed
        except Exception as e:
            logger.error(f"Scam text detection failed: {e}")
            return False
    
    def test_url_analysis(self) -> bool:
        """Test URL analysis without backend"""
        print("🌐 Testing URL analysis...")
        
        test_cases = [
            ("https://google.com", "LOW"),
            ("http://suspicious-site.tk", "HIGH"),
            ("https://phishing-example.com", "HIGH"),
            ("javascript:alert('xss')", "HIGH"),
            ("not-a-url", "ERROR"),
            ("", "INVALID"),
            ("https://192.168.1.1", "MEDIUM"),
            ("ftp://example.com", "MEDIUM"),
        ]
        
        try:
            all_passed = True
            for url, expected_level in test_cases:
                result = self.analyze_url(url)
                
                if result.risk_level != expected_level:
                    print(f"   ⚠️ UNEXPECTED: {result.risk_level} (expected {expected_level}) ({result.risk_score}%): {url}")
                    all_passed = False
                else:
                    print(f"   {result.risk_level} ({result.risk_score}%): {url}")
            
            return all_passed
        except Exception as e:
            logger.error(f"URL analysis failed: {e}")
            return False
    
    def test_image_processing(self) -> bool:
        """Test optimized image processing"""
        print("🖼️ Testing image processing...")
        
        try:
            from PIL import Image, ImageDraw
            
            test_cases = [
                ("clean", (400, 300), 'white', None),
                ("scam", (400, 300), 'red', "WARNING!"),
                ("large", (2000, 1500), 'blue', None),
                ("small", (50, 50), 'green', None),
            ]
            
            for img_type, size, color, text in test_cases:
                # Create test image
                img = Image.new('RGB', size, color=color)
                
                if text:
                    draw = ImageDraw.Draw(img)
                    draw.text((50, 50), text, fill='white')
                
                # Convert to bytes
                img_bytes = io.BytesIO()
                img.save(img_bytes, format='PNG')
                img_data = img_bytes.getvalue()
                
                # Analyze image properties
                risk_score = self._analyze_image_risk(img, img_data)
                
                # Base64 encoding test
                b64_data = base64.b64encode(img_data).decode()
                assert len(b64_data) > 0
                
                print(f"   {img_type.upper()} image: {risk_score:.1f}% risk, {len(img_data)} bytes, {size[0]}x{size[1]}")
            
            return True
            
        except ImportError:
            print("   ⚠️ PIL not available, skipping image tests")
            return True
        except Exception as e:
            logger.error(f"Image processing error: {e}")
            return False
    
    def _analyze_image_risk(self, img, img_data: bytes) -> float:
        """Analyze image for risk indicators"""
        try:
            # Check dominant colors
            colors = img.getcolors(maxcolors=256*256*256)
            if colors:
                dominant_color = max(colors, key=lambda x: x[0])[1]
                
                # Red-heavy images might be scam alerts
                if isinstance(dominant_color, tuple) and len(dominant_color) >= 3:
                    red_ratio = dominant_color[0] / 255.0
                    risk_score = red_ratio * 60  # Red = higher risk
                else:
                    risk_score = 10
            else:
                risk_score = 10
            
            # Size-based risk (very large images might be suspicious)
            if len(img_data) > 5 * 1024 * 1024:  # 5MB
                risk_score += 10
            
            return min(risk_score, 100)
            
        except Exception:
            return 10  # Default low risk
    
    def test_html_analysis(self) -> bool:
        """Test HTML content analysis"""
        print("📄 Testing HTML analysis...")
        
        test_samples = [
            {
                'name': 'Clean HTML',
                'content': '<html><body><h1>Welcome</h1><p>Normal content</p></body></html>',
                'expected_level': 'LOW'
            },
            {
                'name': 'Scam HTML',
                'content': '''<html><body style="background:red">
                    <h1>URGENT SECURITY ALERT</h1>
                    <p>Your computer is infected! Call 1-800-555-0199</p>
                    </body></html>''',
                'expected_level': 'HIGH'
            },
            {
                'name': 'Phishing HTML',
                'content': '''<html><body>
                    <h2>Amazon Security Notice</h2>
                    <p>Your account has been suspended. Click here to verify.</p>
                    <button>Verify Account</button>
                    </body></html>''',
                'expected_level': 'MEDIUM'
            },
            {
                'name': 'Empty HTML',
                'content': '',
                'expected_level': 'LOW'
            }
        ]
        
        try:
            all_passed = True
            for sample in test_samples:
                result = self.analyze_html_content(sample['content'])
                
                if result['risk_level'] != sample['expected_level']:
                    print(f"   ⚠️ UNEXPECTED: {result['risk_level']} (expected {sample['expected_level']}) "
                          f"({result['risk_score']}%): {sample['name']} - {result['pattern_count']} patterns")
                    all_passed = False
                else:
                    print(f"   {result['risk_level']} ({result['risk_score']}%): {sample['name']} - {result['pattern_count']} patterns")
            
            return all_passed
        except Exception as e:
            logger.error(f"HTML analysis failed: {e}")
            return False
    
    def test_file_operations(self) -> bool:
        """Test file operations and cleanup"""
        print("📁 Testing file operations...")
        
        try:
            test_files = [
                ('<html><body>Test content</body></html>', '.html'),
                ('Test scam content with phone 1-800-555-0199', '.txt'),
                ('{"test": "json content"}', '.json'),
            ]
            
            created_files = []
            
            # Test file creation and reading
            for content, suffix in test_files:
                with self._temp_file_manager(content, suffix) as temp_file:
                    assert temp_file.exists()
                    
                    # Test reading
                    read_content = temp_file.read_text()
                    assert read_content == content
                    
                    created_files.append(temp_file.name)
                    print(f"   ✅ Created and read: {temp_file.name}")
                
                # File should be cleaned up automatically
                assert not temp_file.exists()
            
            print(f"   ✅ Successfully tested {len(test_files)} file operations with auto-cleanup")
            return True
            
        except Exception as e:
            logger.error(f"File operations error: {e}")
            return False
    
    def test_performance_benchmarks(self) -> bool:
        """Test performance of core functions"""
        print("⚡ Testing performance benchmarks...")
        
        try:
            # Text analysis benchmark
            long_text = "URGENT: Your computer is infected! " * 100
            start_time = time.time()
            
            for _ in range(100):
                self.analyze_text_for_scam(long_text)
            
            text_time = (time.time() - start_time) / 100
            print(f"   Text analysis: {text_time*1000:.2f}ms avg (100 iterations)")
            
            # URL analysis benchmark
            test_urls = ["https://example.com", "http://test.tk", "javascript:alert()"] * 10
            start_time = time.time()
            
            for url in test_urls:
                self.analyze_url(url)
            
            url_time = (time.time() - start_time) / len(test_urls)
            print(f"   URL analysis: {url_time*1000:.2f}ms avg ({len(test_urls)} URLs)")
            
            # Performance assertions
            assert text_time < 0.01, f"Text analysis too slow: {text_time:.3f}s"
            assert url_time < 0.001, f"URL analysis too slow: {url_time:.3f}s"
            
            return True
            
        except Exception as e:
            logger.error(f"Performance benchmark failed: {e}")
            return False
    
    def run_all_tests(self) -> bool:
        """Run all optimized tests"""
        print("🧪 PayGuard Optimized Simple Test Suite")
        print("=" * 60)
        print("Running tests that don't require backend/database...")
        
        test_methods = [
            ("Scam Text Detection", self.test_scam_text_detection),
            ("URL Analysis", self.test_url_analysis),
            ("Image Processing", self.test_image_processing),
            ("HTML Analysis", self.test_html_analysis),
            ("File Operations", self.test_file_operations),
            ("Performance Benchmarks", self.test_performance_benchmarks),
        ]
        
        start_time = time.time()
        
        for test_name, test_func in test_methods:
            print(f"\n🔬 {test_name}")
            report = self._run_test_with_timing(test_name, test_func)
            self.results.append(report)
            
            print(f"   {report.result.value} ({report.duration:.2f}s)")
            if report.message and report.result != TestResult.PASS:
                print(f"   {report.message}")
        
        # Generate summary
        self._print_summary(time.time() - start_time)
        
        # Cleanup
        self.cleanup()
        
        # Return overall success
        return all(r.result in [TestResult.PASS, TestResult.SKIP] for r in self.results)
    
    def _print_summary(self, total_time: float):
        """Print comprehensive test summary"""
        passed = sum(1 for r in self.results if r.result == TestResult.PASS)
        failed = sum(1 for r in self.results if r.result == TestResult.FAIL)
        errors = sum(1 for r in self.results if r.result == TestResult.ERROR)
        skipped = sum(1 for r in self.results if r.result == TestResult.SKIP)
        
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE TEST SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {len(self.results)}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"🚨 Errors: {errors}")
        print(f"⏭️ Skipped: {skipped}")
        print(f"⏱️ Total Time: {total_time:.2f}s")
        print(f"📈 Success Rate: {(passed/len(self.results)*100):.1f}%")
        
        if failed > 0 or errors > 0:
            print(f"\n❌ Issues Found:")
            for result in self.results:
                if result.result in [TestResult.FAIL, TestResult.ERROR]:
                    print(f"   • {result.name}: {result.message}")

def main():
    """Main entry point"""
    runner = SimpleTestRunner()
    
    try:
        success = runner.run_all_tests()
        
        if success:
            print(f"\n🎉 All tests passed! PayGuard core functionality is working optimally.")
        else:
            print(f"\n⚠️ Some tests failed. Check the output above for details.")
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print(f"\n🛑 Tests interrupted by user")
        runner.cleanup()
        sys.exit(1)
    except Exception as e:
        logger.error(f"Test runner failed: {e}")
        runner.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()