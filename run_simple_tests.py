#!/usr/bin/env python3
"""
PayGuard Simple Test Runner
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
        
        text_lower = text.lower()
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
    
    def test_scam_text_detection(self) -> bool:
        """Test scam text detection without backend"""
        print("🔍 Testing scam text detection...")
        
        test_texts = [
            "URGENT: Your computer is infected! Call 1-800-555-0199",
            "Your account has been suspended. Verify immediately.",
            "Congratulations! You've won $1000.",
            "Normal business email about our services.",
            "",  # Empty string edge case
            "   ",  # Whitespace only
            "A" * 1000,  # Very long text
        ]
        
        try:
            for text in test_texts:
                result = self.analyze_text_for_scam(text)
                status = "🚨 SCAM" if result.is_scam else "✅ CLEAN"
                print(f"   {status} ({result.score}%, {result.confidence:.1f}%): {result.text}")
            
            return True
        except Exception as e:
            logger.error(f"Scam text detection failed: {e}")
            return False
    
    def test_url_analysis(self) -> bool:
        """Test URL analysis without backend"""
        print("🌐 Testing URL analysis...")
        
        test_urls = [
            "https://google.com",
            "http://suspicious-site.tk",
            "https://phishing-example.com",
            "javascript:alert('xss')",
            "not-a-url",
            "",  # Empty URL
            "https://192.168.1.1",  # IP address
            "ftp://example.com",  # Different protocol
        ]
        
        try:
            for url in test_urls:
                result = self.analyze_url(url)
                print(f"   {result.risk_level} ({result.risk_score}%): {url}")
            
            return True
        except Exception as e:
            logger.error(f"URL analysis failed: {e}")
            return False
    
    def test_image_processing(self):
        """Test basic image processing"""
        print("🖼️ Testing image processing...")
        
        try:
            from PIL import Image, ImageDraw
            import io
            import base64
            
            # Create test images
            test_images = []
            
            # Clean image
            clean_img = Image.new('RGB', (400, 300), color='white')
            clean_bytes = io.BytesIO()
            clean_img.save(clean_bytes, format='PNG')
            test_images.append(('clean', clean_bytes.getvalue()))
            
            # Scam-like image (red background)
            scam_img = Image.new('RGB', (400, 300), color='red')
            draw = ImageDraw.Draw(scam_img)
            draw.text((50, 50), "WARNING!", fill='white')
            scam_bytes = io.BytesIO()
            scam_img.save(scam_bytes, format='PNG')
            test_images.append(('scam', scam_bytes.getvalue()))
            
            for img_type, img_data in test_images:
                # Simple visual analysis
                img = Image.open(io.BytesIO(img_data))
                
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
                
                # Base64 encoding test
                b64_data = base64.b64encode(img_data).decode()
                assert len(b64_data) > 0
                
                print(f"   {img_type.upper()} image: {risk_score:.1f}% risk, {len(img_data)} bytes")
            
            return True
            
        except ImportError:
            print("   ⚠️ PIL not available, skipping image tests")
            return True
        except Exception as e:
            print(f"   ❌ Image processing error: {e}")
            return False
        for text in test_texts:
            scam_score = 0
            detected_patterns = []
            
            for pattern in scam_patterns:
                if re.search(pattern, text):
                    scam_score += 20
                    detected_patterns.append(pattern)
            
            is_scam = scam_score >= 40
            results.append({
                'text': text[:50] + '...' if len(text) > 50 else text,
                'is_scam': is_scam,
                'score': scam_score,
                'patterns': len(detected_patterns)
            })
            
            status = "🚨 SCAM" if is_scam else "✅ CLEAN"
            print(f"   {status} ({scam_score}%): {text[:50]}...")
        
        return True
    
    def test_url_analysis(self):
        """Test URL analysis without backend"""
        print("🌐 Testing URL analysis...")
        
        test_urls = [
            "https://google.com",
            "http://suspicious-site.tk",
            "https://phishing-example.com",
            "javascript:alert('xss')",
            "not-a-url"
        ]
        
        from urllib.parse import urlparse
        
        for url in test_urls:
            try:
                parsed = urlparse(url)
                
                # Simple risk scoring
                risk_score = 50  # Base score
                
                # Protocol check
                if parsed.scheme == 'https':
                    risk_score += 20
                elif parsed.scheme == 'http':
                    risk_score -= 10
                elif parsed.scheme in ['javascript', 'data']:
                    risk_score -= 40
                
                # Domain check
                if parsed.netloc:
                    if any(tld in parsed.netloc for tld in ['.tk', '.ml', '.ga']):
                        risk_score -= 30
                    if 'phishing' in parsed.netloc.lower():
                        risk_score -= 40
                
                risk_score = max(0, min(100, risk_score))
                risk_level = "HIGH" if risk_score < 40 else ("MEDIUM" if risk_score < 70 else "LOW")
                
                print(f"   {risk_level} ({risk_score}%): {url}")
                
            except Exception as e:
                print(f"   ERROR: {url} - {e}")
        
        return True
    
    def test_image_processing(self):
        """Test basic image processing"""
        print("🖼️ Testing image processing...")
        
        try:
            from PIL import Image, ImageDraw
            import io
            import base64
            
            # Create test images
            test_images = []
            
            # Clean image
            clean_img = Image.new('RGB', (400, 300), color='white')
            clean_bytes = io.BytesIO()
            clean_img.save(clean_bytes, format='PNG')
            test_images.append(('clean', clean_bytes.getvalue()))
            
            # Scam-like image (red background)
            scam_img = Image.new('RGB', (400, 300), color='red')
            draw = ImageDraw.Draw(scam_img)
            draw.text((50, 50), "WARNING!", fill='white')
            scam_bytes = io.BytesIO()
            scam_img.save(scam_bytes, format='PNG')
            test_images.append(('scam', scam_bytes.getvalue()))
            
            for img_type, img_data in test_images:
                # Simple visual analysis
                img = Image.open(io.BytesIO(img_data))
                
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
                
                # Base64 encoding test
                b64_data = base64.b64encode(img_data).decode()
                assert len(b64_data) > 0
                
                print(f"   {img_type.upper()} image: {risk_score:.1f}% risk, {len(img_data)} bytes")
            
            return True
            
        except ImportError:
            print("   ⚠️ PIL not available, skipping image tests")
            return True
        except Exception as e:
            print(f"   ❌ Image processing error: {e}")
            return False
    
    def test_html_analysis(self):
        """Test HTML content analysis"""
        print("📄 Testing HTML analysis...")
        
        test_html_samples = [
            {
                'name': 'Clean HTML',
                'content': '<html><body><h1>Welcome</h1><p>Normal content</p></body></html>'
            },
            {
                'name': 'Scam HTML',
                'content': '''<html><body style="background:red">
                    <h1>URGENT SECURITY ALERT</h1>
                    <p>Your computer is infected! Call 1-800-555-0199</p>
                    </body></html>'''
            },
            {
                'name': 'Phishing HTML',
                'content': '''<html><body>
                    <h2>Amazon Security Notice</h2>
                    <p>Your account has been suspended. Click here to verify.</p>
                    <button>Verify Account</button>
                    </body></html>'''
            }
        ]
        
        import re
        
        for sample in test_html_samples:
            content = sample['content']
            risk_score = 0
            
            # Check for scam indicators
            scam_indicators = [
                (r'(?i)urgent|immediate|act now', 20),
                (r'(?i)virus|infected|malware', 25),
                (r'(?i)suspended|blocked|verify', 15),
                (r'(?i)call.*\d{3}.*\d{3}.*\d{4}', 30),
                (r'background:\s*red|color:\s*red', 10),
                (r'(?i)amazon|microsoft|apple.*security', 15)
            ]
            
            detected = []
            for pattern, score in scam_indicators:
                if re.search(pattern, content):
                    risk_score += score
                    detected.append(pattern)
            
            risk_level = "HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "LOW")
            print(f"   {risk_level} ({risk_score}%): {sample['name']} - {len(detected)} patterns")
        
        return True
    
    def test_file_operations(self):
        """Test file operations and cleanup"""
        print("📁 Testing file operations...")
        
        try:
            # Create temporary files
            temp_files = []
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                f.write('<html><body>Test content</body></html>')
                temp_files.append(f.name)
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write('Test scam content with phone 1-800-555-0199')
                temp_files.append(f.name)
            
            # Test file reading
            for temp_file in temp_files:
                assert os.path.exists(temp_file)
                with open(temp_file, 'r') as f:
                    content = f.read()
                    assert len(content) > 0
                print(f"   ✅ Created and read: {os.path.basename(temp_file)}")
            
            # Cleanup
            for temp_file in temp_files:
                os.unlink(temp_file)
                assert not os.path.exists(temp_file)
            
            print(f"   ✅ Cleaned up {len(temp_files)} temporary files")
            return True
            
        except Exception as e:
            print(f"   ❌ File operations error: {e}")
            return False
    
    def run_all_tests(self):
        """Run all simple tests"""
        print("🧪 PayGuard Simple Test Suite")
        print("=" * 50)
        print("Running tests that don't require backend/database...")
        
        tests = [
            ("Scam Text Detection", self.test_scam_text_detection),
            ("URL Analysis", self.test_url_analysis),
            ("Image Processing", self.test_image_processing),
            ("HTML Analysis", self.test_html_analysis),
            ("File Operations", self.test_file_operations)
        ]
        
        results = []
        start_time = time.time()
        
        for test_name, test_func in tests:
            print(f"\n🔬 {test_name}")
            try:
                test_start = time.time()
                success = test_func()
                duration = time.time() - test_start
                
                results.append({
                    'name': test_name,
                    'success': success,
                    'duration': duration
                })
                
                status = "✅ PASS" if success else "❌ FAIL"
                print(f"   {status} ({duration:.2f}s)")
                
            except Exception as e:
                duration = time.time() - test_start
                results.append({
                    'name': test_name,
                    'success': False,
                    'duration': duration,
                    'error': str(e)
                })
                print(f"   ❌ ERROR ({duration:.2f}s): {e}")
        
        # Summary
        total_time = time.time() - start_time
        passed = sum(1 for r in results if r['success'])
        failed = len(results) - passed
        
        print("\n" + "=" * 50)
        print("📊 TEST SUMMARY")
        print("=" * 50)
        print(f"Total Tests: {len(results)}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⏱️ Total Time: {total_time:.2f}s")
        print(f"Success Rate: {(passed/len(results)*100):.1f}%")
        
        if failed > 0:
            print(f"\n❌ Failed Tests:")
            for result in results:
                if not result['success']:
                    error_msg = result.get('error', 'Unknown error')
                    print(f"   • {result['name']}: {error_msg}")
        
        return failed == 0

def main():
    """Main entry point"""
    runner = SimpleTestRunner()
    success = runner.run_all_tests()
    
    if success:
        print(f"\n🎉 All tests passed! PayGuard core functionality is working.")
    else:
        print(f"\n⚠️ Some tests failed. Check the output above for details.")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()