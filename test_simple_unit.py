#!/usr/bin/env python3
"""
Simple unit tests for PayGuard that work without backend dependencies
"""

import pytest
import re
from urllib.parse import urlparse
from PIL import Image
import io
import base64

class TestScamDetection:
    """Test scam detection functionality"""
    
    def test_phone_number_detection(self):
        """Test phone number pattern detection"""
        phone_pattern = r'\b1-\d{3}-\d{3}-\d{4}\b'
        
        # Should match
        assert re.search(phone_pattern, "Call 1-800-555-0199 now!")
        assert re.search(phone_pattern, "Support: 1-888-123-4567")
        
        # Should not match
        assert not re.search(phone_pattern, "Call 800-555-0199")  # Missing 1-
        assert not re.search(phone_pattern, "Phone: 555-0199")    # Too short
        assert not re.search(phone_pattern, "Normal text here")
    
    def test_urgency_detection(self):
        """Test urgency pattern detection"""
        urgency_pattern = r'(?i)\b(urgent|immediate|act now|call now)\b'
        
        # Should match
        assert re.search(urgency_pattern, "URGENT: Take action now!")
        assert re.search(urgency_pattern, "Call now for immediate help")
        assert re.search(urgency_pattern, "Act now before it's too late")
        
        # Should not match
        assert not re.search(urgency_pattern, "Please contact us when convenient")
        assert not re.search(urgency_pattern, "Thank you for your patience")
    
    def test_virus_warning_detection(self):
        """Test virus warning pattern detection"""
        virus_pattern = r'(?i)\b(virus|infected|malware|trojan)\b'
        
        # Should match
        assert re.search(virus_pattern, "Your computer is infected!")
        assert re.search(virus_pattern, "VIRUS DETECTED on your system")
        assert re.search(virus_pattern, "Trojan horse found")
        
        # Should not match
        assert not re.search(virus_pattern, "Antivirus software available")
        assert not re.search(virus_pattern, "Regular system maintenance")
    
    def test_scam_confidence_scoring(self):
        """Test scam confidence scoring logic"""
        def calculate_scam_score(text):
            patterns = {
                'phone_number': (r'\b1-\d{3}-\d{3}-\d{4}\b', 30),
                'urgency': (r'(?i)\b(urgent|immediate|act now)\b', 20),
                'virus_warning': (r'(?i)\b(virus|infected|malware)\b', 25),
                'account_threat': (r'(?i)\b(suspended|blocked|expired)\b', 15),
            }
            
            score = 0
            for pattern_name, (pattern, weight) in patterns.items():
                if re.search(pattern, text):
                    score += weight
            
            return min(score, 100)
        
        # High-risk scam text
        scam_text = "URGENT: Your computer is infected! Call 1-800-555-0199"
        assert calculate_scam_score(scam_text) >= 70
        
        # Medium-risk text
        medium_text = "Your account has been suspended"
        score = calculate_scam_score(medium_text)
        assert 10 <= score <= 30
        
        # Low-risk legitimate text
        safe_text = "Thank you for your purchase"
        assert calculate_scam_score(safe_text) == 0

class TestURLAnalysis:
    """Test URL analysis functionality"""
    
    def test_url_parsing(self):
        """Test URL parsing functionality"""
        test_urls = [
            "https://google.com",
            "http://example.com",
            "ftp://files.example.com",
            "javascript:alert('xss')",
            "not-a-url"
        ]
        
        for url in test_urls:
            # Should not crash
            parsed = urlparse(url)
            assert hasattr(parsed, 'scheme')
            assert hasattr(parsed, 'netloc')
    
    def test_suspicious_domain_detection(self):
        """Test detection of suspicious domains"""
        def is_suspicious_domain(domain):
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
            suspicious_keywords = ['phishing', 'scam', 'fake']
            
            domain_lower = domain.lower()
            
            # Check TLD
            if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
                return True
            
            # Check keywords
            if any(keyword in domain_lower for keyword in suspicious_keywords):
                return True
            
            return False
        
        # Should be suspicious
        assert is_suspicious_domain("phishing-site.tk")
        assert is_suspicious_domain("fake-bank.ml")
        assert is_suspicious_domain("scam-alert.com")
        
        # Should not be suspicious
        assert not is_suspicious_domain("google.com")
        assert not is_suspicious_domain("github.com")
        assert not is_suspicious_domain("stackoverflow.com")
    
    def test_protocol_security(self):
        """Test protocol security assessment"""
        def assess_protocol_security(url):
            parsed = urlparse(url)
            
            if parsed.scheme == 'https':
                return 'secure'
            elif parsed.scheme == 'http':
                return 'insecure'
            elif parsed.scheme in ['javascript', 'data']:
                return 'dangerous'
            else:
                return 'unknown'
        
        assert assess_protocol_security("https://example.com") == 'secure'
        assert assess_protocol_security("http://example.com") == 'insecure'
        assert assess_protocol_security("javascript:alert('xss')") == 'dangerous'
        assert assess_protocol_security("ftp://files.com") == 'unknown'

class TestImageProcessing:
    """Test image processing functionality"""
    
    def test_image_creation_and_encoding(self):
        """Test image creation and base64 encoding"""
        # Create test image
        img = Image.new('RGB', (100, 100), color='red')
        
        # Convert to bytes
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        img_data = img_bytes.getvalue()
        
        # Should have data
        assert len(img_data) > 0
        
        # Should be valid PNG
        assert img_data.startswith(b'\x89PNG')
        
        # Should encode to base64
        b64_data = base64.b64encode(img_data).decode()
        assert len(b64_data) > 0
        
        # Should decode back correctly
        decoded = base64.b64decode(b64_data)
        assert decoded == img_data
    
    def test_color_analysis(self):
        """Test color analysis for scam detection"""
        def analyze_dominant_color(img):
            colors = img.getcolors(maxcolors=256*256*256)
            if colors:
                # Get most frequent color
                dominant_color = max(colors, key=lambda x: x[0])[1]
                return dominant_color
            return None
        
        # Red image (suspicious)
        red_img = Image.new('RGB', (100, 100), color='red')
        red_color = analyze_dominant_color(red_img)
        assert red_color == (255, 0, 0)
        
        # White image (normal)
        white_img = Image.new('RGB', (100, 100), color='white')
        white_color = analyze_dominant_color(white_img)
        assert white_color == (255, 255, 255)
    
    def test_visual_scam_indicators(self):
        """Test visual scam indicator detection"""
        def has_scam_colors(img):
            colors = img.getcolors(maxcolors=256*256*256)
            if not colors:
                return False
            
            total_pixels = sum(count for count, color in colors)
            red_pixels = 0
            
            for count, color in colors:
                if isinstance(color, tuple) and len(color) >= 3:
                    r, g, b = color[:3]
                    # Red detection
                    if r > 200 and g < 100 and b < 100:
                        red_pixels += count
            
            red_ratio = red_pixels / total_pixels
            return red_ratio > 0.5  # More than 50% red
        
        # Red image should be flagged
        red_img = Image.new('RGB', (100, 100), color='red')
        assert has_scam_colors(red_img)
        
        # Blue image should not be flagged
        blue_img = Image.new('RGB', (100, 100), color='blue')
        assert not has_scam_colors(blue_img)

class TestHTMLAnalysis:
    """Test HTML analysis functionality"""
    
    def test_html_text_extraction(self):
        """Test extracting text from HTML"""
        def extract_text_from_html(html):
            import re
            # Remove HTML tags
            text = re.sub(r'<[^>]+>', ' ', html)
            # Normalize whitespace
            text = re.sub(r'\s+', ' ', text).strip()
            return text
        
        html = '<html><body><h1>Title</h1><p>Content here</p></body></html>'
        text = extract_text_from_html(html)
        
        assert 'Title' in text
        assert 'Content here' in text
        assert '<h1>' not in text
        assert '<p>' not in text
    
    def test_html_scam_indicators(self):
        """Test HTML-specific scam indicators"""
        def analyze_html_risk(html):
            import re
            risk_score = 0
            html_lower = html.lower()
            
            # Red background
            if re.search(r'background.*red', html_lower) or 'background-color: red' in html_lower:
                risk_score += 15
            
            # Password input (phishing)
            if re.search(r'input.*password', html_lower) or 'type="password"' in html_lower:
                risk_score += 20
            
            # Urgent styling
            if re.search(r'color.*red', html_lower) and ('urgent' in html_lower or 'alert' in html_lower):
                risk_score += 10
            
            return risk_score
        
        # Scam HTML
        scam_html = '''
        <body style="background-color: red;">
            <h1 style="color: red;">URGENT ALERT</h1>
            <input type="password" placeholder="Enter password">
        </body>
        '''
        assert analyze_html_risk(scam_html) >= 40  # Should detect all three patterns
        
        # Normal HTML
        normal_html = '<body><h1>Welcome</h1><p>Normal content</p></body>'
        assert analyze_html_risk(normal_html) == 0

def test_integration_example():
    """Test integration of multiple detection methods"""
    def comprehensive_scam_analysis(content, content_type='text'):
        """Analyze content for scam indicators"""
        scam_score = 0
        detected_patterns = []
        
        # Text analysis
        text_patterns = {
            'phone_number': (r'\b1-\d{3}-\d{3}-\d{4}\b', 30),
            'urgency': (r'(?i)\b(urgent|immediate|act now)\b', 20),
            'virus_warning': (r'(?i)\b(virus|infected|malware)\b', 25),
        }
        
        for pattern_name, (pattern, weight) in text_patterns.items():
            if re.search(pattern, content):
                scam_score += weight
                detected_patterns.append(pattern_name)
        
        # HTML-specific analysis
        if content_type == 'html':
            if 'background.*red' in content.lower():
                scam_score += 15
                detected_patterns.append('red_background')
        
        is_scam = scam_score >= 40
        confidence = min(scam_score, 100)
        
        return {
            'is_scam': is_scam,
            'confidence': confidence,
            'detected_patterns': detected_patterns
        }
    
    # Test high-risk content
    scam_content = "URGENT: Your computer is infected! Call 1-800-555-0199"
    result = comprehensive_scam_analysis(scam_content)
    
    assert result['is_scam'] is True
    assert result['confidence'] >= 70
    assert 'phone_number' in result['detected_patterns']
    assert 'urgency' in result['detected_patterns']
    assert 'virus_warning' in result['detected_patterns']
    
    # Test safe content
    safe_content = "Thank you for your purchase. Your order will arrive soon."
    result = comprehensive_scam_analysis(safe_content)
    
    assert result['is_scam'] is False
    assert result['confidence'] == 0
    assert len(result['detected_patterns']) == 0

if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])