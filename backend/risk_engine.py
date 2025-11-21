import re
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Tuple, List, Optional
from models import RiskLevel, PaymentGateway, RiskScore, Merchant
import logging

logger = logging.getLogger(__name__)

class RiskScoringEngine:
    """
    Rule-based risk scoring engine.
    This can be replaced with ML model later by implementing the same interface.
    """
    
    # Known safe payment gateways
    SAFE_GATEWAYS = [
        'stripe.com', 'paypal.com', 'square.com', 'authorize.net',
        'checkout.com', 'adyen.com', 'braintreepayments.com'
    ]
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        r'verify-?account', r'secure-?login', r'update-?payment',
        r'confirm-?identity', r'urgent', r'suspended', r'limited',
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
    ]
    
    def __init__(self, db):
        self.db = db
    
    async def calculate_risk(self, url: str) -> RiskScore:
        """
        Main method to calculate risk score for a URL.
        Replace this with ML model prediction later.
        """
        domain = self._extract_domain(url)
        
        # Initialize scores
        trust_score = 50.0  # Start at neutral
        risk_factors = []
        safety_indicators = []
        
        # 1. SSL Check
        ssl_valid = self._check_ssl(domain)
        if ssl_valid:
            trust_score += 15
            safety_indicators.append("Valid SSL certificate")
        else:
            trust_score -= 20
            risk_factors.append("No valid SSL certificate")
        
        # 2. Domain Age Check (MOCKED - replace with actual WHOIS lookup)
        domain_age_days = await self._check_domain_age(domain)
        if domain_age_days:
            if domain_age_days > 365:
                trust_score += 15
                safety_indicators.append(f"Domain registered for {domain_age_days // 365} years")
            elif domain_age_days < 90:
                trust_score -= 15
                risk_factors.append("Recently registered domain (less than 3 months)")
        
        # 3. Payment Gateway Detection
        detected_gateways = self._detect_payment_gateways(url, domain)
        has_payment_gateway = len(detected_gateways) > 0
        
        if has_payment_gateway:
            trust_score += 10
            safety_indicators.append(f"Uses trusted payment gateway: {detected_gateways[0].value}")
        
        # 4. Suspicious URL Pattern Check
        if self._has_suspicious_patterns(url):
            trust_score -= 25
            risk_factors.append("URL contains suspicious patterns")
        
        # 5. Check merchant reputation from database
        merchant = await self._get_merchant_reputation(domain)
        merchant_reputation = None
        
        if merchant:
            merchant_reputation = merchant.get('reputation_score', 50.0)
            fraud_rate = merchant.get('fraud_reports', 0) / max(merchant.get('total_reports', 1), 1)
            
            if fraud_rate > 0.3:
                trust_score -= 20
                risk_factors.append("High fraud report rate")
            elif merchant.get('verified'):
                trust_score += 10
                safety_indicators.append("Verified merchant")
        
        # 6. Known blacklist check (MOCKED)
        if await self._is_blacklisted(domain):
            trust_score -= 30
            risk_factors.append("Domain flagged in fraud database")
        
        # Clamp score between 0-100
        trust_score = max(0, min(100, trust_score))
        
        # Determine risk level
        if trust_score >= 70:
            risk_level = RiskLevel.LOW
        elif trust_score >= 40:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.HIGH
        
        # Generate education message
        education_message = self._generate_education_message(risk_level, risk_factors, safety_indicators)
        
        return RiskScore(
            url=url,
            domain=domain,
            risk_level=risk_level,
            trust_score=round(trust_score, 1),
            risk_factors=risk_factors,
            safety_indicators=safety_indicators,
            ssl_valid=ssl_valid,
            domain_age_days=domain_age_days,
            has_payment_gateway=has_payment_gateway,
            detected_gateways=detected_gateways,
            merchant_reputation=merchant_reputation,
            education_message=education_message
        )
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url if url.startswith('http') else f'http://{url}')
        return parsed.netloc or parsed.path.split('/')[0]
    
    def _check_ssl(self, domain: str) -> bool:
        """Check if domain has valid SSL certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return cert is not None
        except Exception as e:
            logger.debug(f"SSL check failed for {domain}: {e}")
            return False
    
    async def _check_domain_age(self, domain: str) -> Optional[int]:
        """Check domain age - MOCKED for now"""
        # TODO: Implement actual WHOIS lookup
        # For now, return random mock values based on domain characteristics
        if any(suspicious in domain.lower() for suspicious in ['verify', 'secure', 'update']):
            return 45  # Suspicious domains are often new
        elif domain.endswith('.com') or domain.endswith('.org'):
            return 730  # Assume established domains are older
        return 180  # Default to 6 months
    
    def _detect_payment_gateways(self, url: str, domain: str) -> List[PaymentGateway]:
        """Detect payment gateways - MOCKED for now"""
        # TODO: Implement actual page scraping or API calls
        detected = []
        
        url_lower = url.lower()
        if 'stripe' in url_lower:
            detected.append(PaymentGateway.STRIPE)
        elif 'paypal' in url_lower:
            detected.append(PaymentGateway.PAYPAL)
        elif 'square' in url_lower:
            detected.append(PaymentGateway.SQUARE)
        elif any(keyword in url_lower for keyword in ['crypto', 'bitcoin', 'eth']):
            detected.append(PaymentGateway.CRYPTO)
        
        # Mock: assume .com domains with no suspicious patterns use Stripe
        if not detected and domain.endswith('.com') and not self._has_suspicious_patterns(url):
            detected.append(PaymentGateway.STRIPE)
        
        return detected
    
    def _has_suspicious_patterns(self, url: str) -> bool:
        """Check for suspicious patterns in URL"""
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in self.SUSPICIOUS_PATTERNS)
    
    async def _get_merchant_reputation(self, domain: str) -> Optional[dict]:
        """Get merchant reputation from database"""
        merchant = await self.db.merchants.find_one({"domain": domain})
        return merchant
    
    async def _is_blacklisted(self, domain: str) -> bool:
        """Check if domain is blacklisted"""
        # Check fraud reports
        fraud_count = await self.db.fraud_reports.count_documents({"domain": domain, "verified": True})
        return fraud_count >= 3
    
    def _generate_education_message(self, risk_level: RiskLevel, risk_factors: List[str], 
                                   safety_indicators: List[str]) -> str:
        """Generate educational message for users"""
        if risk_level == RiskLevel.LOW:
            return ("✅ This website appears safe for transactions. It has valid security measures "
                   "and no significant red flags. Always verify the URL before entering payment details.")
        elif risk_level == RiskLevel.MEDIUM:
            msg = "⚠️ Exercise caution with this website. "
            if risk_factors:
                msg += f"Issues found: {', '.join(risk_factors[:2])}. "
            msg += "Verify the merchant's legitimacy before making payments."
            return msg
        else:
            msg = "🚨 HIGH RISK - We strongly recommend avoiding transactions on this website. "
            if risk_factors:
                msg += f"Red flags: {', '.join(risk_factors[:2])}. "
            msg += "This site may be a scam or unsafe for financial transactions."
            return msg
