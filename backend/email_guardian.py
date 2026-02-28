import difflib
import re
from typing import Dict, List, Optional, Tuple


class EmailGuardian:
    """
    Advanced email typosquatting and scam detection.
    Identifies domains that mimic legitimate brands using homoglyphs,
    small edit distances, or keyword padding.
    """

    # High-value brands often targeted by phishing/scams
    PROTECTED_BRANDS = [
        "microsoft",
        "google",
        "apple",
        "amazon",
        "paypal",
        "facebook",
        "netflix",
        "instagram",
        "twitter",
        "linkedin",
        "dropbox",
        "adobe",
        "outlook",
        "office365",
        "chase",
        "wellsfargo",
        "bankofamerica",
        "citibank",
        "hsbc",
        "stripe",
        "square",
        "coinbase",
        "binance",
        "metamask",
        "norton",
        "mcafee",
    ]

    # Common homoglyph/typosquat mappings (Map scam chars to real chars)
    HOMOGLYPH_MAP = {
        "vv": "w",
        "rn": "m",
        "cl": "d",
        "nn": "m",
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "8": "b",
        "|": "l",
        "!": "i",
        "v": "u",
    }

    # Suspicious TLDs often used for scams
    SUSPICIOUS_TLDS = {
        "xyz",
        "top",
        "work",
        "zip",
        "review",
        "country",
        "bid",
        "lol",
        "link",
        "kim",
        "men",
        "live",
        "ru",
        "biz",
        "info",
        "support",
        "security",
        "account",
        "verify",
        "update",
    }

    # Common URL shorteners used in SMS scams
    URL_SHORTENERS = {
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "is.gd",
        "buff.ly",
        "goo.gl",
        "bit.do",
        "ow.ly",
        "shorte.st",
        "rebrandly.com",
        "tiny.cc",
    }

    def __init__(self, brands: Optional[List[str]] = None):
        self.brands = brands or self.PROTECTED_BRANDS
        # Improved regex to catch emails and potentially malicious URL-like structures in emails
        self.email_regex = re.compile(
            r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
        )
        self.url_regex = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+")

    def normalize_domain(self, domain_part: str) -> str:
        """
        Normalize a domain part by converting to lowercase and replacing common homoglyphs.
        """
        normalized = domain_part.lower()
        # Order matters: replace multi-character homoglyphs first
        for char in sorted(self.HOMOGLYPH_MAP.keys(), key=len, reverse=True):
            normalized = normalized.replace(char, self.HOMOGLYPH_MAP[char])
        return normalized

    def get_similarity(self, s1: str, s2: str) -> float:
        """Calculate similarity ratio between two strings."""
        return difflib.SequenceMatcher(None, s1, s2).ratio()

    def analyze_email(self, email: str) -> Tuple[bool, Optional[str], float]:
        """
        Analyze a single email address for potential typosquatting.
        Returns (is_suspicious, matched_brand, confidence)
        """
        match = self.email_regex.search(email)
        if not match:
            return False, None, 0.0

        full_domain = match.group(1).lower()
        parts = full_domain.split(".")
        if len(parts) < 2:
            return False, None, 0.0

        tld = parts[-1]
        domain_body = ".".join(parts[:-1])

        # Split by common separators to find hidden brands
        body_parts = re.split(r"[-_.]", domain_body)

        # 1. Direct Match Check (Whitelist)
        # If the domain body is exactly a brand AND it's a known TLD, it's probably fine
        # (Though some scams use brand.xyz, so we check TLD later)
        is_exact_brand = False
        for brand in self.brands:
            if domain_body == brand:
                is_exact_brand = True
                break

        # 2. Smart Detection Loop
        max_confidence = 0.0
        found_brand = None

        for brand in self.brands:
            # A. Homoglyph check on the whole body
            normalized_body = self.normalize_domain(domain_body)
            if normalized_body == brand and domain_body != brand:
                max_confidence = max(max_confidence, 1.0)
                found_brand = brand

            # B. Check each part of the domain
            for part in body_parts:
                normalized_part = self.normalize_domain(part)

                # 1. Exact brand found in a part (e.g., microsoft in microsoft-security)
                # But only flag if there are other parts or if it's a homoglyph
                if normalized_part == brand:
                    if part != brand:
                        # Homoglyph in a part (e.g., micros0ft-security)
                        max_confidence = max(max_confidence, 1.0)
                        found_brand = brand
                    elif len(body_parts) > 1:
                        # Exact brand but with other parts (e.g., microsoft-security)
                        max_confidence = max(max_confidence, 0.9)
                        found_brand = brand

                # 2. Brand is a substring of a part (e.g., mymicrosoft-login)
                elif brand in part:
                    max_confidence = max(max_confidence, 0.85)
                    found_brand = brand

                # 3. Fuzzy matching on the part (e.g., mcrosoft)
                else:
                    similarity = self.get_similarity(part, brand)
                    if 0.85 <= similarity < 1.0:
                        max_confidence = max(max_confidence, similarity)
                        found_brand = brand

            # C. Subdomain trickery (e.g., microsoft.com.security-update.net)
            if len(parts) > 2:
                for i in range(len(parts) - 1):
                    if (
                        parts[i] == brand
                        and parts[i + 1] != "com"
                        and parts[i + 1] != "org"
                    ):
                        max_confidence = max(max_confidence, 0.85)
                        found_brand = brand

        # 3. Final Verdict Logic

        # A. Case: Exact brand match with suspicious TLD (e.g., microsoft.xyz)
        if is_exact_brand and tld in self.SUSPICIOUS_TLDS:
            return True, domain_body, 0.9

        # B. Case: Exact brand match with safe TLD (e.g., microsoft.com)
        if is_exact_brand and tld in ["com", "net", "org", "edu", "gov", "io", "co"]:
            return False, None, 0.0

        # C. Case: Suspicious patterns detected (Homoglyphs, Padding, Fuzzy, etc.)
        if max_confidence >= 0.8:
            # Boost confidence for suspicious TLDs
            if tld in self.SUSPICIOUS_TLDS:
                max_confidence = min(1.0, max_confidence + 0.1)

            return True, found_brand, max_confidence

        return False, None, 0.0

    def detect_scam_emails(self, text: str) -> List[Dict]:
        """
        Extract and analyze all emails in a text.
        """
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
        results = []

        for email in emails:
            is_suspicious, matched_brand, confidence = self.analyze_email(email)
            if is_suspicious:
                results.append(
                    {
                        "email": email,
                        "matched_brand": matched_brand,
                        "confidence": confidence,
                        "reason": f"Email domain looks like a fake version of {matched_brand.capitalize()}",
                    }
                )

        return results

    def detect_scam_sms(self, text: str) -> List[Dict]:
        """
        Analyze text for common SMS scam (smishing) patterns.
        """
        results = []
        text_lower = text.lower()

        # 1. Check for URL shorteners in SMS (highly suspicious for bank/service alerts)
        urls = self.url_regex.findall(text)
        for url in urls:
            try:
                domain = urlparse(url).netloc.lower()
                # Check for exact match or subdomain match for shorteners
                is_shortener = False
                for shortener in self.URL_SHORTENERS:
                    if domain == shortener or domain.endswith("." + shortener):
                        is_shortener = True
                        break

                if is_shortener:
                    results.append(
                        {
                            "type": "sms_shortener",
                            "value": url,
                            "confidence": 0.85,
                            "reason": "SMS contains a shortened URL, often used to hide malicious sites.",
                        }
                    )
            except Exception:
                continue

        # 2. SMS-specific scam phrases
        sms_scam_patterns = {
            r"parcel.*waiting|delivery.*failed|shipping.*fee": "Potential package delivery scam",
            r"unpaid.*toll|highway.*bill|toll.*fine": "Potential unpaid toll scam",
            r"refund.*available|tax.*rebate|claim.*refund": "Potential tax or refund scam",
            r"unauthorized.*login|locked.*account|verify.*identity": "Potential account takeover attempt",
            r"suspicious.*activity.*bank|card.*blocked": "Potential banking scam",
        }

        for pattern, reason in sms_scam_patterns.items():
            if re.search(pattern, text_lower):
                results.append(
                    {
                        "type": "sms_pattern",
                        "value": pattern,
                        "confidence": 0.8,
                        "reason": reason,
                    }
                )

        return results


from urllib.parse import urlparse
