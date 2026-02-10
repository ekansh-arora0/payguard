"""
PayGuard V2 - Telemetry Service (Opt-in Only)

This module provides opt-in telemetry collection with full anonymization.
NO data is collected without explicit user consent.

Implements:
- Opt-in only telemetry (Task 30.1)
- Full anonymization (Task 30.2)
- Feedback aggregation with adversarial detection (Task 30.3)

Requirements: 5.8, 18.3, 18.4, 18.8, 18.9
"""

import hashlib
import logging
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Any, Optional, List, Set, Callable
from collections import Counter
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TelemetryError(Exception):
    """Base exception for telemetry operations"""
    pass


class ConsentRequiredError(TelemetryError):
    """Raised when telemetry is attempted without consent"""
    pass


class TelemetryEventType(str, Enum):
    """Types of telemetry events"""
    DETECTION = "detection"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    USER_FEEDBACK = "user_feedback"
    ERROR = "error"
    PERFORMANCE = "performance"


@dataclass
class AnonymizedEvent:
    """
    Anonymized telemetry event.
    
    All identifying information is hashed or removed.
    """
    event_id: str
    event_type: TelemetryEventType
    timestamp: datetime
    
    # Anonymized data
    session_hash: str  # Hash of session ID, not actual ID
    detection_type: Optional[str] = None
    confidence_bucket: Optional[str] = None  # e.g., "80-90" not exact value
    outcome: Optional[str] = None  # "detected", "safe", "unknown"
    
    # Aggregated metrics (no PII)
    url_domain_hash: Optional[str] = None  # Hash of domain
    url_length_bucket: Optional[str] = None  # e.g., "0-50", "51-100"
    detection_time_ms_bucket: Optional[str] = None
    
    # Optional feedback
    user_verdict: Optional[str] = None  # "safe" or "dangerous"
    
    # Metadata (anonymized)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FeedbackEntry:
    """User feedback entry (anonymized)"""
    feedback_id: str
    url_hash: str
    domain_hash: str
    user_verdict: str  # "safe" or "dangerous"
    our_verdict: str
    confidence_bucket: str
    timestamp: datetime
    session_hash: str


@dataclass
class AggregatedFeedback:
    """Aggregated feedback statistics"""
    domain_hash: str
    total_reports: int
    safe_reports: int
    dangerous_reports: int
    confidence: float
    last_updated: datetime


class TelemetryConsent:
    """
    Manages telemetry consent state.
    
    Requirement 18.3: Only collect from opted-in users
    """
    
    def __init__(self):
        self._opted_in = False
        self._consent_timestamp: Optional[datetime] = None
        self._consent_callbacks: List[Callable[[bool], None]] = []
    
    @property
    def is_opted_in(self) -> bool:
        """Check if user has opted in to telemetry"""
        return self._opted_in
    
    def opt_in(self) -> None:
        """Opt in to telemetry collection"""
        self._opted_in = True
        self._consent_timestamp = datetime.now(timezone.utc)
        logger.info("User opted in to telemetry")
        self._notify_callbacks(True)
    
    def opt_out(self) -> None:
        """Opt out of telemetry collection"""
        self._opted_in = False
        self._consent_timestamp = datetime.now(timezone.utc)
        logger.info("User opted out of telemetry")
        self._notify_callbacks(False)
    
    def register_callback(self, callback: Callable[[bool], None]) -> None:
        """Register callback for consent changes"""
        self._consent_callbacks.append(callback)
    
    def _notify_callbacks(self, opted_in: bool) -> None:
        """Notify all registered callbacks of consent change"""
        for callback in self._consent_callbacks:
            try:
                callback(opted_in)
            except Exception as e:
                logger.error(f"Consent callback error: {e}")


class Anonymizer:
    """
    Anonymizes data before telemetry collection.
    
    Requirement 18.4: Hash all identifiers, strip PII
    """
    
    def __init__(self, salt: Optional[str] = None):
        """
        Initialize anonymizer.
        
        Args:
            salt: Secret salt for hashing (auto-generated if not provided)
        """
        self._salt = salt or secrets.token_hex(32)
    
    def hash_identifier(self, identifier: str) -> str:
        """
        Hash an identifier (URL, session ID, etc).
        
        Uses SHA-256 with salt to prevent rainbow table attacks.
        """
        if not identifier:
            return ""
        
        salted = f"{self._salt}:{identifier}"
        return hashlib.sha256(salted.encode()).hexdigest()[:16]
    
    def hash_domain(self, domain: str) -> str:
        """Hash a domain name"""
        return self.hash_identifier(domain.lower().strip())
    
    def hash_url(self, url: str) -> str:
        """Hash a URL"""
        return self.hash_identifier(url)
    
    def bucket_value(self, value: float, buckets: List[int]) -> str:
        """
        Convert a numeric value to a bucket range string.
        
        This prevents exact values from being transmitted.
        
        Args:
            value: Numeric value to bucket
            buckets: List of bucket boundaries [10, 20, 50, 100]
            
        Returns:
            Bucket string like "20-50" or "100+"
        """
        buckets = sorted(buckets)
        
        for i, boundary in enumerate(buckets):
            if value < boundary:
                lower = buckets[i-1] if i > 0 else 0
                return f"{lower}-{boundary}"
        
        return f"{buckets[-1]}+"
    
    def bucket_confidence(self, confidence: float) -> str:
        """Bucket confidence score (0-100)"""
        return self.bucket_value(confidence, [20, 40, 60, 80, 100])
    
    def bucket_url_length(self, length: int) -> str:
        """Bucket URL length"""
        return self.bucket_value(length, [25, 50, 100, 200, 500])
    
    def bucket_time_ms(self, time_ms: float) -> str:
        """Bucket time in milliseconds"""
        return self.bucket_value(time_ms, [10, 50, 100, 500, 1000, 5000])
    
    def strip_pii(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove any PII from a data dictionary.
        
        Removes or hashes fields that might contain PII.
        """
        pii_fields = {
            'ip', 'ip_address', 'email', 'user', 'username', 'name',
            'phone', 'address', 'location', 'cookie', 'session_id',
            'user_agent', 'referer', 'referrer'
        }
        
        result = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            # Skip PII fields entirely
            if any(pii in key_lower for pii in pii_fields):
                continue
            
            # Hash URLs and domains
            if 'url' in key_lower:
                result[key] = self.hash_url(str(value)) if value else None
            elif 'domain' in key_lower:
                result[key] = self.hash_domain(str(value)) if value else None
            else:
                # Keep non-PII fields
                result[key] = value
        
        return result


class AdversarialFeedbackDetector:
    """
    Detects adversarial feedback patterns.
    
    Requirement 18.9: Detect adversarial feedback
    """
    
    # Minimum reports before feedback influences model
    MIN_REPORTS_THRESHOLD = 10
    
    # Maximum reports from single session per day
    MAX_REPORTS_PER_SESSION_DAY = 20
    
    # Suspicion thresholds
    RAPID_FIRE_THRESHOLD = 5  # Reports within 1 minute
    FLIP_FLOP_THRESHOLD = 3   # Same URL, different verdicts
    
    def __init__(self):
        self._session_reports: Dict[str, List[datetime]] = {}  # session_hash -> timestamps
        self._url_verdicts: Dict[str, List[str]] = {}  # url_hash -> list of verdicts
    
    def check_feedback(self, feedback: FeedbackEntry) -> tuple[bool, str]:
        """
        Check if feedback appears adversarial.
        
        Returns:
            Tuple of (is_legitimate, reason)
        """
        session = feedback.session_hash
        url = feedback.url_hash
        timestamp = feedback.timestamp
        
        # Check rapid-fire submissions
        if session in self._session_reports:
            recent = [t for t in self._session_reports[session] 
                     if timestamp - t < timedelta(minutes=1)]
            if len(recent) >= self.RAPID_FIRE_THRESHOLD:
                return False, "Rapid-fire submission detected"
        
        # Check daily limit per session
        if session in self._session_reports:
            today = [t for t in self._session_reports[session]
                    if timestamp.date() == t.date()]
            if len(today) >= self.MAX_REPORTS_PER_SESSION_DAY:
                return False, "Daily limit exceeded for session"
        
        # Check flip-flop pattern (same URL, alternating verdicts)
        if url in self._url_verdicts:
            verdicts = self._url_verdicts[url]
            if len(verdicts) >= self.FLIP_FLOP_THRESHOLD:
                # Check for alternating pattern
                alternating = all(
                    verdicts[i] != verdicts[i+1] 
                    for i in range(len(verdicts)-1)
                )
                if alternating:
                    return False, "Flip-flop pattern detected"
        
        # Record this feedback
        if session not in self._session_reports:
            self._session_reports[session] = []
        self._session_reports[session].append(timestamp)
        
        if url not in self._url_verdicts:
            self._url_verdicts[url] = []
        self._url_verdicts[url].append(feedback.user_verdict)
        
        return True, "Feedback accepted"
    
    def cleanup_old_data(self, max_age_days: int = 7) -> None:
        """Remove data older than max_age_days"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        
        for session in list(self._session_reports.keys()):
            self._session_reports[session] = [
                t for t in self._session_reports[session] if t > cutoff
            ]
            if not self._session_reports[session]:
                del self._session_reports[session]


class TelemetryService:
    """
    PayGuard Telemetry Service (Opt-in Only)
    
    Collects anonymized telemetry data ONLY from users who have explicitly
    opted in. Implements full data anonymization and adversarial detection.
    
    Requirements:
    - 5.8: No telemetry without explicit opt-in
    - 18.3: Only collect from opted-in users  
    - 18.4: Hash all identifiers, strip PII
    - 18.8: Require minimum volume before influencing models
    - 18.9: Detect adversarial feedback
    """
    
    MIN_FEEDBACK_VOLUME = 10  # Minimum reports before influencing model
    
    def __init__(self, consent: Optional[TelemetryConsent] = None):
        """
        Initialize telemetry service.
        
        Args:
            consent: Consent manager (created if not provided)
        """
        self.consent = consent or TelemetryConsent()
        self.anonymizer = Anonymizer()
        self.adversarial_detector = AdversarialFeedbackDetector()
        
        # Storage (in production, would be sent to backend)
        self._events: List[AnonymizedEvent] = []
        self._feedback: List[FeedbackEntry] = []
        self._aggregated_feedback: Dict[str, AggregatedFeedback] = {}
    
    def record_detection(
        self,
        session_id: str,
        url: str,
        detection_type: str,
        confidence: float,
        outcome: str,
        detection_time_ms: float,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Record a detection event.
        
        Requirement 18.3: Only collect from opted-in users
        
        Args:
            session_id: User session identifier
            url: URL that was checked
            detection_type: Type of detection (phishing, scam, etc)
            confidence: Detection confidence (0-100)
            outcome: Detection outcome (detected, safe, unknown)
            detection_time_ms: Time taken for detection
            metadata: Additional metadata (will be anonymized)
            
        Returns:
            Event ID if recorded, None if not opted in
            
        Raises:
            ConsentRequiredError: If telemetry attempted without opt-in
        """
        if not self.consent.is_opted_in:
            logger.debug("Telemetry not recorded - user not opted in")
            return None
        
        # Extract domain from URL
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
        except Exception:
            domain = ""
        
        # Create anonymized event
        event = AnonymizedEvent(
            event_id=secrets.token_hex(8),
            event_type=TelemetryEventType.DETECTION,
            timestamp=datetime.now(timezone.utc),
            session_hash=self.anonymizer.hash_identifier(session_id),
            detection_type=detection_type,
            confidence_bucket=self.anonymizer.bucket_confidence(confidence),
            outcome=outcome,
            url_domain_hash=self.anonymizer.hash_domain(domain),
            url_length_bucket=self.anonymizer.bucket_url_length(len(url)),
            detection_time_ms_bucket=self.anonymizer.bucket_time_ms(detection_time_ms),
            metadata=self.anonymizer.strip_pii(metadata or {})
        )
        
        self._events.append(event)
        logger.debug(f"Recorded detection event: {event.event_id}")
        
        return event.event_id
    
    def record_feedback(
        self,
        session_id: str,
        url: str,
        user_verdict: str,
        our_verdict: str,
        confidence: float
    ) -> tuple[Optional[str], str]:
        """
        Record user feedback on a detection.
        
        Requirement 18.8, 18.9: Aggregate feedback with adversarial detection
        
        Args:
            session_id: User session identifier
            url: URL the feedback is about
            user_verdict: User's verdict ("safe" or "dangerous")
            our_verdict: Our system's verdict
            confidence: Our confidence level
            
        Returns:
            Tuple of (feedback_id or None, message)
        """
        if not self.consent.is_opted_in:
            return None, "User not opted in to telemetry"
        
        if user_verdict not in ("safe", "dangerous"):
            return None, "Invalid verdict"
        
        # Extract domain
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
        except Exception:
            domain = ""
        
        # Create feedback entry
        feedback = FeedbackEntry(
            feedback_id=secrets.token_hex(8),
            url_hash=self.anonymizer.hash_url(url),
            domain_hash=self.anonymizer.hash_domain(domain),
            user_verdict=user_verdict,
            our_verdict=our_verdict,
            confidence_bucket=self.anonymizer.bucket_confidence(confidence),
            timestamp=datetime.now(timezone.utc),
            session_hash=self.anonymizer.hash_identifier(session_id)
        )
        
        # Check for adversarial patterns
        is_legitimate, reason = self.adversarial_detector.check_feedback(feedback)
        if not is_legitimate:
            logger.warning(f"Adversarial feedback detected: {reason}")
            return None, f"Feedback rejected: {reason}"
        
        # Store feedback
        self._feedback.append(feedback)
        
        # Update aggregated feedback
        self._update_aggregated_feedback(feedback)
        
        logger.debug(f"Recorded feedback: {feedback.feedback_id}")
        return feedback.feedback_id, "Feedback recorded"
    
    def _update_aggregated_feedback(self, feedback: FeedbackEntry) -> None:
        """Update aggregated feedback statistics"""
        domain = feedback.domain_hash
        
        if domain not in self._aggregated_feedback:
            self._aggregated_feedback[domain] = AggregatedFeedback(
                domain_hash=domain,
                total_reports=0,
                safe_reports=0,
                dangerous_reports=0,
                confidence=0.0,
                last_updated=datetime.now(timezone.utc)
            )
        
        agg = self._aggregated_feedback[domain]
        agg.total_reports += 1
        
        if feedback.user_verdict == "safe":
            agg.safe_reports += 1
        else:
            agg.dangerous_reports += 1
        
        # Calculate confidence (only reliable after minimum volume)
        if agg.total_reports >= self.MIN_FEEDBACK_VOLUME:
            agg.confidence = max(agg.safe_reports, agg.dangerous_reports) / agg.total_reports
        else:
            agg.confidence = 0.0
        
        agg.last_updated = datetime.now(timezone.utc)
    
    def get_aggregated_feedback(self, domain_hash: str) -> Optional[AggregatedFeedback]:
        """
        Get aggregated feedback for a domain.
        
        Requirement 18.8: Only return if minimum volume reached
        
        Returns:
            AggregatedFeedback if available and minimum volume reached, else None
        """
        if domain_hash not in self._aggregated_feedback:
            return None
        
        agg = self._aggregated_feedback[domain_hash]
        
        # Only return if minimum volume reached
        if agg.total_reports < self.MIN_FEEDBACK_VOLUME:
            return None
        
        return agg
    
    def get_stats(self) -> Dict[str, Any]:
        """Get telemetry statistics (for debugging)"""
        return {
            "opted_in": self.consent.is_opted_in,
            "total_events": len(self._events),
            "total_feedback": len(self._feedback),
            "domains_with_feedback": len(self._aggregated_feedback)
        }
    
    def export_events(self) -> List[Dict[str, Any]]:
        """
        Export anonymized events for transmission.
        
        Returns:
            List of event dictionaries (fully anonymized)
        """
        if not self.consent.is_opted_in:
            return []
        
        return [
            {
                "event_id": e.event_id,
                "event_type": e.event_type.value,
                "timestamp": e.timestamp.isoformat(),
                "session_hash": e.session_hash,
                "detection_type": e.detection_type,
                "confidence_bucket": e.confidence_bucket,
                "outcome": e.outcome,
                "url_domain_hash": e.url_domain_hash,
                "url_length_bucket": e.url_length_bucket,
                "detection_time_ms_bucket": e.detection_time_ms_bucket,
                "user_verdict": e.user_verdict,
                "metadata": e.metadata
            }
            for e in self._events
        ]
    
    def clear_events(self) -> None:
        """Clear stored events (after successful transmission)"""
        self._events.clear()


# Example usage
if __name__ == "__main__":
    # Create telemetry service
    service = TelemetryService()
    
    # User has NOT opted in - telemetry should be rejected
    result = service.record_detection(
        session_id="user-123",
        url="https://example.com/page",
        detection_type="phishing",
        confidence=85.5,
        outcome="detected",
        detection_time_ms=45.3
    )
    print(f"Without opt-in: {result}")  # Should be None
    
    # User opts in
    service.consent.opt_in()
    
    # Now telemetry should work
    result = service.record_detection(
        session_id="user-123",
        url="https://example.com/page",
        detection_type="phishing",
        confidence=85.5,
        outcome="detected",
        detection_time_ms=45.3
    )
    print(f"With opt-in: {result}")  # Should be event ID
    
    # Record feedback
    feedback_id, message = service.record_feedback(
        session_id="user-123",
        url="https://example.com/page",
        user_verdict="dangerous",
        our_verdict="detected",
        confidence=85.5
    )
    print(f"Feedback: {feedback_id}, {message}")
    
    # Check stats
    print(f"Stats: {service.get_stats()}")
    
    # Export events
    events = service.export_events()
    print(f"Exported {len(events)} events")
    
    # Verify anonymization
    if events:
        print(f"Sample event (anonymized): {json.dumps(events[0], indent=2)}")
