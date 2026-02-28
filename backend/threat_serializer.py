"""
PayGuard V2 - Threat Data Serialization with MessagePack

This module provides efficient binary serialization for threat intelligence data
using MessagePack format with SHA-256 integrity verification.

Implements:
- MessagePack serialization for threat data (Task 28.1)
- SHA-256 integrity verification (Task 28.2)

Requirements: 24.4, 24.5
"""

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import msgpack

    MSGPACK_AVAILABLE = True
except ImportError:
    MSGPACK_AVAILABLE = False
    msgpack = None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatDataError(Exception):
    """Base exception for threat data operations"""

    pass


class IntegrityError(ThreatDataError):
    """Raised when data integrity check fails"""

    pass


class SerializationError(ThreatDataError):
    """Raised when serialization/deserialization fails"""

    pass


class ThreatType(str, Enum):
    """Types of threats"""

    PHISHING = "phishing"
    MALWARE = "malware"
    SCAM = "scam"
    SPAM = "spam"
    RANSOMWARE = "ransomware"
    UNKNOWN = "unknown"


class ThreatSeverity(str, Enum):
    """Threat severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatIndicator:
    """Individual threat indicator"""

    id: str
    type: ThreatType
    value: str  # URL, hash, IP, etc.
    severity: ThreatSeverity
    source: str
    first_seen: datetime
    last_seen: datetime
    confidence: float = 0.0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatFeed:
    """Collection of threat indicators from a single source"""

    feed_id: str
    name: str
    version: str
    updated_at: datetime
    indicators: List[ThreatIndicator]
    checksum: str = ""


@dataclass
class ThreatDataPackage:
    """Complete threat data package with integrity verification"""

    version: str
    created_at: datetime
    feeds: List[ThreatFeed]
    total_indicators: int
    checksum: str = ""


class ThreatDataSerializer:
    """
    Serializer for threat intelligence data using MessagePack.

    Provides efficient binary serialization with SHA-256 integrity verification
    for threat data transmission and storage.

    Requirements:
    - 24.4: Use MessagePack for efficient binary serialization
    - 24.5: Implement SHA-256 integrity verification
    """

    MAGIC_HEADER = b"PGTD"  # PayGuard Threat Data
    FORMAT_VERSION = 1

    def __init__(self):
        """Initialize the serializer"""
        if not MSGPACK_AVAILABLE:
            logger.warning("msgpack not available, using JSON fallback")

    def serialize(self, data: ThreatDataPackage) -> bytes:
        """
        Serialize threat data package to binary format with integrity check.

        Args:
            data: ThreatDataPackage to serialize

        Returns:
            Binary data with header, checksum, and payload

        Raises:
            SerializationError: If serialization fails
        """
        try:
            # Convert to dictionary
            payload_dict = self._to_dict(data)

            # Serialize payload
            if MSGPACK_AVAILABLE:
                payload_bytes = msgpack.packb(payload_dict, use_bin_type=True)
            else:
                payload_bytes = json.dumps(payload_dict, default=str).encode("utf-8")

            # Compute checksum
            checksum = self._compute_checksum(payload_bytes)

            # Build final package:
            # [MAGIC_HEADER (4 bytes)][VERSION (1 byte)][CHECKSUM (32 bytes)][PAYLOAD]
            result = bytearray()
            result.extend(self.MAGIC_HEADER)
            result.append(self.FORMAT_VERSION)
            result.extend(checksum)
            result.extend(payload_bytes)

            return bytes(result)

        except Exception as e:
            raise SerializationError(f"Failed to serialize threat data: {e}")

    def deserialize(
        self, data: bytes, verify_integrity: bool = True
    ) -> ThreatDataPackage:
        """
        Deserialize threat data package from binary format.

        Args:
            data: Binary data to deserialize
            verify_integrity: If True, verify SHA-256 checksum

        Returns:
            Deserialized ThreatDataPackage

        Raises:
            IntegrityError: If checksum verification fails
            SerializationError: If deserialization fails
        """
        try:
            # Verify header
            if len(data) < 37:  # 4 + 1 + 32 = 37 minimum
                raise SerializationError("Data too short")

            if data[:4] != self.MAGIC_HEADER:
                raise SerializationError("Invalid magic header")

            version = data[4]
            if version != self.FORMAT_VERSION:
                raise SerializationError(f"Unsupported format version: {version}")

            stored_checksum = data[5:37]
            payload_bytes = data[37:]

            # Verify integrity
            if verify_integrity:
                computed_checksum = self._compute_checksum(payload_bytes)
                if computed_checksum != stored_checksum:
                    raise IntegrityError(
                        "Checksum verification failed - data may be corrupted"
                    )

            # Deserialize payload
            if MSGPACK_AVAILABLE:
                payload_dict = msgpack.unpackb(payload_bytes, raw=False)
            else:
                payload_dict = json.loads(payload_bytes.decode("utf-8"))

            return self._from_dict(payload_dict)

        except IntegrityError:
            raise
        except Exception as e:
            raise SerializationError(f"Failed to deserialize threat data: {e}")

    def verify_integrity(self, data: bytes) -> Tuple[bool, str]:
        """
        Verify the integrity of serialized threat data.

        Args:
            data: Binary data to verify

        Returns:
            Tuple of (is_valid, message)
        """
        try:
            if len(data) < 37:
                return False, "Data too short"

            if data[:4] != self.MAGIC_HEADER:
                return False, "Invalid magic header"

            stored_checksum = data[5:37]
            payload_bytes = data[37:]

            computed_checksum = self._compute_checksum(payload_bytes)

            if computed_checksum == stored_checksum:
                return True, "Integrity verified"
            else:
                return False, "Checksum mismatch - data may be corrupted"

        except Exception as e:
            return False, f"Verification error: {e}"

    def _compute_checksum(self, data: bytes) -> bytes:
        """Compute SHA-256 checksum of data"""
        return hashlib.sha256(data).digest()

    def _to_dict(self, package: ThreatDataPackage) -> Dict[str, Any]:
        """Convert ThreatDataPackage to dictionary"""
        return {
            "version": package.version,
            "created_at": package.created_at.isoformat(),
            "total_indicators": package.total_indicators,
            "checksum": package.checksum,
            "feeds": [self._feed_to_dict(f) for f in package.feeds],
        }

    def _feed_to_dict(self, feed: ThreatFeed) -> Dict[str, Any]:
        """Convert ThreatFeed to dictionary"""
        return {
            "feed_id": feed.feed_id,
            "name": feed.name,
            "version": feed.version,
            "updated_at": feed.updated_at.isoformat(),
            "checksum": feed.checksum,
            "indicators": [self._indicator_to_dict(i) for i in feed.indicators],
        }

    def _indicator_to_dict(self, indicator: ThreatIndicator) -> Dict[str, Any]:
        """Convert ThreatIndicator to dictionary"""
        return {
            "id": indicator.id,
            "type": (
                indicator.type.value
                if isinstance(indicator.type, ThreatType)
                else indicator.type
            ),
            "value": indicator.value,
            "severity": (
                indicator.severity.value
                if isinstance(indicator.severity, ThreatSeverity)
                else indicator.severity
            ),
            "source": indicator.source,
            "first_seen": indicator.first_seen.isoformat(),
            "last_seen": indicator.last_seen.isoformat(),
            "confidence": indicator.confidence,
            "tags": indicator.tags,
            "metadata": indicator.metadata,
        }

    def _from_dict(self, data: Dict[str, Any]) -> ThreatDataPackage:
        """Convert dictionary to ThreatDataPackage"""
        feeds = [self._feed_from_dict(f) for f in data.get("feeds", [])]

        return ThreatDataPackage(
            version=data.get("version", "1.0.0"),
            created_at=datetime.fromisoformat(data["created_at"]),
            feeds=feeds,
            total_indicators=data.get(
                "total_indicators", sum(len(f.indicators) for f in feeds)
            ),
            checksum=data.get("checksum", ""),
        )

    def _feed_from_dict(self, data: Dict[str, Any]) -> ThreatFeed:
        """Convert dictionary to ThreatFeed"""
        indicators = [self._indicator_from_dict(i) for i in data.get("indicators", [])]

        return ThreatFeed(
            feed_id=data["feed_id"],
            name=data["name"],
            version=data.get("version", "1.0.0"),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            indicators=indicators,
            checksum=data.get("checksum", ""),
        )

    def _indicator_from_dict(self, data: Dict[str, Any]) -> ThreatIndicator:
        """Convert dictionary to ThreatIndicator"""
        return ThreatIndicator(
            id=data["id"],
            type=(
                ThreatType(data["type"])
                if data["type"] in [t.value for t in ThreatType]
                else ThreatType.UNKNOWN
            ),
            value=data["value"],
            severity=(
                ThreatSeverity(data["severity"])
                if data["severity"] in [s.value for s in ThreatSeverity]
                else ThreatSeverity.MEDIUM
            ),
            source=data["source"],
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            confidence=data.get("confidence", 0.0),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )


# Convenience functions


def serialize_threat_data(package: ThreatDataPackage) -> bytes:
    """Serialize a threat data package to binary format"""
    serializer = ThreatDataSerializer()
    return serializer.serialize(package)


def deserialize_threat_data(data: bytes, verify: bool = True) -> ThreatDataPackage:
    """Deserialize threat data from binary format"""
    serializer = ThreatDataSerializer()
    return serializer.deserialize(data, verify_integrity=verify)


def verify_threat_data_integrity(data: bytes) -> Tuple[bool, str]:
    """Verify the integrity of serialized threat data"""
    serializer = ThreatDataSerializer()
    return serializer.verify_integrity(data)


# Example usage
if __name__ == "__main__":
    # Create sample threat data
    indicator = ThreatIndicator(
        id="ti-001",
        type=ThreatType.PHISHING,
        value="https://fake-bank-login.com",
        severity=ThreatSeverity.HIGH,
        source="openphish",
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        confidence=0.95,
        tags=["banking", "credential-theft"],
        metadata={"country": "US"},
    )

    feed = ThreatFeed(
        feed_id="openphish-001",
        name="OpenPhish",
        version="1.0.0",
        updated_at=datetime.now(),
        indicators=[indicator],
    )

    package = ThreatDataPackage(
        version="1.0.0", created_at=datetime.now(), feeds=[feed], total_indicators=1
    )

    # Serialize
    serializer = ThreatDataSerializer()
    serialized = serializer.serialize(package)
    print(f"Serialized size: {len(serialized)} bytes")

    # Verify integrity
    is_valid, message = serializer.verify_integrity(serialized)
    print(f"Integrity check: {message}")

    # Deserialize
    deserialized = serializer.deserialize(serialized)
    print(f"Deserialized: {deserialized.total_indicators} indicators")

    # Test corruption detection
    corrupted = bytearray(serialized)
    corrupted[50] ^= 0xFF  # Flip bits
    is_valid, message = serializer.verify_integrity(bytes(corrupted))
    print(f"Corrupted data check: {message}")
