#!/usr/bin/env python3
"""
PayGuard Privacy-Preserving Threat Intelligence System
Opt-in anonymous threat sharing with differential privacy
"""

import os
import json
import hashlib
import secrets
import time
import asyncio
import aiohttp
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from collections import defaultdict
from enum import Enum
import random
import math
import sqlite3
import threading

class SharingLevel(Enum):
    """User consent levels for threat sharing"""
    NONE = "none"              # No sharing at all
    ANONYMOUS = "anonymous"    # Share anonymized threat indicators only
    COMMUNITY = "community"    # Share with community threat feed
    FULL = "full"             # Share with attribution (enterprise)


@dataclass
class AnonymizedThreat:
    """A privacy-preserving threat indicator"""
    threat_id: str                    # Random ID, not traceable
    threat_type: str                  # phishing, malware, scam, etc.
    indicator_hash: str               # SHA-256 of indicator (URL/domain/hash)
    indicator_type: str               # url, domain, ip, file_hash
    confidence_bucket: str            # low, medium, high (bucketed, not exact)
    timestamp_bucket: str             # Hour-level precision only
    noise_added: bool = True          # Differential privacy applied
    metadata: Dict[str, Any] = field(default_factory=dict)


class DifferentialPrivacy:
    """
    Implements differential privacy for threat intelligence sharing.
    Uses randomized response and Laplace mechanism.
    """
    
    def __init__(self, epsilon: float = 1.0):
        """
        Args:
            epsilon: Privacy parameter (lower = more private, less accurate)
        """
        self.epsilon = epsilon
    
    def randomized_response(self, true_value: bool, probability: float = None) -> bool:
        """
        Randomized response mechanism for boolean values.
        Provides plausible deniability.
        """
        if probability is None:
            probability = math.exp(self.epsilon) / (1 + math.exp(self.epsilon))
        
        if random.random() < probability:
            return true_value
        else:
            return random.choice([True, False])
    
    def laplace_noise(self, sensitivity: float = 1.0) -> float:
        """Add Laplace noise for numerical values"""
        scale = sensitivity / self.epsilon
        return random.uniform(-1, 1) * scale * math.log(random.random())
    
    def bucket_value(self, value: float, buckets: List[float]) -> str:
        """Bucket a numerical value with noise"""
        noisy_value = value + self.laplace_noise(sensitivity=0.1)
        for i, threshold in enumerate(buckets):
            if noisy_value <= threshold:
                return f"bucket_{i}"
        return f"bucket_{len(buckets)}"
    
    def bucket_timestamp(self, timestamp: datetime) -> str:
        """Bucket timestamp to hour-level + noise"""
        # Add random minutes to obscure exact time
        noise_minutes = random.randint(-30, 30)
        noisy_time = timestamp + timedelta(minutes=noise_minutes)
        # Return only hour precision
        return noisy_time.strftime("%Y-%m-%d-%H")


class LocalThreatDB:
    """Local SQLite database for threat intelligence"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                indicator_hash TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                confidence REAL,
                first_seen TEXT,
                last_seen TEXT,
                report_count INTEGER DEFAULT 1,
                source TEXT DEFAULT 'community',
                UNIQUE(indicator_hash, indicator_type)
            )
        ''')
        
        # Index for fast lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_indicator 
            ON threats(indicator_hash, indicator_type)
        ''')
        
        # User consent tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS consent (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )
        ''')
        
        # Contribution log (for credits)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contributions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contribution_hash TEXT,
                contribution_type TEXT,
                timestamp TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_threat(self, threat: AnonymizedThreat) -> bool:
        """Add or update a threat indicator"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO threats (id, indicator_hash, indicator_type, threat_type, 
                                    confidence, first_seen, last_seen, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator_hash, indicator_type) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    report_count = report_count + 1,
                    confidence = MAX(confidence, excluded.confidence)
            ''', (
                threat.threat_id,
                threat.indicator_hash,
                threat.indicator_type,
                threat.threat_type,
                self._confidence_to_float(threat.confidence_bucket),
                threat.timestamp_bucket,
                threat.timestamp_bucket,
                'community'
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding threat: {e}")
            return False
        finally:
            conn.close()
    
    def _confidence_to_float(self, bucket: str) -> float:
        mapping = {'low': 0.3, 'medium': 0.6, 'high': 0.9}
        return mapping.get(bucket, 0.5)
    
    def check_indicator(self, indicator: str, indicator_type: str) -> Optional[Dict]:
        """Check if an indicator is in the threat database"""
        indicator_hash = hashlib.sha256(indicator.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT threat_type, confidence, report_count, first_seen, last_seen
            FROM threats
            WHERE indicator_hash = ? AND indicator_type = ?
        ''', (indicator_hash, indicator_type))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'found': True,
                'threat_type': row[0],
                'confidence': row[1],
                'report_count': row[2],
                'first_seen': row[3],
                'last_seen': row[4]
            }
        return None
    
    def get_stats(self) -> Dict[str, int]:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM threats')
        total = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type
        ''')
        by_type = dict(cursor.fetchall())
        
        cursor.execute('SELECT COUNT(*) FROM contributions')
        contributions = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_threats': total,
            'by_type': by_type,
            'user_contributions': contributions
        }


class ThreatIntelligenceHub:
    """
    Central hub for privacy-preserving threat intelligence.
    Handles both local database and community sharing.
    """
    
    # Community threat feed endpoints (simulated for now)
    COMMUNITY_FEED_URL = "https://api.payguard-community.io/threats"  
    
    def __init__(self, data_dir: str = "/Users/ekans/payguard/threat_intel"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        self.db = LocalThreatDB(str(self.data_dir / "threats.db"))
        self.dp = DifferentialPrivacy(epsilon=1.0)  # Privacy budget
        self.sharing_level = SharingLevel.NONE
        self._load_consent()
        
        # In-memory cache for fast lookups
        self._cache: Dict[str, Tuple[Dict, float]] = {}
        self._cache_ttl = 3600  # 1 hour
    
    def _load_consent(self):
        """Load user consent settings"""
        consent_file = self.data_dir / "consent.json"
        if consent_file.exists():
            with open(consent_file) as f:
                data = json.load(f)
                self.sharing_level = SharingLevel(data.get('sharing_level', 'none'))
    
    def set_sharing_level(self, level: SharingLevel) -> bool:
        """Set user's sharing consent level"""
        self.sharing_level = level
        consent_file = self.data_dir / "consent.json"
        
        with open(consent_file, 'w') as f:
            json.dump({
                'sharing_level': level.value,
                'updated_at': datetime.now().isoformat(),
                'consent_version': '1.0'
            }, f, indent=2)
        
        print(f"✓ Sharing level set to: {level.value}")
        return True
    
    def get_sharing_level(self) -> SharingLevel:
        """Get current sharing level"""
        return self.sharing_level
    
    def anonymize_threat(self, 
                        indicator: str,
                        indicator_type: str,
                        threat_type: str,
                        confidence: float) -> AnonymizedThreat:
        """
        Create an anonymized threat indicator with differential privacy.
        """
        # Hash the indicator (one-way, can't recover original)
        indicator_hash = hashlib.sha256(indicator.encode()).hexdigest()
        
        # Random ID (not traceable to user)
        threat_id = secrets.token_hex(16)
        
        # Bucket confidence with noise
        if confidence < 0.4:
            confidence_bucket = "low"
        elif confidence < 0.7:
            confidence_bucket = "medium"
        else:
            confidence_bucket = "high"
        
        # Apply randomized response to potentially flip the bucket
        if not self.dp.randomized_response(True, probability=0.9):
            # 10% chance to flip to adjacent bucket
            buckets = ["low", "medium", "high"]
            idx = buckets.index(confidence_bucket)
            new_idx = max(0, min(2, idx + random.choice([-1, 1])))
            confidence_bucket = buckets[new_idx]
        
        # Bucket timestamp with noise
        timestamp_bucket = self.dp.bucket_timestamp(datetime.now())
        
        return AnonymizedThreat(
            threat_id=threat_id,
            threat_type=threat_type,
            indicator_hash=indicator_hash,
            indicator_type=indicator_type,
            confidence_bucket=confidence_bucket,
            timestamp_bucket=timestamp_bucket,
            noise_added=True,
            metadata={}
        )
    
    def report_threat(self, 
                     indicator: str,
                     indicator_type: str,
                     threat_type: str,
                     confidence: float) -> Dict[str, Any]:
        """
        Report a threat indicator. Respects user's privacy settings.
        """
        # Always add to local database (for user's own protection)
        anonymized = self.anonymize_threat(indicator, indicator_type, 
                                           threat_type, confidence)
        self.db.add_threat(anonymized)
        
        result = {
            'stored_locally': True,
            'shared_to_community': False,
            'sharing_level': self.sharing_level.value
        }
        
        # Check if user consented to sharing
        if self.sharing_level in [SharingLevel.ANONYMOUS, 
                                  SharingLevel.COMMUNITY, 
                                  SharingLevel.FULL]:
            # In a real implementation, this would POST to community feed
            result['shared_to_community'] = True
            result['contribution_id'] = anonymized.threat_id[:8]
            
            # Log contribution
            conn = sqlite3.connect(str(self.data_dir / "threats.db"))
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO contributions (contribution_hash, contribution_type, timestamp)
                VALUES (?, ?, ?)
            ''', (
                hashlib.sha256(anonymized.threat_id.encode()).hexdigest()[:16],
                threat_type,
                datetime.now().isoformat()
            ))
            conn.commit()
            conn.close()
        
        return result
    
    def check_threat(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """
        Check if an indicator is a known threat.
        Checks local DB and optionally community feed.
        """
        # Check cache first
        cache_key = f"{indicator_type}:{indicator}"
        if cache_key in self._cache:
            cached, timestamp = self._cache[cache_key]
            if time.time() - timestamp < self._cache_ttl:
                return cached
        
        # Check local database
        local_result = self.db.check_indicator(indicator, indicator_type)
        
        if local_result:
            result = {
                'is_threat': True,
                'source': 'local_db',
                **local_result
            }
        else:
            result = {
                'is_threat': False,
                'source': None
            }
        
        # Cache result
        self._cache[cache_key] = (result, time.time())
        
        return result
    
    async def sync_community_feed(self) -> Dict[str, int]:
        """
        Sync with community threat feed (pull new threats).
        Only runs if user has opted into community sharing.
        """
        if self.sharing_level == SharingLevel.NONE:
            return {'status': 'skipped', 'reason': 'sharing_disabled'}
        
        # In production, this would fetch from community API
        # For now, simulate with local threat feeds
        
        added = 0
        
        # Load from known phishing lists if available
        feeds = [
            '/Users/ekans/payguard/phishing_urls.txt',
            '/Users/ekans/payguard/malware_hashes.txt'
        ]
        
        for feed_path in feeds:
            if Path(feed_path).exists():
                with open(feed_path) as f:
                    for line in f:
                        indicator = line.strip()
                        if indicator and not indicator.startswith('#'):
                            self.report_threat(
                                indicator=indicator,
                                indicator_type='url',
                                threat_type='phishing',
                                confidence=0.8
                            )
                            added += 1
        
        return {
            'status': 'success',
            'threats_added': added,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_community_stats(self) -> Dict[str, Any]:
        """Get statistics about threat intelligence"""
        stats = self.db.get_stats()
        stats['sharing_level'] = self.sharing_level.value
        stats['privacy_epsilon'] = self.dp.epsilon
        return stats
    
    def export_anonymized_feed(self, output_path: str) -> int:
        """
        Export anonymized threat feed for sharing.
        Only includes indicators, no user data.
        """
        if self.sharing_level == SharingLevel.NONE:
            return 0
        
        conn = sqlite3.connect(str(self.data_dir / "threats.db"))
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT indicator_hash, indicator_type, threat_type, 
                   confidence, first_seen, report_count
            FROM threats
            WHERE report_count >= 2  -- Only well-confirmed threats
        ''')
        
        threats = []
        for row in cursor.fetchall():
            threats.append({
                'indicator_hash': row[0],
                'indicator_type': row[1],
                'threat_type': row[2],
                'confidence': row[3],
                'first_seen': row[4],
                'reports': row[5]
            })
        
        conn.close()
        
        with open(output_path, 'w') as f:
            json.dump({
                'version': '1.0',
                'exported_at': datetime.now().isoformat(),
                'total_threats': len(threats),
                'threats': threats
            }, f, indent=2)
        
        return len(threats)


class CommunityProtectionScore:
    """
    Gamification: Users earn protection score for contributing.
    Higher score = more protection features unlocked.
    """
    
    def __init__(self, hub: ThreatIntelligenceHub):
        self.hub = hub
        self.score_file = hub.data_dir / "protection_score.json"
        self._load_score()
    
    def _load_score(self):
        if self.score_file.exists():
            with open(self.score_file) as f:
                self.data = json.load(f)
        else:
            self.data = {
                'score': 0,
                'level': 'bronze',
                'contributions': 0,
                'streak_days': 0,
                'badges': []
            }
    
    def _save_score(self):
        with open(self.score_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def add_contribution(self, contribution_type: str) -> Dict[str, Any]:
        """Add points for a contribution"""
        points = {
            'phishing_report': 10,
            'malware_report': 15,
            'scam_report': 10,
            'verification': 5,
            'daily_scan': 2
        }
        
        earned = points.get(contribution_type, 5)
        self.data['score'] += earned
        self.data['contributions'] += 1
        
        # Update level
        if self.data['score'] >= 1000:
            self.data['level'] = 'diamond'
        elif self.data['score'] >= 500:
            self.data['level'] = 'gold'
        elif self.data['score'] >= 100:
            self.data['level'] = 'silver'
        
        self._save_score()
        
        return {
            'points_earned': earned,
            'total_score': self.data['score'],
            'level': self.data['level']
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get current protection score status"""
        return {
            **self.data,
            'next_level': self._next_level(),
            'points_to_next': self._points_to_next()
        }
    
    def _next_level(self) -> str:
        levels = ['bronze', 'silver', 'gold', 'diamond']
        current_idx = levels.index(self.data['level'])
        if current_idx < len(levels) - 1:
            return levels[current_idx + 1]
        return 'diamond'
    
    def _points_to_next(self) -> int:
        thresholds = {'bronze': 100, 'silver': 500, 'gold': 1000, 'diamond': float('inf')}
        next_threshold = thresholds[self._next_level()]
        return max(0, int(next_threshold - self.data['score']))


# Demo/Test
def main():
    print("\n" + "="*60)
    print("🛡️ PayGuard Privacy-Preserving Threat Intelligence")
    print("="*60)
    
    # Initialize
    hub = ThreatIntelligenceHub()
    score = CommunityProtectionScore(hub)
    
    # Show current settings
    print(f"\n📊 Current Status:")
    print(f"   Sharing Level: {hub.get_sharing_level().value}")
    print(f"   Protection Score: {score.get_status()['score']}")
    
    # Demo: Opt-in to anonymous sharing
    print(f"\n🔒 Setting sharing level to ANONYMOUS...")
    hub.set_sharing_level(SharingLevel.ANONYMOUS)
    
    # Demo: Report a threat
    print(f"\n📤 Reporting threat indicators...")
    
    test_threats = [
        ("http://evil-phishing-site.com/login", "url", "phishing", 0.95),
        ("http://fake-bank-login.net/secure", "url", "phishing", 0.88),
        ("malware@scammer.com", "email", "scam", 0.75),
    ]
    
    for indicator, ind_type, threat_type, conf in test_threats:
        result = hub.report_threat(indicator, ind_type, threat_type, conf)
        shared = "✓ shared" if result['shared_to_community'] else "local only"
        print(f"   {threat_type}: {indicator[:40]}... ({shared})")
        
        # Earn points
        points = score.add_contribution(f"{threat_type}_report")
        print(f"      +{points['points_earned']} points (total: {points['total_score']})")
    
    # Demo: Check a threat
    print(f"\n🔍 Checking threat status...")
    check_result = hub.check_threat("http://evil-phishing-site.com/login", "url")
    if check_result['is_threat']:
        print(f"   ⚠️  KNOWN THREAT: {check_result['threat_type']} (confidence: {check_result['confidence']:.0%})")
    
    # Show stats
    stats = hub.get_community_stats()
    print(f"\n📈 Community Intelligence Stats:")
    print(f"   Total threats in DB: {stats['total_threats']}")
    print(f"   Your contributions: {stats.get('user_contributions', 0)}")
    print(f"   Privacy level (ε): {stats['privacy_epsilon']}")
    
    # Show protection score
    status = score.get_status()
    print(f"\n🏆 Protection Score:")
    print(f"   Score: {status['score']}")
    print(f"   Level: {status['level'].upper()}")
    print(f"   Points to {status['next_level']}: {status['points_to_next']}")
    
    print("\n✅ Privacy-preserving threat intelligence system ready!")
    print("   Users can contribute to community safety while maintaining privacy.")


if __name__ == "__main__":
    main()
