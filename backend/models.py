import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class RiskLevel(str, Enum):
    LOW = "low"  # Green
    MEDIUM = "medium"  # Yellow
    HIGH = "high"  # Red


class PaymentGateway(str, Enum):
    STRIPE = "stripe"
    PAYPAL = "paypal"
    SQUARE = "square"
    AUTHORIZE_NET = "authorize_net"
    CRYPTO = "crypto"
    UNKNOWN = "unknown"


# API Key Model
class APIKey(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    key: str = Field(..., description="API key for authentication")
    institution_name: str
    tier: str = "free"  # free, premium, enterprise
    requests_count: int = 0
    daily_limit: int = 1000
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


class APIKeyCreate(BaseModel):
    institution_name: str
    tier: str = "free"


# Merchant Model
class Merchant(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain: str
    name: Optional[str] = None
    reputation_score: float = 50.0  # 0-100
    total_reports: int = 0
    fraud_reports: int = 0
    verified: bool = False
    payment_gateways: List[PaymentGateway] = []
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_checked: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ssl_valid: bool = False
    domain_age_days: Optional[int] = None


class MerchantCreate(BaseModel):
    domain: str
    name: Optional[str] = None


# Risk Score Model
class RiskScore(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    domain: str
    risk_level: RiskLevel
    trust_score: float = Field(..., ge=0, le=100, description="Trust score 0-100")
    risk_factors: List[str] = []
    safety_indicators: List[str] = []
    ssl_valid: bool
    domain_age_days: Optional[int] = None
    has_payment_gateway: bool = False
    detected_gateways: List[PaymentGateway] = []
    merchant_reputation: Optional[float] = None
    education_message: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RiskCheckRequest(BaseModel):
    url: str
    overlay_text: Optional[str] = None


# Fraud Report Model
class FraudReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain: str
    url: str
    report_type: str  # phishing, fake_store, payment_fraud, etc
    description: Optional[str] = None
    reported_by: Optional[str] = "anonymous"
    verified: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FraudReportCreate(BaseModel):
    domain: str
    url: str
    report_type: str
    description: Optional[str] = None
    reported_by: Optional[str] = "anonymous"


# Transaction Check Model
class TransactionCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    merchant_domain: str
    amount: Optional[float] = None
    currency: str = "USD"
    risk_level: RiskLevel
    risk_score: float
    approved: bool
    reasons: List[str] = []
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TransactionCheckRequest(BaseModel):
    merchant_domain: str
    amount: Optional[float] = None
    currency: str = "USD"
    payment_method: Optional[str] = None


# Custom Rules for Institutions
class CustomRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    institution_id: str
    rule_name: str
    rule_type: str  # domain_whitelist, domain_blacklist, amount_threshold, etc
    parameters: Dict[str, Any]
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CustomRuleCreate(BaseModel):
    rule_name: str
    rule_type: str
    parameters: Dict[str, Any]


# Stats Model
class Stats(BaseModel):
    total_checks: int
    high_risk_blocked: int
    merchants_tracked: int
    fraud_reports: int
    avg_trust_score: float


class LabelFeedback(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    domain: str
    label: int
    source: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LabelFeedbackCreate(BaseModel):
    url: str
    domain: str
    label: int
    source: Optional[str] = None


class ContentRiskRequest(BaseModel):
    url: str
    content: Optional[str] = None  # Base64 content
    html: Optional[str] = None
    overlay_text: Optional[str] = None
    overlay_meta: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


class ScamAlert(BaseModel):
    """Structured scam alert data with confidence scoring"""

    is_scam: bool
    confidence: float = Field(..., ge=0, le=100, description="Confidence score 0-100")
    detected_patterns: List[str] = []
    senior_message: str
    action_advice: str


class MediaRisk(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    domain: str
    media_score: float = Field(..., ge=0, le=100)
    media_color: RiskLevel
    reasons: List[str] = []
    image_fake_prob: Optional[float] = None
    video_fake_prob: Optional[float] = None
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scam_alert: Optional[ScamAlert] = None  # Enhanced for scam detection
