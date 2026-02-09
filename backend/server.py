from fastapi import FastAPI, APIRouter, HTTPException, Depends, Security, UploadFile, File, Request
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timedelta
import time

from .models import (
    RiskCheckRequest, RiskScore, RiskLevel,
    Merchant, MerchantCreate,
    FraudReport, FraudReportCreate,
    TransactionCheck, TransactionCheckRequest,
    CustomRule, CustomRuleCreate,
    APIKeyCreate, Stats, LabelFeedback, LabelFeedbackCreate, ContentRiskRequest,
    MediaRisk, ScamAlert
)
import httpx
from .risk_engine import RiskScoringEngine
from .auth import APIKeyManager, get_api_key, require_api_key

# Maximum request body size: 10 MB
MAX_REQUEST_BODY_SIZE = 10 * 1024 * 1024

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Initialize services
risk_engine = RiskScoringEngine(db)
api_key_manager = APIKeyManager(db)

# Create the main app
app = FastAPI(title="PayGuard API", version="1.0")

# Create router with /api/v1 prefix (versioned API)
api_router = APIRouter(prefix="/api/v1")

# Legacy /api prefix for backwards compatibility
legacy_router = APIRouter(prefix="/api")

# Configure structured logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("LOG_FORMAT", "text")  # "text" or "json"

if LOG_FORMAT == "json":
    import json as _json

    class _JsonFormatter(logging.Formatter):
        def format(self, record):
            return _json.dumps({
                "timestamp": self.formatTime(record),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "module": record.module,
                "line": record.lineno,
            })

    _handler = logging.StreamHandler()
    _handler.setFormatter(_JsonFormatter())
    logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), handlers=[_handler])
else:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
logger = logging.getLogger(__name__)

# ============= Public Endpoints =============

@api_router.get("/")
async def root():
    return {
        "message": "PayGuard API v1.0",
        "status": "operational",
        "endpoints": [
            "/api/risk",
            "/api/media-risk",
            "/api/media-risk-image",
            "/api/merchant/history",
            "/api/transaction/check",
            "/api/institution/custom-rules",
            "/api/stats"
        ]
    }

@api_router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow()}

# ============= Risk Assessment =============

@api_router.post("/risk", response_model=RiskScore)
async def check_risk(
    request: RiskCheckRequest,
    api_key: str = Depends(require_api_key)
):
    """
    Main endpoint to check risk score for a URL.
    This is where the ML model will be plugged in later.
    """
    try:
        t0 = time.time()
        await api_key_manager.validate_api_key(api_key)
        
        logger.info(f"Checking risk for URL: {request.url}")
        
        # Calculate risk using engine with HTML content to power content ML
        html = None
        try:
            async with httpx.AsyncClient(timeout=3.0) as http_client:
                resp = await http_client.get(request.url, headers={"User-Agent": "PayGuard/1.0"}, follow_redirects=True)
                if resp.status_code < 500:
                    html = resp.text[:100000]
        except Exception:
            html = None
        risk_score = await risk_engine.calculate_risk(request.url, content=html)
        # Overlay text scam analysis if provided
        try:
            if request.overlay_text:
                scam_res = risk_engine._analyze_text_for_scam(request.overlay_text)
                if scam_res.get("is_scam"):
                    risk_score.risk_level = RiskLevel.HIGH
                    risk_score.trust_score = max(0.0, min(100.0, min(risk_score.trust_score, 20.0)))
                    reason = f"Scam popup detected (confidence: {int(scam_res.get('confidence', 0))}%)"
                    risk_score.risk_factors.append(reason)
        except Exception:
            pass
        
        await db.risk_checks.insert_one(risk_score.dict())
        await db.metrics.insert_one({
            "endpoint": "POST /api/risk",
            "url": request.url,
            "trust_score": risk_score.trust_score,
            "risk_level": risk_score.risk_level.value,
            "latency_ms": int((time.time() - t0) * 1000),
            "timestamp": datetime.utcnow()
        })
        
        # Update merchant record
        await _update_merchant_record(risk_score)
        
        return risk_score
        
    except Exception as e:
        logger.error(f"Error checking risk: {str(e)}")
        raise HTTPException(status_code=500, detail="Risk check failed")

@api_router.get("/risk", response_model=RiskScore)
async def get_risk_by_url(
    url: str,
    api_key: str = Depends(require_api_key)
):
    """Get risk score for a URL (GET method for browser extensions)"""
    try:
        t0 = time.time()
        await api_key_manager.validate_api_key(api_key)
        
        # Check if we have recent data
        recent_check = await db.risk_checks.find_one(
            {"url": url, "checked_at": {"$gte": datetime.utcnow() - timedelta(hours=24)}},
            sort=[("checked_at", -1)]
        )
        
        if recent_check:
            return RiskScore(**recent_check)
        
        html = None
        try:
            async with httpx.AsyncClient(timeout=3.0) as http_client:
                resp = await http_client.get(url, headers={"User-Agent": "PayGuard/1.0"}, follow_redirects=True)
                if resp.status_code < 500:
                    html = resp.text[:100000]
        except Exception:
            html = None
        risk_score = await risk_engine.calculate_risk(url, content=html)
        await db.risk_checks.insert_one(risk_score.dict())
        await db.metrics.insert_one({
            "endpoint": "GET /api/risk",
            "url": url,
            "trust_score": risk_score.trust_score,
            "risk_level": risk_score.risk_level.value,
            "latency_ms": int((time.time() - t0) * 1000),
            "timestamp": datetime.utcnow()
        })
        await _update_merchant_record(risk_score)
        
        return risk_score
        
    except Exception as e:
        logger.error(f"Error getting risk: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get risk score")

# ============= Merchant Management =============

@api_router.get("/merchant/history", response_model=List[Merchant])
async def get_merchant_history(
    domain: Optional[str] = None,
    limit: int = 50,
    api_key: str = Depends(require_api_key)
):
    """Get merchant history and reputation data"""
    try:
        await api_key_manager.validate_api_key(api_key)
        
        query = {"domain": domain} if domain else {}
        merchants = await db.merchants.find(query).limit(limit).to_list(limit)
        
        return [Merchant(**m) for m in merchants]
        
    except Exception as e:
        logger.error(f"Error getting merchant history: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get merchant history")

@api_router.get("/merchant/{domain}", response_model=Merchant)
async def get_merchant(
    domain: str,
    api_key: str = Depends(require_api_key)
):
    """Get specific merchant details"""
    try:
        await api_key_manager.validate_api_key(api_key)
        
        merchant = await db.merchants.find_one({"domain": domain})
        
        if not merchant:
            raise HTTPException(status_code=404, detail="Merchant not found")
        
        return Merchant(**merchant)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting merchant: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get merchant")

@api_router.post("/merchant", response_model=Merchant)
async def create_merchant(
    merchant: MerchantCreate,
    api_key: str = Depends(get_api_key)
):
    """Create or update merchant record"""
    try:
        await api_key_manager.validate_api_key(api_key)
        
        existing = await db.merchants.find_one({"domain": merchant.domain})
        
        if existing:
            return Merchant(**existing)
        
        merchant_obj = Merchant(**merchant.dict())
        await db.merchants.insert_one(merchant_obj.dict())
        
        return merchant_obj
        
    except Exception as e:
        logger.error(f"Error creating merchant: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create merchant")

# ============= Transaction Checks =============

@api_router.post("/transaction/check", response_model=TransactionCheck)
async def check_transaction(
    request: TransactionCheckRequest,
    api_key: str = Depends(get_api_key)
):
    """Check if a transaction should be approved based on risk"""
    try:
        await api_key_manager.validate_api_key(api_key)
        
        logger.info(f"Checking transaction for merchant: {request.merchant_domain}")
        
        # Get merchant risk
        merchant = await db.merchants.find_one({"domain": request.merchant_domain})
        
        reasons = []
        risk_score = 50.0
        
        if merchant:
            reputation = merchant.get('reputation_score', 50.0)
            risk_score = reputation
            
            if reputation < 30:
                reasons.append("Low merchant reputation")
            if merchant.get('fraud_reports', 0) > 5:
                reasons.append("Multiple fraud reports")
                risk_score -= 20
        else:
            reasons.append("Unknown merchant")
            risk_score -= 15
        
        # Amount-based risk
        if request.amount and request.amount > 1000:
            reasons.append("High transaction amount")
            risk_score -= 10
        
        # Determine risk level
        risk_score = max(0, min(100, risk_score))
        
        if risk_score >= 70:
            risk_level = RiskLevel.LOW
            approved = True
        elif risk_score >= 40:
            risk_level = RiskLevel.MEDIUM
            approved = True
            reasons.append("Proceed with caution")
        else:
            risk_level = RiskLevel.HIGH
            approved = False
            reasons.append("Transaction blocked due to high risk")
        
        transaction = TransactionCheck(
            merchant_domain=request.merchant_domain,
            amount=request.amount,
            currency=request.currency,
            risk_level=risk_level,
            risk_score=risk_score,
            approved=approved,
            reasons=reasons
        )
        
        await db.transaction_checks.insert_one(transaction.dict())
        
        return transaction
        
    except Exception as e:
        logger.error(f"Error checking transaction: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check transaction")

# ============= Fraud Reporting =============

@api_router.post("/fraud/report", response_model=FraudReport)
async def report_fraud(
    report: FraudReportCreate,
    api_key: str = Depends(require_api_key)
):
    """Submit a fraud report for a domain"""
    try:
        await api_key_manager.validate_api_key(api_key)
        
        fraud_report = FraudReport(**report.dict())
        await db.fraud_reports.insert_one(fraud_report.dict())
        
        # Update merchant fraud count
        await db.merchants.update_one(
            {"domain": report.domain},
            {"$inc": {"fraud_reports": 1, "total_reports": 1}},
            upsert=True
        )
        
        logger.info(f"Fraud report submitted for domain: {report.domain}")
        
        return fraud_report
        
    except Exception as e:
        logger.error(f"Error reporting fraud: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to submit fraud report")

@api_router.get("/fraud/reports", response_model=List[FraudReport])
async def get_fraud_reports(
    domain: Optional[str] = None,
    limit: int = 50,
    api_key: str = Depends(get_api_key)
):
    """Get fraud reports"""
    try:
        await api_key_manager.validate_api_key(api_key)
        
        query = {"domain": domain} if domain else {}
        reports = await db.fraud_reports.find(query).limit(limit).to_list(limit)
        
        return [FraudReport(**r) for r in reports]
        
    except Exception as e:
        logger.error(f"Error getting fraud reports: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get fraud reports")

# ============= Custom Rules for Institutions =============

@api_router.post("/institution/custom-rules", response_model=CustomRule)
async def create_custom_rule(
    rule: CustomRuleCreate,
    api_key: str = Depends(get_api_key)
):
    """Create custom risk rules for institutions"""
    try:
        api_key_doc = await api_key_manager.validate_api_key(api_key)
        institution_id = str(api_key_doc.get('_id'))
        
        custom_rule = CustomRule(
            institution_id=institution_id,
            **rule.dict()
        )
        
        await db.custom_rules.insert_one(custom_rule.dict())
        
        logger.info(f"Custom rule created for institution: {institution_id}")
        
        return custom_rule
        
    except Exception as e:
        logger.error(f"Error creating custom rule: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create custom rule")

@api_router.get("/institution/custom-rules", response_model=List[CustomRule])
async def get_custom_rules(
    api_key: str = Depends(get_api_key)
):
    """Get custom rules for the authenticated institution"""
    try:
        api_key_doc = await api_key_manager.validate_api_key(api_key)
        institution_id = str(api_key_doc.get('_id'))
        
        rules = await db.custom_rules.find({"institution_id": institution_id}).to_list(100)
        
        return [CustomRule(**r) for r in rules]
        
    except Exception as e:
        logger.error(f"Error getting custom rules: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get custom rules")

# ============= API Key Management =============

@api_router.post("/api-key/generate")
async def generate_api_key(request: APIKeyCreate):
    """Generate new API key for institutions"""
    try:
        result = await api_key_manager.generate_api_key(
            institution_name=request.institution_name,
            tier=request.tier
        )
        
        logger.info(f"API key generated for: {request.institution_name}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error generating API key: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate API key")

# ============= Media Risk =============
@api_router.get("/media-risk", response_model=MediaRisk)
async def get_media_risk(url: str, force: Optional[bool] = False, api_key: str = Depends(require_api_key)):
    try:
        t0 = time.time()
        await api_key_manager.validate_api_key(api_key)
        recent = await db.media_checks.find_one(
            {"url": url, "checked_at": {"$gte": datetime.utcnow() - timedelta(hours=24)}},
            sort=[("checked_at", -1)]
        )
        if recent and not force:
            return MediaRisk(**recent)
        media = await risk_engine.calculate_media_risk(url)
        await db.media_checks.insert_one(media.dict())
        await db.metrics.insert_one({
            "endpoint": "GET /api/media-risk",
            "url": url,
            "media_score": media.media_score,
            "media_color": media.media_color.value,
            "latency_ms": int((time.time() - t0) * 1000),
            "timestamp": datetime.utcnow()
        })
        return media
    except Exception as e:
        logger.error(f"Error getting media risk: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get media risk")

@api_router.post("/media-risk-image", response_model=MediaRisk)
async def post_media_risk_image(file: UploadFile = File(...), api_key: str = Depends(require_api_key)):
    try:
        t0 = time.time()
        await api_key_manager.validate_api_key(api_key)
        b = await file.read()
        p = risk_engine._predict_image_fake_bytes(b)
        if p is None:
            score = 0.0
            p = 0.0
        else:
            score = float(p) * 100.0
        color = RiskLevel.HIGH if score >= 80 else (RiskLevel.MEDIUM if score >= 60 else RiskLevel.LOW)
        reasons = []
        if p >= 0.8:
            reasons.append("Image appears AI-generated")
        media = MediaRisk(
            url="uploaded",
            domain="local",
            media_score=round(score, 1),
            media_color=color,
            reasons=reasons,
            image_fake_prob=round(score, 1)
        )
        await db.metrics.insert_one({
            "endpoint": "POST /api/media-risk-image",
            "media_score": media.media_score,
            "media_color": media.media_color.value,
            "latency_ms": int((time.time() - t0) * 1000),
            "timestamp": datetime.utcnow()
        })
        return media
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing uploaded image: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process uploaded image")

@api_router.get("/media-risk-screen", response_model=MediaRisk)
async def get_media_risk_screen(api_key: str = Depends(require_api_key)):
    try:
        t0 = time.time()
        await api_key_manager.validate_api_key(api_key)
        b = await risk_engine.capture_screen_bytes()
        if b is None:
            raise HTTPException(status_code=400, detail="Unable to capture screen")
        p = risk_engine._predict_image_fake_bytes(b)
        if p is None:
            raise HTTPException(status_code=400, detail="Unable to process captured image")
        score = float(p) * 100.0
        color = RiskLevel.HIGH if score >= 70 else (RiskLevel.MEDIUM if score >= 40 else RiskLevel.LOW)
        reasons = []
        scam_alert_data = None
        cues = risk_engine._screen_visual_cues(b)
        if cues.get('visual_scam_any'):
            reasons.append(f"Red/Orange/Yellow alert detected (R:{cues.get('red_ratio')} O:{cues.get('orange_ratio')} Y:{cues.get('yellow_ratio')} T:{cues.get('tile_max_ratio')})")
            if color != RiskLevel.HIGH:
                color = RiskLevel.MEDIUM
        
        try:
            # Enhanced scam detection results
            scam_result = risk_engine._screen_text_alerts(b)
            if scam_result.get("is_scam"):
                from .models import ScamAlert
                scam_alert_data = ScamAlert(
                    is_scam=scam_result["is_scam"],
                    confidence=scam_result["confidence"],
                    detected_patterns=scam_result["detected_patterns"],
                    senior_message=scam_result["senior_message"],
                    action_advice=scam_result["action_advice"]
                )
                reasons.append(f"Scam detected (confidence: {scam_result['confidence']}%)")
                color = RiskLevel.HIGH
            else:
                # Visual + key phrase synergy
                patterns = set(scam_result.get("detected_patterns") or [])
                key_hits = bool(patterns.intersection({
                    "virus_warning","scare_tactics","action_demand","payment_request","phone_number","error_code","do_not_close","phishing_attempt","sensitive_input_request"
                }))
                if (cues.get('visual_scam_any') or cues.get('visual_scam_cues')) and key_hits:
                    from .models import ScamAlert
                    conf = max(75, scam_result.get("confidence") or 0)
                    msg = scam_result.get("senior_message") or "STOP! This is a FAKE warning. Your computer is SAFE."
                    adv = scam_result.get("action_advice") or "Close this window immediately. Do NOT call or pay."
                    scam_alert_data = ScamAlert(
                        is_scam=True,
                        confidence=conf,
                        detected_patterns=list(patterns),
                        senior_message=msg,
                        action_advice=adv
                    )
                    reasons.append(f"Scam detected (confidence: {conf}%)")
                    color = RiskLevel.HIGH
        except Exception as e:
            logger.error(f"Scam detection error: {e}")
            pass
        
        media = MediaRisk(
            url="screen://local",
            domain="local",
            media_score=round(score, 1),
            media_color=color,
            reasons=reasons,
            image_fake_prob=round(score, 1),
            scam_alert=scam_alert_data
        )
        await db.metrics.insert_one({
            "endpoint": "GET /api/media-risk-screen",
            "media_score": media.media_score,
            "media_color": media.media_color.value,
            "scam_detected": scam_alert_data is not None,
            "latency_ms": int((time.time() - t0) * 1000),
            "timestamp": datetime.utcnow()
        })
        return media
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error capturing screen: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to capture screen")

@api_router.post("/media-risk/bytes", response_model=MediaRisk)
async def post_media_risk_bytes(
    request: ContentRiskRequest,
    api_key: str = Depends(require_api_key)
):
    """
    Endpoint for agent to send raw image bytes for risk analysis.
    The agent sends base64 encoded bytes in ContentRiskRequest.content.
    """
    try:
        t0 = time.time()
        await api_key_manager.validate_api_key(api_key)
        
        import base64
        try:
            # Handle potential padding issues or header prefixes
            b64_str = request.content
            if not b64_str:
                raise HTTPException(status_code=400, detail="Missing content field")
            if "," in b64_str:
                b64_str = b64_str.split(",")[1]
            b = base64.b64decode(b64_str)
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Base64 decode error: {e}")
            raise HTTPException(status_code=400, detail="Invalid base64 content")

        static = request.metadata.get("static", False) if request.metadata else False
        
        # Call the risk engine to predict image fake probability
        p = risk_engine._predict_image_fake_bytes(b, static=static)
        
        if p is None:
            score = 0.0
            p = 0.0
        else:
            score = float(p) * 100.0
            
        color = RiskLevel.HIGH if score >= 80 else (RiskLevel.MEDIUM if score >= 60 else RiskLevel.LOW)
        reasons = []
        if score >= 80:
            reasons.append("Image appears AI-generated")
        
        scam_alert_data = None
        
        # Check for visual scam cues
        cues = risk_engine._screen_visual_cues(b)
        if cues.get('visual_scam_any'):
            reasons.append(f"Visual scam patterns detected (R:{cues.get('red_ratio')} O:{cues.get('orange_ratio')})")
            if color != RiskLevel.HIGH:
                color = RiskLevel.MEDIUM
        
        # Check for text scam alerts
        try:
            scam_result = risk_engine._screen_text_alerts(b)
            if scam_result.get("is_scam"):
                scam_alert_data = ScamAlert(
                    is_scam=scam_result["is_scam"],
                    confidence=scam_result["confidence"],
                    detected_patterns=scam_result["detected_patterns"],
                    senior_message=scam_result["senior_message"],
                    action_advice=scam_result["action_advice"]
                )
                reasons.append(f"Scam detected (confidence: {scam_result['confidence']}%)")
                color = RiskLevel.HIGH
        except Exception as e:
            logger.error(f"Scam detection error: {e}")
            
        media = MediaRisk(
            url="bytes://local",
            domain="local",
            media_score=round(score, 1),
            media_color=color,
            reasons=reasons,
            image_fake_prob=round(p, 4),
            scam_alert=scam_alert_data
        )
        
        await db.metrics.insert_one({
            "endpoint": "POST /api/media-risk/bytes",
            "media_score": media.media_score,
            "media_color": media.media_color.value,
            "latency_ms": int((time.time() - t0) * 1000),
            "timestamp": datetime.utcnow()
        })
        
        return media
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing media bytes: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process media")

# ============= Statistics =============

@api_router.get("/stats", response_model=Stats)
async def get_stats(api_key: str = Depends(require_api_key)):
    """Get platform statistics"""
    try:
        await api_key_manager.validate_api_key(api_key)
        
        total_checks = await db.risk_checks.count_documents({})
        high_risk_blocked = await db.risk_checks.count_documents({"risk_level": "high"})
        merchants_tracked = await db.merchants.count_documents({})
        fraud_reports = await db.fraud_reports.count_documents({})
        
        # Calculate average trust score
        pipeline = [
            {"$group": {"_id": None, "avg_score": {"$avg": "$trust_score"}}}
        ]
        result = await db.risk_checks.aggregate(pipeline).to_list(1)
        avg_trust_score = result[0]['avg_score'] if result else 0.0
        
        return Stats(
            total_checks=total_checks,
            high_risk_blocked=high_risk_blocked,
            merchants_tracked=merchants_tracked,
            fraud_reports=fraud_reports,
            avg_trust_score=round(avg_trust_score, 1)
        )
        
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get stats")

# ============= Helper Functions =============

async def _update_merchant_record(risk_score: RiskScore):
    """Update or create merchant record based on risk check"""
    try:
        existing = await db.merchants.find_one({"domain": risk_score.domain})
        
        if existing:
            # Update existing merchant
            await db.merchants.update_one(
                {"domain": risk_score.domain},
                {
                    "$set": {
                        "last_checked": datetime.utcnow(),
                        "ssl_valid": risk_score.ssl_valid,
                        "domain_age_days": risk_score.domain_age_days,
                        "payment_gateways": risk_score.detected_gateways
                    },
                    "$inc": {"total_reports": 1}
                }
            )
        else:
            # Create new merchant
            merchant = Merchant(
                domain=risk_score.domain,
                reputation_score=risk_score.trust_score,
                ssl_valid=risk_score.ssl_valid,
                domain_age_days=risk_score.domain_age_days,
                payment_gateways=risk_score.detected_gateways,
                total_reports=1
            )
            await db.merchants.insert_one(merchant.dict())
            
    except Exception as e:
        logger.error(f"Error updating merchant record: {str(e)}")


from .api_gateway import HSTSMiddleware

# Security: Request body size limit middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse as StarletteJSONResponse


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests with bodies exceeding MAX_REQUEST_BODY_SIZE."""

    def __init__(self, app, max_body_size: int = MAX_REQUEST_BODY_SIZE):
        super().__init__(app)
        self.max_body_size = max_body_size

    async def dispatch(self, request: StarletteRequest, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_body_size:
            return StarletteJSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )
        return await call_next(request)


app.add_middleware(RequestSizeLimitMiddleware)

# Security: HSTS headers on all responses
app.add_middleware(HSTSMiddleware)

# CORS: Restrict origins via env var, default to localhost for dev
_allowed_origins = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8002,http://127.0.0.1:8002"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=[o.strip() for o in _allowed_origins],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

@api_router.post("/feedback/label", response_model=LabelFeedback)
async def submit_label_feedback(
    feedback: LabelFeedbackCreate,
    api_key: str = Depends(require_api_key)
):
    try:
        await api_key_manager.validate_api_key(api_key)
        doc = LabelFeedback(**feedback.dict())
        await db.labels_feedback.insert_one(doc.dict())
        return doc
    except Exception as e:
        logger.error(f"Error submitting label feedback: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to submit feedback")
@api_router.post("/risk/content", response_model=RiskScore)
async def check_risk_with_content(
    request: ContentRiskRequest,
    api_key: str = Depends(require_api_key)
):
    try:
        t0 = time.time()
        await api_key_manager.validate_api_key(api_key)
        # short-term cache to stabilize scores for dynamic pages
        recent_check = await db.risk_checks.find_one(
            {"url": request.url, "checked_at": {"$gte": datetime.utcnow() - timedelta(minutes=10)}},
            sort=[("checked_at", -1)]
        )
        if recent_check:
            return RiskScore(**recent_check)
        html = request.html
        if html is None and request.url:
            async with httpx.AsyncClient(timeout=5.0) as http_client:
                resp = await http_client.get(request.url, headers={"User-Agent": "PayGuard/1.0"})
                resp.raise_for_status()
                html = resp.text[:100000]
        risk_score = await risk_engine.calculate_risk(request.url, content=html)
        await db.risk_checks.insert_one(risk_score.dict())
        await db.metrics.insert_one({
            "endpoint": "POST /api/risk/content",
            "url": request.url,
            "trust_score": risk_score.trust_score,
            "risk_level": risk_score.risk_level.value,
            "latency_ms": int((time.time() - t0) * 1000),
            "timestamp": datetime.utcnow()
        })
        await _update_merchant_record(risk_score)
        return risk_score
    except Exception as e:
        logger.error(f"Error checking risk with content: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check content risk")
@api_router.get("/fast-validate")
async def fast_validate(url: str):
    try:
        res = await risk_engine.fast_validate(url)
        return res
    except Exception as e:
        logger.error(f"Error fast validating: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to validate URL")

# Include versioned router
app.include_router(api_router)


# Legacy /api/* redirect → /api/v1/*  (backwards compatibility)
from starlette.responses import RedirectResponse


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"], include_in_schema=False)
async def legacy_api_redirect(path: str, request: Request):
    """Redirect unversioned /api/* requests to /api/v1/*."""
    url = request.url.replace(path=f"/api/v1/{path}")
    return RedirectResponse(url=str(url), status_code=307)
