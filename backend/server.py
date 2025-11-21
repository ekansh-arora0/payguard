from fastapi import FastAPI, APIRouter, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timedelta

from models import (
    RiskCheckRequest, RiskScore, RiskLevel,
    Merchant, MerchantCreate,
    FraudReport, FraudReportCreate,
    TransactionCheck, TransactionCheckRequest,
    CustomRule, CustomRuleCreate,
    APIKeyCreate, Stats
)
from risk_engine import RiskScoringEngine
from auth import APIKeyManager, get_api_key

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

# Create router with /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
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
    api_key: Optional[str] = Depends(get_api_key)
):
    """
    Main endpoint to check risk score for a URL.
    This is where the ML model will be plugged in later.
    """
    try:
        # Validate API key if provided (optional for public demo)
        if api_key:
            await api_key_manager.validate_api_key(api_key)
        
        logger.info(f"Checking risk for URL: {request.url}")
        
        # Calculate risk using engine (replace with ML model later)
        risk_score = await risk_engine.calculate_risk(request.url)
        
        # Store the check in database
        await db.risk_checks.insert_one(risk_score.dict())
        
        # Update merchant record
        await _update_merchant_record(risk_score)
        
        return risk_score
        
    except Exception as e:
        logger.error(f"Error checking risk: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Risk check failed: {str(e)}")

@api_router.get("/risk", response_model=RiskScore)
async def get_risk_by_url(
    url: str,
    api_key: Optional[str] = Depends(get_api_key)
):
    """Get risk score for a URL (GET method for browser extensions)"""
    try:
        if api_key:
            await api_key_manager.validate_api_key(api_key)
        
        # Check if we have recent data
        recent_check = await db.risk_checks.find_one(
            {"url": url, "checked_at": {"$gte": datetime.utcnow() - timedelta(hours=24)}},
            sort=[("checked_at", -1)]
        )
        
        if recent_check:
            return RiskScore(**recent_check)
        
        # Calculate new risk score
        risk_score = await risk_engine.calculate_risk(url)
        await db.risk_checks.insert_one(risk_score.dict())
        await _update_merchant_record(risk_score)
        
        return risk_score
        
    except Exception as e:
        logger.error(f"Error getting risk: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# ============= Merchant Management =============

@api_router.get("/merchant/history", response_model=List[Merchant])
async def get_merchant_history(
    domain: Optional[str] = None,
    limit: int = 50,
    api_key: Optional[str] = Depends(get_api_key)
):
    """Get merchant history and reputation data"""
    try:
        if api_key:
            await api_key_manager.validate_api_key(api_key)
        
        query = {"domain": domain} if domain else {}
        merchants = await db.merchants.find(query).limit(limit).to_list(limit)
        
        return [Merchant(**m) for m in merchants]
        
    except Exception as e:
        logger.error(f"Error getting merchant history: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/merchant/{domain}", response_model=Merchant)
async def get_merchant(
    domain: str,
    api_key: Optional[str] = Depends(get_api_key)
):
    """Get specific merchant details"""
    try:
        if api_key:
            await api_key_manager.validate_api_key(api_key)
        
        merchant = await db.merchants.find_one({"domain": domain})
        
        if not merchant:
            raise HTTPException(status_code=404, detail="Merchant not found")
        
        return Merchant(**merchant)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting merchant: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

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
        raise HTTPException(status_code=500, detail=str(e))

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
        raise HTTPException(status_code=500, detail=str(e))

# ============= Fraud Reporting =============

@api_router.post("/fraud/report", response_model=FraudReport)
async def report_fraud(
    report: FraudReportCreate,
    api_key: Optional[str] = Depends(get_api_key)
):
    """Submit a fraud report for a domain"""
    try:
        if api_key:
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
        raise HTTPException(status_code=500, detail=str(e))

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
        raise HTTPException(status_code=500, detail=str(e))

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
        raise HTTPException(status_code=500, detail=str(e))

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
        raise HTTPException(status_code=500, detail=str(e))

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
        raise HTTPException(status_code=500, detail=str(e))

# ============= Statistics =============

@api_router.get("/stats", response_model=Stats)
async def get_stats(api_key: Optional[str] = Depends(get_api_key)):
    """Get platform statistics"""
    try:
        if api_key:
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
        raise HTTPException(status_code=500, detail=str(e))

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

# Include router in app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
