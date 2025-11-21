from fastapi import HTTPException, Security, Depends
from fastapi.security import APIKeyHeader
from motor.motor_asyncio import AsyncIOMotorDatabase
import secrets
import hashlib
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

class APIKeyManager:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
    
    async def generate_api_key(self, institution_name: str, tier: str = "free") -> dict:
        """Generate a new API key for an institution"""
        # Generate secure random key
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        # Set rate limits based on tier
        daily_limits = {
            "free": 1000,
            "premium": 10000,
            "enterprise": 100000
        }
        
        api_key_doc = {
            "key_hash": key_hash,
            "institution_name": institution_name,
            "tier": tier,
            "requests_count": 0,
            "daily_limit": daily_limits.get(tier, 1000),
            "created_at": datetime.utcnow(),
            "is_active": True,
            "last_reset": datetime.utcnow()
        }
        
        await self.db.api_keys.insert_one(api_key_doc)
        
        return {
            "api_key": raw_key,
            "institution_name": institution_name,
            "tier": tier,
            "daily_limit": api_key_doc["daily_limit"]
        }
    
    async def validate_api_key(self, api_key: str) -> dict:
        """Validate API key and check rate limits"""
        if not api_key:
            raise HTTPException(status_code=401, detail="API key required")
        
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        api_key_doc = await self.db.api_keys.find_one({"key_hash": key_hash})
        
        if not api_key_doc:
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        if not api_key_doc.get("is_active"):
            raise HTTPException(status_code=401, detail="API key is inactive")
        
        # Check if we need to reset daily counter
        last_reset = api_key_doc.get("last_reset", datetime.utcnow())
        if datetime.utcnow() - last_reset > timedelta(days=1):
            await self.db.api_keys.update_one(
                {"key_hash": key_hash},
                {"$set": {"requests_count": 0, "last_reset": datetime.utcnow()}}
            )
            api_key_doc["requests_count"] = 0
        
        # Check rate limit
        if api_key_doc["requests_count"] >= api_key_doc["daily_limit"]:
            raise HTTPException(
                status_code=429, 
                detail=f"Rate limit exceeded. Daily limit: {api_key_doc['daily_limit']}"
            )
        
        # Increment request count
        await self.db.api_keys.update_one(
            {"key_hash": key_hash},
            {"$inc": {"requests_count": 1}}
        )
        
        return api_key_doc

async def get_api_key(api_key: str = Security(api_key_header)):
    """Dependency for API key validation"""
    return api_key
