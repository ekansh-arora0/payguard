
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
import re
from datetime import datetime

app = FastAPI(title="PayGuard Simple API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

@app.post("/api/media-risk/bytes")
async def analyze_media(payload: dict):
    """Simple scam detection"""
    content = payload.get("content", "")
    
    # Simple text analysis
    scam_patterns = [
        (r'\b1-\d{3}-\d{3}-\d{4}\b', 30, "phone_number"),
        (r'(?i)\b(urgent|immediate|act now)\b', 20, "urgency"),
        (r'(?i)\b(virus|infected|malware)\b', 25, "virus_warning"),
        (r'(?i)\b(suspended|blocked|expired)\b', 15, "account_threat"),
        (r'(?i)do not (close|restart)', 25, "do_not_close"),
    ]
    
    confidence = 0
    detected_patterns = []
    
    # Decode base64 and analyze (simplified)
    try:
        import base64
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        
        for pattern, weight, name in scam_patterns:
            if re.search(pattern, decoded):
                confidence += weight
                detected_patterns.append(name)
    except:
        pass
    
    is_scam = confidence >= 40
    
    scam_alert = None
    if is_scam:
        scam_alert = {
            "is_scam": True,
            "confidence": min(confidence, 100),
            "detected_patterns": detected_patterns,
            "senior_message": "STOP! This appears to be a SCAM.",
            "action_advice": "Close this window immediately."
        }
    
    return {
        "url": "screen://local",
        "domain": "local", 
        "media_score": min(confidence, 100),
        "media_color": "high" if is_scam else "low",
        "reasons": ["Scam detected"] if is_scam else [],
        "scam_alert": scam_alert
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8002, log_level="error")
