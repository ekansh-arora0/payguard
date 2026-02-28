# PayGuard API Documentation

**Version 2.0.0 | REST API Reference**

This document describes the PayGuard REST API for integrating with the backend services.

---

## Overview

### Base URL

```
Development: http://localhost:5000/api/v1
Production:  https://api.payguard.app/api/v1
```

### Authentication

PayGuard uses JWT (JSON Web Token) authentication.

```http
Authorization: Bearer <token>
```

### Security

- **TLS:** All connections require TLS 1.3 (TLS 1.2 and below rejected)
- **Rate Limiting:** 1000 requests/minute per IP
- **API Key:** Required for production access

---

## Authentication

### Register User

```http
POST /auth/register
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "user_id": "uuid-v4-string",
  "message": "Registration successful"
}
```

### Login

```http
POST /auth/login
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 3600,
  "refresh_token": "refresh-token-string"
}
```

### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json
Authorization: Bearer <refresh_token>
```

**Response:**
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 3600
}
```

---

## URL Reputation

### Check Single URL

```http
POST /url/check
Content-Type: application/json
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "url": "https://example.com/page"
}
```

**Response:**
```json
{
  "success": true,
  "url": "https://example.com/page",
  "risk_score": 15,
  "risk_level": "LOW",
  "threats": [],
  "domain_age_days": 8234,
  "ssl_valid": true,
  "reputation_sources": {
    "google_safe_browsing": "clean",
    "phishtank": "clean",
    "urlhaus": "clean"
  },
  "checked_at": "2026-01-15T12:00:00Z"
}
```

### Bulk URL Check

```http
POST /url/check-bulk
Content-Type: application/json
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "urls": [
    "https://example.com",
    "https://suspicious-site.xyz"
  ]
}
```

**Response:**
```json
{
  "success": true,
  "results": [
    {
      "url": "https://example.com",
      "risk_score": 15,
      "risk_level": "LOW"
    },
    {
      "url": "https://suspicious-site.xyz",
      "risk_score": 85,
      "risk_level": "HIGH",
      "threats": ["phishing", "newly_registered"]
    }
  ]
}
```

---

## Threat Detection

### Analyze Image

Submit a screenshot for scam detection.

```http
POST /analyze/image
Content-Type: application/json
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "image": "base64-encoded-image-data",
  "format": "png"
}
```

**Response:**
```json
{
  "success": true,
  "analysis_id": "uuid-v4-string",
  "risk_score": 75,
  "risk_level": "HIGH",
  "detections": [
    {
      "type": "tech_support_scam",
      "confidence": 0.92,
      "bounding_box": {
        "x": 100,
        "y": 200,
        "width": 400,
        "height": 300
      }
    }
  ],
  "signals": {
    "visual_fingerprint_match": 0.87,
    "text_urgency_score": 0.95,
    "suspicious_phone_numbers": ["+1-800-555-0123"]
  },
  "recommendations": [
    "Do not call displayed phone numbers",
    "Close this browser tab immediately",
    "Run a legitimate antivirus scan"
  ],
  "processed_at": "2026-01-15T12:00:00Z"
}
```

### Analyze Text

Check text content for scam indicators.

```http
POST /analyze/text
Content-Type: application/json
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "text": "URGENT: Your account has been compromised. Call +1-800-555-0123 immediately!",
  "context": "email"
}
```

**Response:**
```json
{
  "success": true,
  "risk_score": 88,
  "risk_level": "HIGH",
  "indicators": [
    {
      "type": "urgency_language",
      "text": "URGENT",
      "confidence": 0.95
    },
    {
      "type": "suspicious_phone",
      "text": "+1-800-555-0123",
      "confidence": 0.90
    }
  ],
  "nlp_analysis": {
    "sentiment": "fear_inducing",
    "intent": "call_to_action",
    "phishing_probability": 0.88
  }
}
```

### Analyze Page Behavior

Check for suspicious page behaviors.

```http
POST /analyze/behavior
Content-Type: application/json
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "behaviors": {
    "fullscreen_attempts": 3,
    "alert_dialogs": 5,
    "keyboard_blocking": true,
    "mouse_traps": true,
    "audio_played": true
  },
  "page_url": "https://suspicious-site.xyz/warning"
}
```

**Response:**
```json
{
  "success": true,
  "risk_score": 95,
  "risk_level": "HIGH",
  "behavioral_flags": [
    "fullscreen_abuse",
    "dialog_spam",
    "input_blocking",
    "audio_scare_tactics"
  ],
  "recommendation": "Close tab immediately. This page is exhibiting malicious behavior patterns."
}
```

---

## Consent Management

### Get Consent Status

```http
GET /consent/status
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "consent": {
    "url_checking": true,
    "page_analysis": true,
    "screen_scanning": false,
    "clipboard_access": false,
    "telemetry": false
  },
  "updated_at": "2026-01-10T08:00:00Z"
}
```

### Update Consent

```http
PUT /consent
Content-Type: application/json
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "url_checking": true,
  "page_analysis": true,
  "screen_scanning": true,
  "clipboard_access": false,
  "telemetry": true
}
```

**Response:**
```json
{
  "success": true,
  "message": "Consent preferences updated",
  "updated_at": "2026-01-15T12:00:00Z"
}
```

---

## Telemetry (Opt-In)

### Submit Telemetry

Only available if user has opted into telemetry.

```http
POST /telemetry
Content-Type: application/json
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "event_type": "detection",
  "data": {
    "threat_type": "tech_support_scam",
    "was_blocked": true,
    "user_feedback": null
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Telemetry received"
}
```

### Submit Feedback

```http
POST /telemetry/feedback
Content-Type: application/json
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "detection_id": "uuid-v4-string",
  "feedback": "false_positive",
  "context": "This is my bank's legitimate website"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Thank you for your feedback"
}
```

---

## User Data

### Export User Data

Download all user data (GDPR compliance).

```http
GET /user/data/export
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "export_url": "https://api.payguard.app/exports/uuid.zip",
  "expires_at": "2026-01-16T12:00:00Z",
  "contents": [
    "consent_history.json",
    "audit_logs.json",
    "settings.json"
  ]
}
```

### Delete User Data

Delete all user data (right to erasure).

```http
DELETE /user/data
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "confirm": true,
  "reason": "No longer using service"
}
```

**Response:**
```json
{
  "success": true,
  "message": "All user data scheduled for deletion",
  "deletion_complete_by": "2026-01-22T12:00:00Z"
}
```

---

## Audit Logs

### Get Audit Logs

```http
GET /audit/logs?start=2026-01-01&end=2026-01-15&limit=100
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "logs": [
    {
      "id": "uuid-v4-string",
      "timestamp": "2026-01-15T11:30:00Z",
      "action": "consent_changed",
      "details": {
        "field": "telemetry",
        "old_value": false,
        "new_value": true
      }
    },
    {
      "id": "uuid-v4-string",
      "timestamp": "2026-01-15T10:00:00Z",
      "action": "detection_triggered",
      "details": {
        "threat_type": "phishing",
        "risk_score": 85
      }
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 100,
    "total": 250,
    "total_pages": 3
  }
}
```

---

## Error Responses

### Standard Error Format

```json
{
  "success": false,
  "error": {
    "code": "INVALID_REQUEST",
    "message": "The request body is malformed",
    "details": {
      "field": "url",
      "issue": "Invalid URL format"
    }
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Malformed request |
| `UNAUTHORIZED` | 401 | Invalid or missing token |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONSENT_REQUIRED` | 403 | User hasn't consented to this feature |
| `RATE_LIMITED` | 429 | Too many requests |
| `SERVER_ERROR` | 500 | Internal server error |

---

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/auth/*` | 10 | 1 minute |
| `/url/check` | 1000 | 1 minute |
| `/url/check-bulk` | 100 | 1 minute |
| `/analyze/*` | 500 | 1 minute |
| `/telemetry` | 1000 | 1 minute |

Rate limit headers:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1705320000
```

---

## WebSocket API

### Real-Time Alerts

Connect to receive real-time threat alerts.

```javascript
const ws = new WebSocket('wss://api.payguard.app/ws/alerts');

ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'auth',
    token: 'your-jwt-token'
  }));
};

ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log('Alert:', alert);
};
```

**Alert Message Format:**
```json
{
  "type": "alert",
  "level": "HIGH",
  "threat_type": "phishing",
  "url": "https://suspicious-site.xyz",
  "risk_score": 90,
  "timestamp": "2026-01-15T12:00:00Z"
}
```

---

## SDK Examples

### JavaScript/TypeScript

```typescript
import PayGuard from '@payguard/sdk';

const client = new PayGuard({
  apiKey: 'your-api-key',
  baseUrl: 'https://api.payguard.app/api/v1'
});

// Check URL
const result = await client.url.check('https://example.com');
console.log(result.risk_score); // 15

// Analyze text
const analysis = await client.analyze.text(
  'URGENT: Your account is compromised!'
);
console.log(analysis.risk_level); // "HIGH"
```

### Python

```python
from payguard import PayGuardClient

client = PayGuardClient(
    api_key="your-api-key",
    base_url="https://api.payguard.app/api/v1"
)

# Check URL
result = client.url.check("https://example.com")
print(result["risk_score"])  # 15

# Analyze text
analysis = client.analyze.text(
    "URGENT: Your account is compromised!"
)
print(analysis["risk_level"])  # "HIGH"
```

### cURL

```bash
# Check URL
curl -X POST https://api.payguard.app/api/v1/url/check \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Analyze text
curl -X POST https://api.payguard.app/api/v1/analyze/text \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"text": "URGENT: Your account is compromised!"}'
```

---

## OpenAPI Specification

Full OpenAPI 3.0 specification available at:
- **Development:** http://localhost:5000/openapi.json
- **Production:** https://api.payguard.app/openapi.json

---

## Changelog

### v2.0.0 (2026-01-15)
- Added consent management endpoints
- Added telemetry opt-in endpoints
- Added behavioral analysis endpoint
- TLS 1.3 required
- JWT authentication improved

### v1.5.0 (2025-09-01)
- Added bulk URL checking
- Added WebSocket alerts
- Improved rate limiting

### v1.0.0 (2025-03-01)
- Initial API release

---

## Support

- **Documentation:** https://payguard.app/docs/api
- **Status Page:** https://status.payguard.app
- **Support:** api-support@payguard.app

---

# Quick Start Guide (Current Implementation)

This section documents the current v1 API implementation (localhost:8002).

## Base URL

```
Development: http://localhost:8002
```

## Authentication

Use API key in header:

```bash
-H "X-API-Key: demo_key"
```

## Quick Endpoints

### Health Check

```bash
curl http://localhost:8002/health
```

### Check URL Risk

```bash
curl -X POST "http://localhost:8002/api/v1/risk" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo_key" \
  -d '{"url": "https://example.com"}'
```

### AI Image Detection

```bash
curl -X POST "http://localhost:8002/api/v1/media-risk/ai-metadata" \
  -H "X-API-Key: demo_key" \
  -F "file=@image.png"
```

### Video Deepfake Detection

```bash
curl -X POST "http://localhost:8002/api/v1/media-risk/video-deepfake" \
  -H "X-API-Key: demo_key" \
  -F "file=@video.mp4"
```

### Audio Deepfake Detection

```bash
curl -X POST "http://localhost:8002/api/v1/media-risk/audio-deepfake" \
  -H "X-API-Key: demo_key" \
  -F "file=@audio.mp3"
```

### Get Stats

```bash
curl http://localhost:8002/api/v1/stats/public
```

## API Docs

Full interactive docs available at: http://localhost:8002/docs
