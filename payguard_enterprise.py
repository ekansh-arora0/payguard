#!/usr/bin/env python3
"""
PayGuard Enterprise Dashboard & Email Integration
Admin console + Gmail/Outlook API integration
"""

import os
import json
import asyncio
import hashlib
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import base64
import secrets

# Web framework
try:
    from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from pydantic import BaseModel, EmailStr
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

# Email APIs
try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    GOOGLE_API_AVAILABLE = True
except ImportError:
    GOOGLE_API_AVAILABLE = False


# ============== Data Models ==============

class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatAlert:
    id: str
    timestamp: str
    user_email: str
    threat_type: str
    severity: str
    source: str  # email, url, attachment
    indicator: str
    status: str  # pending, reviewed, resolved, false_positive
    details: Dict[str, Any]


@dataclass
class User:
    id: str
    email: str
    name: str
    role: str  # admin, analyst, user
    organization_id: str
    created_at: str
    last_active: str
    settings: Dict[str, Any]


@dataclass 
class Organization:
    id: str
    name: str
    domain: str
    subscription_tier: str  # free, pro, enterprise
    user_count: int
    created_at: str
    settings: Dict[str, Any]


# ============== Database ==============

class EnterpriseDB:
    """SQLite database for enterprise features"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.environ.get(
                'ENTERPRISE_DB_PATH',
                str(Path(__file__).parent / "enterprise" / "payguard_enterprise.db")
            )
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Schema version tracking for migrations
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
        ''')
        
        # Check current version
        cursor.execute('SELECT MAX(version) FROM schema_version')
        current_version = cursor.fetchone()[0] or 0
        
        # Migration 1: Initial schema
        if current_version < 1:
            # Organizations
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    domain TEXT UNIQUE,
                    subscription_tier TEXT DEFAULT 'free',
                    user_count INTEGER DEFAULT 0,
                    created_at TEXT,
                    settings TEXT DEFAULT '{}'
                )
            ''')
            
            # Users
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT,
                    password_hash TEXT,
                    role TEXT DEFAULT 'user',
                    organization_id TEXT,
                    created_at TEXT,
                    last_active TEXT,
                    settings TEXT DEFAULT '{}',
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')
            
            # Alerts
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    user_email TEXT,
                    threat_type TEXT,
                    severity TEXT,
                    source TEXT,
                    indicator TEXT,
                    status TEXT DEFAULT 'pending',
                    details TEXT DEFAULT '{}',
                    organization_id TEXT,
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')
            
            # Email connections
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_connections (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    provider TEXT,  -- gmail, outlook
                    access_token TEXT,
                    refresh_token TEXT,
                    token_expiry TEXT,
                    last_sync TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Audit log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    user_id TEXT,
                    action TEXT,
                    resource TEXT,
                    details TEXT
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts(organization_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id)')
            
            cursor.execute(
                'INSERT INTO schema_version (version, applied_at) VALUES (?, ?)',
                (1, datetime.now().isoformat())
            )
        
        # Future migrations go here:
        # if current_version < 2:
        #     cursor.execute('ALTER TABLE ...')
        #     cursor.execute('INSERT INTO schema_version ...')
        
        conn.commit()
        conn.close()
    
    def create_organization(self, name: str, domain: str) -> str:
        org_id = secrets.token_hex(8)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO organizations (id, name, domain, created_at)
            VALUES (?, ?, ?, ?)
        ''', (org_id, name, domain, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        return org_id
    
    def create_user(self, email: str, name: str, org_id: str, role: str = 'user') -> str:
        user_id = secrets.token_hex(8)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (id, email, name, organization_id, role, created_at, last_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, email, name, org_id, role, datetime.now().isoformat(), datetime.now().isoformat()))
        
        # Update org user count
        cursor.execute('''
            UPDATE organizations SET user_count = user_count + 1 WHERE id = ?
        ''', (org_id,))
        
        conn.commit()
        conn.close()
        return user_id
    
    def add_alert(self, alert: ThreatAlert, org_id: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (id, timestamp, user_email, threat_type, severity, 
                              source, indicator, status, details, organization_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.id, alert.timestamp, alert.user_email, alert.threat_type,
            alert.severity, alert.source, alert.indicator, alert.status,
            json.dumps(alert.details), org_id
        ))
        
        conn.commit()
        conn.close()
    
    def get_alerts(self, org_id: str, status: str = None, limit: int = 100) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status:
            cursor.execute('''
                SELECT * FROM alerts WHERE organization_id = ? AND status = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (org_id, status, limit))
        else:
            cursor.execute('''
                SELECT * FROM alerts WHERE organization_id = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (org_id, limit))
        
        columns = [desc[0] for desc in cursor.description]
        alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        
        return alerts
    
    def get_dashboard_stats(self, org_id: str) -> Dict[str, Any]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total alerts
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE organization_id = ?', (org_id,))
        total_alerts = cursor.fetchone()[0]
        
        # By severity
        cursor.execute('''
            SELECT severity, COUNT(*) FROM alerts 
            WHERE organization_id = ? GROUP BY severity
        ''', (org_id,))
        by_severity = dict(cursor.fetchall())
        
        # By status
        cursor.execute('''
            SELECT status, COUNT(*) FROM alerts 
            WHERE organization_id = ? GROUP BY status
        ''', (org_id,))
        by_status = dict(cursor.fetchall())
        
        # Last 24 hours
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        cursor.execute('''
            SELECT COUNT(*) FROM alerts 
            WHERE organization_id = ? AND timestamp > ?
        ''', (org_id, yesterday))
        last_24h = cursor.fetchone()[0]
        
        # User count
        cursor.execute('SELECT user_count FROM organizations WHERE id = ?', (org_id,))
        user_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_alerts': total_alerts,
            'alerts_last_24h': last_24h,
            'by_severity': by_severity,
            'by_status': by_status,
            'user_count': user_count,
            'protection_score': self._calculate_protection_score(by_status)
        }
    
    def _calculate_protection_score(self, by_status: Dict) -> int:
        total = sum(by_status.values()) or 1
        resolved = by_status.get('resolved', 0) + by_status.get('false_positive', 0)
        return int((resolved / total) * 100)


# ============== Email Integration ==============

class GmailIntegration:
    """Gmail API integration for email scanning"""
    
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    
    def __init__(self, credentials_path: str = None):
        self.credentials_path = credentials_path or os.environ.get(
            'GMAIL_CREDENTIALS_PATH',
            str(Path(__file__).parent / "enterprise" / "gmail_credentials.json")
        )
        self.token_path = os.environ.get(
            'GMAIL_TOKEN_PATH',
            str(Path(__file__).parent / "enterprise" / "gmail_token.json")
        )
        self.service = None
    
    def authenticate(self) -> bool:
        """Authenticate with Gmail API"""
        if not GOOGLE_API_AVAILABLE:
            print("⚠️  Google API libraries not installed")
            print("   Run: pip install google-auth-oauthlib google-api-python-client")
            return False
        
        creds = None
        
        if os.path.exists(self.token_path):
            creds = Credentials.from_authorized_user_file(self.token_path, self.SCOPES)
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(self.credentials_path):
                    print(f"⚠️  Gmail credentials not found at {self.credentials_path}")
                    print("   Download from Google Cloud Console > APIs > Credentials")
                    return False
                
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_path, self.SCOPES)
                creds = flow.run_local_server(port=0)
            
            with open(self.token_path, 'w') as token:
                token.write(creds.to_json())
        
        self.service = build('gmail', 'v1', credentials=creds)
        return True
    
    def scan_recent_emails(self, max_results: int = 50) -> List[Dict]:
        """Scan recent emails for threats"""
        if not self.service:
            if not self.authenticate():
                return []
        
        results = self.service.users().messages().list(
            userId='me', maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])
        threats = []
        
        for msg in messages:
            msg_data = self.service.users().messages().get(
                userId='me', id=msg['id'], format='full'
            ).execute()
            
            threat = self._analyze_email(msg_data)
            if threat:
                threats.append(threat)
        
        return threats
    
    def _analyze_email(self, msg_data: Dict) -> Optional[Dict]:
        """Analyze a single email for threats"""
        headers = {h['name']: h['value'] for h in msg_data['payload'].get('headers', [])}
        
        subject = headers.get('Subject', '')
        sender = headers.get('From', '')
        
        # Get body
        body = self._get_email_body(msg_data['payload'])
        
        # Simple threat detection
        threat_indicators = {
            'urgency': ['urgent', 'immediately', 'action required', 'verify now'],
            'credential': ['password', 'login', 'verify your account', 'confirm your identity'],
            'financial': ['wire transfer', 'bank account', 'send money', 'prize winner'],
            'suspicious_sender': ['@gmail.com impersonating', 'noreply-', 'security-alert-']
        }
        
        detected = []
        text = f"{subject} {body}".lower()
        
        for threat_type, keywords in threat_indicators.items():
            for kw in keywords:
                if kw in text:
                    detected.append(threat_type)
                    break
        
        if detected:
            return {
                'id': msg_data['id'],
                'subject': subject,
                'sender': sender,
                'threats': detected,
                'severity': 'high' if len(detected) > 2 else 'medium',
                'timestamp': datetime.now().isoformat()
            }
        
        return None
    
    def _get_email_body(self, payload: Dict) -> str:
        """Extract email body from payload"""
        if 'body' in payload and payload['body'].get('data'):
            return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    if 'data' in part['body']:
                        return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
        
        return ''


class OutlookIntegration:
    """Microsoft Graph API integration for Outlook scanning"""
    
    def __init__(self, client_id: str = None, client_secret: str = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
    
    def authenticate(self) -> bool:
        """Authenticate with Microsoft Graph API"""
        # Microsoft OAuth flow would go here
        # Requires Azure AD app registration
        print("⚠️  Outlook integration requires Azure AD configuration")
        print("   1. Register app at portal.azure.com")
        print("   2. Add Microsoft Graph > Mail.Read permission")
        print("   3. Set client_id and client_secret")
        return False
    
    def scan_recent_emails(self, max_results: int = 50) -> List[Dict]:
        """Scan Outlook emails for threats"""
        if not self.access_token:
            if not self.authenticate():
                return []
        
        # Would use Microsoft Graph API
        # https://graph.microsoft.com/v1.0/me/messages
        return []


# ============== Mobile Push Notifications ==============

class MobilePushService:
    """Send push notifications to mobile devices"""
    
    def __init__(self):
        self.webhook_urls: Dict[str, str] = {}  # user_id -> webhook
        self.config_path = Path(os.environ.get(
            'PUSH_CONFIG_PATH',
            str(Path(__file__).parent / "enterprise" / "push_config.json")
        ))
        self._load_config()
    
    def _load_config(self):
        if self.config_path.exists():
            with open(self.config_path) as f:
                data = json.load(f)
                self.webhook_urls = data.get('webhooks', {})
    
    def _save_config(self):
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump({'webhooks': self.webhook_urls}, f)
    
    def register_webhook(self, user_id: str, webhook_url: str):
        """Register a webhook for push notifications (Slack, Discord, IFTTT, etc.)"""
        self.webhook_urls[user_id] = webhook_url
        self._save_config()
    
    async def send_alert(self, user_id: str, alert: ThreatAlert) -> bool:
        """Send push notification via webhook"""
        if user_id not in self.webhook_urls:
            return False
        
        webhook_url = self.webhook_urls[user_id]
        
        payload = {
            'text': f"🚨 PayGuard Alert: {alert.threat_type}",
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f"*{alert.severity.upper()} Threat Detected*\n"
                               f"Type: {alert.threat_type}\n"
                               f"Source: {alert.source}\n"
                               f"Time: {alert.timestamp}"
                    }
                }
            ]
        }
        
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    return response.status == 200
        except Exception as e:
            print(f"Push notification failed: {e}")
            return False


# ============== FastAPI Dashboard ==============

if FASTAPI_AVAILABLE:
    app = FastAPI(title="PayGuard Enterprise", version="3.0.0")
    db = EnterpriseDB()
    push_service = MobilePushService()
    security = HTTPBearer(auto_error=False)

    # Simple API token auth for enterprise endpoints
    ENTERPRISE_API_TOKEN = os.environ.get("ENTERPRISE_API_TOKEN", "")

    async def verify_enterprise_token(
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        """Require a valid Bearer token for enterprise API endpoints."""
        if not ENTERPRISE_API_TOKEN:
            raise HTTPException(
                status_code=503,
                detail="Enterprise API token not configured. Set ENTERPRISE_API_TOKEN env var.",
            )
        if not credentials or credentials.credentials != ENTERPRISE_API_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid or missing bearer token")
        return credentials.credentials
    
    # Pydantic models
    class AlertResponse(BaseModel):
        id: str
        timestamp: str
        threat_type: str
        severity: str
        source: str
        status: str
    
    class DashboardStats(BaseModel):
        total_alerts: int
        alerts_last_24h: int
        by_severity: Dict[str, int]
        by_status: Dict[str, int]
        user_count: int
        protection_score: int
    
    class WebhookRegister(BaseModel):
        user_id: str
        webhook_url: str
    
    class CreateAlertRequest(BaseModel):
        user_email: str = ""
        threat_type: str = "unknown"
        severity: str = "medium"
        source: str = "manual"
        indicator: str = ""
        details: Dict[str, Any] = {}
        user_id: Optional[str] = None
    
    # Routes
    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        """Serve dashboard HTML"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>PayGuard Enterprise Dashboard</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; }
                .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
                .header { display: flex; justify-content: space-between; align-items: center; padding: 20px 0; border-bottom: 1px solid #334155; }
                .header h1 { font-size: 24px; display: flex; align-items: center; gap: 10px; }
                .header h1::before { content: '🛡️'; }
                .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 30px 0; }
                .stat-card { background: #1e293b; border-radius: 12px; padding: 24px; }
                .stat-card h3 { color: #94a3b8; font-size: 14px; margin-bottom: 8px; }
                .stat-card .value { font-size: 36px; font-weight: bold; color: #f8fafc; }
                .stat-card.danger .value { color: #ef4444; }
                .stat-card.warning .value { color: #f59e0b; }
                .stat-card.success .value { color: #22c55e; }
                .alerts-section { background: #1e293b; border-radius: 12px; padding: 24px; margin-top: 20px; }
                .alerts-section h2 { margin-bottom: 20px; }
                .alert-item { display: flex; justify-content: space-between; align-items: center; padding: 16px; border-bottom: 1px solid #334155; }
                .alert-item:last-child { border-bottom: none; }
                .alert-severity { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
                .alert-severity.critical { background: #7f1d1d; color: #fca5a5; }
                .alert-severity.high { background: #7c2d12; color: #fdba74; }
                .alert-severity.medium { background: #713f12; color: #fcd34d; }
                .alert-severity.low { background: #14532d; color: #86efac; }
                .badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; }
                .badge.pending { background: #3b82f6; }
                .badge.resolved { background: #22c55e; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>PayGuard Enterprise</h1>
                    <div>Organization: Demo Corp</div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Alerts</h3>
                        <div class="value" id="total-alerts">-</div>
                    </div>
                    <div class="stat-card warning">
                        <h3>Last 24 Hours</h3>
                        <div class="value" id="alerts-24h">-</div>
                    </div>
                    <div class="stat-card danger">
                        <h3>Critical/High</h3>
                        <div class="value" id="critical-alerts">-</div>
                    </div>
                    <div class="stat-card success">
                        <h3>Protection Score</h3>
                        <div class="value" id="protection-score">-</div>
                    </div>
                </div>
                
                <div class="alerts-section">
                    <h2>Recent Alerts</h2>
                    <div id="alerts-list">Loading...</div>
                </div>
            </div>
            
            <script>
                async function loadDashboard() {
                    try {
                        const stats = await fetch('/api/stats/demo').then(r => r.json());
                        document.getElementById('total-alerts').textContent = stats.total_alerts;
                        document.getElementById('alerts-24h').textContent = stats.alerts_last_24h;
                        document.getElementById('critical-alerts').textContent = 
                            (stats.by_severity.critical || 0) + (stats.by_severity.high || 0);
                        document.getElementById('protection-score').textContent = stats.protection_score + '%';
                        
                        const alerts = await fetch('/api/alerts/demo').then(r => r.json());
                        const alertsHtml = alerts.slice(0, 10).map(a => `
                            <div class="alert-item">
                                <div>
                                    <strong>${a.threat_type}</strong>
                                    <div style="color: #94a3b8; font-size: 13px;">${a.source} • ${a.user_email || 'Unknown'}</div>
                                </div>
                                <div style="display: flex; gap: 10px; align-items: center;">
                                    <span class="alert-severity ${a.severity}">${a.severity}</span>
                                    <span class="badge ${a.status}">${a.status}</span>
                                </div>
                            </div>
                        `).join('');
                        document.getElementById('alerts-list').innerHTML = alertsHtml || '<p>No alerts</p>';
                    } catch (e) {
                        console.error('Dashboard error:', e);
                    }
                }
                loadDashboard();
                setInterval(loadDashboard, 30000);
            </script>
        </body>
        </html>
        """
    
    @app.get("/api/stats/{org_id}")
    async def get_stats(org_id: str, _token: str = Depends(verify_enterprise_token)):
        """Get dashboard statistics"""
        return db.get_dashboard_stats(org_id)
    
    @app.get("/api/alerts/{org_id}")
    async def get_alerts(org_id: str, status: str = None, limit: int = 100, _token: str = Depends(verify_enterprise_token)):
        """Get alerts for organization"""
        # Validate limit to prevent abuse
        limit = max(1, min(limit, 1000))
        return db.get_alerts(org_id, status, limit)
    
    @app.post("/api/alerts/{org_id}")
    async def create_alert(org_id: str, alert: CreateAlertRequest, background_tasks: BackgroundTasks, _token: str = Depends(verify_enterprise_token)):
        """Create new alert"""
        threat_alert = ThreatAlert(
            id=secrets.token_hex(8),
            timestamp=datetime.now().isoformat(),
            user_email=alert.user_email,
            threat_type=alert.threat_type,
            severity=alert.severity,
            source=alert.source,
            indicator=alert.indicator,
            status='pending',
            details=alert.details
        )
        
        db.add_alert(threat_alert, org_id)
        
        # Send push notification in background
        if alert.user_id:
            background_tasks.add_task(push_service.send_alert, alert.user_id, threat_alert)
        
        return {'id': threat_alert.id, 'status': 'created'}
    
    @app.post("/api/webhook/register")
    async def register_webhook(data: WebhookRegister, _token: str = Depends(verify_enterprise_token)):
        """Register webhook for push notifications"""
        push_service.register_webhook(data.user_id, data.webhook_url)
        return {'status': 'registered'}
    
    @app.get("/api/health")
    async def health():
        return {'status': 'healthy', 'version': '3.0.0'}


def create_demo_data():
    """Create demo data for testing"""
    db = EnterpriseDB()
    
    # Create demo organization
    org_id = 'demo'
    try:
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO organizations (id, name, domain, subscription_tier, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', ('demo', 'Demo Corporation', 'demo.com', 'enterprise', datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception:
        logging.getLogger(__name__).debug("Failed to create demo org row (may already exist)")
        pass
    
    # Create demo alerts
    threat_types = ['phishing', 'malware', 'scam', 'suspicious_url', 'credential_theft']
    severities = ['low', 'medium', 'high', 'critical']
    sources = ['email', 'url', 'attachment', 'clipboard']
    
    import random
    for i in range(25):
        alert = ThreatAlert(
            id=secrets.token_hex(8),
            timestamp=(datetime.now() - timedelta(hours=random.randint(0, 72))).isoformat(),
            user_email=f"user{random.randint(1,10)}@demo.com",
            threat_type=random.choice(threat_types),
            severity=random.choice(severities),
            source=random.choice(sources),
            indicator=f"https://malicious-{i}.example.com",
            status=random.choice(['pending', 'resolved', 'false_positive']),
            details={'confidence': random.uniform(0.7, 0.99)}
        )
        db.add_alert(alert, 'demo')
    
    print("✓ Demo data created")


def main():
    print("\n" + "="*60)
    print("🛡️ PayGuard Enterprise Dashboard")
    print("="*60)
    
    # Create demo data
    create_demo_data()
    
    if FASTAPI_AVAILABLE:
        print("\n🌐 Starting dashboard server...")
        print("   Dashboard: http://localhost:8003")
        print("   API docs:  http://localhost:8003/docs")
        print("\nPress Ctrl+C to stop\n")
        
        host = os.environ.get("ENTERPRISE_HOST", "127.0.0.1")
        port = int(os.environ.get("ENTERPRISE_PORT", "8003"))
        uvicorn.run(app, host=host, port=port, log_level="info")
    else:
        print("\n⚠️  FastAPI not installed")
        print("   Run: pip install fastapi uvicorn aiohttp")


if __name__ == "__main__":
    main()
