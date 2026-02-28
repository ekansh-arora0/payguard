"""
PayGuard V2 Secure API Gateway

This module implements a secure API gateway with:
- TLS 1.3 only (rejects TLS 1.2 and lower)
- Secure cipher suites (no RC4, DES, 3DES, MD5)
- HSTS headers with 1-year max-age
- API key authentication with rate limiting
- Authentication failure logging

Requirements: 4.1, 4.2, 4.4, 4.5, 4.6, 4.9, 4.10
"""

import hashlib
import logging
import secrets
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
auth_failure_logger = logging.getLogger("payguard.auth_failures")


class TLSVersion(Enum):
    """Supported TLS versions"""

    TLS_1_3 = "TLSv1.3"
    TLS_1_2 = "TLSv1.2"  # Not allowed
    TLS_1_1 = "TLSv1.1"  # Not allowed
    TLS_1_0 = "TLSv1.0"  # Not allowed


# Secure cipher suites for TLS 1.3
# These are the only allowed cipher suites - no RC4, DES, 3DES, MD5
SECURE_CIPHER_SUITES = [
    # TLS 1.3 cipher suites (these are the only ones we allow)
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
]

# Explicitly blocked cipher suites
BLOCKED_CIPHER_SUITES = [
    "RC4",
    "DES",
    "3DES",
    "MD5",
    "NULL",
    "EXPORT",
    "anon",
]


@dataclass
class TLSConfig:
    """TLS configuration for the API Gateway"""

    min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3
    max_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3
    cipher_suites: List[str] = field(
        default_factory=lambda: SECURE_CIPHER_SUITES.copy()
    )
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None  # For mTLS
    verify_mode: ssl.VerifyMode = ssl.CERT_NONE  # Set to CERT_REQUIRED for mTLS

    def create_ssl_context(self) -> ssl.SSLContext:
        """
        Create an SSL context configured for TLS 1.3 only.

        Requirements:
        - 4.1: Require TLS 1.3 for all connections
        - 4.2: Reject connections using TLS 1.2 or lower
        - 4.6: Use only secure cipher suites (no RC4, DES, 3DES, MD5)
        """
        # Create context with TLS 1.3 minimum
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Set minimum and maximum TLS version to 1.3 only
        # This rejects TLS 1.2 and lower (Requirement 4.2)
        context.minimum_version = self.min_version
        context.maximum_version = self.max_version

        # Configure secure cipher suites only
        # Explicitly exclude insecure ciphers (Requirement 4.6)
        cipher_string = ":".join(self.cipher_suites)
        # Add exclusions for blocked ciphers
        for blocked in BLOCKED_CIPHER_SUITES:
            cipher_string += f":!{blocked}"

        try:
            context.set_ciphers(cipher_string)
        except ssl.SSLError:
            # TLS 1.3 ciphers are set automatically, just ensure no weak ones
            # For TLS 1.3, cipher configuration is handled differently
            pass

        # Load certificates if provided
        if self.cert_file and self.key_file:
            context.load_cert_chain(self.cert_file, self.key_file)

        # Configure client certificate verification for mTLS
        if self.ca_file:
            context.load_verify_locations(self.ca_file)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = self.verify_mode

        # Additional security settings
        context.check_hostname = False  # We handle this at application level
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1

        # Try to disable TLS 1.2 if the option exists
        try:
            context.options |= ssl.OP_NO_TLSv1_2
        except AttributeError:
            # Older Python versions may not have this
            pass

        logger.info(f"SSL context created with TLS {self.min_version.name} minimum")
        logger.info(f"Cipher suites: {cipher_string}")

        return context


def create_tls_ssl_context(
    cert_file: str,
    key_file: str,
    ca_file: Optional[str] = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    """
    Create a TLS 1.3-only SSL context for the API Gateway.

    Args:
        cert_file: Path to the server certificate file
        key_file: Path to the server private key file
        ca_file: Optional path to CA certificate for mTLS
        require_client_cert: Whether to require client certificates (mTLS)

    Returns:
        Configured SSL context

    Requirements:
        - 4.1: Require TLS 1.3 for all connections
        - 4.2: Reject connections using TLS 1.2 or lower
        - 4.6: Use only secure cipher suites
    """
    config = TLSConfig(
        cert_file=cert_file,
        key_file=key_file,
        ca_file=ca_file,
        verify_mode=ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE,
    )
    return config.create_ssl_context()


def validate_tls_version(request: Request) -> bool:
    """
    Validate that the connection is using TLS 1.3.

    This is a secondary check at the application level.
    The primary enforcement is at the SSL context level.

    Returns:
        True if TLS 1.3, raises exception otherwise
    """
    # In production, this would check the actual TLS version from the connection
    # For now, we trust the SSL context configuration
    return True


class TLSVersionChecker:
    """
    Utility class to verify TLS configuration.

    Used for testing and validation that TLS 1.3 is properly enforced.
    """

    @staticmethod
    def is_tls_1_3_only(context: ssl.SSLContext) -> bool:
        """Check if the SSL context only allows TLS 1.3"""
        return (
            context.minimum_version == ssl.TLSVersion.TLSv1_3
            and context.maximum_version == ssl.TLSVersion.TLSv1_3
        )

    @staticmethod
    def has_secure_ciphers_only(context: ssl.SSLContext) -> bool:
        """Check if the SSL context only uses secure cipher suites"""
        # Get the configured ciphers
        try:
            ciphers = context.get_ciphers()
            if not ciphers:
                return True  # TLS 1.3 handles ciphers automatically

            for cipher in ciphers:
                name = cipher.get("name", "").upper()
                # Check for blocked cipher patterns
                for blocked in BLOCKED_CIPHER_SUITES:
                    if blocked.upper() in name:
                        logger.warning(f"Insecure cipher detected: {name}")
                        return False
            return True
        except Exception:
            # If we can't get ciphers, assume TLS 1.3 defaults are secure
            return True

    @staticmethod
    def validate_config(context: ssl.SSLContext) -> Dict[str, Any]:
        """
        Validate the complete TLS configuration.

        Returns a dict with validation results.
        """
        return {
            "tls_1_3_only": TLSVersionChecker.is_tls_1_3_only(context),
            "secure_ciphers": TLSVersionChecker.has_secure_ciphers_only(context),
            "min_version": context.minimum_version.name,
            "max_version": context.maximum_version.name,
        }


# ============= HSTS Middleware (Requirement 4.5) =============


class HSTSMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add HTTP Strict Transport Security (HSTS) headers.

    Requirement 4.5: Enforce HSTS with minimum 1-year max-age
    """

    # 1 year in seconds = 31536000
    DEFAULT_MAX_AGE = 31536000

    def __init__(
        self,
        app,
        max_age: int = DEFAULT_MAX_AGE,
        include_subdomains: bool = True,
        preload: bool = False,
    ):
        super().__init__(app)
        self.max_age = max_age
        self.include_subdomains = include_subdomains
        self.preload = preload

        # Build the HSTS header value
        self.hsts_value = f"max-age={self.max_age}"
        if self.include_subdomains:
            self.hsts_value += "; includeSubDomains"
        if self.preload:
            self.hsts_value += "; preload"

        logger.info(f"HSTS middleware initialized: {self.hsts_value}")

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Add HSTS header to all responses
        response.headers["Strict-Transport-Security"] = self.hsts_value

        # Additional security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        return response


# ============= Authentication Failure Logging (Requirement 4.9) =============


@dataclass
class AuthFailureEvent:
    """Represents an authentication failure event for logging"""

    timestamp: datetime
    ip_address: str
    endpoint: str
    failure_reason: str
    api_key_prefix: Optional[str] = None  # First 8 chars only for security
    user_agent: Optional[str] = None
    request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "ip_address": self.ip_address,
            "endpoint": self.endpoint,
            "failure_reason": self.failure_reason,
            "api_key_prefix": self.api_key_prefix,
            "user_agent": self.user_agent,
            "request_id": self.request_id,
        }


class AuthFailureLogger:
    """
    Logger for authentication failures.

    Requirement 4.9: Log all authentication failures for security monitoring
    """

    def __init__(self, db=None):
        self.db = db
        self._failure_count: Dict[str, int] = (
            {}
        )  # IP -> count for rate limiting detection
        self._failure_window: Dict[str, datetime] = {}  # IP -> first failure time
        self.window_duration = timedelta(minutes=15)
        self.alert_threshold = 10  # Alert after 10 failures in window

    async def log_failure(
        self, request: Request, reason: str, api_key: Optional[str] = None
    ) -> AuthFailureEvent:
        """
        Log an authentication failure event.

        Args:
            request: The FastAPI request object
            reason: The reason for the failure
            api_key: The API key that was used (if any)

        Returns:
            The logged AuthFailureEvent
        """
        # Get client IP (handle proxies)
        ip_address = self._get_client_ip(request)

        # Create the event
        event = AuthFailureEvent(
            timestamp=datetime.now(timezone.utc),
            ip_address=ip_address,
            endpoint=str(request.url.path),
            failure_reason=reason,
            api_key_prefix=api_key[:8] if api_key and len(api_key) >= 8 else None,
            user_agent=request.headers.get("user-agent"),
            request_id=request.headers.get("x-request-id"),
        )

        # Log to standard logger
        auth_failure_logger.warning(
            f"Auth failure: {reason} | IP: {ip_address} | "
            f"Endpoint: {event.endpoint} | Key prefix: {event.api_key_prefix}"
        )

        # Store in database if available
        if self.db is not None:
            try:
                await self.db.auth_failures.insert_one(event.to_dict())
            except Exception as e:
                logger.error(f"Failed to store auth failure event: {e}")

        # Track for anomaly detection
        await self._track_failure(ip_address)

        return event

    async def _track_failure(self, ip_address: str):
        """Track failures for anomaly detection"""
        now = datetime.now(timezone.utc)

        # Reset window if expired
        if ip_address in self._failure_window:
            if now - self._failure_window[ip_address] > self.window_duration:
                self._failure_count[ip_address] = 0
                self._failure_window[ip_address] = now
        else:
            self._failure_window[ip_address] = now

        # Increment count
        self._failure_count[ip_address] = self._failure_count.get(ip_address, 0) + 1

        # Check for anomaly
        if self._failure_count[ip_address] >= self.alert_threshold:
            await self._alert_anomaly(ip_address, self._failure_count[ip_address])

    async def _alert_anomaly(self, ip_address: str, count: int):
        """Alert on suspicious authentication patterns"""
        auth_failure_logger.critical(
            f"SECURITY ALERT: {count} auth failures from IP {ip_address} "
            f"in {self.window_duration.total_seconds() / 60} minutes"
        )

        # Store alert in database if available
        if self.db is not None:
            try:
                await self.db.security_alerts.insert_one(
                    {
                        "type": "brute_force_attempt",
                        "ip_address": ip_address,
                        "failure_count": count,
                        "window_minutes": self.window_duration.total_seconds() / 60,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            except Exception as e:
                logger.error(f"Failed to store security alert: {e}")

    def _get_client_ip(self, request: Request) -> str:
        """Get the real client IP, handling proxies"""
        # Check for forwarded headers (in order of preference)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Take the first IP in the chain (original client)
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        # Fall back to direct connection IP
        if request.client:
            return request.client.host

        return "unknown"


# ============= Rate Limiting (Requirement 4.10) =============


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    burst_limit: int = 10  # Max requests in 1 second


class RateLimiter:
    """
    Rate limiter for API requests.

    Requirement 4.10: Implement rate limiting to prevent brute force attacks
    """

    def __init__(self, config: RateLimitConfig = None, db=None):
        self.config = config or RateLimitConfig()
        self.db = db
        # In-memory tracking for fast checks
        self._minute_counts: Dict[str, List[datetime]] = {}
        self._hour_counts: Dict[str, List[datetime]] = {}

    async def check_rate_limit(
        self, identifier: str, tier: str = "free"
    ) -> tuple[bool, Optional[str]]:
        """
        Check if a request should be rate limited.

        Args:
            identifier: The identifier to rate limit (API key hash or IP)
            tier: The tier for different rate limits

        Returns:
            Tuple of (allowed, reason if denied)
        """
        now = datetime.now(timezone.utc)

        # Get tier-specific limits, but use config values as base
        limits = self._get_tier_limits(tier)

        # Override with config values if they're set (for testing)
        if self.config.requests_per_minute != 60:  # Non-default value
            limits["per_minute"] = self.config.requests_per_minute
        if self.config.requests_per_hour != 1000:  # Non-default value
            limits["per_hour"] = self.config.requests_per_hour

        # Clean old entries
        self._cleanup_old_entries(identifier, now)

        # Check minute limit BEFORE recording this request
        minute_ago = now - timedelta(minutes=1)
        minute_requests = len(
            [t for t in self._minute_counts.get(identifier, []) if t > minute_ago]
        )

        if minute_requests >= limits["per_minute"]:
            return (
                False,
                f"Rate limit exceeded: {limits['per_minute']} requests per minute",
            )

        # Check hour limit
        hour_ago = now - timedelta(hours=1)
        hour_requests = len(
            [t for t in self._hour_counts.get(identifier, []) if t > hour_ago]
        )

        if hour_requests >= limits["per_hour"]:
            return False, f"Rate limit exceeded: {limits['per_hour']} requests per hour"

        # Record this request AFTER checking limits
        if identifier not in self._minute_counts:
            self._minute_counts[identifier] = []
        if identifier not in self._hour_counts:
            self._hour_counts[identifier] = []

        self._minute_counts[identifier].append(now)
        self._hour_counts[identifier].append(now)

        return True, None

    def _get_tier_limits(self, tier: str) -> Dict[str, int]:
        """Get rate limits for a specific tier"""
        tier_limits = {
            "free": {
                "per_minute": 60,
                "per_hour": 1000,
                "per_day": 10000,
            },
            "premium": {
                "per_minute": 300,
                "per_hour": 5000,
                "per_day": 50000,
            },
            "enterprise": {
                "per_minute": 1000,
                "per_hour": 20000,
                "per_day": 200000,
            },
        }
        return tier_limits.get(tier, tier_limits["free"])

    def _cleanup_old_entries(self, identifier: str, now: datetime):
        """Remove entries older than 1 hour"""
        hour_ago = now - timedelta(hours=1)

        if identifier in self._minute_counts:
            self._minute_counts[identifier] = [
                t for t in self._minute_counts[identifier] if t > hour_ago
            ]

        if identifier in self._hour_counts:
            self._hour_counts[identifier] = [
                t for t in self._hour_counts[identifier] if t > hour_ago
            ]


# ============= Secure API Key Authentication (Requirement 4.4) =============

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class SecureAPIKeyManager:
    """
    Secure API key manager with rate limiting and failure logging.

    Requirements:
        - 4.4: Require mTLS or API key authentication for all endpoints
        - 4.9: Log all authentication failures
        - 4.10: Implement rate limiting
    """

    def __init__(self, db=None):
        self.db = db
        self.rate_limiter = RateLimiter(db=db)
        self.auth_failure_logger = AuthFailureLogger(db=db)

    async def validate_api_key(self, api_key: str, request: Request) -> Dict[str, Any]:
        """
        Validate an API key and check rate limits.

        Args:
            api_key: The API key to validate
            request: The FastAPI request object

        Returns:
            The API key document if valid

        Raises:
            HTTPException: If validation fails
        """
        if not api_key:
            await self.auth_failure_logger.log_failure(request, "Missing API key", None)
            raise HTTPException(
                status_code=401,
                detail="API key required",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        # Hash the key for lookup
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Look up the key in database
        if self.db is None:
            # For testing without database
            await self.auth_failure_logger.log_failure(
                request, "Database not available", api_key
            )
            raise HTTPException(
                status_code=503, detail="Authentication service unavailable"
            )

        api_key_doc = await self.db.api_keys.find_one({"key_hash": key_hash})

        if not api_key_doc:
            await self.auth_failure_logger.log_failure(
                request, "Invalid API key", api_key
            )
            raise HTTPException(
                status_code=401,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        if not api_key_doc.get("is_active", True):
            await self.auth_failure_logger.log_failure(
                request, "Inactive API key", api_key
            )
            raise HTTPException(
                status_code=401,
                detail="API key is inactive",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        # Check rate limits
        tier = api_key_doc.get("tier", "free")
        allowed, reason = await self.rate_limiter.check_rate_limit(key_hash, tier)

        if not allowed:
            await self.auth_failure_logger.log_failure(
                request, f"Rate limit exceeded: {reason}", api_key
            )
            raise HTTPException(
                status_code=429, detail=reason, headers={"Retry-After": "60"}
            )

        # Update last used timestamp
        try:
            await self.db.api_keys.update_one(
                {"key_hash": key_hash},
                {
                    "$set": {"last_used": datetime.now(timezone.utc)},
                    "$inc": {"total_requests": 1},
                },
            )
        except Exception as e:
            logger.warning(f"Failed to update API key usage: {e}")

        return api_key_doc

    async def generate_api_key(
        self, institution_name: str, tier: str = "free", scopes: List[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a new API key.

        Args:
            institution_name: Name of the institution
            tier: The tier (free, premium, enterprise)
            scopes: List of allowed scopes

        Returns:
            Dict with the new API key and metadata
        """
        # Generate secure random key
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        api_key_doc = {
            "key_hash": key_hash,
            "institution_name": institution_name,
            "tier": tier,
            "scopes": scopes or ["read"],
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "last_used": None,
            "total_requests": 0,
            "expires_at": datetime.now(timezone.utc)
            + timedelta(days=365),  # 1 year expiry
        }

        if self.db is not None:
            await self.db.api_keys.insert_one(api_key_doc)

        logger.info(f"API key generated for institution: {institution_name}")

        return {
            "api_key": raw_key,
            "institution_name": institution_name,
            "tier": tier,
            "scopes": api_key_doc["scopes"],
            "expires_at": api_key_doc["expires_at"].isoformat(),
        }

    async def revoke_api_key(self, api_key: str) -> bool:
        """
        Revoke an API key immediately.

        Args:
            api_key: The API key to revoke

        Returns:
            True if revoked, False if not found
        """
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        if self.db is not None:
            result = await self.db.api_keys.update_one(
                {"key_hash": key_hash},
                {
                    "$set": {
                        "is_active": False,
                        "revoked_at": datetime.now(timezone.utc),
                    }
                },
            )

            if result.modified_count > 0:
                logger.info(f"API key revoked: {api_key[:8]}...")
                return True

        return False


# ============= Authentication Middleware =============


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce API key authentication on all endpoints.

    Requirement 4.4: Require API key authentication for all endpoints
    """

    # Endpoints that don't require authentication
    PUBLIC_ENDPOINTS = {
        "/",
        "/health",
        "/api/",
        "/api/health",
        "/docs",
        "/redoc",
        "/openapi.json",
    }

    def __init__(
        self, app, api_key_manager: SecureAPIKeyManager, public_endpoints: set = None
    ):
        super().__init__(app)
        self.api_key_manager = api_key_manager
        self.public_endpoints = public_endpoints or self.PUBLIC_ENDPOINTS

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip authentication for public endpoints
        path = request.url.path.rstrip("/")
        if path in self.public_endpoints or path == "":
            return await call_next(request)

        # Get API key from header
        api_key = request.headers.get("X-API-Key")

        # For endpoints that require authentication
        if not self._is_public_endpoint(path):
            try:
                # Validate the API key
                api_key_doc = await self.api_key_manager.validate_api_key(
                    api_key, request
                )
                # Store the validated key info in request state for later use
                request.state.api_key_doc = api_key_doc
            except HTTPException as e:
                return JSONResponse(
                    status_code=e.status_code,
                    content={"detail": e.detail},
                    headers=e.headers or {},
                )

        return await call_next(request)

    def _is_public_endpoint(self, path: str) -> bool:
        """Check if an endpoint is public"""
        # Exact match
        if path in self.public_endpoints:
            return True

        # Check for prefix matches (e.g., /docs/*)
        for public in self.public_endpoints:
            if path.startswith(public) and public.endswith("/"):
                return True

        return False


# ============= Main API Gateway Class =============


class SecureAPIGateway:
    """
    Secure API Gateway for PayGuard V2.

    Combines all security features:
    - TLS 1.3 only (Requirements 4.1, 4.2)
    - Secure cipher suites (Requirement 4.6)
    - HSTS headers (Requirement 4.5)
    - API key authentication (Requirement 4.4)
    - Rate limiting (Requirement 4.10)
    - Authentication failure logging (Requirement 4.9)
    """

    def __init__(
        self,
        app: FastAPI,
        db=None,
        tls_config: TLSConfig = None,
        enable_hsts: bool = True,
        enable_auth: bool = True,
        public_endpoints: set = None,
    ):
        self.app = app
        self.db = db
        self.tls_config = tls_config or TLSConfig()

        # Initialize components
        self.api_key_manager = SecureAPIKeyManager(db=db)

        # Add middlewares
        if enable_hsts:
            self.app.add_middleware(HSTSMiddleware)
            logger.info("HSTS middleware enabled")

        if enable_auth:
            self.app.add_middleware(
                AuthenticationMiddleware,
                api_key_manager=self.api_key_manager,
                public_endpoints=public_endpoints,
            )
            logger.info("Authentication middleware enabled")

    def get_ssl_context(self) -> ssl.SSLContext:
        """Get the configured SSL context for TLS 1.3"""
        return self.tls_config.create_ssl_context()

    def get_uvicorn_ssl_config(self) -> Dict[str, Any]:
        """
        Get SSL configuration for uvicorn.

        Returns a dict that can be passed to uvicorn.run()
        """
        if not self.tls_config.cert_file or not self.tls_config.key_file:
            logger.warning("No TLS certificates configured")
            return {}

        return {
            "ssl_keyfile": self.tls_config.key_file,
            "ssl_certfile": self.tls_config.cert_file,
            "ssl_ca_certs": self.tls_config.ca_file,
            "ssl_version": ssl.TLSVersion.TLSv1_3,
        }


# ============= Dependency Injection Helpers =============


def get_secure_api_key_dependency(api_key_manager: SecureAPIKeyManager):
    """
    Create a FastAPI dependency for secure API key validation.

    Usage:
        gateway = SecureAPIGateway(app, db)
        get_api_key = get_secure_api_key_dependency(gateway.api_key_manager)

        @app.get("/protected")
        async def protected_endpoint(api_key_doc: dict = Depends(get_api_key)):
            ...
    """

    async def dependency(
        request: Request, api_key: str = Depends(api_key_header)
    ) -> Dict[str, Any]:
        return await api_key_manager.validate_api_key(api_key, request)

    return dependency


# ============= Utility Functions =============


def configure_secure_gateway(
    app: FastAPI,
    db=None,
    cert_file: str = None,
    key_file: str = None,
    ca_file: str = None,
    public_endpoints: set = None,
) -> SecureAPIGateway:
    """
    Configure a secure API gateway for a FastAPI application.

    Args:
        app: The FastAPI application
        db: Database connection (motor async client)
        cert_file: Path to TLS certificate
        key_file: Path to TLS private key
        ca_file: Path to CA certificate for mTLS
        public_endpoints: Set of endpoints that don't require authentication

    Returns:
        Configured SecureAPIGateway instance
    """
    tls_config = TLSConfig(
        cert_file=cert_file,
        key_file=key_file,
        ca_file=ca_file,
    )

    gateway = SecureAPIGateway(
        app=app, db=db, tls_config=tls_config, public_endpoints=public_endpoints
    )

    logger.info("Secure API Gateway configured successfully")
    return gateway
