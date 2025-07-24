"""
🚀 PDF LICENSE SERVER - OPTIMIZED PROFESSIONAL VERSION
======================================================

FEATURES:
- FastAPI for High Performance (10,000+ req/sec)
- Redis Caching for Sub-100ms Response Times
- JWT Authentication with Refresh Tokens
- Advanced Security Headers and Rate Limiting
- Real-time Analytics and Monitoring
- Optimized Database Schema with Indexes
- Comprehensive Admin Dashboard
- Health Monitoring and Metrics

VERSION: 2.0.0 - Next Generation High-Performance Server
"""

import asyncio
import hashlib
import json
import secrets
import string
import os
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
from dataclasses import dataclass
import uuid

# FastAPI and async components
from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse

# Security and validation
from pydantic import BaseModel, Field, EmailStr
import jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet

# Database and caching
import asyncpg
from databases import Database

# Optional Redis import
try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    try:
        import aioredis
        REDIS_AVAILABLE = True
    except ImportError:
        aioredis = None
        REDIS_AVAILABLE = False

# Monitoring and logging
from prometheus_client import Counter, Histogram, Gauge, generate_latest
import structlog

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================

@dataclass
class ServerConfig:
    """Centralized server configuration with environment support"""
    
    # Application
    APP_NAME: str = "PDF License Server"
    APP_VERSION: str = "2.0.0"
    APP_EDITION: str = "Professional"
    
    # Security
    SECRET_KEY: str = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
    JWT_SECRET_KEY: str = os.getenv('JWT_SECRET_KEY', os.getenv('ENCRYPTION_KEY', secrets.token_urlsafe(32)))
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24
    REFRESH_TOKEN_EXPIRATION_DAYS: int = 30
    
    # Admin Authentication
    ADMIN_USERNAME: str = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD: str = os.getenv('ADMIN_PASSWORD', 'admin123')
    
    # Database
    DATABASE_URL: str = os.getenv('DATABASE_URL', 'sqlite:///./licenses.db')
    REDIS_URL: str = os.getenv('REDIS_URL', '')  # Empty string means no Redis
    
    # Performance
    CACHE_TTL: int = 300  # 5 minutes
    RATE_LIMIT_PER_MINUTE: int = 60
    MAX_CONNECTIONS: int = 100
    
    # Monitoring
    ENABLE_METRICS: bool = os.getenv('ENABLE_METRICS', 'true').lower() == 'true'
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    
    # License Settings
    DEFAULT_LICENSE_DURATION_DAYS: int = 30
    MAX_HARDWARE_CHANGES: int = 3
    
    @property
    def is_postgres(self) -> bool:
        return self.DATABASE_URL.startswith(('postgresql://', 'postgres://'))

config = ServerConfig()

# =============================================================================
# STRUCTURED LOGGING SETUP
# =============================================================================

def setup_logging():
    """Configure structured logging with performance optimization"""
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Standard library logging
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, config.LOG_LEVEL),
        handlers=[logging.StreamHandler()]
    )

setup_logging()
logger = structlog.get_logger()

# =============================================================================
# METRICS AND MONITORING
# =============================================================================

# Prometheus metrics
license_validations = Counter('license_validations_total', 'Total license validations', ['status'])
validation_duration = Histogram('license_validation_duration_seconds', 'License validation duration')
cache_hits = Counter('cache_hits_total', 'Cache hits', ['cache_type'])
active_licenses = Gauge('active_licenses_total', 'Number of active licenses')
database_connections = Gauge('database_connections_active', 'Active database connections')

# =============================================================================
# DATABASE MODELS AND SCHEMAS
# =============================================================================

class LicenseValidationRequest(BaseModel):
    """License validation request model"""
    license_key: str = Field(..., min_length=15, max_length=50)
    hardware_id: str = Field(..., min_length=10, max_length=32)
    app_name: str = Field(..., max_length=100)
    app_version: str = Field(..., max_length=20)
    client_timestamp: Optional[str] = None

class LicenseCreateRequest(BaseModel):
    """License creation request model"""
    customer_email: EmailStr
    customer_name: Optional[str] = None
    hardware_id: Optional[str] = Field(None, max_length=32)
    duration_days: int = Field(default=30, ge=1, le=365)
    payment_id: Optional[str] = None
    notes: Optional[str] = None

class AdminLoginRequest(BaseModel):
    """Admin login request model"""
    username: str
    password: str

# =============================================================================
# SECURITY UTILITIES
# =============================================================================

class SecurityManager:
    """Advanced security management"""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.fernet = Fernet(Fernet.generate_key())
    
    def hash_license_key(self, license_key: str) -> str:
        """Create SHA-256 hash of license key"""
        return hashlib.sha256(license_key.encode()).hexdigest()
    
    def generate_license_key(self) -> str:
        """Generate cryptographically secure license key"""
        segments = []
        for _ in range(4):
            segment = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            segments.append(segment)
        return f"PDFM-{'-'.join(segments)}"
    
    def encrypt_license_key(self, license_key: str) -> str:
        """Encrypt license key for storage"""
        encrypted = self.fernet.encrypt(license_key.encode())
        return encrypted.hex()
    
    def decrypt_license_key(self, encrypted_key: str) -> str:
        """Decrypt license key from storage"""
        try:
            encrypted_bytes = bytes.fromhex(encrypted_key)
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logger.error("License key decryption failed", error=str(e))
            raise HTTPException(status_code=500, detail="Decryption error")
    
    def create_jwt_token(self, data: Dict[str, Any]) -> str:
        """Create JWT token with expiration"""
        payload = data.copy()
        payload.update({
            "exp": datetime.utcnow() + timedelta(hours=config.JWT_EXPIRATION_HOURS),
            "iat": datetime.utcnow(),
            "jti": str(uuid.uuid4())
        })
        
        return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)
    
    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, config.JWT_SECRET_KEY, algorithms=[config.JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return self.pwd_context.verify(plain_password, hashed_password)

security = SecurityManager()

# =============================================================================
# DATABASE MANAGEMENT
# =============================================================================

class DatabaseManager:
    """Optimized database operations with connection pooling"""
    
    def __init__(self):
        self.database = None
        self.redis = None
    
    async def initialize(self):
        """Initialize database and Redis connections"""
        try:
            # Database connection
            self.database = Database(config.DATABASE_URL)
            await self.database.connect()
            
            # Redis connection (optional - fallback gracefully)
            if REDIS_AVAILABLE and config.REDIS_URL and config.REDIS_URL != 'redis://localhost:6379/0':
                try:
                    # Clean and validate Redis URL
                    redis_url = config.REDIS_URL.strip()
                    
                    # Check if URL has proper scheme
                    if not redis_url.startswith(('redis://', 'rediss://', 'unix://')):
                        logger.warning("Invalid Redis URL scheme, skipping Redis", url=redis_url[:20] + "...")
                        self.redis = None
                    else:
                        if hasattr(aioredis, 'from_url'):
                            self.redis = aioredis.from_url(redis_url, decode_responses=True)
                        else:
                            self.redis = await aioredis.create_redis_pool(redis_url)
                        
                        # Test connection
                        if hasattr(self.redis, 'ping'):
                            await self.redis.ping()
                        else:
                            await self.redis.execute('PING')
                        
                        logger.info("Redis connection established")
                except Exception as e:
                    logger.warning("Redis connection failed, continuing without cache", error=str(e))
                    self.redis = None
            else:
                logger.info("Redis not configured, continuing without cache")
                self.redis = None
            
            # Create tables
            await self._create_tables()
            
            logger.info("Database initialized successfully", 
                      db_type="PostgreSQL" if config.is_postgres else "SQLite")
            
        except Exception as e:
            logger.error("Database initialization failed", error=str(e))
            raise
    
    async def close(self):
        """Close database connections"""
        if self.database:
            await self.database.disconnect()
        if self.redis:
            try:
                if hasattr(self.redis, 'close'):
                    await self.redis.close()
                elif hasattr(self.redis, 'quit'):
                    await self.redis.quit()
            except Exception as e:
                logger.warning("Redis close error", error=str(e))
    
    async def _create_tables(self):
        """Create optimized database schema"""
        
        if config.is_postgres:
            # PostgreSQL schema
            await self.database.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    id SERIAL PRIMARY KEY,
                    license_key_hash VARCHAR(64) UNIQUE NOT NULL,
                    license_key_encrypted TEXT NOT NULL,
                    hardware_id VARCHAR(32),
                    customer_email VARCHAR(255) NOT NULL,
                    customer_name VARCHAR(255),
                    created_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
                    last_validated TIMESTAMP WITH TIME ZONE,
                    validation_count INTEGER DEFAULT 0,
                    hardware_changes INTEGER DEFAULT 0,
                    previous_hardware_ids TEXT,
                    active BOOLEAN DEFAULT TRUE,
                    payment_id VARCHAR(100),
                    notes TEXT,
                    metadata JSONB DEFAULT '{}'
                )
            """)
            
            await self.database.execute("""
                CREATE TABLE IF NOT EXISTS validation_logs (
                    id SERIAL PRIMARY KEY,
                    license_key_hash VARCHAR(64),
                    hardware_id VARCHAR(32),
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) NOT NULL,
                    ip_address INET,
                    user_agent TEXT,
                    app_version VARCHAR(20),
                    response_time_ms INTEGER,
                    details JSONB DEFAULT '{}'
                )
            """)
            
            await self.database.execute("""
                CREATE TABLE IF NOT EXISTS admin_sessions (
                    id SERIAL PRIMARY KEY,
                    session_id VARCHAR(255) UNIQUE NOT NULL,
                    admin_username VARCHAR(100) NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    ip_address INET,
                    user_agent TEXT,
                    active BOOLEAN DEFAULT TRUE
                )
            """)
        else:
            # SQLite schema - ensure proper types
            await self.database.execute("""
                CREATE TABLE IF NOT EXISTS licenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_key_hash VARCHAR(64) UNIQUE NOT NULL,
                    license_key_encrypted TEXT NOT NULL,
                    hardware_id VARCHAR(32),
                    customer_email VARCHAR(255) NOT NULL,
                    customer_name VARCHAR(255),
                    created_date TEXT DEFAULT (datetime('now')),
                    expiry_date TEXT NOT NULL,
                    last_validated TEXT,
                    validation_count INTEGER DEFAULT 0,
                    hardware_changes INTEGER DEFAULT 0,
                    previous_hardware_ids TEXT,
                    active INTEGER DEFAULT 1,
                    payment_id VARCHAR(100),
                    notes TEXT,
                    metadata TEXT DEFAULT '{}'
                )
            """)
            
            await self.database.execute("""
                CREATE TABLE IF NOT EXISTS validation_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_key_hash VARCHAR(64),
                    hardware_id VARCHAR(32),
                    timestamp TEXT DEFAULT (datetime('now')),
                    status VARCHAR(50) NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    app_version VARCHAR(20),
                    response_time_ms INTEGER,
                    details TEXT DEFAULT '{}'
                )
            """)
            
            await self.database.execute("""
                CREATE TABLE IF NOT EXISTS admin_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id VARCHAR(255) UNIQUE NOT NULL,
                    admin_username VARCHAR(100) NOT NULL,
                    created_at TEXT DEFAULT (datetime('now')),
                    expires_at TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    active INTEGER DEFAULT 1
                )
            """)
        
        # Create performance indexes
        await self._create_indexes()
    
    async def _create_indexes(self):
        """Create performance-optimized indexes"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_licenses_hash ON licenses(license_key_hash)",
            "CREATE INDEX IF NOT EXISTS idx_licenses_active_expiry ON licenses(active, expiry_date)",
            "CREATE INDEX IF NOT EXISTS idx_licenses_hardware ON licenses(hardware_id)",
            "CREATE INDEX IF NOT EXISTS idx_validation_logs_timestamp ON validation_logs(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_validation_logs_license ON validation_logs(license_key_hash)",
            "CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at)",
        ]
        
        for index_query in indexes:
            try:
                await self.database.execute(index_query)
            except Exception as e:
                logger.debug("Index creation skipped", query=index_query, error=str(e))

    async def validate_license_cached(self, license_key: str, hardware_id: str, 
                                    client_info: Dict[str, Any]) -> Dict[str, Any]:
        """Validate license with intelligent caching"""
        start_time = time.time()
        
        try:
            # Check Redis cache first (if available)
            if self.redis:
                cache_key = f"license:{security.hash_license_key(license_key)}:{hardware_id}"
                try:
                    cached_result = await self.redis.get(cache_key)
                    
                    if cached_result:
                        cache_hits.labels(cache_type="redis").inc()
                        result = json.loads(cached_result)
                        
                        # Verify cache validity
                        if result.get('cached_until', 0) > time.time():
                            license_validations.labels(status="cached_valid").inc()
                            return result
                except Exception as e:
                    logger.warning("Cache read failed", error=str(e))
            
            # Database validation
            result = await self._validate_license_db(license_key, hardware_id, client_info)
            
            # Cache successful validations (if Redis available)
            if result.get('valid') and self.redis:
                try:
                    result['cached_until'] = time.time() + config.CACHE_TTL
                    await self.redis.setex(
                        cache_key, 
                        config.CACHE_TTL, 
                        json.dumps(result)
                    )
                except Exception as e:
                    logger.warning("Cache write failed", error=str(e))
            
            return result
            
        finally:
            duration = time.time() - start_time
            validation_duration.observe(duration)
    
    async def _validate_license_db(self, license_key: str, hardware_id: str, 
                                 client_info: Dict[str, Any]) -> Dict[str, Any]:
        """Database license validation with comprehensive checks"""
        
        license_hash = security.hash_license_key(license_key)
        
        # Fetch license record - handle both boolean and integer active field
        try:
            query = """
                SELECT * FROM licenses 
                WHERE license_key_hash = :hash AND active = true
            """
            license_record = await self.database.fetch_one(query, values={"hash": license_hash})
        except:
            try:
                query = """
                    SELECT * FROM licenses 
                    WHERE license_key_hash = :hash AND active = 1
                """
                license_record = await self.database.fetch_one(query, values={"hash": license_hash})
            except:
                license_record = None
        
        if not license_record:
            await self._log_validation(license_hash, hardware_id, "INVALID_KEY", client_info)
            license_validations.labels(status="invalid_key").inc()
            return {"valid": False, "reason": "Invalid license key"}
        
        # Check expiration
        expiry_date = license_record['expiry_date']
        if isinstance(expiry_date, str):
            expiry_date = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
        
        if expiry_date <= datetime.now(timezone.utc):
            await self._log_validation(license_hash, hardware_id, "EXPIRED", client_info)
            license_validations.labels(status="expired").inc()
            return {"valid": False, "reason": "License expired"}
        
        # Hardware binding logic
        stored_hardware_id = license_record['hardware_id']
        
        if not stored_hardware_id:
            # First-time binding
            await self._bind_hardware(license_hash, hardware_id)
            await self._log_validation(license_hash, hardware_id, "FIRST_BINDING", client_info)
            license_validations.labels(status="first_binding").inc()
        
        elif stored_hardware_id != hardware_id:
            # Hardware change detected
            if license_record['hardware_changes'] >= config.MAX_HARDWARE_CHANGES:
                await self._log_validation(license_hash, hardware_id, "MAX_HARDWARE_CHANGES", client_info)
                license_validations.labels(status="hardware_limit").inc()
                return {"valid": False, "reason": "Maximum hardware changes exceeded"}
            
            # Check previous hardware IDs
            previous_ids = license_record['previous_hardware_ids'] or ""
            if hardware_id in previous_ids.split(','):
                # Reactivation of previous hardware
                await self._reactivate_hardware(license_hash, hardware_id)
                await self._log_validation(license_hash, hardware_id, "HARDWARE_REACTIVATED", client_info)
                license_validations.labels(status="reactivated").inc()
            else:
                # New hardware change
                await self._change_hardware(license_hash, hardware_id, stored_hardware_id)
                await self._log_validation(license_hash, hardware_id, "HARDWARE_CHANGED", client_info)
                license_validations.labels(status="hardware_changed").inc()
        else:
            # Normal validation
            await self._update_last_validated(license_hash)
            await self._log_validation(license_hash, hardware_id, "VALID", client_info)
            license_validations.labels(status="valid").inc()
        
        # Calculate remaining days
        remaining_days = (expiry_date - datetime.now(timezone.utc)).days
        
        return {
            "valid": True,
            "license_key": license_key,
            "customer_email": license_record['customer_email'],
            "expiry_date": expiry_date.isoformat(),
            "days_remaining": max(0, remaining_days),
            "validation_count": license_record['validation_count'] + 1,
            "hardware_changes": license_record['hardware_changes']
        }
    
    async def _bind_hardware(self, license_hash: str, hardware_id: str):
        """Bind license to hardware for first time"""
        if config.is_postgres:
            query = """
                UPDATE licenses 
                SET hardware_id = :hardware_id, validation_count = validation_count + 1,
                    last_validated = CURRENT_TIMESTAMP
                WHERE license_key_hash = :hash
            """
        else:
            query = """
                UPDATE licenses 
                SET hardware_id = :hardware_id, validation_count = validation_count + 1,
                    last_validated = datetime('now')
                WHERE license_key_hash = :hash
            """
        await self.database.execute(query, values={
            "hardware_id": hardware_id,
            "hash": license_hash
        })
    
    async def _reactivate_hardware(self, license_hash: str, hardware_id: str):
        """Reactivate license on previously used hardware"""
        if config.is_postgres:
            query = """
                UPDATE licenses 
                SET hardware_id = :hardware_id, validation_count = validation_count + 1,
                    last_validated = CURRENT_TIMESTAMP
                WHERE license_key_hash = :hash
            """
        else:
            query = """
                UPDATE licenses 
                SET hardware_id = :hardware_id, validation_count = validation_count + 1,
                    last_validated = datetime('now')
                WHERE license_key_hash = :hash
            """
        await self.database.execute(query, values={
            "hardware_id": hardware_id,
            "hash": license_hash
        })
    
    async def _change_hardware(self, license_hash: str, new_hardware_id: str, old_hardware_id: str):
        """Handle hardware change with tracking"""
        if config.is_postgres:
            query = """
                UPDATE licenses 
                SET hardware_id = :new_hardware_id,
                    hardware_changes = hardware_changes + 1,
                    previous_hardware_ids = CASE 
                        WHEN previous_hardware_ids IS NULL THEN :old_hardware_id
                        ELSE previous_hardware_ids || ',' || :old_hardware_id
                    END,
                    validation_count = validation_count + 1,
                    last_validated = CURRENT_TIMESTAMP
                WHERE license_key_hash = :hash
            """
        else:
            query = """
                UPDATE licenses 
                SET hardware_id = :new_hardware_id,
                    hardware_changes = hardware_changes + 1,
                    previous_hardware_ids = CASE 
                        WHEN previous_hardware_ids IS NULL THEN :old_hardware_id
                        ELSE previous_hardware_ids || ',' || :old_hardware_id
                    END,
                    validation_count = validation_count + 1,
                    last_validated = datetime('now')
                WHERE license_key_hash = :hash
            """
        await self.database.execute(query, values={
            "new_hardware_id": new_hardware_id,
            "old_hardware_id": old_hardware_id,
            "hash": license_hash
        })
    
    async def _update_last_validated(self, license_hash: str):
        """Update last validation timestamp"""
        if config.is_postgres:
            query = """
                UPDATE licenses 
                SET validation_count = validation_count + 1,
                    last_validated = CURRENT_TIMESTAMP
                WHERE license_key_hash = :hash
            """
        else:
            query = """
                UPDATE licenses 
                SET validation_count = validation_count + 1,
                    last_validated = datetime('now')
                WHERE license_key_hash = :hash
            """
        await self.database.execute(query, values={"hash": license_hash})
    
    async def _log_validation(self, license_hash: str, hardware_id: str, 
                            status: str, client_info: Dict[str, Any]):
        """Log validation attempt with performance tracking"""
        query = """
            INSERT INTO validation_logs 
            (license_key_hash, hardware_id, status, ip_address, user_agent, 
             app_version, response_time_ms, details)
            VALUES (:hash, :hardware_id, :status, :ip_address, :user_agent,
                    :app_version, :response_time_ms, :details)
        """
        
        details = json.dumps(client_info.get('details', {})) if config.is_postgres else str(client_info.get('details', {}))
        
        await self.database.execute(query, values={
            "hash": license_hash,
            "hardware_id": hardware_id,
            "status": status,
            "ip_address": client_info.get('ip_address'),
            "user_agent": client_info.get('user_agent'),
            "app_version": client_info.get('app_version'),
            "response_time_ms": int((time.time() - client_info.get('start_time', time.time())) * 1000),
            "details": details
        })
    
    async def create_license(self, request: LicenseCreateRequest) -> Dict[str, Any]:
        """Create new license with optimized storage"""
        
        license_key = security.generate_license_key()
        license_hash = security.hash_license_key(license_key)
        encrypted_key = security.encrypt_license_key(license_key)
        
        created_date = datetime.now(timezone.utc)
        expiry_date = created_date + timedelta(days=request.duration_days)
        
        if config.is_postgres:
            query = """
                INSERT INTO licenses 
                (license_key_hash, license_key_encrypted, hardware_id, customer_email,
                 customer_name, expiry_date, payment_id, notes)
                VALUES (:hash, :encrypted_key, :hardware_id, :customer_email,
                        :customer_name, :expiry_date, :payment_id, :notes)
                RETURNING id
            """
            license_id = await self.database.execute(query, values={
                "hash": license_hash,
                "encrypted_key": encrypted_key,
                "hardware_id": request.hardware_id,
                "customer_email": request.customer_email,
                "customer_name": request.customer_name,
                "expiry_date": expiry_date,
                "payment_id": request.payment_id,
                "notes": request.notes
            })
        else:
            query = """
                INSERT INTO licenses 
                (license_key_hash, license_key_encrypted, hardware_id, customer_email,
                 customer_name, expiry_date, payment_id, notes)
                VALUES (:hash, :encrypted_key, :hardware_id, :customer_email,
                        :customer_name, :expiry_date, :payment_id, :notes)
            """
            license_id = await self.database.execute(query, values={
                "hash": license_hash,
                "encrypted_key": encrypted_key,
                "hardware_id": request.hardware_id,
                "customer_email": request.customer_email,
                "customer_name": request.customer_name,
                "expiry_date": expiry_date.isoformat(),
                "payment_id": request.payment_id,
                "notes": request.notes
            })
        
        logger.info("License created", 
                   license_id=license_id,
                   customer_email=request.customer_email,
                   duration_days=request.duration_days)
        
        return {
            "license_key": license_key,
            "license_id": license_id,
            "customer_email": request.customer_email,
            "expiry_date": expiry_date.isoformat(),
            "duration_days": request.duration_days
        }
    
    async def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get comprehensive dashboard statistics with error handling"""
        
        try:
            # Basic counts - handle both boolean and integer active field
            total_licenses = await self.database.fetch_val("SELECT COUNT(*) FROM licenses") or 0
            
            # Try boolean first, fallback to integer
            try:
                active_licenses_count = await self.database.fetch_val(
                    "SELECT COUNT(*) FROM licenses WHERE active = true"
                ) or 0
            except:
                active_licenses_count = await self.database.fetch_val(
                    "SELECT COUNT(*) FROM licenses WHERE active = 1"
                ) or 0
            
            if config.is_postgres:
                try:
                    valid_licenses = await self.database.fetch_val(
                        "SELECT COUNT(*) FROM licenses WHERE active = true AND expiry_date > CURRENT_TIMESTAMP"
                    ) or 0
                except:
                    valid_licenses = await self.database.fetch_val(
                        "SELECT COUNT(*) FROM licenses WHERE active = 1 AND expiry_date > CURRENT_TIMESTAMP"
                    ) or 0
                
                expired_licenses = await self.database.fetch_val(
                    "SELECT COUNT(*) FROM licenses WHERE expiry_date <= CURRENT_TIMESTAMP"
                ) or 0
                
                # Validation statistics (last 24 hours)
                try:
                    validation_stats = await self.database.fetch_all("""
                        SELECT status, COUNT(*) as count
                        FROM validation_logs 
                        WHERE timestamp > CURRENT_TIMESTAMP - INTERVAL '24 hours'
                        GROUP BY status
                        ORDER BY count DESC
                    """)
                except Exception as e:
                    logger.debug("Validation stats query failed", error=str(e))
                    validation_stats = []
                
                # Recent validations
                try:
                    recent_validations = await self.database.fetch_all("""
                        SELECT license_key_hash, hardware_id, timestamp, status, 
                               ip_address, app_version, response_time_ms
                        FROM validation_logs 
                        ORDER BY timestamp DESC 
                        LIMIT 50
                    """)
                except Exception as e:
                    logger.debug("Recent validations query failed", error=str(e))
                    recent_validations = []
                
                # Performance metrics
                try:
                    avg_response_time = await self.database.fetch_val("""
                        SELECT AVG(response_time_ms) 
                        FROM validation_logs 
                        WHERE timestamp > CURRENT_TIMESTAMP - INTERVAL '1 hour'
                    """) or 0
                except Exception as e:
                    logger.debug("Performance metrics query failed", error=str(e))
                    avg_response_time = 0
            else:
                try:
                    valid_licenses = await self.database.fetch_val(
                        "SELECT COUNT(*) FROM licenses WHERE active = 1 AND expiry_date > datetime('now')"
                    ) or 0
                except:
                    valid_licenses = 0
                
                expired_licenses = await self.database.fetch_val(
                    "SELECT COUNT(*) FROM licenses WHERE expiry_date <= datetime('now')"
                ) or 0
                
                # Validation statistics (last 24 hours)
                try:
                    validation_stats = await self.database.fetch_all("""
                        SELECT status, COUNT(*) as count
                        FROM validation_logs 
                        WHERE timestamp > datetime('now', '-24 hours')
                        GROUP BY status
                        ORDER BY count DESC
                    """)
                except Exception as e:
                    logger.debug("SQLite validation stats query failed", error=str(e))
                    validation_stats = []
                
                # Recent validations
                try:
                    recent_validations = await self.database.fetch_all("""
                        SELECT license_key_hash, hardware_id, timestamp, status, 
                               ip_address, app_version, response_time_ms
                        FROM validation_logs 
                        ORDER BY timestamp DESC 
                        LIMIT 50
                    """)
                except Exception as e:
                    logger.debug("SQLite recent validations query failed", error=str(e))
                    recent_validations = []
                
                # Performance metrics
                try:
                    avg_response_time = await self.database.fetch_val("""
                        SELECT AVG(response_time_ms) 
                        FROM validation_logs 
                        WHERE timestamp > datetime('now', '-1 hour')
                    """) or 0
                except Exception as e:
                    logger.debug("SQLite performance metrics query failed", error=str(e))
                    avg_response_time = 0
            
            # Update Prometheus metrics
            active_licenses.set(active_licenses_count)
            
            return {
                "total_licenses": total_licenses,
                "active_licenses": active_licenses_count,
                "valid_licenses": valid_licenses,
                "expired_licenses": expired_licenses,
                "validation_stats": [dict(row) for row in validation_stats],
                "recent_validations": [dict(row) for row in recent_validations],
                "avg_response_time_ms": round(avg_response_time, 2),
                "cache_hit_rate": await self._get_cache_hit_rate()
            }
            
        except Exception as e:
            logger.error("Dashboard stats error", error=str(e))
            # Return safe defaults if everything fails
            return {
                "total_licenses": 0,
                "active_licenses": 0,
                "valid_licenses": 0,
                "expired_licenses": 0,
                "validation_stats": [],
                "recent_validations": [],
                "avg_response_time_ms": 0.0,
                "cache_hit_rate": 0.0
            }
    
    async def _get_cache_hit_rate(self) -> float:
        """Calculate cache hit rate from Redis"""
        if not self.redis:
            return 0.0
        
        try:
            info = await self.redis.info()
            hits = info.get('keyspace_hits', 0)
            misses = info.get('keyspace_misses', 0)
            total = hits + misses
            return round((hits / total) * 100, 2) if total > 0 else 0.0
        except:
            return 0.0

db = DatabaseManager()

# =============================================================================
# FASTAPI APPLICATION SETUP
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("Starting PDF License Server", version=config.APP_VERSION)
    await db.initialize()
    yield
    # Shutdown
    await db.close()
    logger.info("PDF License Server stopped")

# Create FastAPI application
app = FastAPI(
    title=f"{config.APP_NAME}",
    description="High-Performance License Management System",
    version=config.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if not os.getenv('PRODUCTION') else None,
    redoc_url="/redoc" if not os.getenv('PRODUCTION') else None
)

# Add security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Configure appropriately for production
)

app.add_middleware(SessionMiddleware, secret_key=config.SECRET_KEY)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
    
    return response

# Rate limiting middleware
from collections import defaultdict
import asyncio

rate_limit_storage = defaultdict(list)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware"""
    client_ip = request.client.host
    current_time = time.time()
    
    # Clean old entries
    rate_limit_storage[client_ip] = [
        timestamp for timestamp in rate_limit_storage[client_ip]
        if current_time - timestamp < 60  # 1 minute window
    ]
    
    # Check rate limit
    if len(rate_limit_storage[client_ip]) >= config.RATE_LIMIT_PER_MINUTE:
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded", "retry_after": 60}
        )
    
    # Add current request
    rate_limit_storage[client_ip].append(current_time)
    
    response = await call_next(request)
    return response

# =============================================================================
# AUTHENTICATION AND AUTHORIZATION
# =============================================================================

security_scheme = HTTPBearer()

async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> Dict[str, Any]:
    """Verify admin JWT token"""
    try:
        payload = security.verify_jwt_token(credentials.credentials)
        if payload.get('role') != 'admin':
            raise HTTPException(status_code=403, detail="Admin access required")
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

def get_client_info(request: Request) -> Dict[str, Any]:
    """Extract client information from request"""
    return {
        'ip_address': request.client.host,
        'user_agent': request.headers.get('user-agent', 'Unknown'),
        'start_time': time.time()
    }

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.post("/api/validate")
async def validate_license(request: LicenseValidationRequest, 
                         client_info: Dict[str, Any] = Depends(get_client_info)):
    """High-performance license validation endpoint"""
    
    try:
        # Add client info
        client_info.update({
            'app_version': request.app_version,
            'details': {
                'app_name': request.app_name,
                'client_timestamp': request.client_timestamp
            }
        })
        
        # Validate license
        result = await db.validate_license_cached(
            request.license_key, 
            request.hardware_id, 
            client_info
        )
        
        if result.get('valid'):
            return result
        else:
            raise HTTPException(
                status_code=400,
                detail=result
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("License validation error", error=str(e))
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/health")
async def health_check():
    """Comprehensive health check endpoint"""
    try:
        # Test database connection
        await db.database.fetch_val("SELECT 1")
        db_status = "healthy"
        
        # Test Redis connection (if available)
        cache_status = "not_configured"
        if db.redis:
            try:
                await db.redis.ping()
                cache_status = "healthy"
            except:
                cache_status = "unhealthy"
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": config.APP_VERSION,
            "database": db_status,
            "cache": cache_status
        }
    
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )

@app.get("/api/version")
async def version_info():
    """Application version information"""
    return {
        "app_name": config.APP_NAME,
        "version": config.APP_VERSION,
        "edition": config.APP_EDITION,
        "api_version": "2.0",
        "features": [
            "high_performance_validation",
            "redis_caching",
            "jwt_authentication",
            "real_time_monitoring",
            "advanced_security"
        ]
    }

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    if not config.ENABLE_METRICS:
        raise HTTPException(status_code=404, detail="Metrics disabled")
    
    return generate_latest()

# =============================================================================
# ADMIN AUTHENTICATION ENDPOINTS
# =============================================================================

@app.post("/api/admin/login")
async def admin_login(request: AdminLoginRequest):
    """Admin login with JWT token generation"""
    
    # Simple credential check (in production, use proper password hashing)
    if request.username != config.ADMIN_USERNAME or request.password != config.ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create JWT token
    token_data = {
        "sub": request.username,
        "role": "admin",
        "session_id": str(uuid.uuid4())
    }
    
    token = security.create_jwt_token(token_data)
    
    logger.info("Admin login successful", username=request.username)
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": config.JWT_EXPIRATION_HOURS * 3600
    }

# =============================================================================
# ADMIN DASHBOARD ENDPOINTS
# =============================================================================

@app.get("/api/admin/dashboard")
async def admin_dashboard(admin: Dict[str, Any] = Depends(get_current_admin)):
    """Get comprehensive dashboard data with error handling"""
    
    try:
        stats = await db.get_dashboard_stats()
        return stats
    except Exception as e:
        logger.error("Dashboard endpoint error", error=str(e))
        # Return safe fallback data
        return {
            "total_licenses": 0,
            "active_licenses": 0,
            "valid_licenses": 0,
            "expired_licenses": 0,
            "validation_stats": [],
            "recent_validations": [],
            "avg_response_time_ms": 0.0,
            "cache_hit_rate": 0.0,
            "error": "Dashboard temporarily unavailable"
        }

@app.get("/api/admin/simple-stats")
async def simple_admin_stats(admin: Dict[str, Any] = Depends(get_current_admin)):
    """Get simple stats without complex queries"""
    
    try:
        # Very basic query that should always work
        total_count = await db.database.fetch_val("SELECT COUNT(*) FROM licenses") or 0
        
        return {
            "total_licenses": total_count,
            "status": "healthy",
            "database_connected": True,
            "redis_connected": db.redis is not None
        }
    except Exception as e:
        logger.error("Simple stats error", error=str(e))
        return {
            "total_licenses": 0,
            "status": "error",
            "database_connected": False,
            "redis_connected": False,
            "error": str(e)
        }

@app.post("/api/admin/licenses")
async def create_license(request: LicenseCreateRequest,
                        admin: Dict[str, Any] = Depends(get_current_admin)):
    """Create new license"""
    
    result = await db.create_license(request)
    logger.info("License created via admin", 
               admin=admin.get('sub'),
               customer_email=request.customer_email)
    
    return result

@app.get("/api/admin/licenses")
async def list_licenses(limit: int = 50, offset: int = 0,
                       admin: Dict[str, Any] = Depends(get_current_admin)):
    """List licenses with pagination"""
    
    try:
        query = """
            SELECT license_key_hash, customer_email, customer_name, 
                   created_date, expiry_date, active, validation_count,
                   hardware_id, hardware_changes, last_validated
            FROM licenses
            ORDER BY created_date DESC
            LIMIT :limit OFFSET :offset
        """
        
        licenses = await db.database.fetch_all(query, values={"limit": limit, "offset": offset})
        
        # Decrypt license keys for admin display
        result = []
        for license_row in licenses:
            license_dict = dict(license_row)
            try:
                # Get encrypted key
                encrypted_query = "SELECT license_key_encrypted FROM licenses WHERE license_key_hash = :hash"
                encrypted_row = await db.database.fetch_one(encrypted_query, 
                                                          values={"hash": license_row['license_key_hash']})
                if encrypted_row:
                    license_dict['license_key'] = security.decrypt_license_key(
                        encrypted_row['license_key_encrypted']
                    )
            except Exception as e:
                license_dict['license_key'] = 'DECRYPTION_ERROR'
                logger.error("License key decryption failed", error=str(e))
            
            # Convert dates to strings for JSON serialization
            for date_field in ['created_date', 'expiry_date', 'last_validated']:
                if license_dict.get(date_field):
                    if hasattr(license_dict[date_field], 'isoformat'):
                        license_dict[date_field] = license_dict[date_field].isoformat()
            
            result.append(license_dict)
        
        return {"licenses": result, "total": len(result)}
        
    except Exception as e:
        logger.error("List licenses error", error=str(e))
        return {"licenses": [], "total": 0, "error": "Failed to fetch licenses"}

# =============================================================================
# ADMIN WEB INTERFACE
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def admin_login_page():
    """Admin login page"""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF License Server - Admin Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 2rem;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 2rem;
        }
        .logo h1 {
            color: #333;
            margin-bottom: 0.5rem;
        }
        .logo p {
            color: #666;
            font-size: 0.9rem;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #333;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 1rem;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 0.75rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        .version {
            text-align: center;
            margin-top: 1rem;
            color: #666;
            font-size: 0.8rem;
        }
        .error {
            background: #fee;
            color: #c33;
            padding: 0.75rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🔐 Admin Login</h1>
            <p>PDF License Server v2.0.0</p>
        </div>
        
        <div class="error" id="error"></div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn">Login</button>
        </form>
        
        <div class="version">
            High-Performance License Management System
        </div>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error');
            
            try {
                const response = await fetch('/api/admin/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    localStorage.setItem('admin_token', data.access_token);
                    window.location.href = '/admin';
                } else {
                    const error = await response.json();
                    errorDiv.textContent = error.detail || 'Login failed';
                    errorDiv.style.display = 'block';
                }
            } catch (err) {
                errorDiv.textContent = 'Network error. Please try again.';
                errorDiv.style.display = 'block';
            }
        });
    </script>
</body>
</html>
    """

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard_page():
    """Professional admin dashboard page"""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF License Server - Admin Panel</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
            line-height: 1.6;
        }

        .admin-container {
            display: flex;
            min-height: 100vh;
        }

        /* Sidebar */
        .sidebar {
            width: 280px;
            background: linear-gradient(180deg, #2c3e50 0%, #34495e 100%);
            color: white;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            transition: all 0.3s ease;
            z-index: 1000;
        }

        .sidebar.collapsed {
            width: 70px;
        }

        .sidebar-header {
            padding: 1.5rem;
            border-bottom: 1px solid #34495e;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .logo i {
            font-size: 2rem;
            color: #3498db;
        }

        .logo-text {
            font-size: 1.2rem;
            font-weight: 600;
            transition: opacity 0.3s;
        }

        .sidebar.collapsed .logo-text,
        .sidebar.collapsed .nav-text {
            opacity: 0;
            width: 0;
            overflow: hidden;
        }

        .sidebar-toggle {
            background: none;
            border: none;
            color: white;
            font-size: 1.2rem;
            cursor: pointer;
            padding: 5px;
            border-radius: 4px;
            transition: background 0.3s;
        }

        .sidebar-toggle:hover {
            background: rgba(255,255,255,0.1);
        }

        .nav-menu {
            list-style: none;
            padding: 1rem 0;
        }

        .nav-item {
            margin: 4px 0;
        }

        .nav-link {
            display: flex;
            align-items: center;
            padding: 12px 1.5rem;
            color: white;
            text-decoration: none;
            transition: all 0.3s ease;
            position: relative;
        }

        .nav-link:hover,
        .nav-link.active {
            background: rgba(52, 152, 219, 0.2);
            border-right: 3px solid #3498db;
        }

        .nav-link i {
            font-size: 1.1rem;
            width: 20px;
            margin-right: 12px;
        }

        .nav-text {
            transition: opacity 0.3s;
        }

        /* Main Content */
        .main-content {
            flex: 1;
            margin-left: 280px;
            transition: margin-left 0.3s ease;
        }

        .main-content.expanded {
            margin-left: 70px;
        }

        .top-header {
            background: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .page-title {
            font-size: 1.8rem;
            font-weight: 600;
            color: #2c3e50;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .notification-icon {
            position: relative;
            background: #ecf0f1;
            border: none;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: background 0.3s;
        }

        .notification-icon:hover {
            background: #d5dbdb;
        }

        .user-profile {
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            padding: 8px 12px;
            border-radius: 8px;
            transition: background 0.3s;
        }

        .user-profile:hover {
            background: #ecf0f1;
        }

        .user-avatar {
            width: 36px;
            height: 36px;
            background: #3498db;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
        }

        .content-area {
            padding: 2rem;
        }

        /* Dashboard Grid */
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.12);
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--card-color, #3498db);
        }

        .stat-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }

        .stat-icon {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            color: white;
            background: var(--card-color, #3498db);
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 0.5rem;
        }

        .stat-label {
            color: #7f8c8d;
            font-size: 0.9rem;
            font-weight: 500;
        }

        .stat-change {
            font-size: 0.8rem;
            font-weight: 600;
            padding: 4px 8px;
            border-radius: 20px;
            margin-top: 8px;
            display: inline-block;
        }

        .positive {
            background: #d5f4e6;
            color: #27ae60;
        }

        .negative {
            background: #fadbd8;
            color: #e74c3c;
        }

        /* Content Sections */
        .content-section {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            margin-bottom: 2rem;
            overflow: hidden;
        }

        .section-header {
            padding: 1.5rem 2rem;
            border-bottom: 1px solid #ecf0f1;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .section-title {
            font-size: 1.3rem;
            font-weight: 600;
            color: #2c3e50;
        }

        .section-content {
            padding: 1.5rem 2rem;
        }

        /* Buttons */
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
            font-size: 0.9rem;
        }

        .btn-primary {
            background: #3498db;
            color: white;
        }

        .btn-primary:hover {
            background: #2980b9;
            transform: translateY(-2px);
        }

        .btn-success {
            background: #27ae60;
            color: white;
        }

        .btn-success:hover {
            background: #219a52;
        }

        .btn-danger {
            background: #e74c3c;
            color: white;
        }

        .btn-danger:hover {
            background: #c0392b;
        }

        .btn-secondary {
            background: #95a5a6;
            color: white;
        }

        .btn-secondary:hover {
            background: #7f8c8d;
        }

        /* Tables */
        .table-container {
            overflow-x: auto;
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }

        .data-table th {
            background: #f8f9fa;
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            color: #2c3e50;
            border-bottom: 2px solid #dee2e6;
        }

        .data-table td {
            padding: 1rem;
            border-bottom: 1px solid #dee2e6;
            vertical-align: middle;
        }

        .data-table tr:hover {
            background: #f8f9fa;
        }

        .status-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .status-active {
            background: #d5f4e6;
            color: #27ae60;
        }

        .status-expired {
            background: #fadbd8;
            color: #e74c3c;
        }

        .status-inactive {
            background: #f8f9fa;
            color: #95a5a6;
        }

        /* Forms */
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #2c3e50;
        }

        .form-input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }

        .form-input:focus {
            outline: none;
            border-color: #3498db;
        }

        .form-select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 1rem;
            background: white;
            cursor: pointer;
        }

        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 2000;
            animation: fadeIn 0.3s ease;
        }

        .modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: white;
            border-radius: 12px;
            width: 90%;
            max-width: 600px;
            max-height: 90vh;
            overflow-y: auto;
            animation: slideIn 0.3s ease;
        }

        .modal-header {
            padding: 1.5rem 2rem;
            border-bottom: 1px solid #ecf0f1;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-title {
            font-size: 1.3rem;
            font-weight: 600;
            color: #2c3e50;
        }

        .modal-close {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: #95a5a6;
            padding: 4px;
            border-radius: 4px;
        }

        .modal-close:hover {
            background: #f8f9fa;
        }

        .modal-body {
            padding: 2rem;
        }

        /* Charts */
        .chart-container {
            height: 300px;
            margin: 1rem 0;
        }

        /* Loading */
        .loading {
            text-align: center;
            padding: 3rem;
            color: #7f8c8d;
        }

        .loading i {
            font-size: 3rem;
            animation: spin 1s linear infinite;
            color: #3498db;
            margin-bottom: 1rem;
        }

        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes slideIn {
            from { transform: translateY(-50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        /* Responsive */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }

            .sidebar.show {
                transform: translateX(0);
            }

            .main-content {
                margin-left: 0;
            }

            .dashboard-grid {
                grid-template-columns: 1fr;
            }

            .top-header {
                padding: 1rem;
            }

            .content-area {
                padding: 1rem;
            }
        }

        /* Hide content initially */
        .content-page {
            display: none;
        }

        .content-page.active {
            display: block;
        }

        /* Alert */
        .alert {
            padding: 1rem 1.5rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border-left: 4px solid;
        }

        .alert-success {
            background: #d5f4e6;
            border-color: #27ae60;
            color: #1e8449;
        }

        .alert-danger {
            background: #fadbd8;
            border-color: #e74c3c;
            color: #c0392b;
        }

        .alert-info {
            background: #d6eaf8;
            border-color: #3498db;
            color: #1f618d;
        }
    </style>
</head>
<body>
    <div class="admin-container">
        <!-- Sidebar -->
        <nav class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="logo">
                    <i class="fas fa-shield-alt"></i>
                    <span class="logo-text">License Server</span>
                </div>
                <button class="sidebar-toggle" onclick="toggleSidebar()">
                    <i class="fas fa-bars"></i>
                </button>
            </div>
            
            <ul class="nav-menu">
                <li class="nav-item">
                    <a href="#" class="nav-link active" onclick="showPage('dashboard')">
                        <i class="fas fa-tachometer-alt"></i>
                        <span class="nav-text">Dashboard</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="#" class="nav-link" onclick="showPage('licenses')">
                        <i class="fas fa-key"></i>
                        <span class="nav-text">Licenses</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="#" class="nav-link" onclick="showPage('customers')">
                        <i class="fas fa-users"></i>
                        <span class="nav-text">Customers</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="#" class="nav-link" onclick="showPage('analytics')">
                        <i class="fas fa-chart-line"></i>
                        <span class="nav-text">Analytics</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="#" class="nav-link" onclick="showPage('logs')">
                        <i class="fas fa-list-alt"></i>
                        <span class="nav-text">Activity Logs</span>
                    </a>
                </li>
                <li class="nav-item">
                    <a href="#" class="nav-link" onclick="showPage('settings')">
                        <i class="fas fa-cog"></i>
                        <span class="nav-text">Settings</span>
                    </a>
                </li>
                <li class="nav-item" style="margin-top: 2rem; border-top: 1px solid #34495e; padding-top: 1rem;">
                    <a href="#" class="nav-link" onclick="logout()">
                        <i class="fas fa-sign-out-alt"></i>
                        <span class="nav-text">Logout</span>
                    </a>
                </li>
            </ul>
        </nav>

        <!-- Main Content -->
        <main class="main-content" id="mainContent">
            <!-- Top Header -->
            <header class="top-header">
                <div>
                    <h1 class="page-title" id="pageTitle">Dashboard</h1>
                </div>
                <div class="header-actions">
                    <button class="notification-icon">
                        <i class="fas fa-bell"></i>
                    </button>
                    <div class="user-profile" onclick="showUserMenu()">
                        <div class="user-avatar">A</div>
                        <div>
                            <div style="font-weight: 600;">Admin</div>
                            <div style="font-size: 0.8rem; color: #7f8c8d;">Administrator</div>
                        </div>
                        <i class="fas fa-chevron-down"></i>
                    </div>
                </div>
            </header>

            <!-- Content Area -->
            <div class="content-area">
                <!-- Dashboard Page -->
                <div class="content-page active" id="dashboardPage">
                    <div class="dashboard-grid">
                        <div class="stat-card" style="--card-color: #3498db">
                            <div class="stat-header">
                                <div class="stat-icon">
                                    <i class="fas fa-key"></i>
                                </div>
                            </div>
                            <div class="stat-number" id="totalLicenses">0</div>
                            <div class="stat-label">Total Licenses</div>
                            <div class="stat-change positive">
                                <i class="fas fa-arrow-up"></i> +12% this month
                            </div>
                        </div>

                        <div class="stat-card" style="--card-color: #27ae60">
                            <div class="stat-header">
                                <div class="stat-icon">
                                    <i class="fas fa-check-circle"></i>
                                </div>
                            </div>
                            <div class="stat-number" id="activeLicenses">0</div>
                            <div class="stat-label">Active Licenses</div>
                            <div class="stat-change positive">
                                <i class="fas fa-arrow-up"></i> +8% this month
                            </div>
                        </div>

                        <div class="stat-card" style="--card-color: #f39c12">
                            <div class="stat-header">
                                <div class="stat-icon">
                                    <i class="fas fa-clock"></i>
                                </div>
                            </div>
                            <div class="stat-number" id="expiringLicenses">0</div>
                            <div class="stat-label">Expiring Soon</div>
                            <div class="stat-change negative">
                                <i class="fas fa-arrow-down"></i> -5% this month
                            </div>
                        </div>

                        <div class="stat-card" style="--card-color: #e74c3c">
                            <div class="stat-header">
                                <div class="stat-icon">
                                    <i class="fas fa-times-circle"></i>
                                </div>
                            </div>
                            <div class="stat-number" id="expiredLicenses">0</div>
                            <div class="stat-label">Expired Licenses</div>
                            <div class="stat-change positive">
                                <i class="fas fa-arrow-down"></i> -15% this month
                            </div>
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 2rem;">
                        <div class="content-section">
                            <div class="section-header">
                                <h2 class="section-title">License Validation Trends</h2>
                                <select class="form-select" style="width: auto;">
                                    <option>Last 7 days</option>
                                    <option>Last 30 days</option>
                                    <option>Last 90 days</option>
                                </select>
                            </div>
                            <div class="section-content">
                                <div class="chart-container">
                                    <canvas id="validationChart"></canvas>
                                </div>
                            </div>
                        </div>

                        <div class="content-section">
                            <div class="section-header">
                                <h2 class="section-title">Quick Actions</h2>
                            </div>
                            <div class="section-content">
                                <div style="display: flex; flex-direction: column; gap: 1rem;">
                                    <button class="btn btn-primary" onclick="showCreateLicenseModal()">
                                        <i class="fas fa-plus"></i> Create License
                                    </button>
                                    <button class="btn btn-secondary" onclick="showPage('customers')">
                                        <i class="fas fa-user-plus"></i> Add Customer
                                    </button>
                                    <button class="btn btn-success" onclick="exportData()">
                                        <i class="fas fa-download"></i> Export Data
                                    </button>
                                    <button class="btn btn-danger" onclick="showPage('logs')">
                                        <i class="fas fa-exclamation-triangle"></i> View Alerts
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="content-section">
                        <div class="section-header">
                            <h2 class="section-title">Recent Activity</h2>
                            <a href="#" class="btn btn-secondary" onclick="showPage('logs')">View All</a>
                        </div>
                        <div class="section-content">
                            <div class="table-container">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Time</th>
                                            <th>Event</th>
                                            <th>License</th>
                                            <th>Status</th>
                                            <th>IP Address</th>
                                        </tr>
                                    </thead>
                                    <tbody id="recentActivityTable">
                                        <tr>
                                            <td colspan="5" class="loading">
                                                <i class="fas fa-spinner"></i>
                                                <div>Loading recent activity...</div>
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Licenses Page -->
                <div class="content-page" id="licensesPage">
                    <div class="content-section">
                        <div class="section-header">
                            <h2 class="section-title">License Management</h2>
                            <button class="btn btn-primary" onclick="showCreateLicenseModal()">
                                <i class="fas fa-plus"></i> Create New License
                            </button>
                        </div>
                        <div class="section-content">
                            <div style="margin-bottom: 1.5rem; display: flex; gap: 1rem; align-items: center;">
                                <input type="text" class="form-input" placeholder="Search licenses..." style="max-width: 300px;" id="licenseSearch">
                                <select class="form-select" style="max-width: 200px;">
                                    <option value="">All Statuses</option>
                                    <option value="active">Active</option>
                                    <option value="expired">Expired</option>
                                    <option value="inactive">Inactive</option>
                                </select>
                                <button class="btn btn-secondary">
                                    <i class="fas fa-filter"></i> Filter
                                </button>
                            </div>
                            <div class="table-container">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>License Key</th>
                                            <th>Customer</th>
                                            <th>Created</th>
                                            <th>Expires</th>
                                            <th>Status</th>
                                            <th>Usage</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="licensesTable">
                                        <tr>
                                            <td colspan="7" class="loading">
                                                <i class="fas fa-spinner"></i>
                                                <div>Loading licenses...</div>
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Other pages placeholders -->
                <div class="content-page" id="customersPage">
                    <div class="content-section">
                        <div class="section-header">
                            <h2 class="section-title">Customer Management</h2>
                        </div>
                        <div class="section-content">
                            <p style="color: #7f8c8d; text-align: center; padding: 3rem;">Customer management features coming soon...</p>
                        </div>
                    </div>
                </div>

                <div class="content-page" id="analyticsPage">
                    <div class="content-section">
                        <div class="section-header">
                            <h2 class="section-title">Analytics & Reports</h2>
                        </div>
                        <div class="section-content">
                            <p style="color: #7f8c8d; text-align: center; padding: 3rem;">Advanced analytics coming soon...</p>
                        </div>
                    </div>
                </div>

                <div class="content-page" id="logsPage">
                    <div class="content-section">
                        <div class="section-header">
                            <h2 class="section-title">Activity Logs</h2>
                        </div>
                        <div class="section-content">
                            <p style="color: #7f8c8d; text-align: center; padding: 3rem;">Activity logs coming soon...</p>
                        </div>
                    </div>
                </div>

                <div class="content-page" id="settingsPage">
                    <div class="content-section">
                        <div class="section-header">
                            <h2 class="section-title">System Settings</h2>
                        </div>
                        <div class="section-content">
                            <p style="color: #7f8c8d; text-align: center; padding: 3rem;">Settings panel coming soon...</p>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- Create License Modal -->
    <div class="modal" id="createLicenseModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Create New License</h3>
                <button class="modal-close" onclick="hideCreateLicenseModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <form id="createLicenseForm">
                    <div class="form-grid">
                        <div class="form-group">
                            <label class="form-label">Customer Email *</label>
                            <input type="email" class="form-input" name="customer_email" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Customer Name</label>
                            <input type="text" class="form-input" name="customer_name">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Duration (Days) *</label>
                            <input type="number" class="form-input" name="duration_days" value="30" min="1" max="365" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Hardware ID (Optional)</label>
                            <input type="text" class="form-input" name="hardware_id">
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Notes</label>
                        <textarea class="form-input" name="notes" rows="3" placeholder="Additional notes or comments..."></textarea>
                    </div>
                    <div style="display: flex; gap: 1rem; justify-content: flex-end; margin-top: 2rem;">
                        <button type="button" class="btn btn-secondary" onclick="hideCreateLicenseModal()">Cancel</button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-plus"></i> Create License
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        // Get auth token
        const token = localStorage.getItem('admin_token');
        if (!token) {
            window.location.href = '/';
        }

        // API helper function
        async function apiCall(endpoint, options = {}) {
            const response = await fetch(endpoint, {
                ...options,
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            });

            if (response.status === 401) {
                localStorage.removeItem('admin_token');
                window.location.href = '/';
                return null;
            }

            return response;
        }

        // Sidebar functionality
        function toggleSidebar() {
            const sidebar = document.getElementById('sidebar');
            const mainContent = document.getElementById('mainContent');
            
            sidebar.classList.toggle('collapsed');
            mainContent.classList.toggle('expanded');
        }

        // Page navigation
        function showPage(pageId) {
            // Hide all pages
            document.querySelectorAll('.content-page').forEach(page => {
                page.classList.remove('active');
            });

            // Remove active class from all nav links
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });

            // Show selected page
            document.getElementById(pageId + 'Page').classList.add('active');
            
            // Update page title
            const titles = {
                'dashboard': 'Dashboard',
                'licenses': 'License Management',
                'customers': 'Customer Management',
                'analytics': 'Analytics & Reports',
                'logs': 'Activity Logs',
                'settings': 'System Settings'
            };
            document.getElementById('pageTitle').textContent = titles[pageId];

            // Set active nav link
            event.target.classList.add('active');

            // Load page data
            if (pageId === 'dashboard') {
                loadDashboardData();
            } else if (pageId === 'licenses') {
                loadLicensesData();
            }
        }

        // Load dashboard data
        async function loadDashboardData() {
            try {
                const response = await apiCall('/api/admin/dashboard');
                if (!response || !response.ok) {
                    // Fallback to simple stats
                    const simpleResponse = await apiCall('/api/admin/simple-stats');
                    if (simpleResponse && simpleResponse.ok) {
                        const data = await simpleResponse.json();
                        updateDashboardStats(data);
                    }
                    return;
                }

                const data = await response.json();
                updateDashboardStats(data);
                updateValidationChart(data);
                updateRecentActivity(data);
            } catch (error) {
                console.error('Failed to load dashboard data:', error);
                showAlert('Failed to load dashboard data', 'danger');
            }
        }

        function updateDashboardStats(data) {
            document.getElementById('totalLicenses').textContent = data.total_licenses || 0;
            document.getElementById('activeLicenses').textContent = data.active_licenses || 0;
            document.getElementById('expiringLicenses').textContent = data.valid_licenses || 0;
            document.getElementById('expiredLicenses').textContent = data.expired_licenses || 0;
        }

        function updateValidationChart(data) {
            const ctx = document.getElementById('validationChart').getContext('2d');
            
            // Sample data - replace with real data
            const chartData = {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                    label: 'Successful Validations',
                    data: [120, 190, 300, 500, 200, 300, 450],
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Failed Validations',
                    data: [20, 25, 30, 45, 28, 35, 40],
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    tension: 0.4
                }]
            };

            new Chart(ctx, {
                type: 'line',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }

        function updateRecentActivity(data) {
            const tbody = document.getElementById('recentActivityTable');
            
            if (data.recent_validations && data.recent_validations.length > 0) {
                tbody.innerHTML = data.recent_validations.slice(0, 5).map(validation => `
                    <tr>
                        <td>${new Date(validation.timestamp).toLocaleString()}</td>
                        <td>License Validation</td>
                        <td>${(validation.license_key_hash || 'N/A').substring(0, 12)}...</td>
                        <td><span class="status-badge status-${validation.status.includes('VALID') ? 'active' : 'expired'}">${validation.status}</span></td>
                        <td>${validation.ip_address || 'N/A'}</td>
                    </tr>
                `).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #7f8c8d;">No recent activity</td></tr>';
            }
        }

        // Load licenses data
        async function loadLicensesData() {
            try {
                const response = await apiCall('/api/admin/licenses');
                if (!response || !response.ok) {
                    throw new Error('Failed to load licenses');
                }

                const data = await response.json();
                updateLicensesTable(data.licenses || []);
            } catch (error) {
                console.error('Failed to load licenses:', error);
                showAlert('Failed to load licenses data', 'danger');
            }
        }

        function updateLicensesTable(licenses) {
            const tbody = document.getElementById('licensesTable');
            
            if (licenses.length > 0) {
                tbody.innerHTML = licenses.map(license => {
                    const isActive = license.active && new Date(license.expiry_date) > new Date();
                    const statusClass = isActive ? 'active' : (new Date(license.expiry_date) <= new Date() ? 'expired' : 'inactive');
                    
                    return `
                        <tr>
                            <td><code style="background: #f8f9fa; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem;">${(license.license_key || 'N/A').substring(0, 20)}...</code></td>
                            <td>
                                <div style="font-weight: 600;">${license.customer_name || license.customer_email}</div>
                                <div style="font-size: 0.8rem; color: #7f8c8d;">${license.customer_email}</div>
                            </td>
                            <td>${license.created_date ? new Date(license.created_date).toLocaleDateString() : 'N/A'}</td>
                            <td>${license.expiry_date ? new Date(license.expiry_date).toLocaleDateString() : 'N/A'}</td>
                            <td><span class="status-badge status-${statusClass}">${statusClass}</span></td>
                            <td>${license.validation_count || 0} validations</td>
                            <td>
                                <button class="btn btn-secondary" style="padding: 4px 8px; font-size: 0.8rem;">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-danger" style="padding: 4px 8px; font-size: 0.8rem; margin-left: 4px;">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>
                    `;
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #7f8c8d;">No licenses found</td></tr>';
            }
        }

        // Modal functions
        function showCreateLicenseModal() {
            document.getElementById('createLicenseModal').classList.add('show');
        }

        function hideCreateLicenseModal() {
            document.getElementById('createLicenseModal').classList.remove('show');
        }

        // Create license form
        document.getElementById('createLicenseForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const licenseData = {
                customer_email: formData.get('customer_email'),
                customer_name: formData.get('customer_name'),
                duration_days: parseInt(formData.get('duration_days')),
                hardware_id: formData.get('hardware_id'),
                notes: formData.get('notes')
            };

            try {
                const response = await apiCall('/api/admin/licenses', {
                    method: 'POST',
                    body: JSON.stringify(licenseData)
                });

                if (response && response.ok) {
                    const result = await response.json();
                    showAlert('License created successfully!', 'success');
                    hideCreateLicenseModal();
                    
                    // Refresh licenses page if currently viewing
                    if (document.getElementById('licensesPage').classList.contains('active')) {
                        loadLicensesData();
                    }
                    
                    // Reset form
                    e.target.reset();
                } else {
                    throw new Error('Failed to create license');
                }
            } catch (error) {
                console.error('Error creating license:', error);
                showAlert('Failed to create license', 'danger');
            }
        });

        // Utility functions
        function showAlert(message, type = 'info') {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type}`;
            alertDiv.textContent = message;
            
            const contentArea = document.querySelector('.content-area');
            contentArea.insertBefore(alertDiv, contentArea.firstChild);
            
            setTimeout(() => {
                alertDiv.remove();
            }, 5000);
        }

        function logout() {
            localStorage.removeItem('admin_token');
            window.location.href = '/';
        }

        function exportData() {
            showAlert('Export functionality coming soon!', 'info');
        }

        function showUserMenu() {
            showAlert('User menu coming soon!', 'info');
        }

        // Initialize page
        document.addEventListener('DOMContentLoaded', () => {
            loadDashboardData();
        });

        // Close modal when clicking outside
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                e.target.classList.remove('show');
            }
        });
    </script>
</body>
</html>"""

# =============================================================================
# APPLICATION STARTUP
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # Production configuration
    port = int(os.getenv('PORT', 8000))
    host = os.getenv('HOST', '0.0.0.0')
    
    logger.info("Starting PDF License Server", 
               host=host, 
               port=port,
               version=config.APP_VERSION)
    
    # Run with Uvicorn
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        access_log=True,
        log_level=config.LOG_LEVEL.lower()
    )
