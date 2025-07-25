"""
🔐 RENDER-OPTIMIZED LICENSE SERVER
===================================
Optimized for Render.com deployment following official best practices

Version: 2.1.0
"""

import os
import json
import hashlib
import secrets
import string
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
import asyncio

from fastapi import FastAPI, HTTPException, Depends, Request, Response, File, UploadFile, Form, status
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
import jwt
import uvicorn
import asyncpg

# =============================================================================
# LOGGING SETUP
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}'
)
logger = logging.getLogger("app")

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    APP_NAME = "PDF License Server"
    APP_VERSION = "2.1.0"
    
    # Environment-based configuration
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'Admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'changeme123')
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRATION_HOURS = 24
    
    # Database configuration
    DATABASE_URL = os.getenv('DATABASE_URL')
    if DATABASE_URL and DATABASE_URL.startswith('postgresql://'):
        DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgres://', 1)
    
    # License configuration
    DEFAULT_DURATION_DAYS = 30
    MAX_HARDWARE_CHANGES = 3
    LOG_RETENTION_DAYS = 30
    MAX_LOG_ENTRIES = 10000
    
    # File upload configuration
    RELEASES_DIR = Path("releases")
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    ALLOWED_EXTENSIONS = {'.exe', '.msi', '.zip', '.dmg', '.pkg'}
    
    # Server configuration
    PORT = int(os.getenv('PORT', 8000))
    HOST = os.getenv('HOST', '0.0.0.0')
    
    # Render environment detection
    IS_RENDER = os.getenv('RENDER') is not None
    RENDER_EXTERNAL_HOSTNAME = os.getenv('RENDER_EXTERNAL_HOSTNAME')

config = Config()
config.RELEASES_DIR.mkdir(exist_ok=True)

# =============================================================================
# DATABASE SETUP
# =============================================================================

db_pool = None

async def init_database():
    """Initialize PostgreSQL database for Render"""
    global db_pool
    
    if not config.DATABASE_URL:
        logger.error("DATABASE_URL environment variable not set")
        raise ValueError("DATABASE_URL is required")
    
    try:
        # Create connection pool with proper settings for Render
        db_pool = await asyncpg.create_pool(
            config.DATABASE_URL,
            min_size=1,
            max_size=5,  # Conservative for free tier
            command_timeout=30,
            server_settings={
                'application_name': config.APP_NAME,
                'timezone': 'UTC'
            }
        )
        
        logger.info("Connected to database postgresql://...")
        
        async with db_pool.acquire() as conn:
            # Create tables with proper PostgreSQL types
            try:
                # Licenses table
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS licenses (
                        id SERIAL PRIMARY KEY,
                        license_key VARCHAR(255) UNIQUE NOT NULL,
                        customer_email VARCHAR(255) NOT NULL,
                        customer_name VARCHAR(255),
                        hardware_id VARCHAR(64),
                        created_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
                        last_validated TIMESTAMP WITH TIME ZONE,
                        validation_count INTEGER DEFAULT 0,
                        hardware_changes INTEGER DEFAULT 0,
                        previous_hardware_ids TEXT,
                        active BOOLEAN DEFAULT true,
                        notes TEXT,
                        created_by VARCHAR(255) DEFAULT 'system'
                    )
                ''')
                
                # Activity logs table
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS activity_logs (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        license_key VARCHAR(255),
                        action VARCHAR(255) NOT NULL,
                        status VARCHAR(255),
                        hardware_id VARCHAR(64),
                        ip_address INET,
                        details JSONB
                    )
                ''')
                
                # App versions table
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS app_versions (
                        id SERIAL PRIMARY KEY,
                        version VARCHAR(255) UNIQUE NOT NULL,
                        filename VARCHAR(255) NOT NULL,
                        file_size BIGINT NOT NULL,
                        checksum VARCHAR(255) NOT NULL,
                        release_notes TEXT,
                        is_critical BOOLEAN DEFAULT false,
                        min_required_version VARCHAR(255),
                        created_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        download_count INTEGER DEFAULT 0,
                        active BOOLEAN DEFAULT true
                    )
                ''')
                
                # Wait for table creation to complete
                await conn.execute('SELECT 1')
                
                # Now create indexes - only after tables exist
                try:
                    await conn.execute('CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)')
                    await conn.execute('CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email)')
                    await conn.execute('CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(active)')
                    await conn.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON activity_logs(timestamp)')
                    await conn.execute('CREATE INDEX IF NOT EXISTS idx_logs_license ON activity_logs(license_key)')
                    await conn.execute('CREATE INDEX IF NOT EXISTS idx_versions_version ON app_versions(version)')
                    await conn.execute('CREATE INDEX IF NOT EXISTS idx_versions_active ON app_versions(active)')
                except Exception as index_error:
                    logger.warning(f"Some indexes could not be created: {index_error}")
                
                logger.info({"event": "Database initialized successfully", "db_type": "PostgreSQL"})
                
            except Exception as table_error:
                logger.error(f"Failed to create tables: {table_error}")
                raise
            
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class LicenseValidationRequest(BaseModel):
    license_key: str = Field(..., min_length=10, max_length=50)
    hardware_id: str = Field(..., min_length=5, max_length=64)
    app_name: Optional[str] = None
    app_version: Optional[str] = None
    client_timestamp: Optional[str] = None

class LicenseCreateRequest(BaseModel):
    customer_email: EmailStr
    customer_name: Optional[str] = None
    duration_days: int = Field(default=30, ge=1, le=3650)
    hardware_id: Optional[str] = None
    notes: Optional[str] = None

class AdminLoginRequest(BaseModel):
    username: str
    password: str

class VersionCheckRequest(BaseModel):
    current_version: str
    app_name: Optional[str] = None

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_license_key() -> str:
    """Generate a unique license key"""
    segments = []
    for _ in range(4):
        segment = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        segments.append(segment)
    return f"SLIC-{'-'.join(segments)}"

async def log_activity(license_key: Optional[str], action: str, status: str, 
                      hardware_id: Optional[str] = None, ip_address: Optional[str] = None, 
                      details: Optional[Dict] = None):
    """Log activity to database"""
    try:
        if db_pool:
            async with db_pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO activity_logs (license_key, action, status, hardware_id, ip_address, details)
                    VALUES ($1, $2, $3, $4, $5, $6)
                ''', 
                    license_key,
                    action,
                    status,
                    hardware_id,
                    ip_address,
                    json.dumps(details) if details else None
                )
                
        logger.info({
            "event": f"{action} {status}".lower(),
            "license_key": license_key,
            "hardware_id": hardware_id,
            "ip_address": ip_address
        })
            
    except Exception as e:
        logger.error(f"Failed to log activity: {e}")

def version_compare(version1: str, version2: str) -> int:
    """Compare two version strings"""
    def version_tuple(v):
        try:
            return tuple(map(int, v.split(".")))
        except:
            return (0, 0, 0)
    
    v1_tuple = version_tuple(version1)
    v2_tuple = version_tuple(version2)
    
    if v1_tuple < v2_tuple:
        return -1
    elif v1_tuple > v2_tuple:
        return 1
    else:
        return 0

async def validate_license(license_key: str, hardware_id: str, ip_address: str) -> Dict[str, Any]:
    """Validate a license key with proper error handling"""
    try:
        if not db_pool:
            await log_activity(license_key, "VALIDATION", "DB_ERROR", hardware_id, ip_address)
            return {"valid": False, "reason": "Database unavailable"}
            
        async with db_pool.acquire() as conn:
            # Get license
            license_row = await conn.fetchrow(
                'SELECT * FROM licenses WHERE license_key = $1 AND active = true',
                license_key
            )
            
            if not license_row:
                await log_activity(license_key, "VALIDATION", "INVALID_KEY", hardware_id, ip_address)
                return {"valid": False, "reason": "Invalid or inactive license key"}
            
            # Check expiry
            expiry_date = license_row['expiry_date']
            now = datetime.now(timezone.utc)
            
            if expiry_date < now:
                await log_activity(license_key, "VALIDATION", "EXPIRED", hardware_id, ip_address)
                return {"valid": False, "reason": "License has expired"}
            
            # Hardware binding logic
            stored_hardware_id = license_row['hardware_id']
            
            if not stored_hardware_id:
                # First binding
                await conn.execute('''
                    UPDATE licenses 
                    SET hardware_id = $1, last_validated = $2, validation_count = validation_count + 1
                    WHERE license_key = $3
                ''', hardware_id, now, license_key)
                
                await log_activity(license_key, "VALIDATION", "FIRST_BINDING", hardware_id, ip_address)
                
            elif stored_hardware_id != hardware_id:
                # Hardware change
                hardware_changes = license_row['hardware_changes']
                
                if hardware_changes >= config.MAX_HARDWARE_CHANGES:
                    await log_activity(license_key, "VALIDATION", "MAX_HARDWARE_EXCEEDED", hardware_id, ip_address)
                    return {"valid": False, "reason": "Maximum hardware changes exceeded"}
                
                # Update hardware
                previous_ids = license_row['previous_hardware_ids'] or ''
                if previous_ids:
                    previous_ids += ','
                previous_ids += stored_hardware_id
                
                await conn.execute('''
                    UPDATE licenses 
                    SET hardware_id = $1, hardware_changes = hardware_changes + 1,
                        previous_hardware_ids = $2, last_validated = $3, 
                        validation_count = validation_count + 1
                    WHERE license_key = $4
                ''', hardware_id, previous_ids, now, license_key)
                
                await log_activity(license_key, "VALIDATION", "HARDWARE_CHANGED", hardware_id, ip_address)
                
            else:
                # Normal validation
                await conn.execute('''
                    UPDATE licenses 
                    SET last_validated = $1, validation_count = validation_count + 1
                    WHERE license_key = $2
                ''', now, license_key)
                
                await log_activity(license_key, "VALIDATION", "SUCCESS", hardware_id, ip_address)
            
            # Calculate days remaining
            days_remaining = (expiry_date - now).days
            
            return {
                "valid": True,
                "license_key": license_key,
                "customer_email": license_row['customer_email'],
                "expiry_date": expiry_date.isoformat(),
                "days_remaining": max(0, days_remaining),
                "validation_count": license_row['validation_count'] + 1,
                "hardware_changes": license_row['hardware_changes']
            }
            
    except Exception as e:
        logger.error(f"License validation error: {e}")
        await log_activity(license_key, "VALIDATION", "ERROR", hardware_id, ip_address, {"error": str(e)})
        return {"valid": False, "reason": "Validation error"}

# =============================================================================
# AUTHENTICATION
# =============================================================================

security = HTTPBearer()

def create_admin_token() -> str:
    """Create JWT token for admin"""
    payload = {
        "sub": config.ADMIN_USERNAME,
        "exp": datetime.utcnow() + timedelta(hours=config.JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm=config.JWT_ALGORITHM)

def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verify admin JWT token"""
    try:
        payload = jwt.decode(
            credentials.credentials, 
            config.SECRET_KEY, 
            algorithms=[config.JWT_ALGORITHM]
        )
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# =============================================================================
# FASTAPI APP
# =============================================================================

app = FastAPI(
    title="PDF License Server",
    version=config.APP_VERSION,
    description="Production-ready license management with auto-update",
    docs_url="/docs" if not config.IS_RENDER else None,  # Disable docs in production
    redoc_url="/redoc" if not config.IS_RENDER else None
)

# Add CORS middleware with proper configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if not config.IS_RENDER else [f"https://{config.RENDER_EXTERNAL_HOSTNAME}"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# =============================================================================
# STARTUP/SHUTDOWN EVENTS
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info({
        "version": config.APP_VERSION,
        "event": "Starting PDF License Server"
    })
    
    try:
        await init_database()
        logger.info({"event": "Redis not configured, continuing without cache"})
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global db_pool
    if db_pool:
        await db_pool.close()
        logger.info("Disconnected from database postgresql://...")
        logger.info({"event": "PDF License Server stopped"})

# =============================================================================
# HEALTH CHECK ENDPOINT (RENDER REQUIREMENT)
# =============================================================================

@app.get("/health", status_code=200)
async def health_check():
    """Health check endpoint for Render zero-downtime deployments"""
    try:
        # Test database connection
        if db_pool:
            async with db_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
        
        return {
            "status": "healthy",
            "version": config.APP_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "connected",
            "environment": "render" if config.IS_RENDER else "local"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")

# =============================================================================
# MAIN ENDPOINTS
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint redirects to admin"""
    return HTMLResponse(content="""
    <html>
        <head>
            <meta http-equiv="refresh" content="0; url=/admin">
            <title>PDF License Server</title>
        </head>
        <body>
            <h1>PDF License Server</h1>
            <p>Redirecting to admin panel...</p>
            <p><a href="/admin">Go to Admin Panel</a></p>
        </body>
    </html>
    """)

@app.post("/api/validate")
async def validate_license_endpoint(request: LicenseValidationRequest, req: Request):
    """Validate a license key"""
    client_ip = req.client.host
    
    result = await validate_license(
        request.license_key,
        request.hardware_id,
        client_ip
    )
    
    if result["valid"]:
        return result
    else:
        raise HTTPException(status_code=400, detail=result)

@app.post("/api/admin/login")
async def admin_login(request: AdminLoginRequest, req: Request):
    """Admin login endpoint"""
    client_ip = req.client.host
    
    if request.username != config.ADMIN_USERNAME or request.password != config.ADMIN_PASSWORD:
        await log_activity(None, "ADMIN_LOGIN", "FAILED", None, client_ip, {"username": request.username})
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_admin_token()
    await log_activity(None, "ADMIN_LOGIN", "SUCCESS", None, client_ip, {"username": request.username})
    
    logger.info({
        "username": request.username,
        "event": "Admin login successful"
    })
    
    return {
        "access_token": token,
        "token_type": "bearer"
    }

@app.get("/api/admin/dashboard", dependencies=[Depends(verify_admin_token)])
async def admin_dashboard():
    """Admin dashboard with statistics"""
    try:
        if not db_pool:
            raise HTTPException(status_code=503, detail="Database unavailable")
            
        async with db_pool.acquire() as conn:
            # Get license statistics with proper PostgreSQL queries
            total_licenses = await conn.fetchval("SELECT COUNT(*) FROM licenses")
            active_licenses = await conn.fetchval("SELECT COUNT(*) FROM licenses WHERE active = true")
            
            # Use proper timestamp comparison for PostgreSQL
            valid_licenses = await conn.fetchval("""
                SELECT COUNT(*) FROM licenses 
                WHERE active = true AND expiry_date > NOW()
            """)
            
            expired_licenses = await conn.fetchval("""
                SELECT COUNT(*) FROM licenses 
                WHERE expiry_date <= NOW()
            """)
            
            # Get version statistics
            total_versions = await conn.fetchval("SELECT COUNT(*) FROM app_versions WHERE active = true")
            total_downloads = await conn.fetchval("SELECT COALESCE(SUM(download_count), 0) FROM app_versions")
            
            # Recent activity
            recent_activity = await conn.fetch("""
                SELECT timestamp, license_key, action, status, ip_address
                FROM activity_logs 
                ORDER BY timestamp DESC 
                LIMIT 20
            """)
            
            activity_list = []
            for row in recent_activity:
                activity_list.append({
                    "timestamp": row['timestamp'].isoformat(),
                    "license_key": row['license_key'],
                    "action": row['action'],
                    "status": row['status'],
                    "ip_address": str(row['ip_address']) if row['ip_address'] else None
                })
            
            return {
                "total_licenses": total_licenses,
                "active_licenses": active_licenses,
                "valid_licenses": valid_licenses,
                "expired_licenses": expired_licenses,
                "total_versions": total_versions,
                "total_downloads": total_downloads,
                "recent_activity": activity_list
            }
        
    except Exception as e:
        logger.error({"error": str(e), "event": "Dashboard stats error"})
        raise HTTPException(status_code=500, detail="Dashboard error")

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    """Admin panel interface"""
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF License Server Admin</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333; 
            line-height: 1.6; 
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .header { text-align: center; margin-bottom: 3rem; }
        .header h1 { color: white; font-size: 3rem; margin-bottom: 0.5rem; text-shadow: 0 2px 4px rgba(0,0,0,0.3); }
        .header p { color: rgba(255,255,255,0.9); font-size: 1.2rem; }
        .login-box { 
            background: white; 
            padding: 3rem; 
            border-radius: 15px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            max-width: 450px;
            margin: 0 auto;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin: 2rem 0;
        }
        .stat-card {
            background: white;
            padding: 2rem;
            border-radius: 15px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-card h3 { color: #667eea; font-size: 0.9rem; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 1px; }
        .stat-card p { font-size: 3rem; font-weight: 700; color: #333; }
        .form-group { margin-bottom: 1.5rem; }
        label { display: block; margin-bottom: 0.5rem; font-weight: 600; color: #555; }
        input[type="text"], input[type="password"] { 
            width: 100%; 
            padding: 1rem; 
            border: 2px solid #e1e5e9; 
            border-radius: 10px; 
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            border: none; 
            padding: 1rem 2rem; 
            border-radius: 10px; 
            cursor: pointer; 
            font-size: 1rem; 
            font-weight: 600;
            transition: transform 0.3s ease;
        }
        button:hover { transform: translateY(-2px); }
        .btn-logout {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            padding: 0.75rem 1.5rem;
            font-size: 0.9rem;
        }
        .error-message { 
            background: #ffe6e6; 
            color: #d63031; 
            padding: 1rem; 
            border-radius: 10px; 
            margin: 1rem 0;
            border-left: 4px solid #d63031;
        }
        .dashboard { background: white; border-radius: 15px; padding: 2rem; margin-top: 2rem; box-shadow: 0 10px 25px rgba(0,0,0,0.1); }
        .dashboard-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .dashboard h2 { color: #333; font-size: 2rem; }
        .activity-log { background: #f8f9fa; border-radius: 10px; padding: 1.5rem; margin-top: 2rem; }
        .activity-item { 
            display: flex; 
            justify-content: space-between; 
            align-items: center;
            padding: 0.75rem 0;
            border-bottom: 1px solid #e9ecef;
        }
        .activity-item:last-child { border-bottom: none; }
        .activity-action { font-weight: 600; color: #495057; }
        .activity-time { color: #6c757d; font-size: 0.9rem; }
        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .status-success { background: #d4edda; color: #155724; }
        .status-failed { background: #f8d7da; color: #721c24; }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 PDF License Server</h1>
            <p>Secure License Management & Distribution</p>
        </div>

        <!-- Login Page -->
        <div id="loginPage">
            <div class="login-box">
                <form id="loginForm">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" required>
                    </div>
                    <button type="submit" style="width: 100%;">Login to Dashboard</button>
                </form>
                <div id="loginError" class="error-message hidden"></div>
            </div>
        </div>
        
        <!-- Dashboard Page -->
        <div id="dashboardPage" class="hidden">
            <div class="dashboard">
                <div class="dashboard-header">
                    <h2>License Management Dashboard</h2>
                    <button onclick="logout()" class="btn-logout">Logout</button>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Licenses</h3>
                        <p id="totalLicenses">0</p>
                    </div>
                    <div class="stat-card">
                        <h3>Active Licenses</h3>
                        <p id="activeLicenses">0</p>
                    </div>
                    <div class="stat-card">
                        <h3>Valid Licenses</h3>
                        <p id="validLicenses">0</p>
                    </div>
                    <div class="stat-card">
                        <h3>Total Downloads</h3>
                        <p id="totalDownloads">0</p>
                    </div>
                </div>
                
                <div class="activity-log">
                    <h3>Recent Activity</h3>
                    <div id="activityList">
                        <div class="activity-item">
                            <span class="activity-action">Loading...</span>
                            <span class="activity-time">Please wait</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let authToken = localStorage.getItem('adminToken');
        
        // Check if already logged in
        if (authToken) {
            showDashboard();
        }
        
        // Login form handler
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/api/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    authToken = data.access_token;
                    localStorage.setItem('adminToken', authToken);
                    showDashboard();
                } else {
                    const error = await response.json();
                    showError(error.detail || 'Login failed');
                }
            } catch (error) {
                showError('Network error - please try again');
            }
        });
        
        async function showDashboard() {
            document.getElementById('loginPage').classList.add('hidden');
            document.getElementById('dashboardPage').classList.remove('hidden');
            await loadDashboard();
            
            // Refresh dashboard every 30 seconds
            setInterval(loadDashboard, 30000);
        }
        
        async function loadDashboard() {
            try {
                const response = await fetch('/api/admin/dashboard', {
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Update statistics
                    document.getElementById('totalLicenses').textContent = data.total_licenses || 0;
                    document.getElementById('activeLicenses').textContent = data.active_licenses || 0;
                    document.getElementById('validLicenses').textContent = data.valid_licenses || 0;
                    document.getElementById('totalDownloads').textContent = data.total_downloads || 0;
                    
                    // Update activity log
                    const activityList = document.getElementById('activityList');
                    if (data.recent_activity && data.recent_activity.length > 0) {
                        activityList.innerHTML = data.recent_activity.map(activity => {
                            const time = new Date(activity.timestamp).toLocaleString();
                            const statusClass = activity.status === 'SUCCESS' ? 'status-success' : 'status-failed';
                            
                            return `
                                <div class="activity-item">
                                    <div>
                                        <span class="activity-action">${activity.action}</span>
                                        <span class="status-badge ${statusClass}">${activity.status}</span>
                                        ${activity.license_key ? `<br><small>License: ${activity.license_key}</small>` : ''}
                                    </div>
                                    <span class="activity-time">${time}</span>
                                </div>
                            `;
                        }).join('');
                    } else {
                        activityList.innerHTML = '<div class="activity-item"><span class="activity-action">No recent activity</span></div>';
                    }
                    
                } else if (response.status === 401) {
                    logout();
                } else {
                    console.error('Dashboard load failed');
                }
            } catch (error) {
                console.error('Dashboard load error:', error);
            }
        }
        
        function showError(message) {
            const errorElement = document.getElementById('loginError');
            errorElement.textContent = message;
            errorElement.classList.remove('hidden');
            
            setTimeout(() => {
                errorElement.classList.add('hidden');
            }, 5000);
        }
        
        function logout() {
            localStorage.removeItem('adminToken');
            authToken = null;
            document.getElementById('loginPage').classList.remove('hidden');
            document.getElementById('dashboardPage').classList.add('hidden');
        }
    </script>
</body>
</html>""")

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    logger.info(f"Starting {config.APP_NAME} v{config.APP_VERSION} on {config.HOST}:{config.PORT}")
    logger.info(f"Admin credentials: {config.ADMIN_USERNAME} / {config.ADMIN_PASSWORD}")
    logger.info(f"Environment: {'Render' if config.IS_RENDER else 'Local'}")
    
    uvicorn.run(
        "app:app",
        host=config.HOST,
        port=config.PORT,
        reload=False,
        log_level="info"
    )
