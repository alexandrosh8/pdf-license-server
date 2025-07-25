"""
🔐 SIMPLE LICENSE SERVER FOR PDF TOOL
=====================================
A lightweight, reliable license server designed for Render deployment.
Uses SQLite for simplicity and reliability on free tiers.

Features:
- Simple SQLite database (no PostgreSQL issues)
- Clean admin interface
- License management (create, extend, disable)
- Client validation with hardware binding
- Activity logging
- Auto-cleanup of old logs
- JSON export/import for backups

Version: 1.0.0
"""

import os
import json
import sqlite3
import hashlib
import secrets
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import logging

from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
import jwt
import uvicorn

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    # App settings
    APP_NAME = "Simple License Server"
    APP_VERSION = "1.0.0"
    
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'changeme123')
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRATION_HOURS = 24
    
    # Database
    DATABASE_PATH = Path("licenses.db")
    
    # License settings
    DEFAULT_DURATION_DAYS = 30
    MAX_HARDWARE_CHANGES = 3
    
    # Logging
    LOG_RETENTION_DAYS = 30
    MAX_LOG_ENTRIES = 10000

config = Config()

# =============================================================================
# LOGGING SETUP
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('server.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# =============================================================================
# DATABASE SETUP
# =============================================================================

def init_database():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # Licenses table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            customer_email TEXT NOT NULL,
            customer_name TEXT,
            hardware_id TEXT,
            created_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            last_validated TEXT,
            validation_count INTEGER DEFAULT 0,
            hardware_changes INTEGER DEFAULT 0,
            previous_hardware_ids TEXT,
            active INTEGER DEFAULT 1,
            notes TEXT,
            created_by TEXT DEFAULT 'system'
        )
    ''')
    
    # Activity logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            license_key TEXT,
            action TEXT NOT NULL,
            status TEXT,
            hardware_id TEXT,
            ip_address TEXT,
            details TEXT
        )
    ''')
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON activity_logs(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_license ON activity_logs(license_key)')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

# Initialize database on startup
init_database()

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

# =============================================================================
# DATABASE HELPERS
# =============================================================================

def get_db_connection():
    """Get database connection with row factory"""
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_activity(license_key: Optional[str], action: str, status: str, 
                 hardware_id: Optional[str] = None, ip_address: Optional[str] = None, 
                 details: Optional[Dict] = None):
    """Log activity to database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO activity_logs (timestamp, license_key, action, status, 
                                     hardware_id, ip_address, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now(timezone.utc).isoformat(),
            license_key,
            action,
            status,
            hardware_id,
            ip_address,
            json.dumps(details) if details else None
        ))
        
        conn.commit()
        conn.close()
        
        # Auto cleanup old logs
        cleanup_old_logs()
        
    except Exception as e:
        logger.error(f"Failed to log activity: {e}")

def cleanup_old_logs():
    """Remove old log entries to prevent database bloat"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete logs older than retention period
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=config.LOG_RETENTION_DAYS)).isoformat()
        cursor.execute('DELETE FROM activity_logs WHERE timestamp < ?', (cutoff_date,))
        
        # Keep only the most recent entries if over limit
        cursor.execute('''
            DELETE FROM activity_logs 
            WHERE id IN (
                SELECT id FROM activity_logs 
                ORDER BY timestamp DESC 
                LIMIT -1 OFFSET ?
            )
        ''', (config.MAX_LOG_ENTRIES,))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Log cleanup failed: {e}")

# =============================================================================
# LICENSE MANAGEMENT
# =============================================================================

def generate_license_key() -> str:
    """Generate a unique license key"""
    segments = []
    for _ in range(4):
        segment = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        segments.append(segment)
    return f"SLIC-{'-'.join(segments)}"

def validate_license(license_key: str, hardware_id: str, ip_address: str) -> Dict[str, Any]:
    """Validate a license key"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get license info
        cursor.execute('''
            SELECT * FROM licenses WHERE license_key = ? AND active = 1
        ''', (license_key,))
        
        license_row = cursor.fetchone()
        
        if not license_row:
            log_activity(license_key, "VALIDATION", "INVALID_KEY", hardware_id, ip_address)
            return {"valid": False, "reason": "Invalid or inactive license key"}
        
        # Check expiry
        expiry_date = datetime.fromisoformat(license_row['expiry_date'])
        if expiry_date < datetime.now(timezone.utc):
            log_activity(license_key, "VALIDATION", "EXPIRED", hardware_id, ip_address)
            return {"valid": False, "reason": "License has expired"}
        
        # Hardware binding logic
        stored_hardware_id = license_row['hardware_id']
        
        if not stored_hardware_id:
            # First binding
            cursor.execute('''
                UPDATE licenses 
                SET hardware_id = ?, last_validated = ?, validation_count = validation_count + 1
                WHERE license_key = ?
            ''', (hardware_id, datetime.now(timezone.utc).isoformat(), license_key))
            
            conn.commit()
            log_activity(license_key, "VALIDATION", "FIRST_BINDING", hardware_id, ip_address)
            
        elif stored_hardware_id != hardware_id:
            # Hardware change
            hardware_changes = license_row['hardware_changes']
            
            if hardware_changes >= config.MAX_HARDWARE_CHANGES:
                log_activity(license_key, "VALIDATION", "MAX_HARDWARE_EXCEEDED", hardware_id, ip_address)
                return {"valid": False, "reason": "Maximum hardware changes exceeded"}
            
            # Update hardware
            previous_ids = license_row['previous_hardware_ids'] or ''
            if previous_ids:
                previous_ids += ','
            previous_ids += stored_hardware_id
            
            cursor.execute('''
                UPDATE licenses 
                SET hardware_id = ?, hardware_changes = hardware_changes + 1,
                    previous_hardware_ids = ?, last_validated = ?, 
                    validation_count = validation_count + 1
                WHERE license_key = ?
            ''', (hardware_id, previous_ids, datetime.now(timezone.utc).isoformat(), license_key))
            
            conn.commit()
            log_activity(license_key, "VALIDATION", "HARDWARE_CHANGED", hardware_id, ip_address)
            
        else:
            # Normal validation
            cursor.execute('''
                UPDATE licenses 
                SET last_validated = ?, validation_count = validation_count + 1
                WHERE license_key = ?
            ''', (datetime.now(timezone.utc).isoformat(), license_key))
            
            conn.commit()
            log_activity(license_key, "VALIDATION", "SUCCESS", hardware_id, ip_address)
        
        # Calculate days remaining
        days_remaining = (expiry_date - datetime.now(timezone.utc)).days
        
        conn.close()
        
        return {
            "valid": True,
            "license_key": license_key,
            "customer_email": license_row['customer_email'],
            "expiry_date": license_row['expiry_date'],
            "days_remaining": max(0, days_remaining),
            "validation_count": license_row['validation_count'] + 1,
            "hardware_changes": license_row['hardware_changes']
        }
        
    except Exception as e:
        logger.error(f"License validation error: {e}")
        log_activity(license_key, "VALIDATION", "ERROR", hardware_id, ip_address, {"error": str(e)})
        return {"valid": False, "reason": "Validation error"}
    
    finally:
        conn.close()

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
    title="Simple License Server",
    version=config.APP_VERSION,
    description="Lightweight license management for PDF tools"
)

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """Redirect to admin login"""
    return HTMLResponse(content="""
    <html>
        <head>
            <meta http-equiv="refresh" content="0; url=/admin">
        </head>
        <body>
            <p>Redirecting to admin panel...</p>
        </body>
    </html>
    """)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM licenses")
        license_count = cursor.fetchone()[0]
        conn.close()
        
        return {
            "status": "healthy",
            "version": config.APP_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "connected",
            "licenses": license_count
        }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e)
            }
        )

@app.post("/api/validate")
async def validate_license_endpoint(request: LicenseValidationRequest, req: Request):
    """Validate a license key"""
    client_ip = req.client.host
    
    result = validate_license(
        request.license_key,
        request.hardware_id,
        client_ip
    )
    
    if result["valid"]:
        return result
    else:
        raise HTTPException(status_code=400, detail=result)

@app.post("/api/admin/login")
async def admin_login(request: AdminLoginRequest):
    """Admin login endpoint"""
    if request.username != config.ADMIN_USERNAME or request.password != config.ADMIN_PASSWORD:
        log_activity(None, "ADMIN_LOGIN", "FAILED", details={"username": request.username})
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_admin_token()
    log_activity(None, "ADMIN_LOGIN", "SUCCESS", details={"username": request.username})
    
    return {
        "access_token": token,
        "token_type": "bearer"
    }

@app.get("/api/admin/dashboard", dependencies=[Depends(verify_admin_token)])
async def admin_dashboard():
    """Get dashboard statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get statistics
        cursor.execute("SELECT COUNT(*) FROM licenses")
        total_licenses = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE active = 1")
        active_licenses = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM licenses 
            WHERE active = 1 AND datetime(expiry_date) > datetime('now')
        """)
        valid_licenses = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM licenses 
            WHERE datetime(expiry_date) <= datetime('now')
        """)
        expired_licenses = cursor.fetchone()[0]
        
        # Recent activity
        cursor.execute("""
            SELECT * FROM activity_logs 
            ORDER BY timestamp DESC 
            LIMIT 20
        """)
        recent_activity = [dict(row) for row in cursor.fetchall()]
        
        # License stats by month
        cursor.execute("""
            SELECT 
                strftime('%Y-%m', created_date) as month,
                COUNT(*) as count
            FROM licenses
            GROUP BY month
            ORDER BY month DESC
            LIMIT 12
        """)
        monthly_stats = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "total_licenses": total_licenses,
            "active_licenses": active_licenses,
            "valid_licenses": valid_licenses,
            "expired_licenses": expired_licenses,
            "recent_activity": recent_activity,
            "monthly_stats": monthly_stats
        }
        
    except Exception as e:
        conn.close()
        logger.error(f"Dashboard error: {e}")
        raise HTTPException(status_code=500, detail="Dashboard error")

@app.get("/api/admin/licenses", dependencies=[Depends(verify_admin_token)])
async def list_licenses(
    page: int = 1,
    per_page: int = 20,
    search: Optional[str] = None,
    status: Optional[str] = None
):
    """List licenses with pagination and filtering"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Build query
        query = "SELECT * FROM licenses WHERE 1=1"
        params = []
        
        if search:
            query += " AND (license_key LIKE ? OR customer_email LIKE ? OR customer_name LIKE ?)"
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
        
        if status == "active":
            query += " AND active = 1 AND datetime(expiry_date) > datetime('now')"
        elif status == "expired":
            query += " AND datetime(expiry_date) <= datetime('now')"
        elif status == "inactive":
            query += " AND active = 0"
        
        # Get total count
        count_query = query.replace("*", "COUNT(*)")
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Add pagination
        query += " ORDER BY created_date DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])
        
        cursor.execute(query, params)
        licenses = [dict(row) for row in cursor.fetchall()]
        
        # Add computed fields
        for license in licenses:
            expiry = datetime.fromisoformat(license['expiry_date'])
            now = datetime.now(timezone.utc)
            license['days_remaining'] = max(0, (expiry - now).days)
            license['is_expired'] = expiry < now
        
        conn.close()
        
        return {
            "licenses": licenses,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page
        }
        
    except Exception as e:
        conn.close()
        logger.error(f"License list error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch licenses")

@app.post("/api/admin/licenses", dependencies=[Depends(verify_admin_token)])
async def create_license(request: LicenseCreateRequest, admin: str = Depends(verify_admin_token)):
    """Create a new license"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        license_key = generate_license_key()
        created_date = datetime.now(timezone.utc)
        expiry_date = created_date + timedelta(days=request.duration_days)
        
        cursor.execute('''
            INSERT INTO licenses (license_key, customer_email, customer_name, 
                                hardware_id, created_date, expiry_date, notes, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            license_key,
            request.customer_email,
            request.customer_name,
            request.hardware_id,
            created_date.isoformat(),
            expiry_date.isoformat(),
            request.notes,
            admin
        ))
        
        conn.commit()
        conn.close()
        
        log_activity(license_key, "LICENSE_CREATED", "SUCCESS", 
                    details={"admin": admin, "duration_days": request.duration_days})
        
        return {
            "license_key": license_key,
            "customer_email": request.customer_email,
            "created_date": created_date.isoformat(),
            "expiry_date": expiry_date.isoformat(),
            "duration_days": request.duration_days
        }
        
    except Exception as e:
        conn.close()
        logger.error(f"License creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create license")

@app.put("/api/admin/licenses/{license_id}/extend", dependencies=[Depends(verify_admin_token)])
async def extend_license(
    license_id: int,
    days: int = Field(..., ge=1, le=3650),
    admin: str = Depends(verify_admin_token)
):
    """Extend license expiration"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get current license
        cursor.execute("SELECT * FROM licenses WHERE id = ?", (license_id,))
        license = cursor.fetchone()
        
        if not license:
            raise HTTPException(status_code=404, detail="License not found")
        
        # Calculate new expiry
        current_expiry = datetime.fromisoformat(license['expiry_date'])
        if current_expiry < datetime.now(timezone.utc):
            # If expired, extend from today
            new_expiry = datetime.now(timezone.utc) + timedelta(days=days)
        else:
            # If valid, extend from current expiry
            new_expiry = current_expiry + timedelta(days=days)
        
        # Update license
        cursor.execute('''
            UPDATE licenses 
            SET expiry_date = ?, active = 1
            WHERE id = ?
        ''', (new_expiry.isoformat(), license_id))
        
        conn.commit()
        conn.close()
        
        log_activity(license['license_key'], "LICENSE_EXTENDED", "SUCCESS",
                    details={"admin": admin, "days_added": days})
        
        return {
            "success": True,
            "new_expiry_date": new_expiry.isoformat(),
            "days_added": days
        }
        
    except HTTPException:
        raise
    except Exception as e:
        conn.close()
        logger.error(f"License extension error: {e}")
        raise HTTPException(status_code=500, detail="Failed to extend license")

@app.put("/api/admin/licenses/{license_id}/toggle", dependencies=[Depends(verify_admin_token)])
async def toggle_license(license_id: int, admin: str = Depends(verify_admin_token)):
    """Enable or disable a license"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get current status
        cursor.execute("SELECT license_key, active FROM licenses WHERE id = ?", (license_id,))
        result = cursor.fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="License not found")
        
        license_key = result['license_key']
        new_status = 0 if result['active'] == 1 else 1
        
        # Update status
        cursor.execute("UPDATE licenses SET active = ? WHERE id = ?", (new_status, license_id))
        
        conn.commit()
        conn.close()
        
        action = "LICENSE_ENABLED" if new_status == 1 else "LICENSE_DISABLED"
        log_activity(license_key, action, "SUCCESS", details={"admin": admin})
        
        return {
            "success": True,
            "active": new_status == 1,
            "message": f"License {'enabled' if new_status == 1 else 'disabled'}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        conn.close()
        logger.error(f"License toggle error: {e}")
        raise HTTPException(status_code=500, detail="Failed to toggle license")

@app.delete("/api/admin/licenses/{license_id}", dependencies=[Depends(verify_admin_token)])
async def delete_license(license_id: int, admin: str = Depends(verify_admin_token)):
    """Delete a license"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get license info
        cursor.execute("SELECT license_key FROM licenses WHERE id = ?", (license_id,))
        result = cursor.fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="License not found")
        
        license_key = result['license_key']
        
        # Delete license
        cursor.execute("DELETE FROM licenses WHERE id = ?", (license_id,))
        
        conn.commit()
        conn.close()
        
        log_activity(license_key, "LICENSE_DELETED", "SUCCESS", details={"admin": admin})
        
        return {"success": True, "message": "License deleted"}
        
    except HTTPException:
        raise
    except Exception as e:
        conn.close()
        logger.error(f"License deletion error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete license")

@app.get("/api/admin/export", dependencies=[Depends(verify_admin_token)])
async def export_data():
    """Export all license data as JSON"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM licenses ORDER BY created_date DESC")
        licenses = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 1000")
        logs = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        export_data = {
            "export_date": datetime.now(timezone.utc).isoformat(),
            "version": config.APP_VERSION,
            "licenses": licenses,
            "recent_logs": logs
        }
        
        return Response(
            content=json.dumps(export_data, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=licenses_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            }
        )
        
    except Exception as e:
        conn.close()
        logger.error(f"Export error: {e}")
        raise HTTPException(status_code=500, detail="Export failed")

# =============================================================================
# ADMIN WEB INTERFACE
# =============================================================================

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    """Admin web interface"""
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>License Server Admin</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        
        .login-container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        .login-box {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        
        .login-box h1 {
            text-align: center;
            margin-bottom: 2rem;
            color: #333;
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        
        input[type="text"],
        input[type="password"],
        input[type="email"],
        input[type="number"],
        select {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1rem;
        }
        
        button {
            background: #667eea;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 500;
            transition: background 0.3s;
        }
        
        button:hover {
            background: #5a67d8;
        }
        
        .btn-secondary {
            background: #718096;
        }
        
        .btn-secondary:hover {
            background: #4a5568;
        }
        
        .btn-danger {
            background: #e53e3e;
        }
        
        .btn-danger:hover {
            background: #c53030;
        }
        
        .btn-success {
            background: #48bb78;
        }
        
        .btn-success:hover {
            background: #38a169;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1rem;
        }
        
        .header {
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 1rem 0;
            margin-bottom: 2rem;
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .stat-card h3 {
            font-size: 0.9rem;
            color: #718096;
            margin-bottom: 0.5rem;
        }
        
        .stat-card p {
            font-size: 2rem;
            font-weight: 600;
            color: #333;
        }
        
        .content-section {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }
        
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            text-align: left;
            padding: 0.75rem;
            border-bottom: 1px solid #e2e8f0;
        }
        
        th {
            background: #f7fafc;
            font-weight: 600;
            color: #4a5568;
        }
        
        tr:hover {
            background: #f7fafc;
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 3px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .badge-active {
            background: #c6f6d5;
            color: #276749;
        }
        
        .badge-expired {
            background: #fed7d7;
            color: #9b2c2c;
        }
        
        .badge-inactive {
            background: #e2e8f0;
            color: #4a5568;
        }
        
        .actions {
            display: flex;
            gap: 0.5rem;
        }
        
        .actions button {
            padding: 0.25rem 0.75rem;
            font-size: 0.875rem;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }
        
        .modal-content {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            width: 90%;
            max-width: 500px;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }
        
        .close-modal {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: #718096;
        }
        
        .tab-nav {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            border-bottom: 2px solid #e2e8f0;
        }
        
        .tab-link {
            padding: 0.5rem 1rem;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            color: #718096;
            border-bottom: 2px solid transparent;
            transition: all 0.3s;
        }
        
        .tab-link.active {
            color: #667eea;
            border-bottom-color: #667eea;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .search-bar {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .search-bar input {
            flex: 1;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            gap: 0.5rem;
            margin-top: 1.5rem;
        }
        
        .pagination button {
            padding: 0.5rem 1rem;
        }
        
        .activity-log {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .log-entry {
            padding: 0.5rem;
            border-bottom: 1px solid #e2e8f0;
            font-size: 0.875rem;
        }
        
        .log-entry.success {
            border-left: 3px solid #48bb78;
        }
        
        .log-entry.failed {
            border-left: 3px solid #e53e3e;
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 2rem;
        }
        
        .error-message {
            background: #fed7d7;
            color: #9b2c2c;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
        }
        
        .success-message {
            background: #c6f6d5;
            color: #276749;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div id="app">
        <!-- Login Page -->
        <div id="loginPage" class="login-container">
            <div class="login-box">
                <h1>🔐 License Server</h1>
                <form id="loginForm">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" required>
                    </div>
                    <button type="submit" style="width: 100%;">Login</button>
                </form>
                <div id="loginError" class="error-message" style="display: none; margin-top: 1rem;"></div>
            </div>
        </div>
        
        <!-- Admin Dashboard -->
        <div id="dashboardPage" style="display: none;">
            <header class="header">
                <div class="container">
                    <div class="header-content">
                        <h1>License Server Admin</h1>
                        <div>
                            <button onclick="exportData()" class="btn-secondary">Export Data</button>
                            <button onclick="logout()">Logout</button>
                        </div>
                    </div>
                </div>
            </header>
            
            <main class="container">
                <!-- Statistics -->
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
                        <h3>Expired Licenses</h3>
                        <p id="expiredLicenses">0</p>
                    </div>
                </div>
                
                <!-- Tab Navigation -->
                <div class="tab-nav">
                    <button class="tab-link active" onclick="showTab('licenses')">Licenses</button>
                    <button class="tab-link" onclick="showTab('activity')">Activity Log</button>
                    <button class="tab-link" onclick="showTab('create')">Create License</button>
                </div>
                
                <!-- Licenses Tab -->
                <div id="licensesTab" class="tab-content active">
                    <div class="content-section">
                        <div class="section-header">
                            <h2>License Management</h2>
                        </div>
                        
                        <div class="search-bar">
                            <input type="text" id="searchInput" placeholder="Search licenses...">
                            <select id="statusFilter">
                                <option value="">All Status</option>
                                <option value="active">Active</option>
                                <option value="expired">Expired</option>
                                <option value="inactive">Inactive</option>
                            </select>
                            <button onclick="loadLicenses()">Search</button>
                        </div>
                        
                        <table>
                            <thead>
                                <tr>
                                    <th>License Key</th>
                                    <th>Customer</th>
                                    <th>Created</th>
                                    <th>Expires</th>
                                    <th>Days Left</th>
                                    <th>Uses</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="licensesTable">
                                <tr><td colspan="8" style="text-align: center;">Loading...</td></tr>
                            </tbody>
                        </table>
                        
                        <div class="pagination" id="pagination"></div>
                    </div>
                </div>
                
                <!-- Activity Log Tab -->
                <div id="activityTab" class="tab-content">
                    <div class="content-section">
                        <div class="section-header">
                            <h2>Recent Activity</h2>
                            <button onclick="loadActivity()" class="btn-secondary">Refresh</button>
                        </div>
                        
                        <div class="activity-log" id="activityLog">
                            <div class="loading">Loading activity...</div>
                        </div>
                    </div>
                </div>
                
                <!-- Create License Tab -->
                <div id="createTab" class="tab-content">
                    <div class="content-section">
                        <h2>Create New License</h2>
                        
                        <form id="createLicenseForm">
                            <div class="form-group">
                                <label for="customerEmail">Customer Email</label>
                                <input type="email" id="customerEmail" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="customerName">Customer Name</label>
                                <input type="text" id="customerName">
                            </div>
                            
                            <div class="form-group">
                                <label for="durationDays">Duration (Days)</label>
                                <input type="number" id="durationDays" value="30" min="1" max="3650" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="hardwareId">Hardware ID (Optional)</label>
                                <input type="text" id="hardwareId">
                            </div>
                            
                            <div class="form-group">
                                <label for="notes">Notes</label>
                                <textarea id="notes" rows="3" style="width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 5px;"></textarea>
                            </div>
                            
                            <button type="submit" class="btn-success">Create License</button>
                        </form>
                        
                        <div id="createResult" style="margin-top: 1rem;"></div>
                    </div>
                </div>
            </main>
        </div>
        
        <!-- Extend License Modal -->
        <div id="extendModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>Extend License</h2>
                    <button class="close-modal" onclick="closeModal('extendModal')">×</button>
                </div>
                
                <form id="extendForm">
                    <input type="hidden" id="extendLicenseId">
                    
                    <div class="form-group">
                        <label for="extendDays">Days to Add</label>
                        <input type="number" id="extendDays" value="30" min="1" max="3650" required>
                    </div>
                    
                    <button type="submit" class="btn-success">Extend License</button>
                </form>
            </div>
        </div>
    </div>
    
    <script>
        let authToken = null;
        let currentPage = 1;
        
        // Check if already logged in
        if (localStorage.getItem('adminToken')) {
            authToken = localStorage.getItem('adminToken');
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
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    authToken = data.access_token;
                    localStorage.setItem('adminToken', authToken);
                    showDashboard();
                } else {
                    const error = await response.json();
                    showError('loginError', error.detail || 'Login failed');
                }
            } catch (error) {
                showError('loginError', 'Network error');
            }
        });
        
        // Create license form handler
        document.getElementById('createLicenseForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const data = {
                customer_email: document.getElementById('customerEmail').value,
                customer_name: document.getElementById('customerName').value,
                duration_days: parseInt(document.getElementById('durationDays').value),
                hardware_id: document.getElementById('hardwareId').value || null,
                notes: document.getElementById('notes').value || null
            };
            
            try {
                const response = await fetch('/api/admin/licenses', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`
                    },
                    body: JSON.stringify(data)
                });
                
                if (response.ok) {
                    const result = await response.json();
                    document.getElementById('createResult').innerHTML = `
                        <div class="success-message">
                            <strong>License Created Successfully!</strong><br>
                            License Key: <code>${result.license_key}</code><br>
                            Email: ${result.customer_email}<br>
                            Expires: ${new Date(result.expiry_date).toLocaleDateString()}
                        </div>
                    `;
                    document.getElementById('createLicenseForm').reset();
                    loadDashboard();
                } else {
                    const error = await response.json();
                    document.getElementById('createResult').innerHTML = `
                        <div class="error-message">Failed to create license: ${error.detail}</div>
                    `;
                }
            } catch (error) {
                document.getElementById('createResult').innerHTML = `
                    <div class="error-message">Network error</div>
                `;
            }
        });
        
        // Extend license form handler
        document.getElementById('extendForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const licenseId = document.getElementById('extendLicenseId').value;
            const days = parseInt(document.getElementById('extendDays').value);
            
            try {
                const response = await fetch(`/api/admin/licenses/${licenseId}/extend?days=${days}`, {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    closeModal('extendModal');
                    loadLicenses();
                    alert('License extended successfully!');
                } else {
                    alert('Failed to extend license');
                }
            } catch (error) {
                alert('Network error');
            }
        });
        
        async function showDashboard() {
            document.getElementById('loginPage').style.display = 'none';
            document.getElementById('dashboardPage').style.display = 'block';
            
            await loadDashboard();
            await loadLicenses();
        }
        
        async function loadDashboard() {
            try {
                const response = await fetch('/api/admin/dashboard', {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    document.getElementById('totalLicenses').textContent = data.total_licenses;
                    document.getElementById('activeLicenses').textContent = data.active_licenses;
                    document.getElementById('validLicenses').textContent = data.valid_licenses;
                    document.getElementById('expiredLicenses').textContent = data.expired_licenses;
                } else if (response.status === 401) {
                    logout();
                }
            } catch (error) {
                console.error('Dashboard load error:', error);
            }
        }
        
        async function loadLicenses(page = 1) {
            currentPage = page;
            const search = document.getElementById('searchInput').value;
            const status = document.getElementById('statusFilter').value;
            
            const params = new URLSearchParams({
                page: page,
                per_page: 20
            });
            
            if (search) params.append('search', search);
            if (status) params.append('status', status);
            
            try {
                const response = await fetch(`/api/admin/licenses?${params}`, {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    displayLicenses(data.licenses);
                    displayPagination(data);
                } else if (response.status === 401) {
                    logout();
                }
            } catch (error) {
                console.error('Licenses load error:', error);
            }
        }
        
        function displayLicenses(licenses) {
            const tbody = document.getElementById('licensesTable');
            
            if (licenses.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center;">No licenses found</td></tr>';
                return;
            }
            
            tbody.innerHTML = licenses.map(license => {
                const createdDate = new Date(license.created_date).toLocaleDateString();
                const expiryDate = new Date(license.expiry_date).toLocaleDateString();
                const daysLeft = license.days_remaining;
                
                let statusBadge = '';
                if (!license.active) {
                    statusBadge = '<span class="badge badge-inactive">Inactive</span>';
                } else if (license.is_expired) {
                    statusBadge = '<span class="badge badge-expired">Expired</span>';
                } else {
                    statusBadge = '<span class="badge badge-active">Active</span>';
                }
                
                return `
                    <tr>
                        <td><code>${license.license_key}</code></td>
                        <td>
                            ${license.customer_name || '-'}<br>
                            <small>${license.customer_email}</small>
                        </td>
                        <td>${createdDate}</td>
                        <td>${expiryDate}</td>
                        <td>${daysLeft}</td>
                        <td>${license.validation_count || 0}</td>
                        <td>${statusBadge}</td>
                        <td>
                            <div class="actions">
                                <button onclick="extendLicense(${license.id})" class="btn-success" title="Extend">+Days</button>
                                <button onclick="toggleLicense(${license.id})" class="btn-secondary" title="Toggle">
                                    ${license.active ? 'Disable' : 'Enable'}
                                </button>
                                <button onclick="deleteLicense(${license.id})" class="btn-danger" title="Delete">Delete</button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }
        
        function displayPagination(data) {
            const pagination = document.getElementById('pagination');
            const totalPages = data.total_pages;
            
            if (totalPages <= 1) {
                pagination.innerHTML = '';
                return;
            }
            
            let html = '';
            
            if (currentPage > 1) {
                html += `<button onclick="loadLicenses(${currentPage - 1})">Previous</button>`;
            }
            
            for (let i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
                if (i === currentPage) {
                    html += `<button disabled>${i}</button>`;
                } else {
                    html += `<button onclick="loadLicenses(${i})">${i}</button>`;
                }
            }
            
            if (currentPage < totalPages) {
                html += `<button onclick="loadLicenses(${currentPage + 1})">Next</button>`;
            }
            
            pagination.innerHTML = html;
        }
        
        async function loadActivity() {
            try {
                const response = await fetch('/api/admin/dashboard', {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    displayActivity(data.recent_activity);
                }
            } catch (error) {
                console.error('Activity load error:', error);
            }
        }
        
        function displayActivity(activities) {
            const container = document.getElementById('activityLog');
            
            if (activities.length === 0) {
                container.innerHTML = '<div style="text-align: center; padding: 2rem;">No recent activity</div>';
                return;
            }
            
            container.innerHTML = activities.map(activity => {
                const timestamp = new Date(activity.timestamp).toLocaleString();
                const statusClass = activity.status.includes('SUCCESS') ? 'success' : 'failed';
                
                return `
                    <div class="log-entry ${statusClass}">
                        <strong>${timestamp}</strong><br>
                        Action: ${activity.action}<br>
                        License: ${activity.license_key || 'N/A'}<br>
                        Status: ${activity.status}
                        ${activity.hardware_id ? `<br>Hardware: ${activity.hardware_id}` : ''}
                        ${activity.ip_address ? `<br>IP: ${activity.ip_address}` : ''}
                    </div>
                `;
            }).join('');
        }
        
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remove active class from all tab links
            document.querySelectorAll('.tab-link').forEach(link => {
                link.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + 'Tab').classList.add('active');
            
            // Add active class to clicked tab link
            event.target.classList.add('active');
            
            // Load activity if activity tab is selected
            if (tabName === 'activity') {
                loadActivity();
            }
        }
        
        function extendLicense(licenseId) {
            document.getElementById('extendLicenseId').value = licenseId;
            document.getElementById('extendModal').style.display = 'flex';
        }
        
        async function toggleLicense(licenseId) {
            if (!confirm('Are you sure you want to toggle this license?')) return;
            
            try {
                const response = await fetch(`/api/admin/licenses/${licenseId}/toggle`, {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    loadLicenses(currentPage);
                } else {
                    alert('Failed to toggle license');
                }
            } catch (error) {
                alert('Network error');
            }
        }
        
        async function deleteLicense(licenseId) {
            if (!confirm('Are you sure you want to delete this license? This cannot be undone.')) return;
            
            try {
                const response = await fetch(`/api/admin/licenses/${licenseId}`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    loadLicenses(currentPage);
                } else {
                    alert('Failed to delete license');
                }
            } catch (error) {
                alert('Network error');
            }
        }
        
        async function exportData() {
            try {
                const response = await fetch('/api/admin/export', {
                    headers: {
                        'Authorization': `Bearer ${authToken}`
                    }
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = `licenses_export_${new Date().toISOString().split('T')[0]}.json`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                } else {
                    alert('Export failed');
                }
            } catch (error) {
                alert('Network error');
            }
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        function showError(elementId, message) {
            const element = document.getElementById(elementId);
            element.textContent = message;
            element.style.display = 'block';
            
            setTimeout(() => {
                element.style.display = 'none';
            }, 5000);
        }
        
        function logout() {
            localStorage.removeItem('adminToken');
            authToken = null;
            document.getElementById('loginPage').style.display = 'flex';
            document.getElementById('dashboardPage').style.display = 'none';
        }
        
        // Close modals when clicking outside
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
            }
        }
    </script>
</body>
</html>""")

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    port = int(os.getenv('PORT', 8000))
    host = os.getenv('HOST', '0.0.0.0')
    
    logger.info(f"Starting {config.APP_NAME} v{config.APP_VERSION} on {host}:{port}")
    logger.info(f"Admin credentials: {config.ADMIN_USERNAME} / {config.ADMIN_PASSWORD}")
    logger.info("Database: SQLite (no configuration needed)")
    
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )
