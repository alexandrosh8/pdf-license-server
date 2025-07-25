"""
🔐 CLEAN LICENSE SERVER WITH AUTO-UPDATE
========================================
Clean version with minimal imports - guaranteed to work on Render.

Version: 2.0.1
"""

import os
import json
import sqlite3
import hashlib
import secrets
import string
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, Depends, Request, Response, File, UploadFile, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
import jwt
import uvicorn

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    APP_NAME = "Clean License Server"
    APP_VERSION = "2.0.1"
    
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'changeme123')
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRATION_HOURS = 24
    
    DATABASE_PATH = Path("licenses.db")
    DEFAULT_DURATION_DAYS = 30
    MAX_HARDWARE_CHANGES = 3
    LOG_RETENTION_DAYS = 30
    MAX_LOG_ENTRIES = 10000
    
    RELEASES_DIR = Path("releases")
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    ALLOWED_EXTENSIONS = {'.exe', '.msi', '.zip', '.dmg', '.pkg'}

config = Config()
config.RELEASES_DIR.mkdir(exist_ok=True)

# =============================================================================
# DATABASE SETUP
# =============================================================================

def init_database():
    """Initialize SQLite database"""
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
    
    # App versions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            checksum TEXT NOT NULL,
            release_notes TEXT,
            is_critical INTEGER DEFAULT 0,
            min_required_version TEXT,
            created_date TEXT NOT NULL,
            download_count INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1
        )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON activity_logs(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_license ON activity_logs(license_key)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_versions_version ON app_versions(version)')
    
    conn.commit()
    conn.close()

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

class VersionCheckRequest(BaseModel):
    current_version: str
    app_name: Optional[str] = None

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_db_connection():
    """Get database connection with row factory"""
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def calculate_file_checksum(file_path: Path) -> str:
    """Calculate SHA256 checksum of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def version_compare(version1: str, version2: str) -> int:
    """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2"""
    def version_tuple(v):
        return tuple(map(int, (v.split("."))))
    
    try:
        v1_tuple = version_tuple(version1)
        v2_tuple = version_tuple(version2)
        
        if v1_tuple < v2_tuple:
            return -1
        elif v1_tuple > v2_tuple:
            return 1
        else:
            return 0
    except:
        return 0

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
        
    except Exception as e:
        print(f"Failed to log activity: {e}")

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
        cursor.execute('SELECT * FROM licenses WHERE license_key = ? AND active = 1', (license_key,))
        license_row = cursor.fetchone()
        
        if not license_row:
            log_activity(license_key, "VALIDATION", "INVALID_KEY", hardware_id, ip_address)
            return {"valid": False, "reason": "Invalid or inactive license key"}
        
        # Check expiry
        expiry_date = datetime.fromisoformat(license_row['expiry_date'])
        if expiry_date < datetime.now(timezone.utc):
            log_activity(license_key, "VALIDATION", "EXPIRED", hardware_id, ip_address)
            return {"valid": False, "reason": "License has expired"}
        
        # Hardware binding
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
        log_activity(license_key, "VALIDATION", "ERROR", hardware_id, ip_address, {"error": str(e)})
        return {"valid": False, "reason": "Validation error"}
    
    finally:
        conn.close()

def get_latest_version() -> Optional[Dict[str, Any]]:
    """Get the latest active version"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT * FROM app_versions 
            WHERE active = 1 
            ORDER BY created_date DESC 
            LIMIT 1
        ''')
        
        version_row = cursor.fetchone()
        conn.close()
        
        if version_row:
            return dict(version_row)
        return None
        
    except Exception as e:
        conn.close()
        return None

def check_for_updates(current_version: str) -> Dict[str, Any]:
    """Check if an update is available"""
    latest = get_latest_version()
    
    if not latest:
        return {"update_available": False, "message": "No versions available"}
    
    latest_version = latest['version']
    comparison = version_compare(current_version, latest_version)
    
    if comparison < 0:  # Current version is older
        return {
            "update_available": True,
            "latest_version": latest_version,
            "current_version": current_version,
            "is_critical": bool(latest['is_critical']),
            "release_notes": latest['release_notes'],
            "download_url": f"/api/download/{latest_version}",
            "file_size": latest['file_size'],
            "checksum": latest['checksum']
        }
    else:
        return {
            "update_available": False,
            "latest_version": latest_version,
            "current_version": current_version,
            "message": "You have the latest version"
        }

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
    title="Clean License Server",
    version=config.APP_VERSION,
    description="Lightweight license management with auto-update"
)

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
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
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM licenses")
        license_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM app_versions WHERE active = 1")
        version_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "status": "healthy",
            "version": config.APP_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "connected",
            "licenses": license_count,
            "app_versions": version_count
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
    client_ip = req.client.host
    
    result = validate_license(
        request.license_key,
        request.hardware_id,
        client_ip
    )
    
    # Add update check to validation response
    if result["valid"] and request.app_version:
        update_info = check_for_updates(request.app_version)
        result["update_info"] = update_info
    
    if result["valid"]:
        return result
    else:
        raise HTTPException(status_code=400, detail=result)

@app.post("/api/check-updates")
async def check_updates(request: VersionCheckRequest):
    log_activity(None, "UPDATE_CHECK", "SUCCESS", 
                details={"current_version": request.current_version, "app_name": request.app_name})
    
    return check_for_updates(request.current_version)

@app.get("/api/download/{version}")
async def download_version(version: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT * FROM app_versions 
            WHERE version = ? AND active = 1
        ''', (version,))
        
        version_row = cursor.fetchone()
        
        if not version_row:
            raise HTTPException(status_code=404, detail="Version not found")
        
        file_path = config.RELEASES_DIR / version_row['filename']
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        # Update download count
        cursor.execute('''
            UPDATE app_versions 
            SET download_count = download_count + 1 
            WHERE version = ?
        ''', (version,))
        conn.commit()
        
        log_activity(None, "FILE_DOWNLOAD", "SUCCESS", 
                    details={"version": version, "filename": version_row['filename']})
        
        return FileResponse(
            path=file_path,
            filename=version_row['filename'],
            media_type='application/octet-stream'
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Download failed")
    finally:
        conn.close()

@app.post("/api/admin/login")
async def admin_login(request: AdminLoginRequest):
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
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get license statistics
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
        
        # Get version statistics
        cursor.execute("SELECT COUNT(*) FROM app_versions WHERE active = 1")
        total_versions = cursor.fetchone()[0]
        
        cursor.execute("SELECT SUM(download_count) FROM app_versions")
        total_downloads = cursor.fetchone()[0] or 0
        
        # Recent activity
        cursor.execute("""
            SELECT * FROM activity_logs 
            ORDER BY timestamp DESC 
            LIMIT 20
        """)
        recent_activity = [dict(row) for row in cursor.fetchall()]
        
        # Latest version info
        latest_version = get_latest_version()
        
        conn.close()
        
        return {
            "total_licenses": total_licenses,
            "active_licenses": active_licenses,
            "valid_licenses": valid_licenses,
            "expired_licenses": expired_licenses,
            "total_versions": total_versions,
            "total_downloads": total_downloads,
            "latest_version": latest_version,
            "recent_activity": recent_activity
        }
        
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail="Dashboard error")

@app.post("/api/admin/upload-release", dependencies=[Depends(verify_admin_token)])
async def upload_release(
    file: UploadFile = File(...),
    version: str = Form(...),
    release_notes: str = Form(""),
    is_critical: bool = Form(False),
    min_required_version: str = Form(""),
    admin: str = Depends(verify_admin_token)
):
    # Validate file
    if file.size > config.MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail=f"File too large. Max size: {config.MAX_FILE_SIZE // (1024*1024)}MB")
    
    file_extension = Path(file.filename).suffix.lower()
    if file_extension not in config.ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Invalid file type. Allowed: {', '.join(config.ALLOWED_EXTENSIONS)}")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if version already exists
        cursor.execute("SELECT id FROM app_versions WHERE version = ?", (version,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Version already exists")
        
        # Save file
        filename = f"{version}_{file.filename}"
        file_path = config.RELEASES_DIR / filename
        
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Calculate checksum
        checksum = calculate_file_checksum(file_path)
        
        # Save to database
        cursor.execute('''
            INSERT INTO app_versions (version, filename, file_size, checksum, 
                                    release_notes, is_critical, min_required_version, created_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            version,
            filename,
            file.size,
            checksum,
            release_notes,
            1 if is_critical else 0,
            min_required_version if min_required_version else None,
            datetime.now(timezone.utc).isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        log_activity(None, "RELEASE_UPLOADED", "SUCCESS", 
                    details={"version": version, "admin": admin, "filename": filename})
        
        return {
            "success": True,
            "version": version,
            "filename": filename,
            "file_size": file.size,
            "checksum": checksum
        }
        
    except HTTPException:
        if 'file_path' in locals() and file_path.exists():
            file_path.unlink()
        raise
    except Exception as e:
        if 'file_path' in locals() and file_path.exists():
            file_path.unlink()
        conn.close()
        raise HTTPException(status_code=500, detail="Upload failed")

@app.get("/api/admin/licenses", dependencies=[Depends(verify_admin_token)])
async def list_licenses(
    page: int = 1,
    per_page: int = 20,
    search: Optional[str] = None,
    status: Optional[str] = None
):
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
        raise HTTPException(status_code=500, detail="Failed to fetch licenses")

@app.post("/api/admin/licenses", dependencies=[Depends(verify_admin_token)])
async def create_license(request: LicenseCreateRequest, admin: str = Depends(verify_admin_token)):
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
        raise HTTPException(status_code=500, detail="Failed to create license")

@app.get("/api/admin/versions", dependencies=[Depends(verify_admin_token)])
async def list_versions():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM app_versions ORDER BY created_date DESC')
        versions = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return {"versions": versions}
        
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail="Failed to fetch versions")

@app.delete("/api/admin/versions/{version_id}", dependencies=[Depends(verify_admin_token)])
async def delete_version(version_id: int, admin: str = Depends(verify_admin_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get version info
        cursor.execute("SELECT version, filename FROM app_versions WHERE id = ?", (version_id,))
        result = cursor.fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="Version not found")
        
        version = result['version']
        filename = result['filename']
        
        # Delete from database
        cursor.execute("DELETE FROM app_versions WHERE id = ?", (version_id,))
        conn.commit()
        conn.close()
        
        # Delete file
        file_path = config.RELEASES_DIR / filename
        if file_path.exists():
            file_path.unlink()
        
        log_activity(None, "VERSION_DELETED", "SUCCESS", 
                    details={"version": version, "admin": admin})
        
        return {"success": True, "message": "Version deleted"}
        
    except HTTPException:
        raise
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail="Failed to delete version")

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>License Server Admin</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f5f5f5; color: #333; line-height: 1.6; }
        .login-container { display: flex; justify-content: center; align-items: center; min-height: 100vh; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .login-box { background: white; padding: 2rem; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }
        .login-box h1 { text-align: center; margin-bottom: 2rem; color: #333; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
        input[type="text"], input[type="password"], input[type="email"], input[type="number"], select, textarea { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 5px; font-size: 1rem; }
        button { background: #667eea; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 5px; cursor: pointer; font-size: 1rem; font-weight: 500; transition: background 0.3s; }
        button:hover { background: #5a67d8; }
        .btn-secondary { background: #718096; }
        .btn-secondary:hover { background: #4a5568; }
        .btn-danger { background: #e53e3e; }
        .btn-danger:hover { background: #c53030; }
        .btn-success { background: #48bb78; }
        .btn-success:hover { background: #38a169; }
        .container { max-width: 1200px; margin: 0 auto; padding: 0 1rem; }
        .header { background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 1rem 0; margin-bottom: 2rem; }
        .header-content { display: flex; justify-content: space-between; align-items: center; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-card h3 { font-size: 0.9rem; color: #718096; margin-bottom: 0.5rem; }
        .stat-card p { font-size: 2rem; font-weight: 600; color: #333; }
        .content-section { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 2rem; }
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #e2e8f0; }
        th { background: #f7fafc; font-weight: 600; color: #4a5568; }
        tr:hover { background: #f7fafc; }
        .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 3px; font-size: 0.875rem; font-weight: 500; }
        .badge-active { background: #c6f6d5; color: #276749; }
        .badge-expired { background: #fed7d7; color: #9b2c2c; }
        .badge-inactive { background: #e2e8f0; color: #4a5568; }
        .actions { display: flex; gap: 0.5rem; }
        .actions button { padding: 0.25rem 0.75rem; font-size: 0.875rem; }
        .tab-nav { display: flex; gap: 1rem; margin-bottom: 2rem; border-bottom: 2px solid #e2e8f0; }
        .tab-link { padding: 0.5rem 1rem; background: none; border: none; cursor: pointer; font-size: 1rem; color: #718096; border-bottom: 2px solid transparent; transition: all 0.3s; }
        .tab-link.active { color: #667eea; border-bottom-color: #667eea; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .error-message { background: #fed7d7; color: #9b2c2c; padding: 1rem; border-radius: 5px; margin-bottom: 1rem; }
        .success-message { background: #c6f6d5; color: #276749; padding: 1rem; border-radius: 5px; margin-bottom: 1rem; }
        .upload-area { border: 2px dashed #e2e8f0; border-radius: 8px; padding: 2rem; text-align: center; margin-bottom: 1rem; transition: border-color 0.3s; }
        .upload-area.dragover { border-color: #667eea; background: #f7fafc; }
        .file-info { background: #f7fafc; padding: 1rem; border-radius: 5px; margin: 0.5rem 0; }
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
                        <h3>Total Downloads</h3>
                        <p id="totalDownloads">0</p>
                    </div>
                </div>
                
                <!-- Tab Navigation -->
                <div class="tab-nav">
                    <button class="tab-link active" onclick="showTab('licenses')">Licenses</button>
                    <button class="tab-link" onclick="showTab('versions')">Versions</button>
                    <button class="tab-link" onclick="showTab('create')">Create License</button>
                    <button class="tab-link" onclick="showTab('upload')">Upload Release</button>
                </div>
                
                <!-- Licenses Tab -->
                <div id="licensesTab" class="tab-content active">
                    <div class="content-section">
                        <div class="section-header">
                            <h2>License Management</h2>
                            <button onclick="loadLicenses()">Refresh</button>
                        </div>
                        
                        <table>
                            <thead>
                                <tr>
                                    <th>License Key</th>
                                    <th>Customer</th>
                                    <th>Created</th>
                                    <th>Expires</th>
                                    <th>Days Left</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody id="licensesTable">
                                <tr><td colspan="6" style="text-align: center;">Loading...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <!-- Versions Tab -->
                <div id="versionsTab" class="tab-content">
                    <div class="content-section">
                        <div class="section-header">
                            <h2>Version Management</h2>
                            <button onclick="loadVersions()">Refresh</button>
                        </div>
                        
                        <table>
                            <thead>
                                <tr>
                                    <th>Version</th>
                                    <th>Filename</th>
                                    <th>Size</th>
                                    <th>Downloads</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="versionsTable">
                                <tr><td colspan="6" style="text-align: center;">Loading...</td></tr>
                            </tbody>
                        </table>
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
                            
                            <button type="submit" class="btn-success">Create License</button>
                        </form>
                        
                        <div id="createResult" style="margin-top: 1rem;"></div>
                    </div>
                </div>
                
                <!-- Upload Release Tab -->
                <div id="uploadTab" class="tab-content">
                    <div class="content-section">
                        <h2>Upload New Release</h2>
                        
                        <form id="uploadForm">
                            <div class="upload-area" id="uploadArea">
                                <p>Drag & drop your release file here, or <strong>click to browse</strong></p>
                                <input type="file" id="fileInput" accept=".exe,.msi,.zip,.dmg,.pkg" style="display: none;">
                            </div>
                            
                            <div id="fileInfo" class="file-info" style="display: none;"></div>
                            
                            <div class="form-group">
                                <label for="releaseVersion">Version</label>
                                <input type="text" id="releaseVersion" placeholder="e.g., 1.2.3" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="releaseNotes">Release Notes</label>
                                <textarea id="releaseNotes" rows="4"></textarea>
                            </div>
                            
                            <button type="submit" id="uploadBtn" class="btn-success">Upload Release</button>
                        </form>
                        
                        <div id="uploadResult" style="margin-top: 1rem;"></div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <script>
        let authToken = null;
        let selectedFile = null;
        
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
                duration_days: parseInt(document.getElementById('durationDays').value)
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
                            License Key: <code>${result.license_key}</code>
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
        
        // File upload handling
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        
        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            handleFileSelect(e.dataTransfer.files[0]);
        });
        
        fileInput.addEventListener('change', (e) => {
            handleFileSelect(e.target.files[0]);
        });
        
        function handleFileSelect(file) {
            if (!file) return;
            
            selectedFile = file;
            document.getElementById('fileInfo').innerHTML = `
                <strong>Selected File:</strong> ${file.name}<br>
                <strong>Size:</strong> ${(file.size / (1024*1024)).toFixed(2)} MB
            `;
            document.getElementById('fileInfo').style.display = 'block';
        }
        
        // Upload form handler
        document.getElementById('uploadForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (!selectedFile) {
                alert('Please select a file first');
                return;
            }
            
            const formData = new FormData();
            formData.append('file', selectedFile);
            formData.append('version', document.getElementById('releaseVersion').value);
            formData.append('release_notes', document.getElementById('releaseNotes').value);
            
            const uploadBtn = document.getElementById('uploadBtn');
            uploadBtn.disabled = true;
            uploadBtn.textContent = 'Uploading...';
            
            try {
                const response = await fetch('/api/admin/upload-release', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${authToken}` },
                    body: formData
                });
                
                if (response.ok) {
                    const result = await response.json();
                    document.getElementById('uploadResult').innerHTML = `
                        <div class="success-message">
                            <strong>Release Uploaded Successfully!</strong><br>
                            Version: ${result.version}
                        </div>
                    `;
                    document.getElementById('uploadForm').reset();
                    selectedFile = null;
                    document.getElementById('fileInfo').style.display = 'none';
                    loadVersions();
                } else {
                    const error = await response.json();
                    document.getElementById('uploadResult').innerHTML = `
                        <div class="error-message">Upload failed: ${error.detail}</div>
                    `;
                }
                
                uploadBtn.disabled = false;
                uploadBtn.textContent = 'Upload Release';
                
            } catch (error) {
                document.getElementById('uploadResult').innerHTML = `
                    <div class="error-message">Upload error: ${error.message}</div>
                `;
                uploadBtn.disabled = false;
                uploadBtn.textContent = 'Upload Release';
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
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    document.getElementById('totalLicenses').textContent = data.total_licenses;
                    document.getElementById('activeLicenses').textContent = data.active_licenses;
                    document.getElementById('validLicenses').textContent = data.valid_licenses;
                    document.getElementById('totalDownloads').textContent = data.total_downloads;
                } else if (response.status === 401) {
                    logout();
                }
            } catch (error) {
                console.error('Dashboard load error:', error);
            }
        }
        
        async function loadLicenses() {
            try {
                const response = await fetch('/api/admin/licenses', {
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    displayLicenses(data.licenses);
                }
            } catch (error) {
                console.error('Licenses load error:', error);
            }
        }
        
        function displayLicenses(licenses) {
            const tbody = document.getElementById('licensesTable');
            
            if (licenses.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No licenses found</td></tr>';
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
                        <td>${statusBadge}</td>
                    </tr>
                `;
            }).join('');
        }
        
        async function loadVersions() {
            try {
                const response = await fetch('/api/admin/versions', {
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    displayVersions(data.versions);
                }
            } catch (error) {
                console.error('Versions load error:', error);
            }
        }
        
        function displayVersions(versions) {
            const tbody = document.getElementById('versionsTable');
            
            if (versions.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No versions found</td></tr>';
                return;
            }
            
            tbody.innerHTML = versions.map(version => {
                const createdDate = new Date(version.created_date).toLocaleDateString();
                const fileSize = (version.file_size / (1024*1024)).toFixed(2) + ' MB';
                
                return `
                    <tr>
                        <td><strong>${version.version}</strong></td>
                        <td>${version.filename}</td>
                        <td>${fileSize}</td>
                        <td>${version.download_count}</td>
                        <td>${createdDate}</td>
                        <td>
                            <div class="actions">
                                <button onclick="downloadVersion('${version.version}')" class="btn-secondary">Download</button>
                                <button onclick="deleteVersion(${version.id})" class="btn-danger">Delete</button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }
        
        function downloadVersion(version) {
            window.open(`/api/download/${version}`, '_blank');
        }
        
        async function deleteVersion(versionId) {
            if (!confirm('Are you sure you want to delete this version?')) return;
            
            try {
                const response = await fetch(`/api/admin/versions/${versionId}`, {
                    method: 'DELETE',
                    headers: { 'Authorization': `Bearer ${authToken}` }
                });
                
                if (response.ok) {
                    loadVersions();
                } else {
                    alert('Failed to delete version');
                }
            } catch (error) {
                alert('Network error');
            }
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
            
            // Load data based on tab
            if (tabName === 'versions') {
                loadVersions();
            }
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
    </script>
</body>
</html>""")

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    port = int(os.getenv('PORT', 8000))
    host = os.getenv('HOST', '0.0.0.0')
    
    print(f"Starting {config.APP_NAME} v{config.APP_VERSION} on {host}:{port}")
    print(f"Admin credentials: {config.ADMIN_USERNAME} / {config.ADMIN_PASSWORD}")
    print("Database: SQLite (no configuration needed)")
    print(f"Releases directory: {config.RELEASES_DIR}")
    
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )
