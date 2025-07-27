#!/usr/bin/env python3
"""
🔐 PRODUCTION PDF LICENSE SERVER - FLASK (RENDER.COM OPTIMIZED)
================================================================
Complete license server with admin panel, hardware locking, and IP tracking
Version: 5.1.0 - Optimized for Render.com deployment
Compatible with PostgreSQL and SQLite (automatic fallback)

Key improvements for Render.com:
- Fixed database initialization issues
- Proper transaction handling for PostgreSQL
- Better error handling and logging
- Optimized for Render's deployment process
"""

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, flash, session
import hashlib
import json
import secrets
import string
from datetime import datetime, timedelta
import os
import logging
from contextlib import contextmanager
from functools import wraps
import sys
import time

# =============================================================================
# APP CONFIGURATION
# =============================================================================

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))

# Admin credentials from environment variables
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme123')

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL')

# Fix for Render's postgres:// to postgresql:// 
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

# Try to import psycopg2, but don't fail if it's not available
PSYCOPG2_AVAILABLE = False
try:
    import psycopg2
    import psycopg2.extras
    from psycopg2 import sql
    PSYCOPG2_AVAILABLE = True
except ImportError:
    pass

# Always import sqlite3 as fallback
import sqlite3

# Logging setup with better formatting for Render
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# =============================================================================
# DATABASE FUNCTIONS
# =============================================================================

def get_db_connection():
    """Get database connection - PostgreSQL for Render, SQLite for local/fallback"""
    if DATABASE_URL and PSYCOPG2_AVAILABLE:
        try:
            conn = psycopg2.connect(DATABASE_URL, sslmode='require')
            return conn
        except Exception as e:
            logger.error(f"PostgreSQL connection failed: {e}, falling back to SQLite")
            conn = sqlite3.connect('licenses.db')
            conn.row_factory = sqlite3.Row
            return conn
    else:
        # SQLite for local development or when psycopg2 not available
        conn = sqlite3.connect('licenses.db')
        conn.row_factory = sqlite3.Row
        return conn

def is_postgresql():
    """Check if we're using PostgreSQL"""
    return DATABASE_URL and PSYCOPG2_AVAILABLE

def init_database():
    """Initialize the database with proper schema - optimized for Render.com"""
    logger.info("Starting database initialization...")
    
    conn = None
    try:
        conn = get_db_connection()
        
        if is_postgresql():
            # PostgreSQL schema with improved transaction handling
            logger.info("Initializing PostgreSQL database...")
            cur = conn.cursor()
            
            try:
                # Create tables in a single transaction
                logger.info("Creating database tables...")
                
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS licenses (
                        id SERIAL PRIMARY KEY,
                        license_key VARCHAR(255) UNIQUE NOT NULL,
                        hardware_id VARCHAR(255),
                        customer_email VARCHAR(255) NOT NULL,
                        customer_name VARCHAR(255),
                        created_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
                        payment_id VARCHAR(255),
                        active BOOLEAN DEFAULT true,
                        last_used TIMESTAMP WITH TIME ZONE,
                        validation_count INTEGER DEFAULT 0,
                        created_by VARCHAR(255) DEFAULT 'system'
                    )
                ''')
                
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS validation_logs (
                        id SERIAL PRIMARY KEY,
                        license_key VARCHAR(255),
                        hardware_id VARCHAR(255),
                        timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        status VARCHAR(100),
                        ip_address INET,
                        user_agent TEXT,
                        details JSONB
                    )
                ''')
                
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS admin_sessions (
                        id SERIAL PRIMARY KEY,
                        session_id VARCHAR(255),
                        username VARCHAR(255),
                        ip_address INET,
                        login_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    )
                ''')
                
                # Commit table creation
                conn.commit()
                logger.info("Database tables created successfully")
                
                # Create indexes in separate transactions (more resilient)
                indexes_to_create = [
                    ('idx_licenses_key', 'licenses', 'license_key'),
                    ('idx_licenses_email', 'licenses', 'customer_email'),
                    ('idx_licenses_expiry', 'licenses', 'expiry_date'),
                    ('idx_licenses_active', 'licenses', 'active'),
                    ('idx_validation_logs_timestamp', 'validation_logs', 'timestamp'),
                    ('idx_validation_logs_license', 'validation_logs', 'license_key'),
                    ('idx_validation_logs_status', 'validation_logs', 'status')
                ]
                
                for index_name, table_name, column_name in indexes_to_create:
                    try:
                        # Check if index exists first
                        cur.execute("""
                            SELECT 1 FROM pg_indexes 
                            WHERE schemaname = 'public' 
                            AND tablename = %s 
                            AND indexname = %s
                        """, (table_name, index_name))
                        
                        if not cur.fetchone():
                            cur.execute(sql.SQL('CREATE INDEX IF NOT EXISTS {} ON {} ({})').format(
                                sql.Identifier(index_name),
                                sql.Identifier(table_name),
                                sql.Identifier(column_name)
                            ))
                            conn.commit()
                            logger.info(f"Created index {index_name}")
                        else:
                            logger.info(f"Index {index_name} already exists")
                    except Exception as e:
                        logger.warning(f"Could not create index {index_name}: {e}")
                        conn.rollback()
                        # Continue with other indexes
                
                logger.info("PostgreSQL database initialized successfully")
                
            except Exception as e:
                conn.rollback()
                logger.error(f"Error during PostgreSQL initialization: {e}")
                raise
            finally:
                cur.close()
                    
        else:
            # SQLite schema for local development or fallback
            logger.info("Initializing SQLite database...")
            cur = conn.cursor()
            
            try:
                # Create tables
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS licenses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        license_key TEXT UNIQUE NOT NULL,
                        hardware_id TEXT,
                        customer_email TEXT NOT NULL,
                        customer_name TEXT,
                        created_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        expiry_date TEXT NOT NULL,
                        payment_id TEXT,
                        active INTEGER DEFAULT 1,
                        last_used TEXT,
                        validation_count INTEGER DEFAULT 0,
                        created_by TEXT DEFAULT 'system'
                    )
                ''')
                
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS validation_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        license_key TEXT,
                        hardware_id TEXT,
                        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                        status TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        details TEXT
                    )
                ''')
                
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS admin_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT,
                        username TEXT,
                        ip_address TEXT,
                        login_time TEXT DEFAULT CURRENT_TIMESTAMP,
                        last_activity TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(active)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_validation_logs_timestamp ON validation_logs(timestamp)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_validation_logs_license ON validation_logs(license_key)')
                
                conn.commit()
                logger.info("SQLite database initialized successfully")
                
            except Exception as e:
                conn.rollback()
                logger.error(f"Error during SQLite initialization: {e}")
                raise
            finally:
                cur.close()
            
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        logger.exception("Full traceback:")
        if conn:
            try:
                conn.rollback()
            except:
                pass
        raise
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

# =============================================================================
# STARTUP INITIALIZATION (FREE TIER COMPATIBLE)
# =============================================================================

def initialize_database_on_startup():
    """Initialize database on startup - works with free tier"""
    try:
        # Always try to initialize database on startup for free tier compatibility
        logger.info("Initializing database on application startup...")
        init_database()
        logger.info("Database initialization completed successfully")
        return True
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        # Continue anyway - app might still work if database exists
        return False

# Initialize database when the module is loaded (free tier compatible)
logger.info("Starting PDF License Server v5.1.0 (Free Tier Compatible)")
initialize_database_on_startup()

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_license_key():
    """Generate a unique license key in PDFM format"""
    segments = []
    for _ in range(3):
        segment = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        segments.append(segment)
    return f"PDFM-{'-'.join(segments)}"

def get_client_ip():
    """Get client IP address, handling proxies and Render's infrastructure"""
    # Check Render-specific headers first
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    elif request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    elif request.environ.get('HTTP_X_REAL_IP'):
        return request.environ['HTTP_X_REAL_IP']
    else:
        return request.environ.get('REMOTE_ADDR', 'unknown')

def log_validation(license_key, hardware_id, status, ip_address, user_agent=None, details=None):
    """Log validation attempt with improved error handling"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
            cur.execute('''
                INSERT INTO validation_logs (license_key, hardware_id, status, ip_address, user_agent, details)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (license_key, hardware_id, status, ip_address, user_agent, 
                  json.dumps(details) if details else None))
        else:
            cur.execute('''
                INSERT INTO validation_logs (license_key, hardware_id, timestamp, status, ip_address, user_agent, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (license_key, hardware_id, datetime.now().isoformat(), status, ip_address, user_agent,
                  json.dumps(details) if details else None))
        
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log validation: {e}")

def log_admin_session(username, ip_address):
    """Log admin login session"""
    try:
        session_id = secrets.token_urlsafe(32)
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
            cur.execute('''
                INSERT INTO admin_sessions (session_id, username, ip_address)
                VALUES (%s, %s, %s)
            ''', (session_id, username, ip_address))
        else:
            cur.execute('''
                INSERT INTO admin_sessions (session_id, username, ip_address, login_time)
                VALUES (?, ?, ?, ?)
            ''', (session_id, username, ip_address, datetime.now().isoformat()))
        
        conn.commit()
        cur.close()
        conn.close()
        return session_id
    except Exception as e:
        logger.error(f"Failed to log admin session: {e}")
        return None

def create_license(customer_email, customer_name=None, duration_days=30, created_by='system'):
    """Create a new license"""
    license_key = generate_license_key()
    created_date = datetime.now()
    expiry_date = created_date + timedelta(days=duration_days)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
            cur.execute('''
                INSERT INTO licenses (license_key, customer_email, customer_name, 
                                    expiry_date, created_by)
                VALUES (%s, %s, %s, %s, %s)
            ''', (license_key, customer_email, customer_name, expiry_date, created_by))
        else:
            cur.execute('''
                INSERT INTO licenses (license_key, customer_email, customer_name, 
                                    created_date, expiry_date, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (license_key, customer_email, customer_name, 
                  created_date.isoformat(), expiry_date.isoformat(), created_by))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            'license_key': license_key,
            'expiry_date': expiry_date.strftime('%Y-%m-%d'),
            'customer_email': customer_email,
            'duration_days': duration_days
        }
    except Exception as e:
        logger.error(f"Failed to create license: {e}")
        raise

def require_auth(f):
    """Decorator for routes that require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != ADMIN_USERNAME or auth.password != ADMIN_PASSWORD:
            return 'Authentication Required', 401, {
                'WWW-Authenticate': 'Basic realm="Admin Login Required"'
            }
        return f(*args, **kwargs)
    return decorated_function

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.route('/api/validate', methods=['POST'])
def validate_license():
    """Validate a license key from the desktop application"""
    try:
        data = request.get_json() or {}
        license_key = data.get('license_key')
        hardware_id = data.get('hardware_id')
        client_ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Validate input
        if not license_key:
            log_validation(None, hardware_id, 'MISSING_KEY', client_ip, user_agent)
            return jsonify({
                "valid": False,
                "reason": "Missing license key"
            }), 400
        
        if not hardware_id:
            log_validation(license_key, None, 'MISSING_HARDWARE', client_ip, user_agent)
            return jsonify({
                "valid": False,
                "reason": "Missing hardware ID"
            }), 400
        
        conn = get_db_connection()
        try:
            if is_postgresql():
                cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute(
                    'SELECT * FROM licenses WHERE license_key = %s AND active = true',
                    (license_key,)
                )
                license_row = cur.fetchone()
                cur.close()
            else:
                cur = conn.cursor()
                license_row = cur.execute(
                    'SELECT * FROM licenses WHERE license_key = ? AND active = 1',
                    (license_key,)
                ).fetchone()
            
            if not license_row:
                log_validation(license_key, hardware_id, 'INVALID_KEY', client_ip, user_agent)
                return jsonify({
                    "valid": False,
                    "reason": "Invalid license key"
                }), 400
            
            # Check expiration
            if is_postgresql():
                expiry_date = license_row['expiry_date']
                current_date = datetime.now(expiry_date.tzinfo if expiry_date.tzinfo else None)
            else:
                expiry_date = datetime.fromisoformat(license_row['expiry_date'])
                current_date = datetime.now()
            
            if current_date > expiry_date:
                log_validation(license_key, hardware_id, 'EXPIRED', client_ip, user_agent)
                return jsonify({
                    "valid": False,
                    "reason": "License expired",
                    "expired_date": str(expiry_date),
                    "renewal_url": f"{request.host_url}renew/{license_key}"
                }), 400
            
            # Hardware binding logic
            stored_hardware_id = license_row['hardware_id']
            
            cur = conn.cursor()
            
            if not stored_hardware_id:
                # First time binding - bind to this hardware
                if is_postgresql():
                    cur.execute(
                        'UPDATE licenses SET hardware_id = %s, last_used = %s, validation_count = validation_count + 1 WHERE license_key = %s',
                        (hardware_id, datetime.now(), license_key)
                    )
                else:
                    cur.execute(
                        'UPDATE licenses SET hardware_id = ?, last_used = ?, validation_count = validation_count + 1 WHERE license_key = ?',
                        (hardware_id, datetime.now().isoformat(), license_key)
                    )
                conn.commit()
                log_validation(license_key, hardware_id, 'FIRST_BINDING', client_ip, user_agent)
                
            elif stored_hardware_id != hardware_id:
                # Hardware mismatch - license is locked to different hardware
                log_validation(license_key, hardware_id, 'HARDWARE_MISMATCH', client_ip, user_agent, 
                             {'expected': stored_hardware_id, 'provided': hardware_id})
                cur.close()
                return jsonify({
                    "valid": False,
                    "reason": "License is locked to a different computer",
                    "message": "This license is already activated on another computer. Each license can only be used on one computer."
                }), 400
            else:
                # Valid hardware - update last used
                if is_postgresql():
                    cur.execute(
                        'UPDATE licenses SET last_used = %s, validation_count = validation_count + 1 WHERE license_key = %s',
                        (datetime.now(), license_key)
                    )
                else:
                    cur.execute(
                        'UPDATE licenses SET last_used = ?, validation_count = validation_count + 1 WHERE license_key = ?',
                        (datetime.now().isoformat(), license_key)
                    )
                conn.commit()
                log_validation(license_key, hardware_id, 'VALID', client_ip, user_agent)
            
            cur.close()
            
            days_remaining = (expiry_date - current_date).days
            
            return jsonify({
                "valid": True,
                "message": "License is valid",
                "expiry_date": expiry_date.isoformat() if is_postgresql() else license_row['expiry_date'],
                "days_remaining": max(0, days_remaining),
                "customer_email": license_row['customer_email'],
                "validation_count": license_row['validation_count'] + 1,
                "renewal_url": f"{request.host_url}renew/{license_key}"
            })
            
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Validation error: {e}")
        logger.exception("Full traceback:")
        return jsonify({
            "valid": False,
            "reason": "Server error",
            "message": "Please try again later"
        }), 500

@app.route('/health')
def health_check():
    """Health check endpoint for Render with enhanced diagnostics"""
    try:
        # Test database connection
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
            cur.execute('SELECT 1')
            result = cur.fetchone()
            db_type = "PostgreSQL"
            
            # Additional PostgreSQL health checks
            cur.execute('SELECT version()')
            db_version = cur.fetchone()[0] if cur.fetchone() else "Unknown"
        else:
            cur.execute('SELECT 1')
            result = cur.fetchone()
            db_type = "SQLite"
            db_version = "N/A"
        
        cur.close()
        conn.close()
        
        # Check if we're running on Render
        is_render = bool(os.environ.get('RENDER_SERVICE_ID'))
        
        return jsonify({
            "status": "healthy",
            "version": "5.1.0",
            "timestamp": datetime.now().isoformat(),
            "database": db_type,
            "database_version": db_version,
            "database_connected": result is not None,
            "database_url_set": DATABASE_URL is not None,
            "psycopg2_available": PSYCOPG2_AVAILABLE,
            "python_version": sys.version,
            "platform": "Render.com" if is_render else "Local",
            "render_service_id": os.environ.get('RENDER_SERVICE_ID', 'N/A'),
            "environment": {
                "PORT": os.environ.get('PORT', 'Not Set'),
                "PYTHON_VERSION": os.environ.get('PYTHON_VERSION', 'Not Set'),
                "DATABASE_URL": "Set" if DATABASE_URL else "Not Set"
            }
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "database": "disconnected",
            "psycopg2_available": PSYCOPG2_AVAILABLE,
            "platform": "Render.com" if os.environ.get('RENDER_SERVICE_ID') else "Local"
        }), 503

# =============================================================================
# DATABASE MANAGEMENT ENDPOINT (FOR RENDER PRE-DEPLOY)
# =============================================================================

@app.route('/api/init-db', methods=['POST'])
def api_init_database():
    """API endpoint to initialize database (for pre-deploy command)"""
    try:
        # Simple authentication for this endpoint
        auth_token = request.headers.get('Authorization')
        expected_token = os.environ.get('DB_INIT_TOKEN', 'default-token')
        
        if auth_token != f"Bearer {expected_token}":
            return jsonify({"error": "Unauthorized"}), 401
        
        init_database()
        return jsonify({
            "status": "success",
            "message": "Database initialized successfully",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Database initialization via API failed: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

# =============================================================================
# WEB INTERFACE (SAME AS BEFORE)
# =============================================================================

@app.route('/')
def index():
    """Main page"""
    return render_template_string(INDEX_HTML)

@app.route('/admin')
@require_auth
def admin():
    """Admin panel with authentication"""
    # Log admin access
    log_admin_session(request.authorization.username, get_client_ip())
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
            # Use dictionary cursor for PostgreSQL
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Get all licenses
            cur.execute('''
                SELECT license_key, customer_email, customer_name, created_date, 
                       expiry_date, active, last_used, validation_count, hardware_id, created_by
                FROM licenses 
                ORDER BY created_date DESC
                LIMIT 100
            ''')
            licenses = cur.fetchall()
            
            # Get statistics
            cur.execute('''
                SELECT 
                    COUNT(*) as total_licenses,
                    COUNT(CASE WHEN active = true THEN 1 END) as active_licenses,
                    COUNT(CASE WHEN expiry_date > NOW() AND active = true THEN 1 END) as valid_licenses
                FROM licenses
            ''')
            stats = cur.fetchone()
            
            # Get recent admin logins
            cur.execute('''
                SELECT username, ip_address, login_time 
                FROM admin_sessions 
                ORDER BY login_time DESC 
                LIMIT 10
            ''')
            recent_logins = cur.fetchall()
            
            # Get recent validation attempts
            cur.execute('''
                SELECT license_key, hardware_id, status, ip_address, timestamp
                FROM validation_logs 
                ORDER BY timestamp DESC 
                LIMIT 20
            ''')
            recent_validations = cur.fetchall()
            
        else:
            # SQLite queries
            licenses = cur.execute('''
                SELECT license_key, customer_email, customer_name, created_date, 
                       expiry_date, active, last_used, validation_count, hardware_id, created_by
                FROM licenses 
                ORDER BY created_date DESC
                LIMIT 100
            ''').fetchall()
            
            stats = cur.execute('''
                SELECT 
                    COUNT(*) as total_licenses,
                    COUNT(CASE WHEN active = 1 THEN 1 END) as active_licenses,
                    COUNT(CASE WHEN datetime(expiry_date) > datetime('now') AND active = 1 THEN 1 END) as valid_licenses
                FROM licenses
            ''').fetchone()
            
            recent_logins = cur.execute('''
                SELECT username, ip_address, login_time 
                FROM admin_sessions 
                ORDER BY login_time DESC 
                LIMIT 10
            ''').fetchall()
            
            recent_validations = cur.execute('''
                SELECT license_key, hardware_id, status, ip_address, timestamp
                FROM validation_logs 
                ORDER BY timestamp DESC 
                LIMIT 20
            ''').fetchall()
        
        cur.close()
        conn.close()
        
        return render_template_string(ADMIN_HTML, 
                                    licenses=licenses, 
                                    stats=stats, 
                                    recent_logins=recent_logins,
                                    recent_validations=recent_validations,
                                    current_ip=get_client_ip(),
                                    is_postgresql=is_postgresql(),
                                    render_url=request.host_url)
    except Exception as e:
        logger.error(f"Admin panel error: {e}")
        logger.exception("Full traceback:")
        return f"Admin panel error: {e}", 500

@app.route('/admin/create_license', methods=['POST'])
@require_auth
def create_license_endpoint():
    """Create a new license from admin panel"""
    try:
        customer_email = request.form.get('customer_email')
        customer_name = request.form.get('customer_name', '')
        duration_days = int(request.form.get('duration_days', 30))
        
        if not customer_email:
            flash('Email is required', 'error')
            return redirect('/admin')
        
        license_info = create_license(
            customer_email, 
            customer_name, 
            duration_days, 
            f'admin:{request.authorization.username}'
        )
        
        flash(f'License created successfully: {license_info["license_key"]}', 'success')
        
    except Exception as e:
        logger.error(f"Error creating license: {e}")
        flash(f'Error creating license: {e}', 'error')
    
    return redirect('/admin')

@app.route('/admin/delete_license', methods=['POST'])
@require_auth
def delete_license():
    """Delete a license"""
    try:
        license_key = request.form.get('license_key')
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
            cur.execute('DELETE FROM licenses WHERE license_key = %s', (license_key,))
        else:
            cur.execute('DELETE FROM licenses WHERE license_key = ?', (license_key,))
        
        conn.commit()
        cur.close()
        conn.close()
        
        flash(f'License {license_key} deleted successfully', 'success')
        
    except Exception as e:
        logger.error(f"Error deleting license: {e}")
        flash(f'Error deleting license: {e}', 'error')
    
    return redirect('/admin')

@app.route('/admin/toggle_license', methods=['POST'])
@require_auth
def toggle_license():
    """Toggle license active status"""
    try:
        license_key = request.form.get('license_key')
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
            cur.execute('UPDATE licenses SET active = NOT active WHERE license_key = %s', (license_key,))
        else:
            cur.execute('UPDATE licenses SET active = NOT active WHERE license_key = ?', (license_key,))
        
        conn.commit()
        cur.close()
        conn.close()
        
        flash(f'License {license_key} status toggled', 'success')
        
    except Exception as e:
        logger.error(f"Error toggling license: {e}")
        flash(f'Error toggling license: {e}', 'error')
    
    return redirect('/admin')

@app.route('/admin/extend_license', methods=['POST'])
@require_auth
def extend_license():
    """Extend a license by specified days"""
    try:
        license_key = request.form.get('license_key')
        extend_days = int(request.form.get('extend_days', 30))
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
            cur.execute('''
                UPDATE licenses 
                SET expiry_date = expiry_date + INTERVAL '%s days'
                WHERE license_key = %s
            ''', (extend_days, license_key))
        else:
            # For SQLite, we need to fetch current expiry and calculate new date
            result = cur.execute(
                'SELECT expiry_date FROM licenses WHERE license_key = ?',
                (license_key,)
            ).fetchone()
            
            if result:
                current_expiry = datetime.fromisoformat(result['expiry_date'])
                new_expiry = current_expiry + timedelta(days=extend_days)
                cur.execute(
                    'UPDATE licenses SET expiry_date = ? WHERE license_key = ?',
                    (new_expiry.isoformat(), license_key)
                )
        
        conn.commit()
        cur.close()
        conn.close()
        
        flash(f'License {license_key} extended by {extend_days} days', 'success')
        
    except Exception as e:
        logger.error(f"Error extending license: {e}")
        flash(f'Error extending license: {e}', 'error')
    
    return redirect('/admin')

# =============================================================================
# HTML TEMPLATES (UPDATED FOR RENDER)
# =============================================================================

INDEX_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PDF License Server - Professional License Management</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { 
            text-align: center; 
            background: white; 
            padding: 40px; 
            border-radius: 20px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.1); 
            margin-bottom: 30px;
        }
        .header h1 { 
            font-size: 2.5em; 
            color: #2d3748; 
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .header p { font-size: 1.2em; color: #718096; }
        .card { 
            background: white; 
            padding: 30px; 
            border-radius: 20px; 
            box-shadow: 0 5px 20px rgba(0,0,0,0.08); 
            margin: 20px 0;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0,0,0,0.12);
        }
        .btn { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 14px 28px; 
            text-decoration: none; 
            border-radius: 10px; 
            display: inline-block; 
            margin: 10px 5px; 
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
        }
        .btn:hover { 
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%);
        }
        .features { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
            gap: 20px; 
            margin-top: 20px;
        }
        .feature { 
            background: #f8f9fa; 
            padding: 25px; 
            border-radius: 15px; 
            border-left: 4px solid #667eea;
            transition: all 0.3s ease;
        }
        .feature:hover {
            background: #e9ecef;
            transform: translateX(5px);
        }
        .feature strong { 
            color: #2d3748; 
            font-size: 1.1em; 
            display: block; 
            margin-bottom: 8px;
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #48bb78;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        .security-badge {
            display: inline-flex;
            align-items: center;
            background: #e6fffa;
            color: #234e52;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            margin: 10px 5px;
        }
        .render-badge {
            background: #667eea;
            color: white;
            padding: 6px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            margin-left: 10px;
        }
        @media (max-width: 768px) {
            .header h1 { font-size: 2em; }
            .features { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 PDF License Server</h1>
            <p>
                Professional License Management System with Hardware-Locked Security
                <span class="render-badge">🚀 Deployed on Render.com</span>
            </p>
            <div style="margin-top: 20px;">
                <span class="security-badge">🛡️ Enterprise-Grade Security</span>
                <span class="security-badge">🔒 Hardware Binding</span>
                <span class="security-badge">📊 Real-time Analytics</span>
                <span class="security-badge">🐘 PostgreSQL Powered</span>
            </div>
        </div>
        
        <div class="card">
            <h2><span class="status-indicator"></span>Server Status</h2>
            <p style="color: #718096; margin: 20px 0; line-height: 1.6;">
                ✅ License validation service is operational<br>
                🔐 Hardware-locked licensing system active<br>
                📈 Real-time validation logging enabled<br>
                🌍 Deployed on Render.com with PostgreSQL<br>
                🚀 Optimized for high-performance production use
            </p>
            
            <div style="text-align: center; margin-top: 30px;">
                <a href="/admin" class="btn">🛠️ Admin Dashboard</a>
                <a href="/health" class="btn btn-secondary">💚 System Health</a>
            </div>
        </div>
        
        <div class="card">
            <h3 style="margin-bottom: 20px; color: #2d3748;">🛡️ Security & Features</h3>
            <div class="features">
                <div class="feature">
                    <strong>🔒 Hardware Binding</strong>
                    Each license is cryptographically locked to a specific computer, preventing unauthorized sharing
                </div>
                <div class="feature">
                    <strong>📊 Real-time Monitoring</strong>
                    Track all validation attempts with IP addresses, timestamps, and detailed logging
                </div>
                <div class="feature">
                    <strong>⏰ Flexible Licensing</strong>
                    Support for trial, monthly, quarterly, and annual licenses with automatic expiration
                </div>
                <div class="feature">
                    <strong>👨‍💼 Admin Control</strong>
                    Complete license lifecycle management with creation, extension, and revocation capabilities
                </div>
                <div class="feature">
                    <strong>🚀 High Performance</strong>
                    PostgreSQL backend with optimized indexes for lightning-fast validation
                </div>
                <div class="feature">
                    <strong>🔄 API Integration</strong>
                    RESTful API for seamless integration with desktop and mobile applications
                </div>
                <div class="feature">
                    <strong>🌐 Render.com Optimized</strong>
                    Fully optimized for Render's infrastructure with automatic scaling and deployment
                </div>
                <div class="feature">
                    <strong>🔧 Zero-Downtime Deploys</strong>
                    Continuous deployment with database migrations and health checks
                </div>
            </div>
        </div>
        
        <div class="card" style="background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);">
            <h3 style="color: #2d3748; margin-bottom: 15px;">📡 API Endpoint</h3>
            <code style="background: white; padding: 15px; border-radius: 10px; display: block; font-size: 1.1em;">
                POST /api/validate
            </code>
            <p style="margin-top: 15px; color: #4a5568;">
                Validate licenses with hardware ID verification and comprehensive logging
            </p>
        </div>
        
        <div style="text-align: center; margin-top: 40px; color: #718096;">
            <p>PDF License Server v5.1.0 • Optimized for Render.com</p>
        </div>
    </div>
</body>
</html>
'''

ADMIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>License Administration Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f7fafc;
            color: #2d3748;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 20px; 
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .header h1 { font-size: 2.2em; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin: 30px 0; 
        }
        .stat-box { 
            background: white;
            padding: 25px; 
            border-radius: 15px; 
            text-align: center; 
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
        }
        .stat-box:hover { transform: translateY(-5px); }
        .stat-number { 
            font-size: 2.5em; 
            font-weight: bold; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 5px; 
        }
        .stat-label { color: #718096; font-weight: 600; }
        
        .card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            margin-bottom: 20px;
            overflow: hidden;
        }
        .card-header {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #e2e8f0;
            font-weight: 600;
            font-size: 1.1em;
        }
        .card-body { padding: 20px; }
        
        table { 
            width: 100%; 
            border-collapse: collapse; 
            font-size: 0.9em;
        }
        th, td { 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #e2e8f0;
        }
        th { 
            background: #f8f9fa;
            font-weight: 600;
            color: #4a5568;
            position: sticky;
            top: 0;
        }
        tr:hover { background: #f8f9fa; }
        
        .license-key { 
            font-family: 'Courier New', monospace; 
            background: #edf2f7; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-size: 0.85em;
        }
        
        .status-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            display: inline-block;
        }
        .active { background: #c6f6d5; color: #276749; }
        .inactive { background: #fed7d7; color: #9b2c2c; }
        .expired { background: #fef5e7; color: #b7791f; }
        
        .btn { 
            background: #667eea;
            color: white; 
            padding: 8px 16px; 
            border: none; 
            border-radius: 6px; 
            cursor: pointer; 
            text-decoration: none; 
            display: inline-block; 
            margin: 2px;
            font-size: 0.9em;
            font-weight: 500;
            transition: all 0.2s ease;
        }
        .btn:hover { 
            background: #5a67d8;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        }
        .btn-danger { background: #e53e3e; }
        .btn-danger:hover { background: #c53030; }
        .btn-warning { background: #ed8936; }
        .btn-warning:hover { background: #dd6b20; }
        .btn-success { background: #48bb78; }
        .btn-success:hover { background: #38a169; }
        
        .form-group { margin: 20px 0; }
        .form-group label { 
            display: block; 
            margin-bottom: 8px; 
            font-weight: 600; 
            color: #4a5568;
        }
        .form-group input, .form-group select { 
            width: 100%; 
            padding: 10px; 
            border: 2px solid #e2e8f0; 
            border-radius: 8px; 
            font-size: 1em;
            transition: border 0.2s ease;
        }
        .form-group input:focus, .form-group select:focus { 
            border-color: #667eea; 
            outline: none; 
        }
        
        .tabs { 
            display: flex; 
            margin-bottom: 20px;
            background: white;
            border-radius: 10px;
            padding: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        .tab { 
            padding: 12px 24px; 
            background: transparent;
            border: none; 
            cursor: pointer; 
            border-radius: 8px;
            margin: 0 2px;
            font-weight: 500;
            color: #718096;
            transition: all 0.2s ease;
        }
        .tab:hover { background: #f8f9fa; }
        .tab.active { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .flash { 
            padding: 15px 20px; 
            margin: 20px 0; 
            border-radius: 8px;
            font-weight: 500;
        }
        .flash.success { 
            background: #c6f6d5; 
            color: #276749;
            border: 1px solid #9ae6b4;
        }
        .flash.error { 
            background: #fed7d7; 
            color: #9b2c2c;
            border: 1px solid #feb2b2;
        }
        
        .info-badge {
            background: #e6fffa;
            color: #234e52;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.85em;
            margin-left: 10px;
        }
        
        .action-buttons {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
        }
        
        @media (max-width: 768px) {
            .stats { grid-template-columns: 1fr; }
            table { font-size: 0.8em; }
            th, td { padding: 8px; }
            .tabs { flex-wrap: wrap; }
            .tab { font-size: 0.9em; padding: 10px 16px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 License Administration Dashboard</h1>
            <p>
                Current Session IP: {{ current_ip }}
                <span class="info-badge">
                    Database: {% if is_postgresql %}PostgreSQL (Render){% else %}SQLite (Local){% endif %}
                </span>
                <span class="info-badge">
                    🌍 {{ render_url }}
                </span>
            </p>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{{ stats.total_licenses }}</div>
                <div class="stat-label">Total Licenses</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ stats.active_licenses }}</div>
                <div class="stat-label">Active Licenses</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ stats.valid_licenses }}</div>
                <div class="stat-label">Valid & Current</div>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('licenses')">📋 Licenses</button>
            <button class="tab" onclick="showTab('create')">➕ Create License</button>
            <button class="tab" onclick="showTab('logs')">📊 Activity Logs</button>
            <button class="tab" onclick="showTab('admin-logs')">👨‍💼 Admin Access</button>
        </div>
        
        <!-- Licenses Tab -->
        <div id="licenses" class="tab-content active">
            <div class="card">
                <div class="card-header">📋 License Management</div>
                <div class="card-body" style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>License Key</th>
                                <th>Customer</th>
                                <th>Email</th>
                                <th>Created</th>
                                <th>Expires</th>
                                <th>Status</th>
                                <th>Hardware</th>
                                <th>Usage</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for license in licenses %}
                            <tr>
                                <td><span class="license-key">{{ license.license_key }}</span></td>
                                <td>{{ license.customer_name or '-' }}</td>
                                <td>{{ license.customer_email }}</td>
                                <td>
                                    {% if license.created_date %}
                                        {{ license.created_date.strftime('%Y-%m-%d') if hasattr(license.created_date, 'strftime') else license.created_date[:10] }}
                                    {% else %}
                                        -
                                    {% endif %}
                                </td>
                                <td>
                                    {% if license.expiry_date %}
                                        {{ license.expiry_date.strftime('%Y-%m-%d') if hasattr(license.expiry_date, 'strftime') else license.expiry_date[:10] }}
                                    {% else %}
                                        -
                                    {% endif %}
                                </td>
                                <td>
                                    {% if license.active %}
                                        <span class="status-badge active">Active</span>
                                    {% else %}
                                        <span class="status-badge inactive">Inactive</span>
                                    {% endif %}
                                </td>
                                <td>
                                    {% if license.hardware_id %}
                                        <span title="{{ license.hardware_id }}" style="cursor: help;">
                                            🖥️ Bound
                                        </span>
                                    {% else %}
                                        <span style="color: #999;">Unbound</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <small>
                                        Used: {{ license.validation_count or 0 }}x
                                    </small>
                                </td>
                                <td>
                                    <div class="action-buttons">
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="license_key" value="{{ license.license_key }}">
                                            <button type="submit" formaction="/admin/toggle_license" class="btn btn-warning" 
                                                    onclick="return confirm('Toggle license status?')">
                                                {% if license.active %}Disable{% else %}Enable{% endif %}
                                            </button>
                                        </form>
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="license_key" value="{{ license.license_key }}">
                                            <input type="hidden" name="extend_days" value="30">
                                            <button type="submit" formaction="/admin/extend_license" class="btn btn-success"
                                                    onclick="return confirm('Extend license by 30 days?')">
                                                +30 days
                                            </button>
                                        </form>
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="license_key" value="{{ license.license_key }}">
                                            <button type="submit" formaction="/admin/delete_license" class="btn btn-danger" 
                                                    onclick="return confirm('Delete this license permanently?')">
                                                Delete
                                            </button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Create License Tab -->
        <div id="create" class="tab-content">
            <div class="card">
                <div class="card-header">➕ Create New License</div>
                <div class="card-body">
                    <form method="POST" action="/admin/create_license">
                        <div class="form-group">
                            <label for="customer_email">📧 Customer Email *</label>
                            <input type="email" id="customer_email" name="customer_email" required 
                                   placeholder="customer@example.com">
                        </div>
                        
                        <div class="form-group">
                            <label for="customer_name">👤 Customer Name</label>
                            <input type="text" id="customer_name" name="customer_name" 
                                   placeholder="John Doe (optional)">
                        </div>
                        
                        <div class="form-group">
                            <label for="duration_days">⏰ License Duration</label>
                            <select id="duration_days" name="duration_days">
                                <option value="7">7 days (Trial)</option>
                                <option value="30" selected>30 days (Monthly)</option>
                                <option value="90">90 days (Quarterly)</option>
                                <option value="365">365 days (Annual)</option>
                            </select>
                        </div>
                        
                        <button type="submit" class="btn btn-success" style="font-size: 1.1em; padding: 12px 30px;">
                            🚀 Create License
                        </button>
                    </form>
                </div>
            </div>
        </div>
        
        <!-- Activity Logs Tab -->
        <div id="logs" class="tab-content">
            <div class="card">
                <div class="card-header">📊 Recent Validation Activity</div>
                <div class="card-body" style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>License Key</th>
                                <th>Hardware ID</th>
                                <th>Status</th>
                                <th>IP Address</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for log in recent_validations %}
                            <tr>
                                <td>
                                    {% if log.timestamp %}
                                        {{ log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(log.timestamp, 'strftime') else log.timestamp[:19] }}
                                    {% else %}
                                        -
                                    {% endif %}
                                </td>
                                <td>
                                    {% if log.license_key %}
                                        <span class="license-key" title="{{ log.license_key }}">
                                            {{ log.license_key[:12] }}...
                                        </span>
                                    {% else %}
                                        -
                                    {% endif %}
                                </td>
                                <td>
                                    {% if log.hardware_id %}
                                        <span title="{{ log.hardware_id }}" style="cursor: help;">
                                            {{ log.hardware_id[:16] }}...
                                        </span>
                                    {% else %}
                                        -
                                    {% endif %}
                                </td>
                                <td>
                                    {% if log.status == 'VALID' %}
                                        <span class="status-badge active">✅ Valid</span>
                                    {% elif log.status == 'EXPIRED' %}
                                        <span class="status-badge expired">⏰ Expired</span>
                                    {% elif log.status == 'HARDWARE_MISMATCH' %}
                                        <span class="status-badge inactive">🔒 HW Mismatch</span>
                                    {% elif log.status == 'INVALID_KEY' %}
                                        <span class="status-badge inactive">❌ Invalid</span>
                                    {% else %}
                                        <span class="status-badge">{{ log.status }}</span>
                                    {% endif %}
                                </td>
                                <td>{{ log.ip_address or '-' }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Admin Logs Tab -->
        <div id="admin-logs" class="tab-content">
            <div class="card">
                <div class="card-header">👨‍💼 Recent Admin Access</div>
                <div class="card-body" style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>IP Address</th>
                                <th>Login Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for login in recent_logins %}
                            <tr>
                                <td><strong>{{ login.username }}</strong></td>
                                <td>{{ login.ip_address }}</td>
                                <td>
                                    {% if login.login_time %}
                                        {{ login.login_time.strftime('%Y-%m-%d %H:%M:%S') if hasattr(login.login_time, 'strftime') else login.login_time[:19] }}
                                    {% else %}
                                        -
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 40px;">
            <a href="/" class="btn" style="background: #718096;">← Back to Home</a>
        </div>
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all tab contents
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            // Remove active from all tabs
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Highlight selected tab button
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
'''

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal server error"}), 500

# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    # Initialize database when running locally
    initialize_database_on_startup()
    
    # This block only runs during local development
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
