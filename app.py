#!/usr/bin/env python3
"""
🔐 MODERN PDF LICENSE SERVER - FLASK 3.0+ PROFESSIONAL EDITION
================================================================
Complete license server with modern admin panel, hardware locking, IP tracking, and data preservation
Version: 6.0.0 - Modern Flask 3.0+ Edition with Data Preservation and Modern UI

🚀 PROFESSIONAL FEATURES:
- Modern Flask 3.0+ architecture with data preservation
- Professional modern UI with Material Design principles
- Complete license key and hardware ID display
- Enhanced error handling and logging
- Data-preserving database management
- Responsive modern dashboard design
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
import traceback

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

# Enhanced logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Global flag to track database initialization status
DATABASE_INITIALIZED = False
INITIALIZATION_ATTEMPTS = 0
MAX_INITIALIZATION_ATTEMPTS = 3
FIRST_REQUEST_HANDLED = False

# =============================================================================
# PROFESSIONAL JINJA2 FILTERS
# =============================================================================

@app.template_filter('formatdatetime')
def format_datetime(value, format='%Y-%m-%d'):
    """Format a datetime object to a string. Handles None values gracefully."""
    if value is None:
        return "-"
    try:
        if hasattr(value, 'strftime'):
            return value.strftime(format)
        elif isinstance(value, str):
            try:
                parsed_date = datetime.fromisoformat(value.replace('Z', '+00:00'))
                return parsed_date.strftime(format)
            except:
                return value[:10] if len(value) >= 10 else value
        else:
            return str(value)
    except Exception as e:
        logger.warning(f"Error formatting datetime {value}: {e}")
        return str(value) if value else "-"

@app.template_filter('formatdatetimefull')
def format_datetime_full(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a datetime object to a full string with time."""
    if value is None:
        return "-"
    try:
        if hasattr(value, 'strftime'):
            return value.strftime(format)
        elif isinstance(value, str):
            try:
                parsed_date = datetime.fromisoformat(value.replace('Z', '+00:00'))
                return parsed_date.strftime(format)
            except:
                return value[:19] if len(value) >= 19 else value
        else:
            return str(value)
    except Exception as e:
        logger.warning(f"Error formatting datetime {value}: {e}")
        return str(value) if value else "-"

# Make Python built-ins available in templates
app.jinja_env.globals.update({
    'hasattr': hasattr,
    'len': len,
    'str': str,
    'int': int,
    'float': float,
    'bool': bool,
})

# =============================================================================
# DATA-PRESERVING DATABASE FUNCTIONS
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

def check_table_exists(table_name):
    """Check if a specific table exists in the database"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = %s
                );
            """, (table_name,))
            exists = cur.fetchone()[0]
        else:
            cur.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name=?;
            """, (table_name,))
            exists = cur.fetchone() is not None
        
        cur.close()
        conn.close()
        return exists
    except Exception as e:
        logger.error(f"Error checking if table {table_name} exists: {e}")
        return False

def get_database_status():
    """Get comprehensive database status for diagnostics"""
    status = {
        'connection': False,
        'type': 'unknown',
        'tables': {},
        'version': 'unknown',
        'issues': []
    }
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        status['connection'] = True
        
        if is_postgresql():
            status['type'] = 'PostgreSQL'
            try:
                cur.execute('SELECT version()')
                status['version'] = cur.fetchone()[0]
            except:
                status['version'] = 'Unknown PostgreSQL'
            
            # Check all required tables
            required_tables = ['licenses', 'validation_logs', 'admin_sessions']
            for table in required_tables:
                status['tables'][table] = {
                    'exists': check_table_exists(table),
                    'columns': []
                }
                
                if status['tables'][table]['exists']:
                    try:
                        cur.execute("""
                            SELECT column_name FROM information_schema.columns 
                            WHERE table_name = %s AND table_schema = 'public'
                            ORDER BY ordinal_position
                        """, (table,))
                        status['tables'][table]['columns'] = [row[0] for row in cur.fetchall()]
                    except Exception as e:
                        status['issues'].append(f"Could not get columns for {table}: {e}")
                else:
                    status['issues'].append(f"Table {table} does not exist")
        else:
            status['type'] = 'SQLite'
            try:
                cur.execute('SELECT sqlite_version()')
                status['version'] = f"SQLite {cur.fetchone()[0]}"
            except:
                status['version'] = 'Unknown SQLite'
            
            # Check all required tables
            required_tables = ['licenses', 'validation_logs', 'admin_sessions']
            for table in required_tables:
                status['tables'][table] = {
                    'exists': check_table_exists(table),
                    'columns': []
                }
                
                if status['tables'][table]['exists']:
                    try:
                        cur.execute(f"PRAGMA table_info({table})")
                        status['tables'][table]['columns'] = [column[1] for column in cur.fetchall()]
                    except Exception as e:
                        status['issues'].append(f"Could not get columns for {table}: {e}")
                else:
                    status['issues'].append(f"Table {table} does not exist")
        
        cur.close()
        conn.close()
        
    except Exception as e:
        status['issues'].append(f"Database connection failed: {e}")
        logger.error(f"Database status check failed: {e}")
    
    return status

def safe_init_database():
    """SAFE database initialization - creates tables ONLY if they don't exist (preserves data)"""
    global DATABASE_INITIALIZED, INITIALIZATION_ATTEMPTS
    
    INITIALIZATION_ATTEMPTS += 1
    logger.info(f"🔧 SAFE DATABASE INITIALIZATION - Attempt {INITIALIZATION_ATTEMPTS}")
    
    conn = None
    try:
        conn = get_db_connection()
        
        if is_postgresql():
            logger.info("🐘 Safely initializing PostgreSQL database...")
            conn.autocommit = True
            cur = conn.cursor()
            
            try:
                # Create licenses table ONLY if it doesn't exist
                if not check_table_exists('licenses'):
                    logger.info("📋 Creating licenses table...")
                    cur.execute('''
                        CREATE TABLE licenses (
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
                    logger.info("✅ Licenses table created successfully")
                else:
                    logger.info("✅ Licenses table already exists, preserving data")
                
                # Create validation_logs table ONLY if it doesn't exist
                if not check_table_exists('validation_logs'):
                    logger.info("📊 Creating validation_logs table...")
                    cur.execute('''
                        CREATE TABLE validation_logs (
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
                    logger.info("✅ Validation_logs table created successfully")
                else:
                    logger.info("✅ Validation_logs table already exists, preserving data")
                
                # Create admin_sessions table ONLY if it doesn't exist
                if not check_table_exists('admin_sessions'):
                    logger.info("👨‍💼 Creating admin_sessions table...")
                    cur.execute('''
                        CREATE TABLE admin_sessions (
                            id SERIAL PRIMARY KEY,
                            session_id VARCHAR(255),
                            username VARCHAR(255),
                            ip_address INET,
                            login_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                            last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                        )
                    ''')
                    logger.info("✅ Admin_sessions table created successfully")
                else:
                    logger.info("✅ Admin_sessions table already exists, preserving data")
                
                # Create indexes for performance (IF NOT EXISTS)
                logger.info("🚀 Creating performance indexes...")
                indexes = [
                    'CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)',
                    'CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email)',
                    'CREATE INDEX IF NOT EXISTS idx_licenses_expiry ON licenses(expiry_date)',
                    'CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(active)',
                    'CREATE INDEX IF NOT EXISTS idx_validation_logs_timestamp ON validation_logs(timestamp)',
                    'CREATE INDEX IF NOT EXISTS idx_validation_logs_license ON validation_logs(license_key)',
                    'CREATE INDEX IF NOT EXISTS idx_validation_logs_status ON validation_logs(status)'
                ]
                
                for index_sql in indexes:
                    try:
                        cur.execute(index_sql)
                        logger.info(f"✅ Created/verified index: {index_sql.split()[-1]}")
                    except Exception as e:
                        logger.warning(f"⚠️ Index creation warning: {e}")
                
                # Insert sample data ONLY if licenses table is empty
                cur.execute('SELECT COUNT(*) FROM licenses')
                count = cur.fetchone()[0]
                if count == 0:
                    logger.info("🎯 Creating sample license for testing...")
                    cur.execute('''
                        INSERT INTO licenses (license_key, customer_email, customer_name, expiry_date, created_by)
                        VALUES (%s, %s, %s, %s, %s)
                    ''', ('PDFM-DEMO-TEST-SMPL', 'demo@example.com', 'Demo User', 
                          (datetime.now() + timedelta(days=365)).isoformat(), 'auto-setup'))
                    logger.info("✅ Sample license created")
                else:
                    logger.info(f"✅ Found {count} existing licenses, preserving all data")
                
                logger.info("🎉 PostgreSQL database safely initialized with data preservation!")
                
            except Exception as e:
                logger.error(f"❌ Error during PostgreSQL initialization: {e}")
                logger.error(f"Full traceback: {traceback.format_exc()}")
                raise
            finally:
                cur.close()
                    
        else:
            # SQLite schema for local development or fallback
            logger.info("💾 Safely initializing SQLite database...")
            cur = conn.cursor()
            
            try:
                # Create tables ONLY if they don't exist
                if not check_table_exists('licenses'):
                    cur.execute('''
                        CREATE TABLE licenses (
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
                    logger.info("✅ Licenses table created")
                else:
                    logger.info("✅ Licenses table already exists, preserving data")
                
                if not check_table_exists('validation_logs'):
                    cur.execute('''
                        CREATE TABLE validation_logs (
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
                    logger.info("✅ Validation_logs table created")
                else:
                    logger.info("✅ Validation_logs table already exists, preserving data")
                
                if not check_table_exists('admin_sessions'):
                    cur.execute('''
                        CREATE TABLE admin_sessions (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            session_id TEXT,
                            username TEXT,
                            ip_address TEXT,
                            login_time TEXT DEFAULT CURRENT_TIMESTAMP,
                            last_activity TEXT DEFAULT CURRENT_TIMESTAMP
                        )
                    ''')
                    logger.info("✅ Admin_sessions table created")
                else:
                    logger.info("✅ Admin_sessions table already exists, preserving data")
                
                # Create indexes
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(active)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_validation_logs_timestamp ON validation_logs(timestamp)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_validation_logs_license ON validation_logs(license_key)')
                
                # Insert sample data ONLY if licenses table is empty
                result = cur.execute('SELECT COUNT(*) FROM licenses').fetchone()
                count = result[0] if result else 0
                if count == 0:
                    cur.execute('''
                        INSERT OR IGNORE INTO licenses (license_key, customer_email, customer_name, expiry_date, created_by)
                        VALUES (?, ?, ?, ?, ?)
                    ''', ('PDFM-DEMO-TEST-SMPL', 'demo@example.com', 'Demo User', 
                          (datetime.now() + timedelta(days=365)).isoformat(), 'auto-setup'))
                    logger.info("✅ Sample license created")
                else:
                    logger.info(f"✅ Found {count} existing licenses, preserving all data")
                
                conn.commit()
                logger.info("🎉 SQLite database safely initialized with data preservation!")
                
            except Exception as e:
                conn.rollback()
                logger.error(f"❌ Error during SQLite initialization: {e}")
                logger.error(f"Full traceback: {traceback.format_exc()}")
                raise
            finally:
                cur.close()
        
        DATABASE_INITIALIZED = True
        logger.info("✅ SAFE DATABASE INITIALIZATION COMPLETED SUCCESSFULLY!")
        return True
            
    except Exception as e:
        logger.error(f"💥 CRITICAL: Safe database initialization failed: {e}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        DATABASE_INITIALIZED = False
        return False
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

def ensure_database_ready():
    """Ensure database is ready with intelligent checking"""
    global DATABASE_INITIALIZED
    
    if DATABASE_INITIALIZED:
        return True
    
    # Check if essential tables exist
    required_tables = ['licenses', 'validation_logs', 'admin_sessions']
    missing_tables = []
    
    for table in required_tables:
        if not check_table_exists(table):
            missing_tables.append(table)
    
    if missing_tables:
        logger.warning(f"🔧 Missing tables detected: {missing_tables}. Triggering safe initialization...")
        return safe_init_database()
    else:
        DATABASE_INITIALIZED = True
        return True

# =============================================================================
# FLASK 3.0+ COMPATIBLE STARTUP SYSTEM
# =============================================================================

@app.before_request
def initialize_database_before_first_request():
    """Flask 3.0+ compatible database auto-initialization"""
    global DATABASE_INITIALIZED, FIRST_REQUEST_HANDLED
    
    if not FIRST_REQUEST_HANDLED:
        FIRST_REQUEST_HANDLED = True
        logger.info("🔧 Flask 3.0+ auto-initialization triggered")
        
        if not DATABASE_INITIALIZED:
            logger.info("🔄 Database not initialized, attempting safe initialization...")
            success = safe_init_database()
            
            if success:
                logger.info("✅ Database successfully initialized before first request!")
            else:
                logger.error("❌ Database initialization failed before first request!")

def initialize_database_on_startup():
    """Initialize database on startup - Flask 3.0+ edition with safe approach"""
    global DATABASE_INITIALIZED
    
    logger.info("🚀 PDF License Server v6.0.0 - Modern Flask 3.0+ Edition Starting...")
    logger.info("🔧 Safe database initialization for data preservation...")
    
    try:
        logger.info("📡 Safe initialization with app context...")
        with app.app_context():
            if safe_init_database():
                logger.info("✅ SUCCESS - Database safely initialized with data preservation")
                return True
    except Exception as e:
        logger.warning(f"⚠️ Startup initialization warning: {e}")
    
    logger.info("🎯 Will use @app.before_request fallback (Flask 3.0+ compatible)")
    DATABASE_INITIALIZED = False
    return False

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
        if not ensure_database_ready():
            logger.error("Database not ready for logging validation")
            return
        
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
    """Log admin login session with database readiness check"""
    try:
        if not ensure_database_ready():
            logger.error("Database not ready for logging admin session")
            return None
        
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
    """Create a new license with database readiness check"""
    if not ensure_database_ready():
        raise Exception("Database not ready for license creation")
    
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
        if not ensure_database_ready():
            return jsonify({
                "valid": False,
                "reason": "Server database error - please try again",
                "message": "The server is currently initializing. Please retry in a moment."
            }), 503
        
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
    """Enhanced health check endpoint with comprehensive diagnostics"""
    try:
        db_status = get_database_status()
        is_render = bool(os.environ.get('RENDER_SERVICE_ID'))
        overall_health = "healthy" if db_status['connection'] and len(db_status['issues']) == 0 else "degraded"
        status_code = 200 if overall_health == "healthy" else 503
        
        return jsonify({
            "status": overall_health,
            "version": "6.0.0 - Modern Flask 3.0+ Edition with Data Preservation",
            "timestamp": datetime.now().isoformat(),
            "flask_version": "3.0+ Modern Compatible",
            "database": {
                "type": db_status['type'],
                "version": db_status['version'],
                "connected": db_status['connection'],
                "initialized": DATABASE_INITIALIZED,
                "tables": db_status['tables'],
                "issues": db_status['issues']
            },
            "initialization": {
                "attempts": INITIALIZATION_ATTEMPTS,
                "max_attempts": MAX_INITIALIZATION_ATTEMPTS,
                "status": "success" if DATABASE_INITIALIZED else "pending",
                "first_request_handled": FIRST_REQUEST_HANDLED
            },
            "environment": {
                "platform": "Render.com" if is_render else "Local",
                "render_service_id": os.environ.get('RENDER_SERVICE_ID', 'N/A'),
                "port": os.environ.get('PORT', 'Not Set'),
                "python_version": sys.version,
                "database_url_set": DATABASE_URL is not None,
                "psycopg2_available": PSYCOPG2_AVAILABLE
            }
        }), status_code
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        logger.exception("Health check error details:")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "database": "disconnected",
            "psycopg2_available": PSYCOPG2_AVAILABLE,
            "platform": "Render.com" if os.environ.get('RENDER_SERVICE_ID') else "Local"
        }), 503

# =============================================================================
# MODERN WEB INTERFACE
# =============================================================================

@app.route('/')
def index():
    """Modern main page"""
    ensure_database_ready()
    return render_template_string(MODERN_INDEX_HTML, 
                                database_status=DATABASE_INITIALIZED,
                                initialization_attempts=INITIALIZATION_ATTEMPTS)

@app.route('/admin')
@require_auth
def admin():
    """Modern admin panel with data preservation"""
    log_admin_session(request.authorization.username, get_client_ip())
    
    if not ensure_database_ready():
        return render_template_string(MODERN_REPAIR_HTML, 
                                    current_ip=get_client_ip(),
                                    db_status=get_database_status(),
                                    initialization_attempts=INITIALIZATION_ATTEMPTS)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
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
            
            recent_validations = cur.execute('''
                SELECT license_key, hardware_id, status, ip_address, timestamp
                FROM validation_logs 
                ORDER BY timestamp DESC 
                LIMIT 20
            ''').fetchall()
        
        cur.close()
        conn.close()
        
        return render_template_string(MODERN_ADMIN_HTML, 
                                    licenses=licenses, 
                                    stats=stats, 
                                    recent_validations=recent_validations,
                                    current_ip=get_client_ip(),
                                    is_postgresql=is_postgresql(),
                                    render_url=request.host_url,
                                    db_status=get_database_status(),
                                    database_initialized=DATABASE_INITIALIZED,
                                    initialization_attempts=INITIALIZATION_ATTEMPTS)
    except Exception as e:
        logger.error(f"Admin panel error: {e}")
        logger.exception("Full traceback:")
        
        return render_template_string(MODERN_REPAIR_HTML, 
                                    current_ip=get_client_ip(),
                                    db_status=get_database_status(),
                                    initialization_attempts=INITIALIZATION_ATTEMPTS,
                                    error_message=str(e))

@app.route('/admin/safe-repair', methods=['POST'])
@require_auth
def admin_safe_repair():
    """Admin panel safe database repair - preserves data"""
    try:
        logger.info("🔧 ADMIN PANEL SAFE DATABASE REPAIR INITIATED")
        
        success = safe_init_database()
        
        if success:
            flash('✅ Database safely repaired! Missing tables created, existing data preserved.', 'success')
        else:
            flash('❌ Database repair failed. Please check the logs for details.', 'error')
        
    except Exception as e:
        logger.error(f"Admin safe repair failed: {e}")
        flash(f'❌ Database repair error: {e}', 'error')
    
    return redirect('/admin')

@app.route('/admin/create_license', methods=['POST'])
@require_auth
def create_license_endpoint():
    """Create a new license from admin panel"""
    try:
        if not ensure_database_ready():
            flash('❌ Database not ready. Please try the repair button first.', 'error')
            return redirect('/admin')
        
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
        
        flash(f'✅ License created successfully: {license_info["license_key"]}', 'success')
        
    except Exception as e:
        logger.error(f"Error creating license: {e}")
        flash(f'❌ Error creating license: {e}', 'error')
    
    return redirect('/admin')

@app.route('/admin/delete_license', methods=['POST'])
@require_auth
def delete_license():
    """Delete a license"""
    try:
        if not ensure_database_ready():
            flash('❌ Database not ready. Please try the repair button first.', 'error')
            return redirect('/admin')
        
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
        
        flash(f'✅ License {license_key} deleted successfully', 'success')
        
    except Exception as e:
        logger.error(f"Error deleting license: {e}")
        flash(f'❌ Error deleting license: {e}', 'error')
    
    return redirect('/admin')

@app.route('/admin/toggle_license', methods=['POST'])
@require_auth
def toggle_license():
    """Toggle license active status"""
    try:
        if not ensure_database_ready():
            flash('❌ Database not ready. Please try the repair button first.', 'error')
            return redirect('/admin')
        
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
        
        flash(f'✅ License {license_key} status toggled', 'success')
        
    except Exception as e:
        logger.error(f"Error toggling license: {e}")
        flash(f'❌ Error toggling license: {e}', 'error')
    
    return redirect('/admin')

@app.route('/admin/extend_license', methods=['POST'])
@require_auth
def extend_license():
    """Extend a license by specified days"""
    try:
        if not ensure_database_ready():
            flash('❌ Database not ready. Please try the repair button first.', 'error')
            return redirect('/admin')
        
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
        
        flash(f'✅ License {license_key} extended by {extend_days} days', 'success')
        
    except Exception as e:
        logger.error(f"Error extending license: {e}")
        flash(f'❌ Error extending license: {e}', 'error')
    
    return redirect('/admin')

# =============================================================================
# MODERN HTML TEMPLATES
# =============================================================================

MODERN_INDEX_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>PDF License Server - Modern Flask Edition</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2563eb;
            --primary-dark: #1d4ed8;
            --secondary-color: #64748b;
            --success-color: #059669;
            --background: #f8fafc;
            --surface: #ffffff;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --border: #e2e8f0;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
        }

        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
        }

        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--background);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 2rem; 
        }

        .header {
            text-align: center;
            background: var(--surface);
            padding: 3rem;
            border-radius: 1rem;
            box-shadow: var(--shadow-lg);
            margin-bottom: 2rem;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(135deg, var(--primary-color), var(--success-color));
        }

        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, var(--primary-color), var(--success-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header p {
            font-size: 1.125rem;
            color: var(--text-secondary);
            margin-bottom: 2rem;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: #dcfce7;
            color: #166534;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-weight: 500;
            font-size: 0.875rem;
        }

        .card {
            background: var(--surface);
            border-radius: 1rem;
            box-shadow: var(--shadow);
            margin-bottom: 2rem;
            overflow: hidden;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }

        .card-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border);
            background: #f8fafc;
        }

        .card-body {
            padding: 2rem;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 0.5rem;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.2s;
            cursor: pointer;
            font-size: 0.875rem;
        }

        .btn-primary {
            background: var(--primary-color);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
        }

        .btn-success {
            background: var(--success-color);
            color: white;
        }

        .btn-success:hover {
            background: #047857;
            transform: translateY(-1px);
        }

        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-top: 2rem;
        }

        .feature {
            background: #f8fafc;
            padding: 1.5rem;
            border-radius: 0.75rem;
            border-left: 4px solid var(--primary-color);
            transition: all 0.2s;
        }

        .feature:hover {
            background: #f1f5f9;
            transform: translateX(4px);
        }

        .feature h3 {
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
        }

        .feature p {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }

        .actions {
            display: flex;
            gap: 1rem;
            justify-content: center;
            margin-top: 2rem;
        }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 1rem;
            background: {% if database_status %}#dcfce7{% else %}#fef3c7{% endif %};
            border: 1px solid {% if database_status %}#bbf7d0{% else %}#fde68a{% endif %};
            border-radius: 0.5rem;
            margin-bottom: 2rem;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: {% if database_status %}#059669{% else %}#d97706{% endif %};
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .header h1 { font-size: 2rem; }
            .features { grid-template-columns: 1fr; }
            .actions { flex-direction: column; align-items: center; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="bi bi-shield-lock"></i> PDF License Server</h1>
            <p>Modern Flask 3.0+ Professional Edition with Data Preservation Technology</p>
            <div class="status-badge">
                <i class="bi bi-check-circle"></i>
                Enterprise License Management System
            </div>
        </div>

        <div class="status-indicator">
            <div class="status-dot"></div>
            <div>
                <strong>System Status:</strong>
                {% if database_status %}
                    <span style="color: #059669;">✅ Database Operational ({{ initialization_attempts }} initialization attempts)</span>
                {% else %}
                    <span style="color: #d97706;">⚠️ Database Initializing ({{ initialization_attempts }} attempts)</span>
                {% endif %}
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h2><i class="bi bi-server"></i> Professional License Validation Service</h2>
            </div>
            <div class="card-body">
                <p style="margin-bottom: 2rem; font-size: 1.125rem; color: var(--text-secondary);">
                    Modern Flask 3.0+ architecture providing enterprise-grade license validation with hardware binding,
                    real-time analytics, and comprehensive audit logging. Deployed on Render.com with PostgreSQL for
                    maximum reliability and performance.
                </p>
                
                <div class="actions">
                    <a href="/admin" class="btn btn-primary">
                        <i class="bi bi-gear"></i>
                        Admin Dashboard
                    </a>
                    <a href="/health" class="btn btn-success">
                        <i class="bi bi-heart-pulse"></i>
                        System Health
                    </a>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3><i class="bi bi-stars"></i> Modern Professional Features</h3>
            </div>
            <div class="card-body">
                <div class="features">
                    <div class="feature">
                        <h3><i class="bi bi-shield-check"></i> Data Preservation</h3>
                        <p>Smart initialization that preserves existing license data while creating missing database structures</p>
                    </div>
                    <div class="feature">
                        <h3><i class="bi bi-cpu"></i> Hardware Binding</h3>
                        <p>Cryptographically secure hardware locking prevents unauthorized license sharing</p>
                    </div>
                    <div class="feature">
                        <h3><i class="bi bi-graph-up"></i> Real-time Analytics</h3>
                        <p>Comprehensive validation logging and usage analytics with professional dashboard</p>
                    </div>
                    <div class="feature">
                        <h3><i class="bi bi-cloud"></i> Cloud Optimized</h3>
                        <p>Fully optimized for Render.com with PostgreSQL and automatic scaling capabilities</p>
                    </div>
                    <div class="feature">
                        <h3><i class="bi bi-clock-history"></i> Flexible Licensing</h3>
                        <p>Support for trial, monthly, quarterly, and annual licenses with automatic expiration handling</p>
                    </div>
                    <div class="feature">
                        <h3><i class="bi bi-lightning"></i> Modern Architecture</h3>
                        <p>Flask 3.0+ compatible with modern UI, responsive design, and professional aesthetics</p>
                    </div>
                </div>
            </div>
        </div>

        <div style="text-align: center; margin-top: 3rem; padding: 2rem; color: var(--text-secondary);">
            <p><strong>PDF License Server v6.0.0 - Modern Flask 3.0+ Edition</strong></p>
            <p>Professional License Management • Data Preservation Technology • Modern UI Design</p>
        </div>
    </div>
</body>
</html>
'''

MODERN_REPAIR_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Database Repair - Modern Flask Edition</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --danger-color: #dc2626;
            --warning-color: #d97706;
            --success-color: #059669;
            --background: #fef2f2;
            --surface: #ffffff;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --border: #e2e8f0;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body { 
            font-family: 'Inter', sans-serif;
            background: var(--background);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 2rem;
        }

        .container { max-width: 800px; margin: 0 auto; }

        .header {
            text-align: center;
            background: var(--surface);
            padding: 2rem;
            border-radius: 1rem;
            box-shadow: 0 10px 25px rgba(220, 38, 38, 0.1);
            margin-bottom: 2rem;
            border: 1px solid #fecaca;
        }

        .card {
            background: var(--surface);
            border-radius: 1rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 2rem;
            overflow: hidden;
        }

        .card-header {
            padding: 1.5rem;
            background: #f8fafc;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
        }

        .card-body { padding: 2rem; }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 0.5rem;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.2s;
            cursor: pointer;
        }

        .btn-danger {
            background: var(--danger-color);
            color: white;
        }

        .btn-danger:hover {
            background: #b91c1c;
            transform: translateY(-1px);
        }

        .diagnostic-table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }

        .diagnostic-table th, .diagnostic-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        .diagnostic-table th {
            background: #f8fafc;
            font-weight: 600;
        }

        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            font-weight: 500;
        }

        .status-error { background: #fecaca; color: #991b1b; }
        .status-success { background: #dcfce7; color: #166534; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="bi bi-tools"></i> Database Repair System</h1>
            <p>Modern Flask 3.0+ Professional Database Recovery</p>
        </div>

        {% if error_message %}
        <div class="card">
            <div class="card-header" style="color: var(--danger-color);">
                <i class="bi bi-exclamation-triangle"></i> Critical Error Detected
            </div>
            <div class="card-body">
                <p><strong>Error:</strong> {{ error_message }}</p>
            </div>
        </div>
        {% endif %}

        <div class="card">
            <div class="card-header">
                <i class="bi bi-clipboard-data"></i> Database Diagnostic Report
            </div>
            <div class="card-body">
                <p><strong>Initialization Attempts:</strong> {{ initialization_attempts }}</p>
                <p><strong>Database Type:</strong> {{ db_status.type }}</p>
                <p><strong>Connection Status:</strong>
                    {% if db_status.connection %}
                        <span class="status-badge status-success">Connected</span>
                    {% else %}
                        <span class="status-badge status-error">Disconnected</span>
                    {% endif %}
                </p>

                <h4 style="margin: 1.5rem 0 1rem 0;">Table Status:</h4>
                <table class="diagnostic-table">
                    <thead>
                        <tr>
                            <th>Table Name</th>
                            <th>Status</th>
                            <th>Columns</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for table_name, table_info in db_status.tables.items() %}
                        <tr>
                            <td><strong>{{ table_name }}</strong></td>
                            <td>
                                {% if table_info.exists %}
                                    <span class="status-badge status-success">Exists</span>
                                {% else %}
                                    <span class="status-badge status-error">Missing</span>
                                {% endif %}
                            </td>
                            <td>{{ table_info.columns|length if table_info.columns else 0 }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <i class="bi bi-wrench"></i> Safe Repair Actions
            </div>
            <div class="card-body">
                <p style="margin-bottom: 1.5rem;">
                    The safe repair system will create missing database tables and indexes while 
                    <strong>preserving all existing data</strong>. This operation is completely safe 
                    and will not affect your current licenses or logs.
                </p>
                
                <form method="POST" action="/admin/safe-repair" style="text-align: center;">
                    <button type="submit" class="btn btn-danger" 
                            onclick="return confirm('Proceed with safe database repair? Existing data will be preserved.')">
                        <i class="bi bi-tools"></i>
                        Execute Safe Repair
                    </button>
                </form>
                
                <div style="text-align: center; margin-top: 2rem;">
                    <a href="/admin" class="btn" style="background: #6b7280; color: white;">
                        <i class="bi bi-arrow-left"></i> Back to Admin
                    </a>
                    <a href="/" class="btn" style="background: #059669; color: white;">
                        <i class="bi bi-house"></i> Home
                    </a>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''

MODERN_ADMIN_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>License Admin Dashboard - Modern Edition</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2563eb;
            --success-color: #059669;
            --warning-color: #d97706;
            --danger-color: #dc2626;
            --background: #f8fafc;
            --surface: #ffffff;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --border: #e2e8f0;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body { 
            font-family: 'Inter', sans-serif;
            background: var(--background);
            color: var(--text-primary);
        }

        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 1.5rem; 
        }

        .header {
            background: linear-gradient(135deg, var(--primary-color), #1d4ed8);
            color: white;
            padding: 2rem;
            border-radius: 1rem;
            margin-bottom: 2rem;
            box-shadow: 0 10px 25px rgba(37, 99, 235, 0.15);
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }

        .stat-box {
            background: var(--surface);
            padding: 2rem;
            border-radius: 1rem;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            transition: transform 0.2s;
        }

        .stat-box:hover { transform: translateY(-2px); }

        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }

        .card {
            background: var(--surface);
            border-radius: 1rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            margin-bottom: 2rem;
            overflow: hidden;
        }

        .card-header {
            background: #f8fafc;
            padding: 1.5rem;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
            display: flex;
            justify-content: between;
            align-items: center;
        }

        .card-body { padding: 1.5rem; }

        .tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 2rem;
            background: var(--surface);
            padding: 0.5rem;
            border-radius: 0.75rem;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }

        .tab {
            padding: 0.75rem 1.5rem;
            border: none;
            background: transparent;
            border-radius: 0.5rem;
            cursor: pointer;
            font-weight: 500;
            color: var(--text-secondary);
            transition: all 0.2s;
        }

        .tab.active {
            background: var(--primary-color);
            color: white;
        }

        .tab-content { display: none; }
        .tab-content.active { display: block; }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }

        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: #f8fafc;
            font-weight: 600;
            color: var(--text-primary);
        }

        tr:hover { background: #f8fafc; }

        .license-key, .hardware-id {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            background: #f1f5f9;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.8rem;
            cursor: pointer;
            position: relative;
            max-width: 200px;
            word-break: break-all;
        }

        .hardware-id { background: #ecfdf5; }

        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .active { background: #dcfce7; color: #166534; }
        .inactive { background: #fecaca; color: #991b1b; }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 0.375rem;
            cursor: pointer;
            text-decoration: none;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.2s;
            margin: 0.125rem;
        }

        .btn-primary { background: var(--primary-color); color: white; }
        .btn-success { background: var(--success-color); color: white; }
        .btn-warning { background: var(--warning-color); color: white; }
        .btn-danger { background: var(--danger-color); color: white; }

        .btn:hover { transform: translateY(-1px); opacity: 0.9; }

        .form-group { margin: 1rem 0; }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }

        .form-group input, .form-group select {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            font-size: 1rem;
        }

        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .flash {
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 0.5rem;
            font-weight: 500;
        }

        .flash.success {
            background: #dcfce7;
            color: #166534;
            border: 1px solid #bbf7d0;
        }

        .flash.error {
            background: #fecaca;
            color: #991b1b;
            border: 1px solid #fca5a5;
        }

        .action-buttons {
            display: flex;
            gap: 0.25rem;
            flex-wrap: wrap;
        }

        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .stats { grid-template-columns: 1fr; }
            .tabs { flex-wrap: wrap; }
            table { font-size: 0.75rem; }
            th, td { padding: 0.5rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="bi bi-shield-lock"></i> License Administration Dashboard</h1>
            <p>Modern Flask 3.0+ Professional Edition • IP: {{ current_ip }} • Database: {% if is_postgresql %}PostgreSQL{% else %}SQLite{% endif %}</p>
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
            <button class="tab active" onclick="showTab('licenses')">
                <i class="bi bi-list-ul"></i> Licenses
            </button>
            <button class="tab" onclick="showTab('create')">
                <i class="bi bi-plus-circle"></i> Create License
            </button>
            <button class="tab" onclick="showTab('activity')">
                <i class="bi bi-activity"></i> Activity Logs
            </button>
            <button class="tab" onclick="showTab('diagnostics')">
                <i class="bi bi-wrench"></i> Diagnostics
            </button>
        </div>

        <!-- Licenses Tab -->
        <div id="licenses" class="tab-content active">
            <div class="card">
                <div class="card-header">
                    <span><i class="bi bi-list-ul"></i> License Management</span>
                    <span style="background: #e0e7ff; color: #3730a3; padding: 0.25rem 0.75rem; border-radius: 0.375rem; font-size: 0.875rem;">
                        Total: {{ licenses|length }}
                    </span>
                </div>
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
                                <th>Hardware ID</th>
                                <th>Usage</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for license in licenses %}
                            <tr>
                                <td>
                                    <div class="license-key" title="{{ license.license_key }}">
                                        {{ license.license_key }}
                                    </div>
                                </td>
                                <td>{{ license.customer_name or '-' }}</td>
                                <td>{{ license.customer_email }}</td>
                                <td>{{ license.created_date|formatdatetime }}</td>
                                <td>{{ license.expiry_date|formatdatetime }}</td>
                                <td>
                                    {% if license.active %}
                                        <span class="status-badge active">Active</span>
                                    {% else %}
                                        <span class="status-badge inactive">Inactive</span>
                                    {% endif %}
                                </td>
                                <td>
                                    {% if license.hardware_id %}
                                        <div class="hardware-id" title="{{ license.hardware_id }}">
                                            {{ license.hardware_id }}
                                        </div>
                                    {% else %}
                                        <span style="color: #9ca3af;">Unbound</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <small>{{ license.validation_count or 0 }}x</small>
                                </td>
                                <td>
                                    <div class="action-buttons">
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="license_key" value="{{ license.license_key }}">
                                            <button type="submit" formaction="/admin/toggle_license" class="btn btn-warning">
                                                {% if license.active %}Disable{% else %}Enable{% endif %}
                                            </button>
                                        </form>
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="license_key" value="{{ license.license_key }}">
                                            <input type="hidden" name="extend_days" value="30">
                                            <button type="submit" formaction="/admin/extend_license" class="btn btn-success">
                                                +30d
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
                <div class="card-header">
                    <i class="bi bi-plus-circle"></i> Create New License
                </div>
                <div class="card-body">
                    <form method="POST" action="/admin/create_license">
                        <div class="form-group">
                            <label for="customer_email"><i class="bi bi-envelope"></i> Customer Email *</label>
                            <input type="email" id="customer_email" name="customer_email" required 
                                   placeholder="customer@example.com">
                        </div>
                        
                        <div class="form-group">
                            <label for="customer_name"><i class="bi bi-person"></i> Customer Name</label>
                            <input type="text" id="customer_name" name="customer_name" 
                                   placeholder="John Doe (optional)">
                        </div>
                        
                        <div class="form-group">
                            <label for="duration_days"><i class="bi bi-calendar"></i> License Duration</label>
                            <select id="duration_days" name="duration_days">
                                <option value="7">7 days (Trial)</option>
                                <option value="30" selected>30 days (Monthly)</option>
                                <option value="90">90 days (Quarterly)</option>
                                <option value="365">365 days (Annual)</option>
                            </select>
                        </div>
                        
                        <button type="submit" class="btn btn-success" style="padding: 0.75rem 2rem;">
                            <i class="bi bi-plus-circle"></i>
                            Create License
                        </button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Activity Logs Tab -->
        <div id="activity" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-activity"></i> Recent Validation Activity
                </div>
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
                                <td>{{ log.timestamp|formatdatetimefull }}</td>
                                <td>
                                    {% if log.license_key %}
                                        <div class="license-key" title="{{ log.license_key }}">
                                            {{ log.license_key }}
                                        </div>
                                    {% else %}
                                        -
                                    {% endif %}
                                </td>
                                <td>
                                    {% if log.hardware_id %}
                                        <div class="hardware-id" title="{{ log.hardware_id }}">
                                            {{ log.hardware_id }}
                                        </div>
                                    {% else %}
                                        -
                                    {% endif %}
                                </td>
                                <td>
                                    {% if log.status == 'VALID' %}
                                        <span class="status-badge active">✅ Valid</span>
                                    {% elif log.status == 'EXPIRED' %}
                                        <span class="status-badge" style="background: #fef3c7; color: #92400e;">⏰ Expired</span>
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

        <!-- Diagnostics Tab -->
        <div id="diagnostics" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <span><i class="bi bi-wrench"></i> System Diagnostics</span>
                    <div>
                        <a href="/health" class="btn btn-success">
                            <i class="bi bi-heart-pulse"></i> Health Report
                        </a>
                        <form method="POST" action="/admin/safe-repair" style="display: inline;">
                            <button type="submit" class="btn btn-warning" 
                                    onclick="return confirm('Execute safe database repair? This will create missing tables while preserving existing data.')">
                                <i class="bi bi-tools"></i> Safe Repair
                            </button>
                        </form>
                    </div>
                </div>
                <div class="card-body">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
                        <div style="background: #f8fafc; padding: 1.5rem; border-radius: 0.75rem;">
                            <h4><i class="bi bi-database"></i> Database Status</h4>
                            <p><strong>Type:</strong> {{ db_status.type }}</p>
                            <p><strong>Version:</strong> {{ db_status.version }}</p>
                            <p><strong>Connection:</strong> 
                                {% if db_status.connection %}
                                    <span class="status-badge active">Connected</span>
                                {% else %}
                                    <span class="status-badge inactive">Disconnected</span>
                                {% endif %}
                            </p>
                            <p><strong>Initialized:</strong> 
                                {% if database_initialized %}
                                    <span class="status-badge active">Yes</span>
                                {% else %}
                                    <span class="status-badge inactive">No</span>
                                {% endif %}
                            </p>
                        </div>
                        
                        <div style="background: #f8fafc; padding: 1.5rem; border-radius: 0.75rem;">
                            <h4><i class="bi bi-gear"></i> System Info</h4>
                            <p><strong>Attempts:</strong> {{ initialization_attempts }}</p>
                            <p><strong>Platform:</strong> Render.com</p>
                            <p><strong>Flask:</strong> 3.0+ Modern</p>
                            <p><strong>Data Safety:</strong> <span class="status-badge active">Preserved</span></p>
                        </div>
                    </div>
                    
                    {% if db_status.issues %}
                    <div style="margin-top: 1.5rem; padding: 1rem; background: #fecaca; border-radius: 0.75rem; border: 1px solid #fca5a5;">
                        <h4 style="color: #991b1b;"><i class="bi bi-exclamation-triangle"></i> Issues Detected:</h4>
                        <ul style="margin-left: 1rem; color: #991b1b;">
                            {% for issue in db_status.issues %}
                            <li>{{ issue }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>

        <div style="text-align: center; margin-top: 3rem;">
            <a href="/" class="btn" style="background: #6b7280; color: white;">
                <i class="bi bi-arrow-left"></i> Back to Home
            </a>
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
# MAIN - FLASK 3.0+ COMPATIBLE
# =============================================================================

if __name__ == '__main__':
    # Initialize database when running locally with app context
    with app.app_context():
        initialize_database_on_startup()
    
    # This block only runs during local development
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

# Initialize database on startup for production (with app context)
with app.app_context():
    initialize_database_on_startup()
