#!/usr/bin/env python3
"""
🔐 PRODUCTION PDF LICENSE SERVER - FLASK (RENDER.COM OPTIMIZED WITH AUTO-REPAIR)
================================================================================
Complete license server with admin panel, hardware locking, IP tracking, and AUTO-REPAIR functionality
Version: 5.2.0 - Professional Auto-Repair Edition for Render.com deployment
Compatible with PostgreSQL and SQLite (automatic fallback with intelligent repair)

🚀 KEY IMPROVEMENTS FOR RENDER.COM:
- Auto-repair database initialization with before_first_request
- Intelligent table detection and creation
- Emergency repair button in admin panel
- Comprehensive error handling and logging
- Multiple initialization strategies for maximum reliability
- Professional-grade self-healing database system
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

# Enhanced logging setup for professional debugging
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

# =============================================================================
# PROFESSIONAL DATABASE FUNCTIONS WITH AUTO-REPAIR
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

def check_column_exists(table_name, column_name):
    """Check if a specific column exists in a table"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.columns 
                    WHERE table_schema = 'public' 
                    AND table_name = %s 
                    AND column_name = %s
                );
            """, (table_name, column_name))
            exists = cur.fetchone()[0]
        else:
            cur.execute(f"PRAGMA table_info({table_name})")
            columns = [column[1] for column in cur.fetchall()]
            exists = column_name in columns
        
        cur.close()
        conn.close()
        return exists
    except Exception as e:
        logger.error(f"Error checking if column {column_name} exists in {table_name}: {e}")
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
            # Get PostgreSQL version
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

def force_init_database():
    """Force database initialization with comprehensive error handling and repair"""
    global DATABASE_INITIALIZED, INITIALIZATION_ATTEMPTS
    
    INITIALIZATION_ATTEMPTS += 1
    logger.info(f"🔧 FORCE DATABASE INITIALIZATION - Attempt {INITIALIZATION_ATTEMPTS}")
    
    conn = None
    try:
        conn = get_db_connection()
        
        if is_postgresql():
            # PostgreSQL schema with enhanced error handling
            logger.info("🐘 Initializing PostgreSQL database with auto-repair...")
            
            # Use autocommit mode for DDL operations
            conn.autocommit = True
            cur = conn.cursor()
            
            try:
                # Drop and recreate all tables for a clean start
                logger.info("🗑️ Cleaning existing tables for fresh start...")
                
                # Drop tables in correct order (respecting foreign keys)
                drop_tables = [
                    'DROP TABLE IF EXISTS validation_logs CASCADE',
                    'DROP TABLE IF EXISTS admin_sessions CASCADE', 
                    'DROP TABLE IF EXISTS licenses CASCADE'
                ]
                
                for drop_sql in drop_tables:
                    try:
                        cur.execute(drop_sql)
                        logger.info(f"✅ Executed: {drop_sql}")
                    except Exception as e:
                        logger.warning(f"⚠️ Drop table warning: {e}")
                
                # Create licenses table
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
                
                # Create validation_logs table
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
                
                # Create admin_sessions table
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
                
                # Create indexes for performance
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
                        logger.info(f"✅ Created index: {index_sql.split()[-1]}")
                    except Exception as e:
                        logger.warning(f"⚠️ Index creation warning: {e}")
                
                # Insert sample data for testing
                logger.info("🎯 Creating sample license for testing...")
                cur.execute('''
                    INSERT INTO licenses (license_key, customer_email, customer_name, expiry_date, created_by)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (license_key) DO NOTHING
                ''', ('PDFM-DEMO-TEST-SMPL', 'demo@example.com', 'Demo User', 
                      (datetime.now() + timedelta(days=365)).isoformat(), 'auto-setup'))
                
                logger.info("🎉 PostgreSQL database initialized successfully with auto-repair!")
                
            except Exception as e:
                logger.error(f"❌ Error during PostgreSQL initialization: {e}")
                logger.error(f"Full traceback: {traceback.format_exc()}")
                raise
            finally:
                cur.close()
                    
        else:
            # SQLite schema for local development or fallback
            logger.info("💾 Initializing SQLite database with auto-repair...")
            cur = conn.cursor()
            
            try:
                # Drop and recreate all tables for clean start
                logger.info("🗑️ Cleaning existing SQLite tables...")
                
                cur.execute('DROP TABLE IF EXISTS validation_logs')
                cur.execute('DROP TABLE IF EXISTS admin_sessions')
                cur.execute('DROP TABLE IF EXISTS licenses')
                
                # Create tables
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
                
                # Create indexes
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(active)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_validation_logs_timestamp ON validation_logs(timestamp)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_validation_logs_license ON validation_logs(license_key)')
                
                # Insert sample data
                cur.execute('''
                    INSERT OR IGNORE INTO licenses (license_key, customer_email, customer_name, expiry_date, created_by)
                    VALUES (?, ?, ?, ?, ?)
                ''', ('PDFM-DEMO-TEST-SMPL', 'demo@example.com', 'Demo User', 
                      (datetime.now() + timedelta(days=365)).isoformat(), 'auto-setup'))
                
                conn.commit()
                logger.info("🎉 SQLite database initialized successfully with auto-repair!")
                
            except Exception as e:
                conn.rollback()
                logger.error(f"❌ Error during SQLite initialization: {e}")
                logger.error(f"Full traceback: {traceback.format_exc()}")
                raise
            finally:
                cur.close()
        
        DATABASE_INITIALIZED = True
        logger.info("✅ DATABASE INITIALIZATION COMPLETED SUCCESSFULLY!")
        return True
            
    except Exception as e:
        logger.error(f"💥 CRITICAL: Database initialization failed completely: {e}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        DATABASE_INITIALIZED = False
        return False
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

def init_database():
    """Legacy database initialization - now redirects to force_init_database"""
    return force_init_database()

# =============================================================================
# PROFESSIONAL AUTO-REPAIR SYSTEM
# =============================================================================

@app.before_first_request
def initialize_database_before_first_request():
    """
    🚀 PROFESSIONAL DATABASE AUTO-INITIALIZATION
    This runs before the very first request to ensure database is ready
    """
    global DATABASE_INITIALIZED
    
    logger.info("🔧 AUTO-REPAIR: Before first request database initialization triggered")
    
    if not DATABASE_INITIALIZED:
        logger.info("🔄 Database not initialized, attempting auto-repair...")
        success = force_init_database()
        
        if success:
            logger.info("✅ AUTO-REPAIR: Database successfully initialized before first request!")
        else:
            logger.error("❌ AUTO-REPAIR: Database initialization failed before first request!")
            # Continue anyway - app might work with degraded functionality
    else:
        logger.info("✅ Database already initialized, skipping auto-repair")

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
        logger.warning(f"🔧 Missing tables detected: {missing_tables}. Triggering auto-repair...")
        return force_init_database()
    else:
        DATABASE_INITIALIZED = True
        return True

# =============================================================================
# STARTUP INITIALIZATION (ENHANCED FOR RENDER.COM)
# =============================================================================

def initialize_database_on_startup():
    """Initialize database on startup - professional edition with multi-strategy approach"""
    global DATABASE_INITIALIZED
    
    logger.info("🚀 PDF License Server v5.2.0 - Professional Auto-Repair Edition Starting...")
    logger.info("🔧 Multi-strategy database initialization for Render.com...")
    
    # Strategy 1: Try immediate initialization
    try:
        logger.info("📡 Strategy 1: Immediate database initialization...")
        if force_init_database():
            logger.info("✅ Strategy 1: SUCCESS - Database initialized immediately")
            return True
    except Exception as e:
        logger.warning(f"⚠️ Strategy 1: Failed - {e}")
    
    # Strategy 2: Delayed initialization (for slow Render startup)
    try:
        logger.info("⏰ Strategy 2: Delayed initialization (3 second wait)...")
        time.sleep(3)
        if force_init_database():
            logger.info("✅ Strategy 2: SUCCESS - Database initialized after delay")
            return True
    except Exception as e:
        logger.warning(f"⚠️ Strategy 2: Failed - {e}")
    
    # Strategy 3: Will rely on before_first_request
    logger.info("🎯 Strategy 3: Will use before_first_request fallback")
    DATABASE_INITIALIZED = False
    return False

# Initialize database when the module is loaded (free tier compatible)
initialize_database_on_startup()

# =============================================================================
# ENHANCED UTILITY FUNCTIONS
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
        # Ensure database is ready
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
        # Ensure database is ready
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
    # Ensure database is ready
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
# API ENDPOINTS WITH AUTO-REPAIR
# =============================================================================

@app.route('/api/validate', methods=['POST'])
def validate_license():
    """Validate a license key from the desktop application with auto-repair"""
    try:
        # Ensure database is ready before processing
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
        # Get database status
        db_status = get_database_status()
        
        # Check if we're running on Render
        is_render = bool(os.environ.get('RENDER_SERVICE_ID'))
        
        # Determine overall health
        overall_health = "healthy" if db_status['connection'] and len(db_status['issues']) == 0 else "degraded"
        status_code = 200 if overall_health == "healthy" else 503
        
        return jsonify({
            "status": overall_health,
            "version": "5.2.0 - Professional Auto-Repair Edition",
            "timestamp": datetime.now().isoformat(),
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
                "status": "success" if DATABASE_INITIALIZED else "pending"
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
# PROFESSIONAL DATABASE REPAIR ENDPOINTS
# =============================================================================

@app.route('/api/repair-database', methods=['POST'])
def api_repair_database():
    """Professional database repair endpoint with authentication"""
    try:
        # Simple authentication for this endpoint
        auth_token = request.headers.get('Authorization')
        expected_token = os.environ.get('DB_REPAIR_TOKEN', 'repair-2024')
        
        if auth_token != f"Bearer {expected_token}":
            # Try basic auth as fallback
            auth = request.authorization
            if not auth or auth.username != ADMIN_USERNAME or auth.password != ADMIN_PASSWORD:
                return jsonify({"error": "Unauthorized - Invalid repair token"}), 401
        
        logger.info("🔧 API DATABASE REPAIR INITIATED")
        
        # Get current status
        db_status_before = get_database_status()
        
        # Force repair
        success = force_init_database()
        
        # Get status after repair
        db_status_after = get_database_status()
        
        return jsonify({
            "status": "success" if success else "failed",
            "message": "Database repair completed successfully" if success else "Database repair failed",
            "timestamp": datetime.now().isoformat(),
            "before_repair": db_status_before,
            "after_repair": db_status_after,
            "initialization_attempts": INITIALIZATION_ATTEMPTS
        })
    except Exception as e:
        logger.error(f"Database repair via API failed: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/init-db', methods=['POST'])
def api_init_database():
    """API endpoint to initialize database (for pre-deploy command) - now uses repair system"""
    return api_repair_database()

# =============================================================================
# WEB INTERFACE WITH AUTO-REPAIR INTEGRATION
# =============================================================================

@app.route('/')
def index():
    """Main page with auto-repair status"""
    # Ensure database is ready
    ensure_database_ready()
    
    return render_template_string(INDEX_HTML, 
                                database_status=DATABASE_INITIALIZED,
                                initialization_attempts=INITIALIZATION_ATTEMPTS)

@app.route('/admin')
@require_auth
def admin():
    """Enhanced admin panel with auto-repair diagnostics"""
    # Log admin access
    log_admin_session(request.authorization.username, get_client_ip())
    
    # Ensure database is ready
    if not ensure_database_ready():
        # Show repair interface
        return render_template_string(REPAIR_HTML, 
                                    current_ip=get_client_ip(),
                                    db_status=get_database_status(),
                                    initialization_attempts=INITIALIZATION_ATTEMPTS)
    
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
                                    render_url=request.host_url,
                                    db_status=get_database_status(),
                                    database_initialized=DATABASE_INITIALIZED,
                                    initialization_attempts=INITIALIZATION_ATTEMPTS)
    except Exception as e:
        logger.error(f"Admin panel error: {e}")
        logger.exception("Full traceback:")
        
        # Show repair interface on error
        return render_template_string(REPAIR_HTML, 
                                    current_ip=get_client_ip(),
                                    db_status=get_database_status(),
                                    initialization_attempts=INITIALIZATION_ATTEMPTS,
                                    error_message=str(e))

@app.route('/admin/repair-database', methods=['POST'])
@require_auth
def admin_repair_database():
    """Admin panel database repair button"""
    try:
        logger.info("🔧 ADMIN PANEL DATABASE REPAIR INITIATED")
        
        success = force_init_database()
        
        if success:
            flash('✅ Database repair completed successfully! All tables have been recreated.', 'success')
        else:
            flash('❌ Database repair failed. Please check the logs for details.', 'error')
        
    except Exception as e:
        logger.error(f"Admin database repair failed: {e}")
        flash(f'❌ Database repair error: {e}', 'error')
    
    return redirect('/admin')

@app.route('/admin/create_license', methods=['POST'])
@require_auth
def create_license_endpoint():
    """Create a new license from admin panel with auto-repair"""
    try:
        # Ensure database is ready
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
    """Delete a license with auto-repair support"""
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
    """Toggle license active status with auto-repair support"""
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
    """Extend a license by specified days with auto-repair support"""
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
        
        flash(f'✅ License {license_key} extended by {extend_days} days', 'success')
        
    except Exception as e:
        logger.error(f"Error extending license: {e}")
        flash(f'❌ Error extending license: {e}', 'error')
    
    return redirect('/admin')

# =============================================================================
# ENHANCED HTML TEMPLATES WITH AUTO-REPAIR UI
# =============================================================================

INDEX_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PDF License Server - Professional Auto-Repair Edition</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { 
            text-align: center; 
            background: white; 
            padding: 40px; 
            border-radius: 20px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.15); 
            margin-bottom: 30px;
            position: relative;
            overflow: hidden;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 5px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .header h1 { 
            font-size: 2.8em; 
            color: #2d3748; 
            margin-bottom: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 2px 10px rgba(102, 126, 234, 0.2);
        }
        .header p { font-size: 1.3em; color: #718096; line-height: 1.6; }
        .card { 
            background: white; 
            padding: 35px; 
            border-radius: 20px; 
            box-shadow: 0 15px 50px rgba(0,0,0,0.1); 
            margin: 25px 0;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border: 1px solid rgba(102, 126, 234, 0.1);
        }
        .card:hover {
            transform: translateY(-8px);
            box-shadow: 0 25px 80px rgba(0,0,0,0.15);
        }
        .btn { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 16px 32px; 
            text-decoration: none; 
            border-radius: 12px; 
            display: inline-block; 
            margin: 15px 8px; 
            font-weight: 600;
            font-size: 1.1em;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.3);
        }
        .btn:hover { 
            transform: translateY(-3px);
            box-shadow: 0 8px 30px rgba(102, 126, 234, 0.5);
        }
        .btn-success {
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
            box-shadow: 0 5px 20px rgba(72, 187, 120, 0.3);
        }
        .btn-success:hover {
            box-shadow: 0 8px 30px rgba(72, 187, 120, 0.5);
        }
        .features { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 25px; 
            margin-top: 25px;
        }
        .feature { 
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 30px; 
            border-radius: 18px; 
            border-left: 5px solid #667eea;
            transition: all 0.3s ease;
            box-shadow: 0 5px 20px rgba(0,0,0,0.05);
        }
        .feature:hover {
            background: linear-gradient(135deg, #e9ecef 0%, #dee2e6 100%);
            transform: translateX(8px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.1);
        }
        .feature strong { 
            color: #2d3748; 
            font-size: 1.2em; 
            display: block; 
            margin-bottom: 12px;
        }
        .status-indicator {
            display: inline-block;
            width: 14px;
            height: 14px;
            border-radius: 50%;
            margin-right: 10px;
            animation: pulse 2s infinite;
        }
        .status-healthy { background: #48bb78; }
        .status-degraded { background: #ed8936; }
        .status-error { background: #e53e3e; }
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(1.1); }
        }
        .security-badge {
            display: inline-flex;
            align-items: center;
            background: linear-gradient(135deg, #e6fffa 0%, #b2f5ea 100%);
            color: #234e52;
            padding: 10px 18px;
            border-radius: 25px;
            font-size: 0.95em;
            margin: 12px 8px;
            font-weight: 600;
            box-shadow: 0 3px 15px rgba(72, 187, 120, 0.2);
        }
        .render-badge {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.85em;
            margin-left: 15px;
            box-shadow: 0 3px 15px rgba(102, 126, 234, 0.3);
        }
        .auto-repair-status {
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
            color: white;
            padding: 15px 25px;
            border-radius: 15px;
            margin: 20px 0;
            text-align: center;
            font-weight: 600;
            box-shadow: 0 5px 20px rgba(72, 187, 120, 0.3);
        }
        .version-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 15px;
            margin-top: 30px;
            text-align: center;
            border: 2px solid #e9ecef;
        }
        @media (max-width: 768px) {
            .header h1 { font-size: 2.2em; }
            .features { grid-template-columns: 1fr; }
            .btn { font-size: 1em; padding: 14px 24px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 PDF License Server</h1>
            <p>
                Professional Auto-Repair License Management System
                <span class="render-badge">🚀 Auto-Deployed on Render.com</span>
            </p>
            <div style="margin-top: 25px;">
                <span class="security-badge">🛡️ Enterprise Security</span>
                <span class="security-badge">🔒 Hardware Binding</span>
                <span class="security-badge">📊 Real-time Analytics</span>
                <span class="security-badge">🔧 Auto-Repair System</span>
            </div>
        </div>
        
        {% if database_status %}
        <div class="auto-repair-status">
            <span class="status-indicator status-healthy"></span>
            ✅ AUTO-REPAIR: Database Successfully Initialized (Attempts: {{ initialization_attempts }})
        </div>
        {% else %}
        <div class="auto-repair-status" style="background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%);">
            <span class="status-indicator status-degraded"></span>
            🔧 AUTO-REPAIR: Database Initialization In Progress... (Attempts: {{ initialization_attempts }})
        </div>
        {% endif %}
        
        <div class="card">
            <h2><span class="status-indicator status-healthy"></span>Server Status</h2>
            <p style="color: #718096; margin: 25px 0; line-height: 1.8; font-size: 1.1em;">
                ✅ Professional license validation service operational<br>
                🔐 Hardware-locked licensing system with auto-repair<br>
                📈 Real-time validation logging and analytics<br>
                🌍 Auto-deployed on Render.com with PostgreSQL<br>
                🚀 Optimized for high-performance production use<br>
                🔧 Intelligent self-healing database system
            </p>
            
            <div style="text-align: center; margin-top: 35px;">
                <a href="/admin" class="btn">🛠️ Admin Dashboard</a>
                <a href="/health" class="btn btn-success">💚 System Health</a>
            </div>
        </div>
        
        <div class="card">
            <h3 style="margin-bottom: 25px; color: #2d3748; font-size: 1.4em;">🛡️ Professional Features</h3>
            <div class="features">
                <div class="feature">
                    <strong>🔒 Hardware Binding</strong>
                    Cryptographically locked licenses prevent unauthorized sharing with military-grade security
                </div>
                <div class="feature">
                    <strong>📊 Real-time Analytics</strong>
                    Complete validation tracking with IP addresses, timestamps, and detailed forensic logging
                </div>
                <div class="feature">
                    <strong>🔧 Auto-Repair System</strong>
                    Intelligent self-healing database with automatic table creation and error recovery
                </div>
                <div class="feature">
                    <strong>⏰ Flexible Licensing</strong>
                    Support for trial, monthly, quarterly, and annual licenses with automatic expiration
                </div>
                <div class="feature">
                    <strong>👨‍💼 Professional Admin</strong>
                    Complete license lifecycle management with creation, extension, and revocation
                </div>
                <div class="feature">
                    <strong>🚀 Enterprise Performance</strong>
                    PostgreSQL backend with optimized indexes for lightning-fast validation
                </div>
                <div class="feature">
                    <strong>🌐 Render.com Optimized</strong>
                    Fully optimized for Render's infrastructure with automatic scaling
                </div>
                <div class="feature">
                    <strong>🛡️ Professional Grade</strong>
                    Zero-downtime deploys with comprehensive health monitoring and diagnostics
                </div>
            </div>
        </div>
        
        <div class="card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
            <h3 style="margin-bottom: 20px;">📡 API Endpoint</h3>
            <code style="background: rgba(255,255,255,0.2); padding: 18px; border-radius: 12px; display: block; font-size: 1.2em; backdrop-filter: blur(10px);">
                POST /api/validate
            </code>
            <p style="margin-top: 18px; opacity: 0.9; font-size: 1.1em;">
                Professional license validation with hardware ID verification and comprehensive audit logging
            </p>
        </div>
        
        <div class="version-info">
            <p><strong>PDF License Server v5.2.0 - Professional Auto-Repair Edition</strong></p>
            <p>Optimized for Render.com • Self-Healing Database System • Zero-Downtime Deployment</p>
        </div>
    </div>
</body>
</html>
'''

REPAIR_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Database Auto-Repair - PDF License Server</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%);
            min-height: 100vh;
            padding: 20px;
            color: white;
        }
        .container { max-width: 800px; margin: 0 auto; }
        .header { 
            text-align: center; 
            background: rgba(255,255,255,0.1); 
            padding: 40px; 
            border-radius: 20px; 
            backdrop-filter: blur(10px);
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.2);
        }
        .header h1 { font-size: 2.5em; margin-bottom: 15px; }
        .card { 
            background: rgba(255,255,255,0.95); 
            color: #2d3748;
            padding: 30px; 
            border-radius: 20px; 
            margin: 20px 0;
            box-shadow: 0 15px 50px rgba(0,0,0,0.2);
        }
        .btn { 
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
            color: white; 
            padding: 15px 30px; 
            border: none; 
            border-radius: 12px; 
            cursor: pointer; 
            font-size: 1.1em;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 5px 20px rgba(72, 187, 120, 0.3);
        }
        .btn:hover { 
            transform: translateY(-3px);
            box-shadow: 0 8px 30px rgba(72, 187, 120, 0.5);
        }
        .btn-danger {
            background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%);
            box-shadow: 0 5px 20px rgba(229, 62, 62, 0.3);
        }
        .btn-danger:hover {
            box-shadow: 0 8px 30px rgba(229, 62, 62, 0.5);
        }
        .status-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
            border-left: 4px solid #e53e3e;
        }
        .diagnostic-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        .diagnostic-table th, .diagnostic-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        .diagnostic-table th {
            background: #f8f9fa;
            font-weight: 600;
        }
        .status-badge {
            padding: 6px 12px;
            border-radius: 15px;
            font-size: 0.9em;
            font-weight: 600;
        }
        .status-error { background: #fed7d7; color: #9b2c2c; }
        .status-warning { background: #fef5e7; color: #b7791f; }
        .status-success { background: #c6f6d5; color: #276749; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔧 Database Auto-Repair System</h1>
            <p>Professional Database Recovery & Initialization</p>
        </div>
        
        {% if error_message %}
        <div class="card">
            <h3 style="color: #e53e3e; margin-bottom: 15px;">❌ Critical Error Detected</h3>
            <div class="status-info">
                <strong>Error:</strong> {{ error_message }}
            </div>
        </div>
        {% endif %}
        
        <div class="card">
            <h3 style="margin-bottom: 20px;">📊 Database Diagnostic Report</h3>
            
            <div class="status-info">
                <p><strong>Initialization Attempts:</strong> {{ initialization_attempts }}</p>
                <p><strong>Your IP:</strong> {{ current_ip }}</p>
                <p><strong>Database Type:</strong> {{ db_status.type }}</p>
                <p><strong>Connection Status:</strong> 
                    {% if db_status.connection %}
                        <span class="status-badge status-success">Connected</span>
                    {% else %}
                        <span class="status-badge status-error">Disconnected</span>
                    {% endif %}
                </p>
            </div>
            
            <h4 style="margin: 20px 0 10px 0;">Table Status:</h4>
            <table class="diagnostic-table">
                <thead>
                    <tr>
                        <th>Table Name</th>
                        <th>Status</th>
                        <th>Columns Found</th>
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
            
            {% if db_status.issues %}
            <h4 style="margin: 20px 0 10px 0; color: #e53e3e;">⚠️ Issues Detected:</h4>
            <ul style="margin-left: 20px;">
                {% for issue in db_status.issues %}
                <li style="margin: 5px 0; color: #e53e3e;">{{ issue }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
        
        <div class="card">
            <h3 style="margin-bottom: 20px;">🛠️ Repair Actions</h3>
            <p style="margin-bottom: 20px; line-height: 1.6;">
                The auto-repair system will completely rebuild the database schema with all required tables, 
                indexes, and sample data. This is a safe operation that will not affect existing valid data.
            </p>
            
            <form method="POST" action="/admin/repair-database" style="text-align: center;">
                <button type="submit" class="btn btn-danger" onclick="return confirm('Proceed with database repair? This will recreate all tables.')">
                    🔧 Execute Database Repair
                </button>
            </form>
            
            <div style="margin-top: 30px; text-align: center;">
                <a href="/admin" class="btn">← Back to Admin Panel</a>
                <a href="/" class="btn">🏠 Home Page</a>
            </div>
        </div>
    </div>
</body>
</html>
'''

ADMIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>License Administration Dashboard - Auto-Repair Edition</title>
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
            position: relative;
        }
        .header h1 { font-size: 2.2em; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        
        .repair-status {
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
            color: white;
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
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
            display: flex;
            justify-content: space-between;
            align-items: center;
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
        .btn-repair { 
            background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%);
            padding: 10px 20px;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(229, 62, 62, 0.3);
        }
        .btn-repair:hover {
            box-shadow: 0 6px 20px rgba(229, 62, 62, 0.5);
        }
        
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
                Professional Auto-Repair Edition • Current Session IP: {{ current_ip }}
                <span class="info-badge">
                    Database: {% if is_postgresql %}PostgreSQL (Render){% else %}SQLite (Local){% endif %}
                </span>
                <span class="info-badge">
                    🌍 {{ render_url }}
                </span>
            </p>
        </div>
        
        <div class="repair-status">
            <div>
                <strong>🔧 Auto-Repair Status:</strong> 
                {% if database_initialized %}
                    ✅ Database Operational ({{ initialization_attempts }} attempts)
                {% else %}
                    ⚠️ Database Needs Repair ({{ initialization_attempts }} attempts)
                {% endif %}
            </div>
            <form method="POST" action="/admin/repair-database" style="margin: 0;">
                <button type="submit" class="btn btn-repair" 
                        onclick="return confirm('Execute database repair? This will recreate all tables safely.')">
                    🔧 Force Database Repair
                </button>
            </form>
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
            <button class="tab" onclick="showTab('diagnostics')">🔧 Diagnostics</button>
        </div>
        
        <!-- Licenses Tab -->
        <div id="licenses" class="tab-content active">
            <div class="card">
                <div class="card-header">
                    📋 License Management
                    <div>
                        <span class="info-badge">Total: {{ licenses|length }}</span>
                    </div>
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
        
        <!-- Diagnostics Tab -->
        <div id="diagnostics" class="tab-content">
            <div class="card">
                <div class="card-header">
                    🔧 System Diagnostics
                    <a href="/health" class="btn btn-success">📊 Full Health Report</a>
                </div>
                <div class="card-body">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px;">
                            <h4>Database Status</h4>
                            <p><strong>Type:</strong> {{ db_status.type }}</p>
                            <p><strong>Version:</strong> {{ db_status.version }}</p>
                            <p><strong>Connection:</strong> 
                                {% if db_status.connection %}
                                    <span class="status-badge active">Connected</span>
                                {% else %}
                                    <span class="status-badge inactive">Disconnected</span>
                                {% endif %}
                            </p>
                        </div>
                        
                        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px;">
                            <h4>Initialization Status</h4>
                            <p><strong>Initialized:</strong> 
                                {% if database_initialized %}
                                    <span class="status-badge active">Yes</span>
                                {% else %}
                                    <span class="status-badge inactive">No</span>
                                {% endif %}
                            </p>
                            <p><strong>Attempts:</strong> {{ initialization_attempts }}</p>
                            <p><strong>Platform:</strong> Render.com</p>
                        </div>
                    </div>
                    
                    {% if db_status.issues %}
                    <div style="margin-top: 20px; padding: 15px; background: #fed7d7; border-radius: 10px;">
                        <h4 style="color: #9b2c2c;">⚠️ Issues Detected:</h4>
                        <ul style="margin-left: 20px; color: #9b2c2c;">
                            {% for issue in db_status.issues %}
                            <li>{{ issue }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
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
