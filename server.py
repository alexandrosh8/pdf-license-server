#!/usr/bin/env python3
"""
🔐 ENHANCED PDF LICENSE SERVER - FLASK 3.0+ PROFESSIONAL EDITION
================================================================
Complete license server with automated client deployment, GitHub integration, and professional UI
Version: 6.1.0 - Enhanced Flask 3.0+ Edition with GitHub Auto-Deploy

🚀 NEW PROFESSIONAL FEATURES:
- Automated client deployment via GitHub API
- One-click license key copying
- Professional dashboard layout optimization
- Enhanced file upload and build system
- Real-time client update notifications
- Improved security and performance
- Full hardware ID display
- Environment-only authentication

⚙️ REQUIRED ENVIRONMENT VARIABLES:
- ADMIN_USERNAME: Admin login username
- ADMIN_PASSWORD: Admin login password

🔧 OPTIONAL ENVIRONMENT VARIABLES:
- SECRET_KEY: Flask secret key (auto-generated if not set)
- GITHUB_TOKEN: GitHub Personal Access Token for auto-deploy
- GITHUB_REPO: GitHub repository (format: username/repo-name)
- GITHUB_BRANCH: Git branch (default: main)
- DATABASE_URL: PostgreSQL connection string (uses SQLite if not set)
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
import requests
import base64
from pathlib import Path
import tempfile
import zipfile
import shutil

# =============================================================================
# APP CONFIGURATION
# =============================================================================

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))

# Enhanced logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Admin credentials from environment variables (required)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')

# Validate that admin credentials are set
if not ADMIN_USERNAME or not ADMIN_PASSWORD:
    logger.error("❌ ADMIN_USERNAME and ADMIN_PASSWORD environment variables must be set!")
    logger.error("Please set these environment variables before running the server.")
    sys.exit(1)

# GitHub Integration (set these in environment variables)
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')  # GitHub Personal Access Token
GITHUB_REPO = os.environ.get('GITHUB_REPO', 'alexandrosh8/pdf-license-server')  # Your repo
GITHUB_BRANCH = os.environ.get('GITHUB_BRANCH', 'main')

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

# Global flag to track database initialization status
DATABASE_INITIALIZED = False
INITIALIZATION_ATTEMPTS = 0
MAX_INITIALIZATION_ATTEMPTS = 3
FIRST_REQUEST_HANDLED = False

# =============================================================================
# GITHUB INTEGRATION CLASS
# =============================================================================

class GitHubDeployment:
    """Professional GitHub API integration for automated client deployment"""
    
    def __init__(self):
        self.token = GITHUB_TOKEN
        self.repo = GITHUB_REPO
        self.branch = GITHUB_BRANCH
        self.base_url = "https://api.github.com"
        
    def upload_client_file(self, file_content, filename="client.py", commit_message=None):
        """Upload client file to GitHub repository"""
        if not self.token:
            raise Exception("GitHub token not configured")
        
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
        
        try:
            # Get current file (if exists) to get SHA
            get_url = f"{self.base_url}/repos/{self.repo}/contents/{filename}"
            response = requests.get(get_url, headers=headers)
            
            sha = None
            if response.status_code == 200:
                sha = response.json().get("sha")
            
            # Encode file content
            content_encoded = base64.b64encode(file_content.encode()).decode()
            
            # Prepare commit data
            commit_data = {
                "message": commit_message or f"Auto-update {filename} via License Server",
                "content": content_encoded,
                "branch": self.branch
            }
            
            if sha:
                commit_data["sha"] = sha
            
            # Upload file
            put_url = f"{self.base_url}/repos/{self.repo}/contents/{filename}"
            response = requests.put(put_url, headers=headers, json=commit_data)
            
            if response.status_code in [200, 201]:
                return {
                    "success": True,
                    "message": "File uploaded successfully",
                    "download_url": response.json().get("content", {}).get("download_url"),
                    "html_url": response.json().get("content", {}).get("html_url")
                }
            else:
                raise Exception(f"GitHub API error: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"GitHub upload failed: {e}")
            raise
    
    def create_release(self, tag_name, release_name, body="", prerelease=False):
        """Create a new GitHub release"""
        if not self.token:
            raise Exception("GitHub token not configured")
        
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
        
        release_data = {
            "tag_name": tag_name,
            "name": release_name,
            "body": body,
            "draft": False,
            "prerelease": prerelease
        }
        
        url = f"{self.base_url}/repos/{self.repo}/releases"
        response = requests.post(url, headers=headers, json=release_data)
        
        if response.status_code == 201:
            return response.json()
        else:
            raise Exception(f"Release creation failed: {response.status_code} - {response.text}")
    
    def trigger_build_workflow(self):
        """Trigger GitHub Actions workflow for building executable"""
        if not self.token:
            raise Exception("GitHub token not configured")
        
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
        
        workflow_data = {
            "ref": self.branch,
            "inputs": {
                "build_client": "true"
            }
        }
        
        url = f"{self.base_url}/repos/{self.repo}/actions/workflows/build.yml/dispatches"
        response = requests.post(url, headers=headers, json=workflow_data)
        
        if response.status_code == 204:
            return {"success": True, "message": "Build workflow triggered"}
        else:
            raise Exception(f"Workflow trigger failed: {response.status_code} - {response.text}")

# =============================================================================
# PROFESSIONAL JINJA2 FILTERS (Enhanced)
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
# DATABASE FUNCTIONS (Enhanced)
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
                
                # NEW: Create client_uploads table for file management
                if not check_table_exists('client_uploads'):
                    logger.info("📁 Creating client_uploads table...")
                    cur.execute('''
                        CREATE TABLE client_uploads (
                            id SERIAL PRIMARY KEY,
                            filename VARCHAR(255) NOT NULL,
                            upload_date TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                            uploaded_by VARCHAR(255),
                            file_size INTEGER,
                            github_url TEXT,
                            build_status VARCHAR(50) DEFAULT 'pending',
                            version_tag VARCHAR(50),
                            build_number INTEGER,
                            commit_sha VARCHAR(100),
                            release_url TEXT
                        )
                    ''')
                    
                    # Create index for version_tag for better performance
                    cur.execute('CREATE INDEX IF NOT EXISTS idx_client_uploads_version ON client_uploads(version_tag)')
                    
                    logger.info("✅ Client_uploads table created successfully")
                else:
                    logger.info("✅ Client_uploads table already exists, preserving data")
                    
                    # Add new columns if they don't exist (for existing databases)
                    try:
                        cur.execute('ALTER TABLE client_uploads ADD COLUMN IF NOT EXISTS build_number INTEGER')
                        cur.execute('ALTER TABLE client_uploads ADD COLUMN IF NOT EXISTS commit_sha VARCHAR(100)')
                        cur.execute('ALTER TABLE client_uploads ADD COLUMN IF NOT EXISTS release_url TEXT')
                        logger.info("✅ Added new columns to existing client_uploads table")
                    except Exception as e:
                        logger.info(f"ℹ️ Columns may already exist: {e}")
                
                # Create indexes for performance (IF NOT EXISTS)
                logger.info("🚀 Creating performance indexes...")
                indexes = [
                    'CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)',
                    'CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email)',
                    'CREATE INDEX IF NOT EXISTS idx_licenses_expiry ON licenses(expiry_date)',
                    'CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(active)',
                    'CREATE INDEX IF NOT EXISTS idx_validation_logs_timestamp ON validation_logs(timestamp)',
                    'CREATE INDEX IF NOT EXISTS idx_validation_logs_license ON validation_logs(license_key)',
                    'CREATE INDEX IF NOT EXISTS idx_validation_logs_status ON validation_logs(status)',
                    'CREATE INDEX IF NOT EXISTS idx_client_uploads_date ON client_uploads(upload_date)'
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
                
                # NEW: SQLite client_uploads table
                if not check_table_exists('client_uploads'):
                    cur.execute('''
                        CREATE TABLE client_uploads (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            filename TEXT NOT NULL,
                            upload_date TEXT DEFAULT CURRENT_TIMESTAMP,
                            uploaded_by TEXT,
                            file_size INTEGER,
                            github_url TEXT,
                            build_status TEXT DEFAULT 'pending',
                            version_tag TEXT,
                            build_number INTEGER,
                            commit_sha TEXT,
                            release_url TEXT
                        )
                    ''')
                    logger.info("✅ Client_uploads table created")
                else:
                    logger.info("✅ Client_uploads table already exists, preserving data")
                    
                    # Add new columns if they don't exist (for existing databases)
                    try:
                        cur.execute('ALTER TABLE client_uploads ADD COLUMN build_number INTEGER')
                        cur.execute('ALTER TABLE client_uploads ADD COLUMN commit_sha TEXT') 
                        cur.execute('ALTER TABLE client_uploads ADD COLUMN release_url TEXT')
                        logger.info("✅ Added new columns to existing client_uploads table")
                    except Exception as e:
                        logger.info(f"ℹ️ Columns may already exist: {e}")
                
                # Create indexes
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(active)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_validation_logs_timestamp ON validation_logs(timestamp)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_validation_logs_license ON validation_logs(license_key)')
                cur.execute('CREATE INDEX IF NOT EXISTS idx_client_uploads_date ON client_uploads(upload_date)')
                
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
    
    logger.info("🚀 PDF License Server v6.1.0 - Enhanced Flask 3.0+ Edition Starting...")
    logger.info("🔧 Safe database initialization for data preservation...")
    
    try:
        logger.info("📡 Safe initialization with app context...")
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
# GITHUB INTEGRATION ENDPOINTS
# =============================================================================

@app.route('/api/release-notification', methods=['POST'])
def release_notification():
    """Webhook endpoint for GitHub release notifications - Compatible with your workflow"""
    try:
        if not ensure_database_ready():
            return jsonify({"error": "Database not ready"}), 503
        
        data = request.get_json() or {}
        version = data.get('version', 'unknown')
        download_url = data.get('download_url', '')
        release_date = data.get('release_date', datetime.now().isoformat())
        build_number = data.get('build_number', 0)
        commit_sha = data.get('commit_sha', '')
        filename = data.get('filename', f'PDF-Metadata-Tool-{version}.exe')
        release_url = data.get('release_url', '')
        
        # Extract just the filename from download_url if not provided
        if not filename and download_url:
            filename = download_url.split('/')[-1]
        
        logger.info(f"🔔 GitHub release notification received: {version}")
        logger.info(f"📥 Download URL: {download_url}")
        logger.info(f"🏷️ Build: #{build_number} | Commit: {commit_sha[:8]}")
        
        # Update client_uploads table with new release info
        conn = get_db_connection()
        cur = conn.cursor()
        
        try:
            if is_postgresql():
                # First try to update existing record, then insert if not exists
                cur.execute('''
                    UPDATE client_uploads 
                    SET build_status = 'completed', 
                        github_url = %s,
                        upload_date = NOW(),
                        build_number = %s,
                        commit_sha = %s,
                        release_url = %s
                    WHERE version_tag = %s
                ''', (download_url, build_number, commit_sha, release_url, version))
                
                if cur.rowcount == 0:
                    # No existing record, insert new one
                    cur.execute('''
                        INSERT INTO client_uploads 
                        (filename, version_tag, github_url, build_status, uploaded_by, 
                         build_number, commit_sha, release_url)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (filename, version, download_url, 'completed', 'github-actions',
                          build_number, commit_sha, release_url))
                    
            else:
                # SQLite - use INSERT OR REPLACE
                cur.execute('''
                    INSERT OR REPLACE INTO client_uploads 
                    (filename, version_tag, github_url, build_status, uploaded_by, upload_date,
                     build_number, commit_sha, release_url)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (filename, version, download_url, 'completed', 'github-actions', 
                      datetime.now().isoformat(), build_number, commit_sha, release_url))
            
            conn.commit()
            logger.info(f"✅ Database updated for version {version}")
            
        except Exception as db_error:
            logger.error(f"Database update error: {db_error}")
            # Continue - don't fail the notification for DB issues
            
        finally:
            cur.close()
            conn.close()
        
        # Return success response that matches your workflow expectations
        response_data = {
            "success": True,
            "message": f"Release {version} notification processed successfully",
            "version": version,
            "build_number": build_number,
            "download_url": download_url,
            "filename": filename,
            "processed_at": datetime.now().isoformat()
        }
        
        logger.info(f"🎉 Release notification processed successfully: {version}")
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"❌ Release notification failed: {e}")
        logger.exception("Full traceback:")
        
        # Return error but don't fail completely - GitHub Actions should continue
        return jsonify({
            "success": False,
            "error": str(e),
            "message": "Notification received but processing failed"
        }), 200  # Return 200 so GitHub doesn't retry

@app.route('/api/client-update-check', methods=['GET'])
def client_update_check():
    """API endpoint for clients to check for updates"""
    try:
        if not ensure_database_ready():
            return jsonify({"update_available": False, "error": "Server not ready"})
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get latest successful upload
        if is_postgresql():
            cur.execute('''
                SELECT filename, version_tag, github_url, upload_date 
                FROM client_uploads 
                WHERE build_status = 'completed' 
                ORDER BY upload_date DESC 
                LIMIT 1
            ''')
        else:
            cur.execute('''
                SELECT filename, version_tag, github_url, upload_date 
                FROM client_uploads 
                WHERE build_status = 'completed' 
                ORDER BY upload_date DESC 
                LIMIT 1
            ''')
        
        latest_upload = cur.fetchone()
        cur.close()
        conn.close()
        
        if latest_upload:
            return jsonify({
                "update_available": True,
                "latest_version": latest_upload[1] or "latest",  # version_tag
                "download_url": latest_upload[2],  # github_url
                "release_date": latest_upload[3],  # upload_date
                "filename": latest_upload[0]  # filename
            })
        else:
            return jsonify({"update_available": False})
            
    except Exception as e:
        logger.error(f"Client update check failed: {e}")
        return jsonify({"update_available": False, "error": str(e)})

@app.route('/admin/upload-client', methods=['POST'])
@require_auth
def upload_client_file():
    """Upload new client file and deploy to GitHub"""
    try:
        if not ensure_database_ready():
            flash('❌ Database not ready. Please try the repair button first.', 'error')
            return redirect('/admin')
        
        if 'client_file' not in request.files:
            flash('❌ No file selected', 'error')
            return redirect('/admin')
        
        file = request.files['client_file']
        if file.filename == '':
            flash('❌ No file selected', 'error')
            return redirect('/admin')
        
        # Read file content
        file_content = file.read().decode('utf-8')
        version_tag = request.form.get('version_tag', f"v{datetime.now().strftime('%Y.%m.%d.%H%M')}")
        
        # Initialize GitHub deployment
        github = GitHubDeployment()
        
        if not github.token:
            flash('❌ GitHub token not configured. Please set GITHUB_TOKEN environment variable.', 'error')
            return redirect('/admin')
        
        # Upload to GitHub
        result = github.upload_client_file(
            file_content, 
            filename="client.py",
            commit_message=f"Auto-deploy client {version_tag} via License Server"
        )
        
        # Save upload record
        conn = get_db_connection()
        cur = conn.cursor()
        
        if is_postgresql():
            cur.execute('''
                INSERT INTO client_uploads (filename, uploaded_by, file_size, github_url, version_tag, build_status)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (file.filename, request.authorization.username, len(file_content), 
                  result['download_url'], version_tag, 'uploaded'))
        else:
            cur.execute('''
                INSERT INTO client_uploads (filename, uploaded_by, file_size, github_url, version_tag, build_status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (file.filename, request.authorization.username, len(file_content), 
                  result['download_url'], version_tag, 'uploaded'))
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Try to trigger build (optional)
        try:
            build_result = github.trigger_build_workflow()
            flash(f'✅ Client uploaded to GitHub and build triggered! Version: {version_tag}', 'success')
        except Exception as e:
            logger.warning(f"Build trigger failed: {e}")
            flash(f'✅ Client uploaded to GitHub! Version: {version_tag} (Manual build required)', 'success')
        
    except Exception as e:
        logger.error(f"Client upload failed: {e}")
        flash(f'❌ Upload failed: {e}', 'error')
    
    return redirect('/admin')

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
        github_configured = bool(GITHUB_TOKEN and GITHUB_REPO)
        
        db_status = get_database_status()
        is_render = bool(os.environ.get('RENDER_SERVICE_ID'))
        overall_health = "healthy" if db_status['connection'] and len(db_status['issues']) == 0 else "degraded"
        status_code = 200 if overall_health == "healthy" else 503
        
        return jsonify({
            "status": overall_health,
            "version": "6.1.0 - Enhanced Flask 3.0+ Edition with GitHub Integration",
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
            "github_integration": {
                "configured": github_configured,
                "repository": GITHUB_REPO if github_configured else "Not configured",
                "branch": GITHUB_BRANCH if github_configured else "Not configured"
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
            
            # Check all required tables including new ones
            required_tables = ['licenses', 'validation_logs', 'admin_sessions', 'client_uploads']
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
            
            # Check all required tables including new ones
            required_tables = ['licenses', 'validation_logs', 'admin_sessions', 'client_uploads']
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

# =============================================================================
# WEB INTERFACE
# =============================================================================

@app.route('/')
def index():
    """Enhanced main page with GitHub status"""
    ensure_database_ready()
    github_configured = bool(GITHUB_TOKEN and GITHUB_REPO)
    return render_template_string(ENHANCED_INDEX_HTML, 
                                database_status=DATABASE_INITIALIZED,
                                initialization_attempts=INITIALIZATION_ATTEMPTS,
                                github_configured=github_configured,
                                github_repo=GITHUB_REPO if github_configured else "Not configured")

@app.route('/admin')
@require_auth
def admin():
    """Enhanced admin panel with GitHub integration"""
    log_admin_session(request.authorization.username, get_client_ip())
    
    if not ensure_database_ready():
        return render_template_string(ENHANCED_REPAIR_HTML, 
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
            
            # Get client uploads history with new fields
            cur.execute('''
                SELECT filename, upload_date, uploaded_by, version_tag, build_status, github_url,
                       build_number, commit_sha, release_url
                FROM client_uploads 
                ORDER BY upload_date DESC 
                LIMIT 10
            ''')
            client_uploads = cur.fetchall()
            
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
            
            client_uploads = cur.execute('''
                SELECT filename, upload_date, uploaded_by, version_tag, build_status, github_url,
                       build_number, commit_sha, release_url
                FROM client_uploads 
                ORDER BY upload_date DESC 
                LIMIT 10
            ''').fetchall()
        
        cur.close()
        conn.close()
        
        github_configured = bool(GITHUB_TOKEN and GITHUB_REPO)
        
        return render_template_string(ENHANCED_ADMIN_HTML, 
                                    licenses=licenses, 
                                    stats=stats, 
                                    recent_validations=recent_validations,
                                    client_uploads=client_uploads,
                                    current_ip=get_client_ip(),
                                    is_postgresql=is_postgresql(),
                                    render_url=request.host_url,
                                    db_status=get_database_status(),
                                    database_initialized=DATABASE_INITIALIZED,
                                    initialization_attempts=INITIALIZATION_ATTEMPTS,
                                    github_configured=github_configured,
                                    github_repo=GITHUB_REPO if github_configured else "Not configured",
                                    github_branch=GITHUB_BRANCH if github_configured else "main")
    except Exception as e:
        logger.error(f"Admin panel error: {e}")
        logger.exception("Full traceback:")
        
        return render_template_string(ENHANCED_REPAIR_HTML, 
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
            flash('❌ Email is required', 'error')
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
                current_expiry = datetime.fromisoformat(result[0])
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

# =============================================================================
# HTML TEMPLATES
# =============================================================================

ENHANCED_INDEX_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>PDF License Server - Enhanced Professional Edition</title>
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

        .github-status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-top: 0.5rem;
            font-size: 0.875rem;
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
            <p>Enhanced Flask 3.0+ Professional Edition with GitHub Auto-Deploy</p>
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
                <div class="github-status">
                    <i class="bi bi-github"></i>
                    {% if github_configured %}
                        <span style="color: #059669;">✅ GitHub Integration: {{ github_repo }}</span>
                    {% else %}
                        <span style="color: #d97706;">⚠️ GitHub Integration: Not configured</span>
                    {% endif %}
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h2><i class="bi bi-server"></i> Professional License Validation Service</h2>
            </div>
            <div class="card-body">
                <p style="margin-bottom: 2rem; font-size: 1.125rem; color: var(--text-secondary);">
                    Enhanced Flask 3.0+ architecture with automated GitHub deployment, real-time client updates,
                    one-click license management, and professional analytics. Deployed on Render.com with PostgreSQL
                    for maximum reliability and automated CI/CD workflows.
                </p>
                
                <div class="actions">
                    <a href="/admin" class="btn btn-primary">
                        <i class="bi bi-gear"></i>
                        Admin Dashboard
                    </a>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3><i class="bi bi-stars"></i> Features</h3>
            </div>
            <div class="card-body">
                <div class="features">
                    <div class="feature">
                        <h3><i class="bi bi-shield-check"></i> Data Preservation</h3>
                        <p>Smart initialization that preserves existing license data while creating missing database structures</p>
                    </div>
                    <div class="feature">
                        <h3><i class="bi bi-github"></i> GitHub Auto-Deploy</h3>
                        <p>Upload client files directly to GitHub with automatic building and release management</p>
                    </div>
                    <div class="feature">
                        <h3><i class="bi bi-cpu"></i> Hardware Binding</h3>
                        <p>Cryptographically secure hardware locking prevents unauthorized license sharing</p>
                    </div>
                    <div class="feature">
                        <h3><i class="bi bi-copy"></i> One-Click Copy</h3>
                        <p>Professional UI with instant license key copying and optimized admin workflows</p>
                    </div>
                    <div class="feature">
                        <h3><i class="bi bi-bell"></i> Auto-Updates</h3>
                        <p>Clients automatically receive notifications for new versions without manual checks</p>
                    </div>
                    <div class="feature">
                        <h3><i class="bi bi-lightning"></i> Modern Architecture</h3>
                        <p>Flask 3.0+ with responsive design, professional aesthetics, and optimized performance</p>
                    </div>
                </div>
            </div>
        </div>

        <div style="text-align: center; margin-top: 3rem; padding: 2rem; color: var(--text-secondary);">
            <p><strong>PDF License Server v6.1.0 - Enhanced Flask 3.0+ Edition</strong></p>
            <p>Professional License Management • GitHub Auto-Deploy • Modern UI Design</p>
        </div>
    </div>
</body>
</html>
'''

ENHANCED_ADMIN_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>License Admin Dashboard - Enhanced Professional Edition</title>
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
            max-width: 1600px; 
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

        .header h1 {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
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

        .stat-label {
            color: var(--text-secondary);
            font-weight: 500;
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
            justify-content: space-between;
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

        .licenses-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }

        .licenses-table th, .licenses-table td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }

        .licenses-table th {
            background: #f8fafc;
            font-weight: 600;
            color: var(--text-primary);
            position: sticky;
            top: 0;
            z-index: 10;
        }

        .licenses-table tr:hover { background: #f8fafc; }

        .license-info {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            min-width: 280px;
        }

        .license-key-row {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .license-key {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            background: #f1f5f9;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--primary-color);
            cursor: pointer;
            user-select: all;
            border: 1px solid #e2e8f0;
            transition: all 0.2s;
        }

        .license-key:hover {
            background: #e2e8f0;
            border-color: var(--primary-color);
            transform: scale(1.02);
        }

        .copy-btn {
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            cursor: pointer;
            font-size: 0.75rem;
            transition: all 0.2s;
        }

        .copy-btn:hover {
            background: #1d4ed8;
            transform: scale(1.05);
        }

        .copy-btn.copied {
            background: var(--success-color);
        }

        .hardware-id {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            background: #ecfdf5;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            color: #065f46;
            word-break: break-all;
            border: 1px solid #bbf7d0;
            max-width: 300px;
            overflow-wrap: break-word;
        }

        .customer-info {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        .customer-name {
            font-weight: 600;
            color: var(--text-primary);
        }

        .customer-email {
            color: var(--text-secondary);
        }

        .date-info {
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        .usage-count {
            font-weight: 700;
            font-size: 1.1rem;
            color: var(--primary-color);
            background: #e0e7ff;
            padding: 0.25rem 0.75rem;
            border-radius: 0.5rem;
            display: inline-block;
            min-width: 50px;
            text-align: center;
        }

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

        .upload-section {
            background: linear-gradient(135deg, #f8fafc, #f1f5f9);
            border: 2px dashed var(--border);
            border-radius: 1rem;
            padding: 2rem;
            text-align: center;
            margin: 2rem 0;
            transition: all 0.3s;
        }

        .upload-section:hover {
            border-color: var(--primary-color);
            background: linear-gradient(135deg, #f1f5f9, #e2e8f0);
        }

        .file-input {
            margin: 1rem 0;
        }

        .file-input input[type="file"] {
            display: none;
        }

        .file-input label {
            display: inline-block;
            padding: 0.75rem 2rem;
            background: var(--primary-color);
            color: white;
            border-radius: 0.5rem;
            cursor: pointer;
            transition: all 0.2s;
        }

        .file-input label:hover {
            background: #1d4ed8;
            transform: translateY(-1px);
        }

        @media (max-width: 1200px) {
            .licenses-table {
                display: block;
                overflow-x: auto;
                white-space: nowrap;
            }
        }

        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .stats { grid-template-columns: 1fr; }
            .tabs { flex-wrap: wrap; }
            .licenses-table { font-size: 0.75rem; }
            .licenses-table th, .licenses-table td { padding: 0.5rem; }
            .license-info { min-width: 250px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1><i class="bi bi-shield-lock"></i> License Admin Dashboard</h1>
            <p>Enhanced Flask 3.0+ Professional Edition</p>
            <div style="margin-top: 1rem; font-size: 0.875rem; opacity: 0.9;">
                Connected from: {{ current_ip }} | 
                Database: {{ 'PostgreSQL' if is_postgresql else 'SQLite' }} | 
                Status: {{ 'Ready' if database_initialized else 'Initializing' }}
                {% if github_configured %}
                | GitHub: {{ github_repo }}
                {% endif %}
            </div>
        </div>

        <!-- Flash Messages -->
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <!-- Statistics -->
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number">{{ stats.total_licenses if stats else 0 }}</div>
                <div class="stat-label">Total Licenses</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ stats.active_licenses if stats else 0 }}</div>
                <div class="stat-label">Active Licenses</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ stats.valid_licenses if stats else 0 }}</div>
                <div class="stat-label">Valid Licenses</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ (recent_validations | length) if recent_validations else 0 }}</div>
                <div class="stat-label">Recent Validations</div>
            </div>
        </div>

        <!-- System Actions -->
        <div class="card">
            <div class="card-header">
                <span><i class="bi bi-tools"></i> System Actions</span>
            </div>
            <div class="card-body">
                <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
                    <a href="/" class="btn btn-primary">
                        <i class="bi bi-house"></i> Home
                    </a>
                    <form method="POST" action="/admin/safe-repair" style="display: inline;">
                        <button type="submit" class="btn btn-warning" 
                                onclick="return confirm('Repair database? This is safe and preserves data.')">
                            <i class="bi bi-wrench"></i> Safe Repair
                        </button>
                    </form>
                    <a href="/health" class="btn btn-success" target="_blank">
                        <i class="bi bi-heart-pulse"></i> Health Check
                    </a>
                </div>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab active" onclick="showTab('licenses')">
                <i class="bi bi-key"></i> Licenses
            </button>
            <button class="tab" onclick="showTab('create')">
                <i class="bi bi-plus-circle"></i> Create License
            </button>
            <button class="tab" onclick="showTab('validations')">
                <i class="bi bi-activity"></i> Validation Logs
            </button>
            {% if github_configured %}
            <button class="tab" onclick="showTab('github')">
                <i class="bi bi-github"></i> GitHub Deploy
            </button>
            {% endif %}
        </div>

        <!-- Tab: Licenses -->
        <div id="licenses" class="tab-content active">
            <div class="card">
                <div class="card-header">
                    <span><i class="bi bi-key"></i> License Management ({{ (licenses | length) if licenses else 0 }} licenses)</span>
                </div>
                <div class="card-body">
                    {% if licenses %}
                    <div style="overflow-x: auto;">
                        <table class="licenses-table">
                            <thead>
                                <tr>
                                    <th>License Info</th>
                                    <th>Customer</th>
                                    <th>Dates</th>
                                    <th>Hardware</th>
                                    <th>Usage</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for license in licenses %}
                                <tr>
                                    <td>
                                        <div class="license-info">
                                            <div class="license-key-row">
                                                <span class="license-key" onclick="copyToClipboard('{{ license.license_key if license.license_key else license[0] }}', this)">
                                                    {{ license.license_key if license.license_key else license[0] }}
                                                </span>
                                                <button class="copy-btn" onclick="copyToClipboard('{{ license.license_key if license.license_key else license[0] }}', this)">
                                                    <i class="bi bi-copy"></i>
                                                </button>
                                            </div>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="customer-info">
                                            {% if license.customer_name or (license|length > 2 and license[2]) %}
                                                <div class="customer-name">{{ license.customer_name if license.customer_name else license[2] }}</div>
                                            {% endif %}
                                            <div class="customer-email">{{ license.customer_email if license.customer_email else license[1] }}</div>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="date-info">
                                            <div><strong>Created:</strong> {{ license.created_date | formatdatetime if license.created_date else (license[3] | formatdatetime if license|length > 3 else 'N/A') }}</div>
                                            <div><strong>Expires:</strong> {{ license.expiry_date | formatdatetime if license.expiry_date else (license[4] | formatdatetime if license|length > 4 else 'N/A') }}</div>
                                            {% if license.last_used or (license|length > 6 and license[6]) %}
                                                <div><strong>Last Used:</strong> {{ license.last_used | formatdatetime if license.last_used else (license[6] | formatdatetime) }}</div>
                                            {% endif %}
                                        </div>
                                    </td>
                                    <td>
                                        {% if license.hardware_id or (license|length > 8 and license[8]) %}
                                            <div class="hardware-id">{{ license.hardware_id if license.hardware_id else license[8] }}</div>
                                        {% else %}
                                            <span style="color: var(--text-secondary); font-style: italic;">Not bound</span>
                                        {% endif %}
                                    </td>
                                    <td>
                                        <div class="usage-count">{{ license.validation_count if license.validation_count else (license[7] if license|length > 7 else 0) }}</div>
                                    </td>
                                    <td>
                                        {% if (license.active if license.active is not none else (license[5] if license|length > 5 else 1)) %}
                                            <span class="status-badge active">Active</span>
                                        {% else %}
                                            <span class="status-badge inactive">Inactive</span>
                                        {% endif %}
                                    </td>
                                    <td>
                                        <div class="action-buttons">
                                            <form method="POST" action="/admin/toggle_license" style="display: inline;">
                                                <input type="hidden" name="license_key" value="{{ license.license_key if license.license_key else license[0] }}">
                                                <button type="submit" class="btn btn-warning">
                                                    <i class="bi bi-toggle-off"></i>
                                                </button>
                                            </form>
                                            <form method="POST" action="/admin/extend_license" style="display: inline;">
                                                <input type="hidden" name="license_key" value="{{ license.license_key if license.license_key else license[0] }}">
                                                <input type="hidden" name="extend_days" value="30">
                                                <button type="submit" class="btn btn-success" title="Extend 30 days">
                                                    <i class="bi bi-calendar-plus"></i>
                                                </button>
                                            </form>
                                            <form method="POST" action="/admin/delete_license" style="display: inline;">
                                                <input type="hidden" name="license_key" value="{{ license.license_key if license.license_key else license[0] }}">
                                                <button type="submit" class="btn btn-danger" 
                                                        onclick="return confirm('Delete license {{ license.license_key if license.license_key else license[0] }}?')">
                                                    <i class="bi bi-trash"></i>
                                                </button>
                                            </form>
                                        </div>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}
                    <div style="text-align: center; padding: 3rem; color: var(--text-secondary);">
                        <i class="bi bi-key" style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;"></i>
                        <h3>No licenses found</h3>
                        <p>Create your first license using the "Create License" tab.</p>
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>

        <!-- Tab: Create License -->
        <div id="create" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <span><i class="bi bi-plus-circle"></i> Create New License</span>
                </div>
                <div class="card-body">
                    <form method="POST" action="/admin/create_license">
                        <div class="form-group">
                            <label for="customer_email">Customer Email *</label>
                            <input type="email" id="customer_email" name="customer_email" required>
                        </div>
                        <div class="form-group">
                            <label for="customer_name">Customer Name</label>
                            <input type="text" id="customer_name" name="customer_name">
                        </div>
                        <div class="form-group">
                            <label for="duration_days">License Duration (days)</label>
                            <select id="duration_days" name="duration_days">
                                <option value="7">7 days (Trial)</option>
                                <option value="30" selected>30 days (Monthly)</option>
                                <option value="90">90 days (Quarterly)</option>
                                <option value="365">365 days (Yearly)</option>
                                <option value="1095">3 years</option>
                                <option value="1825">5 years</option>
                            </select>
                        </div>
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-plus-circle"></i> Create License
                        </button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Tab: Validation Logs -->
        <div id="validations" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <span><i class="bi bi-activity"></i> Recent Validation Attempts ({{ (recent_validations | length) if recent_validations else 0 }} shown)</span>
                </div>
                <div class="card-body">
                    {% if recent_validations %}
                    <div style="overflow-x: auto;">
                        <table class="licenses-table">
                            <thead>
                                <tr>
                                    <th>License Key</th>
                                    <th>Hardware ID</th>
                                    <th>Status</th>
                                    <th>IP Address</th>
                                    <th>Timestamp</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for validation in recent_validations %}
                                <tr>
                                    <td>
                                        <span class="license-key">{{ validation.license_key if validation.license_key else (validation[0] if validation|length > 0 else 'N/A') }}</span>
                                    </td>
                                    <td>
                                        {% if validation.hardware_id or (validation|length > 1 and validation[1]) %}
                                            <span class="hardware-id">{{ validation.hardware_id if validation.hardware_id else validation[1] }}</span>
                                        {% else %}
                                            <span style="color: var(--text-secondary);">N/A</span>
                                        {% endif %}
                                    </td>
                                    <td>
                                        {% if (validation.status if validation.status else (validation[2] if validation|length > 2 else '')) == 'VALID' %}
                                            <span class="status-badge active">{{ validation.status if validation.status else validation[2] }}</span>
                                        {% else %}
                                            <span class="status-badge inactive">{{ validation.status if validation.status else (validation[2] if validation|length > 2 else 'Unknown') }}</span>
                                        {% endif %}
                                    </td>
                                    <td>{{ validation.ip_address if validation.ip_address else (validation[3] if validation|length > 3 else 'Unknown') }}</td>
                                    <td>{{ validation.timestamp | formatdatetimefull if validation.timestamp else (validation[4] | formatdatetimefull if validation|length > 4 else 'N/A') }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}
                    <div style="text-align: center; padding: 3rem; color: var(--text-secondary);">
                        <i class="bi bi-activity" style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;"></i>
                        <h3>No validation logs</h3>
                        <p>Validation attempts will appear here when clients validate licenses.</p>
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>

        <!-- Tab: GitHub Deploy (only if configured) -->
        {% if github_configured %}
        <div id="github" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <span><i class="bi bi-github"></i> GitHub Auto-Deploy System</span>
                    <span style="font-size: 0.875rem; color: var(--text-secondary);">{{ github_repo }}</span>
                </div>
                <div class="card-body">
                    <div class="upload-section">
                        <h3><i class="bi bi-upload"></i> Deploy New Client Version</h3>
                        <p style="margin: 1rem 0; color: var(--text-secondary);">
                            Upload a new client file to automatically deploy to GitHub and trigger builds
                        </p>
                        
                        <form method="POST" action="/admin/upload-client" enctype="multipart/form-data">
                            <div class="file-input">
                                <input type="file" id="client_file" name="client_file" accept=".py" required>
                                <label for="client_file">
                                    <i class="bi bi-file-earmark-code"></i> Choose Python File
                                </label>
                            </div>
                            <div class="form-group" style="max-width: 300px; margin: 1rem auto;">
                                <label for="version_tag">Version Tag</label>
                                <input type="text" id="version_tag" name="version_tag" 
                                       placeholder="v2024.01.15.1200">
                            </div>
                            <button type="submit" class="btn btn-primary">
                                <i class="bi bi-github"></i> Deploy to GitHub
                            </button>
                        </form>
                    </div>

                    <!-- Client Upload History -->
                    {% if client_uploads %}
                    <h4 style="margin: 2rem 0 1rem 0;">Recent Deployments</h4>
                    <div style="overflow-x: auto;">
                        <table class="licenses-table">
                            <thead>
                                <tr>
                                    <th>Filename</th>
                                    <th>Version</th>
                                    <th>Upload Date</th>
                                    <th>Build Info</th>
                                    <th>Build Status</th>
                                    <th>Links</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for upload in client_uploads %}
                                <tr>
                                    <td>{{ upload.filename if upload.filename else (upload[0] if upload|length > 0 else 'N/A') }}</td>
                                    <td>{{ upload.version_tag if upload.version_tag else (upload[3] if upload|length > 3 else 'N/A') }}</td>
                                    <td>{{ upload.upload_date | formatdatetimefull if upload.upload_date else (upload[1] | formatdatetimefull if upload|length > 1 else 'N/A') }}</td>
                                    <td>
                                        <div style="font-size: 0.8rem;">
                                            {% set build_num = upload.build_number if upload.build_number else (upload[6] if upload|length > 6 else '') %}
                                            {% set commit = upload.commit_sha if upload.commit_sha else (upload[7] if upload|length > 7 else '') %}
                                            {% if build_num %}
                                                <div><strong>Build:</strong> #{{ build_num }}</div>
                                            {% endif %}
                                            {% if commit %}
                                                <div><strong>Commit:</strong> {{ commit[:8] }}...</div>
                                            {% endif %}
                                            <div><strong>By:</strong> {{ upload.uploaded_by if upload.uploaded_by else (upload[2] if upload|length > 2 else 'Unknown') }}</div>
                                        </div>
                                    </td>
                                    <td>
                                        {% set status = upload.build_status if upload.build_status else (upload[4] if upload|length > 4 else 'pending') %}
                                        {% if status == 'completed' %}
                                            <span class="status-badge active">Completed</span>
                                        {% elif status == 'uploaded' %}
                                            <span class="status-badge" style="background: #fbbf24; color: #92400e;">Uploaded</span>
                                        {% else %}
                                            <span class="status-badge inactive">{{ status or 'Pending' }}</span>
                                        {% endif %}
                                    </td>
                                    <td>
                                        <div style="display: flex; gap: 0.25rem; flex-direction: column;">
                                            {% set github_url = upload.github_url if upload.github_url else (upload[5] if upload|length > 5 else '') %}
                                            {% set release_url = upload.release_url if upload.release_url else (upload[8] if upload|length > 8 else '') %}
                                            
                                            {% if github_url %}
                                                <a href="{{ github_url }}" target="_blank" class="btn btn-primary" style="font-size: 0.7rem; padding: 0.2rem 0.4rem;">
                                                    <i class="bi bi-download"></i> Download
                                                </a>
                                            {% endif %}
                                            
                                            {% if release_url %}
                                                <a href="{{ release_url }}" target="_blank" class="btn btn-success" style="font-size: 0.7rem; padding: 0.2rem 0.4rem;">
                                                    <i class="bi bi-tag"></i> Release
                                                </a>
                                            {% endif %}
                                            
                                            {% if not github_url and not release_url %}
                                                <span style="color: var(--text-secondary); font-size: 0.8rem;">N/A</span>
                                            {% endif %}
                                        </div>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>
        {% endif %}
    </div>

    <script>
        // Tab functionality
        function showTab(tabName) {
            // Hide all tab contents
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));

            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => tab.classList.remove('active'));

            // Show selected tab content
            document.getElementById(tabName).classList.add('active');

            // Add active class to clicked tab
            event.target.classList.add('active');
        }

        // Copy to clipboard functionality
        function copyToClipboard(text, button) {
            navigator.clipboard.writeText(text).then(function() {
                const originalText = button.innerHTML;
                button.innerHTML = '<i class="bi bi-check"></i>';
                button.classList.add('copied');
                
                setTimeout(function() {
                    button.innerHTML = originalText;
                    button.classList.remove('copied');
                }, 2000);
            }).catch(function(err) {
                console.error('Failed to copy: ', err);
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                
                button.innerHTML = '<i class="bi bi-check"></i>';
                button.classList.add('copied');
                setTimeout(function() {
                    button.innerHTML = '<i class="bi bi-copy"></i>';
                    button.classList.remove('copied');
                }, 2000);
            });
        }

        // File input display
        document.addEventListener('DOMContentLoaded', function() {
            const fileInput = document.getElementById('client_file');
            if (fileInput) {
                fileInput.addEventListener('change', function() {
                    const label = document.querySelector('label[for="client_file"]');
                    if (this.files && this.files[0]) {
                        label.innerHTML = `<i class="bi bi-file-earmark-code"></i> ${this.files[0].name}`;
                    }
                });
            }
        });
    </script>
</body>
</html>
'''

ENHANCED_REPAIR_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Database Repair - Enhanced Professional Edition</title>
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
            <p>Enhanced Flask 3.0+ Professional Database Recovery</p>
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
                <p><strong>Database Type:</strong> {{ db_status.type if db_status else 'Unknown' }}</p>
                <p><strong>Connection Status:</strong>
                    {% if db_status and db_status.connection %}
                        <span class="status-badge status-success">Connected</span>
                    {% else %}
                        <span class="status-badge status-error">Disconnected</span>
                    {% endif %}
                </p>

                {% if db_status and db_status.tables %}
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
                {% endif %}
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
