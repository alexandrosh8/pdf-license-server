"""
🔐 PRODUCTION PDF LICENSE SERVER - FLASK
=========================================
Complete license server with admin panel, hardware locking, and IP tracking

Version: 2.2.0
Compatible with Render.com deployment and PostgreSQL
"""

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, flash
import hashlib
import json
import secrets
import string
from datetime import datetime, timedelta
import os
import logging
from contextlib import contextmanager
import psycopg2
import psycopg2.extras
from urllib.parse import urlparse

# =============================================================================
# APP CONFIGURATION
# =============================================================================

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))

# Admin credentials
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'Admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme123')

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgresql://'):
    DATABASE_URL = DATABASE_URL.replace('postgresql://', 'postgres://', 1)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# DATABASE FUNCTIONS
# =============================================================================

def get_db_connection():
    """Get database connection - PostgreSQL for Render, SQLite for local/fallback"""
    if DATABASE_URL and PSYCOPG2_AVAILABLE:
        try:
            # Try PostgreSQL first
            return psycopg2.connect(DATABASE_URL)
        except Exception as e:
            logger.error(f"PostgreSQL connection failed: {e}, falling back to SQLite")
            # Fall back to SQLite on any PostgreSQL error
            import sqlite3
            conn = sqlite3.connect('licenses.db')
            conn.row_factory = sqlite3.Row
            return conn
    else:
        # SQLite for local development or when psycopg2 not available
        import sqlite3
        conn = sqlite3.connect('licenses.db')
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    """Initialize the license database with proper schema"""
    try:
        with get_db_connection() as conn:
            if DATABASE_URL and PSYCOPG2_AVAILABLE:
                # PostgreSQL schema
                with conn.cursor() as cur:
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
                    
                    # Create indexes
                    cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)')
                    cur.execute('CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(customer_email)')
                    cur.execute('CREATE INDEX IF NOT EXISTS idx_validation_logs_timestamp ON validation_logs(timestamp)')
                    
                logger.info("PostgreSQL database initialized successfully")
                    
            else:
                # SQLite schema for local development or fallback
                cur = conn.cursor()
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS licenses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        license_key TEXT UNIQUE NOT NULL,
                        hardware_id TEXT,
                        customer_email TEXT NOT NULL,
                        customer_name TEXT,
                        created_date TEXT NOT NULL,
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
                        timestamp TEXT,
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
                        login_time TEXT,
                        last_activity TEXT
                    )
                ''')
                
                logger.info("SQLite database initialized successfully")
                
            conn.commit()
            
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_license_key():
    """Generate a unique license key in SLIC format"""
    segments = []
    for _ in range(4):
        segment = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        segments.append(segment)
    return f"SLIC-{'-'.join(segments)}"

def log_validation(license_key, hardware_id, status, ip_address, user_agent=None, details=None):
    """Log validation attempt"""
    try:
        with get_db_connection() as conn:
            if DATABASE_URL and PSYCOPG2_AVAILABLE:
                with conn.cursor() as cur:
                    cur.execute('''
                        INSERT INTO validation_logs (license_key, hardware_id, status, ip_address, user_agent, details)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    ''', (license_key, hardware_id, status, ip_address, user_agent, 
                          json.dumps(details) if details else None))
            else:
                cur = conn.cursor()
                cur.execute('''
                    INSERT INTO validation_logs (license_key, hardware_id, timestamp, status, ip_address, user_agent, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (license_key, hardware_id, datetime.now().isoformat(), status, ip_address, user_agent,
                      json.dumps(details) if details else None))
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to log validation: {e}")

def log_admin_session(username, ip_address):
    """Log admin login session"""
    try:
        session_id = secrets.token_urlsafe(32)
        with get_db_connection() as conn:
            if DATABASE_URL and PSYCOPG2_AVAILABLE:
                with conn.cursor() as cur:
                    cur.execute('''
                        INSERT INTO admin_sessions (session_id, username, ip_address)
                        VALUES (%s, %s, %s)
                    ''', (session_id, username, ip_address))
            else:
                cur = conn.cursor()
                cur.execute('''
                    INSERT INTO admin_sessions (session_id, username, ip_address, login_time)
                    VALUES (?, ?, ?, ?)
                ''', (session_id, username, ip_address, datetime.now().isoformat()))
            conn.commit()
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
        with get_db_connection() as conn:
            if DATABASE_URL and PSYCOPG2_AVAILABLE:
                with conn.cursor() as cur:
                    cur.execute('''
                        INSERT INTO licenses (license_key, customer_email, customer_name, 
                                            expiry_date, created_by)
                        VALUES (%s, %s, %s, %s, %s)
                    ''', (license_key, customer_email, customer_name, expiry_date, created_by))
            else:
                cur = conn.cursor()
                cur.execute('''
                    INSERT INTO licenses (license_key, customer_email, customer_name, 
                                        created_date, expiry_date, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (license_key, customer_email, customer_name, 
                      created_date.isoformat(), expiry_date.isoformat(), created_by))
            conn.commit()
            
        return {
            'license_key': license_key,
            'expiry_date': expiry_date.strftime('%Y-%m-%d'),
            'customer_email': customer_email,
            'duration_days': duration_days
        }
    except Exception as e:
        logger.error(f"Failed to create license: {e}")
        raise

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.route('/api/validate', methods=['POST'])
def validate_license():
    """Validate a license key from the desktop application"""
    try:
        data = request.get_json()
        license_key = data.get('license_key')
        hardware_id = data.get('hardware_id')
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        if not license_key:
            return jsonify({
                "valid": False,
                "reason": "Missing license key"
            }), 400
        
        if not hardware_id:
            return jsonify({
                "valid": False,
                "reason": "Missing hardware ID"
            }), 400
        
        with get_db_connection() as conn:
            if DATABASE_URL and PSYCOPG2_AVAILABLE:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        'SELECT * FROM licenses WHERE license_key = %s AND active = true',
                        (license_key,)
                    )
                    license_row = cur.fetchone()
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
            if DATABASE_URL and PSYCOPG2_AVAILABLE:
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
                    "expired_date": license_row['expiry_date'],
                    "renewal_url": f"{request.host_url}renew/{license_key}"
                }), 400
            
            # Hardware binding logic
            stored_hardware_id = license_row['hardware_id']
            
            if not stored_hardware_id:
                # First time binding - bind to this hardware
                if DATABASE_URL and PSYCOPG2_AVAILABLE:
                    with conn.cursor() as cur:
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
                return jsonify({
                    "valid": False,
                    "reason": "License is locked to a different computer",
                    "message": "This license is already activated on another computer. Each license can only be used on one computer."
                }), 400
            else:
                # Valid hardware - update last used
                if DATABASE_URL and PSYCOPG2_AVAILABLE:
                    with conn.cursor() as cur:
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
            
            days_remaining = (expiry_date - current_date).days
            
            return jsonify({
                "valid": True,
                "message": "License is valid",
                "expiry_date": expiry_date.isoformat() if DATABASE_URL else license_row['expiry_date'],
                "days_remaining": max(0, days_remaining),
                "customer_email": license_row['customer_email'],
                "validation_count": license_row['validation_count'] + 1,
                "renewal_url": f"{request.host_url}renew/{license_key}"
            })
            
    except Exception as e:
        logger.error(f"Validation error: {e}")
        return jsonify({
            "valid": False,
            "reason": "Server error",
            "message": "Please try again later"
        }), 500

@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    try:
        # Test database connection
        with get_db_connection() as conn:
            if DATABASE_URL and PSYCOPG2_AVAILABLE:
                with conn.cursor() as cur:
                    cur.execute('SELECT 1')
                db_type = "PostgreSQL"
            else:
                cur = conn.cursor()
                cur.execute('SELECT 1')
                db_type = "SQLite"
        
        return jsonify({
            "status": "healthy",
            "version": "2.2.0",
            "timestamp": datetime.now().isoformat(),
            "database": db_type,
            "psycopg2_available": PSYCOPG2_AVAILABLE
        })
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "database": "disconnected",
            "psycopg2_available": PSYCOPG2_AVAILABLE
        }), 503

# =============================================================================
# WEB INTERFACE
# =============================================================================

@app.route('/')
def index():
    """Main page"""
    return render_template_string(INDEX_HTML)

@app.route('/admin')
def admin():
    """Admin panel - check credentials first"""
    auth = request.authorization
    
    if not auth or auth.username != ADMIN_USERNAME or auth.password != ADMIN_PASSWORD:
        return '''<script>
            const credentials = prompt("Enter admin credentials (username:password):");
            if (credentials) {
                const [username, password] = credentials.split(":");
                if (username === "''' + ADMIN_USERNAME + '''" && password === "''' + ADMIN_PASSWORD + '''") {
                    location.reload();
                } else {
                    alert("Invalid credentials!");
                    history.back();
                }
            } else {
                history.back();
            }
        </script>''', 401, {'WWW-Authenticate': 'Basic realm="Admin Login Required"'}
    
    # Log admin access
    log_admin_session(auth.username, request.remote_addr)
    
    try:
        with get_db_connection() as conn:
            if DATABASE_URL and PSYCOPG2_AVAILABLE:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    # Get all licenses
                    cur.execute('''
                        SELECT license_key, customer_email, customer_name, created_date, 
                               expiry_date, active, last_used, validation_count, hardware_id, created_by
                        FROM licenses 
                        ORDER BY created_date DESC
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
                    
                    # Get recent admin logins with IPs
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
                cur = conn.cursor()
                licenses = cur.execute('''
                    SELECT license_key, customer_email, customer_name, created_date, 
                           expiry_date, active, last_used, validation_count, hardware_id, created_by
                    FROM licenses 
                    ORDER BY created_date DESC
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
    
        return render_template_string(ADMIN_HTML, 
                                    licenses=licenses, 
                                    stats=stats, 
                                    recent_logins=recent_logins,
                                    recent_validations=recent_validations,
                                    current_ip=request.remote_addr)
    except Exception as e:
        logger.error(f"Admin panel error: {e}")
        return f"Admin panel error: {e}", 500

@app.route('/admin/create_license', methods=['POST'])
def create_license_endpoint():
    """Create a new license from admin panel"""
    auth = request.authorization
    if not auth or auth.username != ADMIN_USERNAME or auth.password != ADMIN_PASSWORD:
        return "Unauthorized", 401
    
    try:
        customer_email = request.form.get('customer_email')
        customer_name = request.form.get('customer_name', '')
        duration_days = int(request.form.get('duration_days', 30))
        
        if not customer_email:
            flash('Email is required', 'error')
            return redirect('/admin')
        
        license_info = create_license(customer_email, customer_name, duration_days, f'admin:{auth.username}')
        flash(f'License created successfully: {license_info["license_key"]}', 'success')
        
    except Exception as e:
        flash(f'Error creating license: {e}', 'error')
    
    return redirect('/admin')

@app.route('/admin/delete_license', methods=['POST'])
def delete_license():
    """Delete a license"""
    auth = request.authorization
    if not auth or auth.username != ADMIN_USERNAME or auth.password != ADMIN_PASSWORD:
        return "Unauthorized", 401
    
    try:
        license_key = request.form.get('license_key')
        
        with get_db_connection() as conn:
            if DATABASE_URL:
                with conn.cursor() as cur:
                    cur.execute('DELETE FROM licenses WHERE license_key = %s', (license_key,))
            else:
                cur = conn.cursor()
                cur.execute('DELETE FROM licenses WHERE license_key = ?', (license_key,))
            conn.commit()
            
        flash(f'License {license_key} deleted successfully', 'success')
        
    except Exception as e:
        flash(f'Error deleting license: {e}', 'error')
    
    return redirect('/admin')

@app.route('/admin/toggle_license', methods=['POST'])
def toggle_license():
    """Toggle license active status"""
    auth = request.authorization
    if not auth or auth.username != ADMIN_USERNAME or auth.password != ADMIN_PASSWORD:
        return "Unauthorized", 401
    
    try:
        license_key = request.form.get('license_key')
        
        with get_db_connection() as conn:
            if DATABASE_URL:
                with conn.cursor() as cur:
                    cur.execute('UPDATE licenses SET active = NOT active WHERE license_key = %s', (license_key,))
            else:
                cur = conn.cursor()
                cur.execute('UPDATE licenses SET active = NOT active WHERE license_key = ?', (license_key,))
            conn.commit()
            
        flash(f'License {license_key} status toggled', 'success')
        
    except Exception as e:
        flash(f'Error toggling license: {e}', 'error')
    
    return redirect('/admin')

# =============================================================================
# HTML TEMPLATES
# =============================================================================

INDEX_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PDF License Server - Administration</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .header { text-align: center; background: #fff; padding: 30px; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .card { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin: 20px 0; }
        .btn { background: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block; margin: 10px 5px; font-weight: bold; }
        .btn:hover { background: #5a67d8; }
        .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .feature { background: #f8f9fa; padding: 20px; border-radius: 10px; border-left: 4px solid #667eea; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 PDF License Server</h1>
        <p style="font-size: 18px; color: #666;">Secure license management system with hardware binding</p>
    </div>
    
    <div class="card">
        <h2>Server Status</h2>
        <p>✅ License server is running and ready to validate licenses</p>
        <p>🔒 Hardware-locked licensing system active</p>
        <p>📊 Real-time validation logging enabled</p>
        
        <div style="text-align: center; margin-top: 30px;">
            <a href="/admin" class="btn">🛠️ Admin Panel</a>
            <a href="/health" class="btn">💚 Health Check</a>
        </div>
    </div>
    
    <div class="card">
        <h3>🛡️ Security Features</h3>
        <div class="features">
            <div class="feature">
                <strong>🔒 Hardware Binding</strong><br>
                Each license is locked to a specific computer
            </div>
            <div class="feature">
                <strong>📊 Real-time Monitoring</strong><br>
                All validation attempts are logged with IP addresses
            </div>
            <div class="feature">
                <strong>⏰ Expiration Control</strong><br>
                Automatic license expiration and renewal system
            </div>
            <div class="feature">
                <strong>👨‍💼 Admin Management</strong><br>
                Complete license lifecycle management
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
    <title>License Administration Panel</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 10px; overflow: hidden; }
        th, td { border: 1px solid #e1e5e9; padding: 12px; text-align: left; font-size: 14px; }
        th { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-weight: bold; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-box { background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%); padding: 25px; border-radius: 15px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .stat-number { font-size: 32px; font-weight: bold; color: #2d3748; margin-bottom: 5px; }
        .stat-label { color: #4a5568; font-weight: bold; }
        .expired { color: #e53e3e; font-weight: bold; }
        .active { color: #38a169; font-weight: bold; }
        .inactive { color: #718096; font-weight: bold; }
        .license-key { font-family: 'Courier New', monospace; background: #f7fafc; padding: 5px 8px; border-radius: 5px; font-size: 12px; }
        .form-group { margin: 15px 0; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 5px; }
        .btn { background: #667eea; color: white; padding: 8px 16px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; margin: 2px; }
        .btn-danger { background: #e53e3e; }
        .btn-warning { background: #ed8936; }
        .btn-success { background: #38a169; }
        .btn:hover { opacity: 0.9; }
        .flash { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .flash.success { background: #c6f6d5; color: #276749; }
        .flash.error { background: #fed7d7; color: #9b2c2c; }
        .create-form { background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .tabs { display: flex; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #e2e8f0; border: none; cursor: pointer; border-radius: 5px 5px 0 0; margin-right: 5px; }
        .tab.active { background: #667eea; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 License Administration Panel</h1>
        <p><strong>Current Session IP:</strong> {{ current_ip }}</p>
        
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
            <h2>📋 All Licenses</h2>
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
                        <th>Created By</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for license in licenses %}
                    <tr>
                        <td><span class="license-key">{{ license.license_key }}</span></td>
                        <td>{{ license.customer_name or 'N/A' }}</td>
                        <td>{{ license.customer_email }}</td>
                        <td>{{ license.created_date[:10] if license.created_date else 'N/A' }}</td>
                        <td>{{ license.expiry_date[:10] if license.expiry_date else 'N/A' }}</td>
                        <td>
                            {% if license.active %}
                                <span class="active">● Active</span>
                            {% else %}
                                <span class="inactive">● Inactive</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if license.hardware_id %}
                                <code style="font-size: 10px;">{{ license.hardware_id[:16] }}...</code>
                            {% else %}
                                <span style="color: #999;">Unbound</span>
                            {% endif %}
                        </td>
                        <td>
                            <small>
                                Count: {{ license.validation_count or 0 }}<br>
                                Last: {{ license.last_used[:10] if license.last_used else 'Never' }}
                            </small>
                        </td>
                        <td><small>{{ license.created_by or 'system' }}</small></td>
                        <td>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="license_key" value="{{ license.license_key }}">
                                <button type="submit" formaction="/admin/toggle_license" class="btn btn-warning" 
                                        onclick="return confirm('Toggle license status?')">
                                    {% if license.active %}Disable{% else %}Enable{% endif %}
                                </button>
                                <button type="submit" formaction="/admin/delete_license" class="btn btn-danger" 
                                        onclick="return confirm('Delete this license permanently?')">Delete</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <!-- Create License Tab -->
        <div id="create" class="tab-content">
            <h2>➕ Create New License</h2>
            <div class="create-form">
                <form method="POST" action="/admin/create_license">
                    <div class="form-group">
                        <label for="customer_email">📧 Customer Email *</label>
                        <input type="email" id="customer_email" name="customer_email" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="customer_name">👤 Customer Name</label>
                        <input type="text" id="customer_name" name="customer_name">
                    </div>
                    
                    <div class="form-group">
                        <label for="duration_days">⏰ Duration (Days)</label>
                        <select id="duration_days" name="duration_days">
                            <option value="7">7 days (Trial)</option>
                            <option value="30" selected>30 days (Monthly)</option>
                            <option value="90">90 days (Quarterly)</option>
                            <option value="365">365 days (Annual)</option>
                        </select>
                    </div>
                    
                    <button type="submit" class="btn btn-success">🚀 Create License</button>
                </form>
            </div>
        </div>
        
        <!-- Activity Logs Tab -->
        <div id="logs" class="tab-content">
            <h2>📊 Recent Validation Activity</h2>
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
                        <td>{{ log.timestamp[:19] if log.timestamp else 'N/A' }}</td>
                        <td><span class="license-key">{{ log.license_key[:20] if log.license_key else 'N/A' }}...</span></td>
                        <td><code style="font-size: 10px;">{{ log.hardware_id[:16] if log.hardware_id else 'N/A' }}...</code></td>
                        <td>
                            {% if log.status == 'VALID' %}
                                <span class="active">✅ {{ log.status }}</span>
                            {% elif log.status == 'EXPIRED' %}
                                <span class="expired">⏰ {{ log.status }}</span>
                            {% elif log.status == 'HARDWARE_MISMATCH' %}
                                <span class="expired">🔒 {{ log.status }}</span>
                            {% else %}
                                <span class="inactive">❌ {{ log.status }}</span>
                            {% endif %}
                        </td>
                        <td>{{ log.ip_address or 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <!-- Admin Logs Tab -->
        <div id="admin-logs" class="tab-content">
            <h2>👨‍💼 Recent Admin Access</h2>
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
                        <td>{{ login.login_time[:19] if login.login_time else 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <p style="margin-top: 30px;"><a href="/" style="color: #667eea; text-decoration: none; font-weight: bold;">← Back to Home</a></p>
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all tab contents
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            // Hide all tab buttons
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
# MAIN APPLICATION
# =============================================================================

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
