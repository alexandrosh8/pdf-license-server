# app.py - Admin-Only License Server
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
import hashlib
import json
import secrets
import string
from datetime import datetime, timedelta
import os
import sqlite3
from contextlib import contextmanager

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

# Admin credentials - CHANGE THESE!
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# Database setup
DATABASE = 'licenses.db'

def init_db():
    """Initialize the license database."""
    conn = sqlite3.connect(DATABASE)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            hardware_id TEXT,
            customer_email TEXT,
            customer_name TEXT,
            created_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            payment_id TEXT,
            active INTEGER DEFAULT 1,
            last_used TEXT,
            notes TEXT
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS validation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT,
            hardware_id TEXT,
            timestamp TEXT,
            status TEXT,
            ip_address TEXT
        )
    ''')
    conn.commit()
    conn.close()

@contextmanager
def get_db():
    """Database context manager."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def generate_license_key():
    """Generate a unique license key."""
    def random_segment():
        return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    
    return f"PDFM-{random_segment()}-{random_segment()}-{random_segment()}"

def create_monthly_license(customer_email, customer_name=None, payment_id=None, notes=None):
    """Create a new monthly license."""
    license_key = generate_license_key()
    created_date = datetime.now()
    expiry_date = created_date + timedelta(days=30)  # Monthly license
    
    with get_db() as conn:
        conn.execute('''
            INSERT INTO licenses (license_key, customer_email, customer_name, 
                                created_date, expiry_date, payment_id, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (license_key, customer_email, customer_name, 
              created_date.isoformat(), expiry_date.isoformat(), payment_id, notes))
        conn.commit()
    
    return {
        'license_key': license_key,
        'expiry_date': expiry_date.strftime('%Y-%m-%d'),
        'customer_email': customer_email
    }

def require_admin():
    """Check if user is logged in as admin."""
    return session.get('admin_logged_in') == True

# =============================================================================
# PUBLIC API ENDPOINTS (for PDF application)
# =============================================================================

@app.route('/api/validate', methods=['POST'])
def validate_license():
    """Validate a license key from the desktop application."""
    try:
        data = request.get_json()
        license_key = data.get('license_key')
        hardware_id = data.get('hardware_id')
        
        if not license_key:
            return jsonify({
                "valid": False,
                "reason": "Missing license key"
            }), 400
        
        with get_db() as conn:
            license_row = conn.execute(
                'SELECT * FROM licenses WHERE license_key = ? AND active = 1',
                (license_key,)
            ).fetchone()
            
            if not license_row:
                # Log failed validation
                conn.execute('''
                    INSERT INTO validation_logs (license_key, hardware_id, timestamp, status, ip_address)
                    VALUES (?, ?, ?, ?, ?)
                ''', (license_key, hardware_id, datetime.now().isoformat(), 'INVALID_KEY', request.remote_addr))
                conn.commit()
                
                return jsonify({
                    "valid": False,
                    "reason": "Invalid license key"
                }), 400
            
            # Check expiration
            expiry_date = datetime.fromisoformat(license_row['expiry_date'])
            current_date = datetime.now()
            
            if current_date > expiry_date:
                # Log expired validation
                conn.execute('''
                    INSERT INTO validation_logs (license_key, hardware_id, timestamp, status, ip_address)
                    VALUES (?, ?, ?, ?, ?)
                ''', (license_key, hardware_id, datetime.now().isoformat(), 'EXPIRED', request.remote_addr))
                conn.commit()
                
                return jsonify({
                    "valid": False,
                    "reason": "License expired",
                    "expired_date": license_row['expiry_date']
                }), 400
            
            # Update hardware ID and last used
            if not license_row['hardware_id'] or license_row['hardware_id'] != hardware_id:
                conn.execute(
                    'UPDATE licenses SET hardware_id = ?, last_used = ? WHERE license_key = ?',
                    (hardware_id, datetime.now().isoformat(), license_key)
                )
                conn.commit()
            
            # Log successful validation
            conn.execute('''
                INSERT INTO validation_logs (license_key, hardware_id, timestamp, status, ip_address)
                VALUES (?, ?, ?, ?, ?)
            ''', (license_key, hardware_id, datetime.now().isoformat(), 'VALID', request.remote_addr))
            conn.commit()
            
            days_remaining = (expiry_date - current_date).days
            
            return jsonify({
                "valid": True,
                "message": "License is valid",
                "expiry_date": license_row['expiry_date'],
                "days_remaining": days_remaining,
                "customer_email": license_row['customer_email']
            })
            
    except Exception as e:
        return jsonify({
            "valid": False,
            "reason": "Server error",
            "message": str(e)
        }), 500

@app.route('/check/<license_key>')
def check_license(license_key):
    """Public license check for customer support."""
    with get_db() as conn:
        license_row = conn.execute(
            'SELECT license_key, customer_email, created_date, expiry_date, active FROM licenses WHERE license_key = ?',
            (license_key,)
        ).fetchone()
        
        if not license_row:
            return render_template_string(CHECK_RESULT_HTML, 
                                        status="not_found", license_key=license_key)
        
        expiry_date = datetime.fromisoformat(license_row['expiry_date'])
        current_date = datetime.now()
        
        if current_date > expiry_date:
            status = "expired"
        elif not license_row['active']:
            status = "inactive"
        else:
            status = "valid"
        
        days_remaining = (expiry_date - current_date).days if status == "valid" else 0
        
        return render_template_string(CHECK_RESULT_HTML, 
                                    status=status, 
                                    license_info=license_row,
                                    days_remaining=days_remaining,
                                    license_key=license_key)

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    return jsonify({"status": "healthy"})

# =============================================================================
# ADMIN AUTHENTICATION
# =============================================================================

@app.route('/')
def index():
    """Main page - redirect to admin login."""
    if require_admin():
        return redirect('/admin')
    return render_template_string(LOGIN_HTML)

@app.route('/login', methods=['POST'])
def login():
    """Handle admin login."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        return redirect('/admin')
    else:
        return render_template_string(LOGIN_HTML, error="Invalid credentials")

@app.route('/logout')
def logout():
    """Admin logout."""
    session.pop('admin_logged_in', None)
    return redirect('/')

# =============================================================================
# ADMIN PANEL
# =============================================================================

@app.route('/admin')
def admin():
    """Admin dashboard."""
    if not require_admin():
        return redirect('/')
    
    with get_db() as conn:
        licenses = conn.execute('''
            SELECT license_key, customer_email, customer_name, created_date, 
                   expiry_date, active, last_used, notes
            FROM licenses 
            ORDER BY created_date DESC
        ''').fetchall()
        
        stats = conn.execute('''
            SELECT 
                COUNT(*) as total_licenses,
                COUNT(CASE WHEN active = 1 THEN 1 END) as active_licenses,
                COUNT(CASE WHEN datetime(expiry_date) > datetime('now') AND active = 1 THEN 1 END) as valid_licenses
            FROM licenses
        ''').fetchone()
        
        recent_validations = conn.execute('''
            SELECT license_key, hardware_id, timestamp, status, ip_address
            FROM validation_logs 
            ORDER BY timestamp DESC 
            LIMIT 20
        ''').fetchall()
    
    return render_template_string(ADMIN_HTML, 
                                licenses=licenses, 
                                stats=stats, 
                                validations=recent_validations)

@app.route('/admin/create', methods=['GET', 'POST'])
def admin_create_license():
    """Create new license (admin only)."""
    if not require_admin():
        return redirect('/')
    
    if request.method == 'POST':
        customer_email = request.form.get('email')
        customer_name = request.form.get('name')
        payment_id = request.form.get('payment_id')
        notes = request.form.get('notes')
        
        if not customer_email:
            return render_template_string(CREATE_LICENSE_HTML, error="Email is required")
        
        license_info = create_monthly_license(customer_email, customer_name, payment_id, notes)
        
        return render_template_string(LICENSE_CREATED_HTML, license_info=license_info)
    
    return render_template_string(CREATE_LICENSE_HTML)

@app.route('/admin/extend/<license_key>', methods=['POST'])
def extend_license(license_key):
    """Extend license by 30 days (admin only)."""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    with get_db() as conn:
        current_expiry = conn.execute(
            'SELECT expiry_date FROM licenses WHERE license_key = ?',
            (license_key,)
        ).fetchone()
        
        if not current_expiry:
            return jsonify({'error': 'License not found'}), 404
        
        current_expiry_date = datetime.fromisoformat(current_expiry['expiry_date'])
        new_expiry_date = max(current_expiry_date, datetime.now()) + timedelta(days=30)
        
        conn.execute(
            'UPDATE licenses SET expiry_date = ?, active = 1 WHERE license_key = ?',
            (new_expiry_date.isoformat(), license_key)
        )
        conn.commit()
    
    return redirect('/admin')

@app.route('/admin/deactivate/<license_key>', methods=['POST'])
def deactivate_license(license_key):
    """Deactivate license (admin only)."""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    with get_db() as conn:
        conn.execute(
            'UPDATE licenses SET active = 0 WHERE license_key = ?',
            (license_key,)
        )
        conn.commit()
    
    return redirect('/admin')

@app.route('/admin/activate/<license_key>', methods=['POST'])
def activate_license(license_key):
    """Activate license (admin only)."""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    with get_db() as conn:
        conn.execute(
            'UPDATE licenses SET active = 1 WHERE license_key = ?',
            (license_key,)
        )
        conn.commit()
    
    return redirect('/admin')

# =============================================================================
# HTML TEMPLATES
# =============================================================================

LOGIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login - PDF License Server</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
        .form-group { margin: 20px 0; }
        label { display: block; margin-bottom: 8px; font-weight: bold; color: #333; }
        input { width: 100%; padding: 15px; border: 2px solid #e1e5e9; border-radius: 10px; box-sizing: border-box; font-size: 16px; }
        input:focus { border-color: #667eea; outline: none; }
        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; border: none; border-radius: 10px; cursor: pointer; width: 100%; font-size: 18px; font-weight: bold; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        .error { color: #e53e3e; margin: 10px 0; padding: 10px; background: #fed7d7; border-radius: 5px; }
        .header { text-align: center; margin-bottom: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🔐 Admin Login</h2>
            <p>PDF License Server Administration</p>
        </div>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <div class="form-group">
                <button type="submit" class="btn">Login</button>
            </div>
        </form>
        
        <div style="text-align: center; margin-top: 20px; color: #666; font-size: 14px;">
            Admin access only • Authorized personnel only
        </div>
    </div>
</body>
</html>
'''

ADMIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard - PDF License Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
        .container { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #e1e5e9; padding: 12px; text-align: left; font-size: 14px; }
        th { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-weight: bold; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-box { background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%); padding: 25px; border-radius: 15px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .stat-number { font-size: 32px; font-weight: bold; color: #2d3748; margin-bottom: 5px; }
        .stat-label { color: #4a5568; font-weight: bold; }
        .expired { color: #e53e3e; font-weight: bold; }
        .active { color: #38a169; font-weight: bold; }
        .inactive { color: #9ca3af; font-weight: bold; }
        .license-key { font-family: 'Courier New', monospace; background: #f7fafc; padding: 5px 8px; border-radius: 5px; font-size: 12px; }
        .btn { background: #667eea; color: white; padding: 8px 15px; text-decoration: none; border-radius: 5px; font-size: 12px; margin: 2px; display: inline-block; }
        .btn-success { background: #38a169; }
        .btn-warning { background: #d69e2e; }
        .btn-danger { background: #e53e3e; }
        .btn:hover { opacity: 0.8; }
        .logout-btn { background: #e53e3e; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🔐 License Administration</h1>
            <p>PDF Metadata Tool License Management</p>
        </div>
        <div>
            <a href="/admin/create" class="btn btn-success">+ Create License</a>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
    </div>
    
    <div class="container">
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
                    <th>Last Used</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for license in licenses %}
                <tr>
                    <td><span class="license-key">{{ license.license_key }}</span></td>
                    <td>{{ license.customer_name or 'N/A' }}</td>
                    <td>{{ license.customer_email }}</td>
                    <td>{{ license.created_date[:10] }}</td>
                    <td>{{ license.expiry_date[:10] }}</td>
                    <td>
                        {% if license.active %}
                            <span class="active">● Active</span>
                        {% else %}
                            <span class="inactive">● Inactive</span>
                        {% endif %}
                    </td>
                    <td>{{ license.last_used[:10] if license.last_used else 'Never' }}</td>
                    <td>
                        {% if license.active %}
                            <form method="POST" action="/admin/deactivate/{{ license.license_key }}" style="display: inline;">
                                <button type="submit" class="btn btn-danger">Deactivate</button>
                            </form>
                        {% else %}
                            <form method="POST" action="/admin/activate/{{ license.license_key }}" style="display: inline;">
                                <button type="submit" class="btn btn-success">Activate</button>
                            </form>
                        {% endif %}
                        <form method="POST" action="/admin/extend/{{ license.license_key }}" style="display: inline;">
                            <button type="submit" class="btn btn-warning">+30 Days</button>
                        </form>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <h2>📊 Recent Validation Attempts</h2>
        <table>
            <thead>
                <tr>
                    <th>License Key</th>
                    <th>Hardware ID</th>
                    <th>Timestamp</th>
                    <th>Status</th>
                    <th>IP Address</th>
                </tr>
            </thead>
            <tbody>
                {% for validation in validations %}
                <tr>
                    <td><span class="license-key">{{ validation.license_key[:20] }}...</span></td>
                    <td>{{ validation.hardware_id[:16] if validation.hardware_id else 'N/A' }}</td>
                    <td>{{ validation.timestamp[:19] }}</td>
                    <td>
                        {% if validation.status == 'VALID' %}
                            <span class="active">{{ validation.status }}</span>
                        {% else %}
                            <span class="expired">{{ validation.status }}</span>
                        {% endif %}
                    </td>
                    <td>{{ validation.ip_address }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
'''

CREATE_LICENSE_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Create License - Admin</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
        .form-group { margin: 20px 0; }
        label { display: block; margin-bottom: 8px; font-weight: bold; color: #333; }
        input, textarea { width: 100%; padding: 15px; border: 2px solid #e1e5e9; border-radius: 10px; box-sizing: border-box; font-size: 16px; }
        input:focus, textarea:focus { border-color: #667eea; outline: none; }
        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; border: none; border-radius: 10px; cursor: pointer; width: 100%; font-size: 18px; font-weight: bold; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        .back-link { color: #667eea; text-decoration: none; }
        .error { color: #e53e3e; margin: 10px 0; padding: 10px; background: #fed7d7; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🆕 Create New License</h1>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="form-group">
                <label for="email">📧 Customer Email *</label>
                <input type="email" id="email" name="email" required placeholder="customer@example.com">
            </div>
            
            <div class="form-group">
                <label for="name">👤 Customer Name</label>
                <input type="text" id="name" name="name" placeholder="Customer Full Name">
            </div>
            
            <div class="form-group">
                <label for="payment_id">💳 Payment ID</label>
                <input type="text" id="payment_id" name="payment_id" placeholder="PayPal/Stripe transaction ID">
            </div>
            
            <div class="form-group">
                <label for="notes">📝 Notes</label>
                <textarea id="notes" name="notes" rows="3" placeholder="Internal notes about this license..."></textarea>
            </div>
            
            <div class="form-group">
                <button type="submit" class="btn">🚀 Create 30-Day License</button>
            </div>
        </form>
        
        <p><a href="/admin" class="back-link">← Back to Admin Dashboard</a></p>
    </div>
</body>
</html>
'''

LICENSE_CREATED_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>License Created Successfully</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
        .success-box { background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%); border-radius: 15px; color: #2d3748; padding: 30px; margin: 20px 0; text-align: center; }
        .license-key { font-family: 'Courier New', monospace; font-size: 20px; font-weight: bold; background: #2d3748; color: #84fab0; padding: 20px; border-radius: 10px; text-align: center; margin: 20px 0; border: 3px solid #84fab0; letter-spacing: 2px; }
        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 25px; text-decoration: none; border-radius: 25px; display: inline-block; margin: 10px 5px; font-weight: bold; }
        .copy-btn { background: #38a169; }
        .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
        .info-item { background: #f8f9fa; padding: 15px; border-radius: 10px; border-left: 4px solid #84fab0; }
    </style>
    <script>
        function copyLicenseKey() {
            const licenseKey = document.getElementById('licenseKey').textContent;
            navigator.clipboard.writeText(licenseKey).then(function() {
                alert('License key copied to clipboard!');
            });
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="success-box">
            <h1>✅ License Created Successfully!</h1>
            <p style="font-size: 18px; margin: 0;">New 30-day license has been generated and is ready to send to customer.</p>
        </div>
        
        <h3>🔑 License Key:</h3>
        <div class="license-key" id="licenseKey">{{ license_info.license_key }}</div>
        <div style="text-align: center;">
            <button onclick="copyLicenseKey()" class="btn copy-btn">📋 Copy License Key</button>
        </div>
        
        <div class="info-grid">
            <div class="info-item">
                <strong>📧 Customer:</strong><br>{{ license_info.customer_email }}
            </div>
            <div class="info-item">
                <strong>📅 Expires:</strong><br>{{ license_info.expiry_date }}
            </div>
        </div>
        
        <h3>📧 Send to Customer:</h3>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; border-left: 4px solid #667eea;">
            <p><strong>Email Template:</strong></p>
            <p style="font-style: italic;">
                "Your PDF Metadata Tool license is ready!<br><br>
                License Key: <strong>{{ license_info.license_key }}</strong><br>
                Valid until: <strong>{{ license_info.expiry_date }}</strong><br><br>
                Instructions: Run the PDF tool and enter this license key when prompted."
            </p>
        </div>
        
        <div style="text-align: center; margin-top: 30px;">
            <a href="/admin" class="btn">← Back to Dashboard</a>
            <a href="/admin/create" class="btn">+ Create Another</a>
        </div>
    </div>
</body>
</html>
'''

CHECK_RESULT_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>License Status Check</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
        .status-valid { background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%); color: #2d3748; }
        .status-expired { background: linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%); color: #2d3748; }
        .status-not-found { background: linear-gradient(135deg, #ffeaa7 0%, #fab1a0 100%); color: #2d3748; }
        .status-box { padding: 30px; border-radius: 15px; margin: 20px 0; text-align: center; }
        .support-info { background: #e3f2fd; padding: 20px; border-radius: 10px; margin-top: 20px; border-left: 4px solid #2196f3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 License Status Check</h1>
        
        {% if status == 'valid' %}
        <div class="status-box status-valid">
            <h2>✅ License is Valid</h2>
            <p><strong>License Key:</strong> <code>{{ license_key }}</code></p>
            <p><strong>Days Remaining:</strong> {{ days_remaining }} days</p>
            <p><strong>Expires:</strong> {{ license_info.expiry_date[:10] }}</p>
            <p><strong>Customer:</strong> {{ license_info.customer_email }}</p>
        </div>
        {% elif status == 'expired' %}
        <div class="status-box status-expired">
            <h2>❌ License Expired</h2>
            <p><strong>License Key:</strong> <code>{{ license_key }}</code></p>
            <p><strong>Expired:</strong> {{ license_info.expiry_date[:10] }}</p>
            <p><strong>Customer:</strong> {{ license_info.customer_email }}</p>
        </div>
        {% else %}
        <div class="status-box status-not-found">
            <h2>❓ License Not Found</h2>
            <p><strong>License Key:</strong> <code>{{ license_key }}</code></p>
            <p>This license key was not found in our database.</p>
        </div>
        {% endif %}
        
        <div class="support-info">
            <strong>💡 Customer Support:</strong>
            <p>For license issues, renewals, or technical support, please contact our support team with your license key.</p>
        </div>
    </div>
</body>
</html>
'''

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
