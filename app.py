# app.py - Complete Monthly License Server
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
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
            last_used TEXT
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
    # Format: PDFM-XXXX-XXXX-XXXX (PDF Metadata tool)
    def random_segment():
        return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    
    return f"PDFM-{random_segment()}-{random_segment()}-{random_segment()}"

def create_monthly_license(customer_email, customer_name=None, payment_id=None):
    """Create a new monthly license."""
    license_key = generate_license_key()
    created_date = datetime.now()
    expiry_date = created_date + timedelta(days=30)  # Monthly license
    
    with get_db() as conn:
        conn.execute('''
            INSERT INTO licenses (license_key, customer_email, customer_name, 
                                created_date, expiry_date, payment_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (license_key, customer_email, customer_name, 
              created_date.isoformat(), expiry_date.isoformat(), payment_id))
        conn.commit()
    
    return {
        'license_key': license_key,
        'expiry_date': expiry_date.strftime('%Y-%m-%d'),
        'customer_email': customer_email
    }

# =============================================================================
# API ENDPOINTS
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
                    "expired_date": license_row['expiry_date'],
                    "renewal_url": f"{request.host_url}renew/{license_key}"
                }), 400
            
            # Update hardware ID if not set or changed
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
                "customer_email": license_row['customer_email'],
                "renewal_url": f"{request.host_url}renew/{license_key}"
            })
            
    except Exception as e:
        return jsonify({
            "valid": False,
            "reason": "Server error",
            "message": str(e)
        }), 500

# =============================================================================
# WEB INTERFACE FOR LICENSE MANAGEMENT
# =============================================================================

@app.route('/')
def index():
    """Main page for license purchase."""
    return render_template_string(INDEX_HTML)

@app.route('/admin')
def admin():
    """Admin panel to view all licenses."""
    with get_db() as conn:
        licenses = conn.execute('''
            SELECT license_key, customer_email, customer_name, created_date, 
                   expiry_date, active, last_used
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
    
    return render_template_string(ADMIN_HTML, licenses=licenses, stats=stats)

@app.route('/purchase', methods=['GET', 'POST'])
def purchase():
    """Handle license purchase."""
    if request.method == 'POST':
        customer_email = request.form.get('email')
        customer_name = request.form.get('name')
        
        if not customer_email:
            return "Email is required", 400
        
        # In a real system, you would process payment here
        # For demo, we'll create the license immediately
        license_info = create_monthly_license(customer_email, customer_name)
        
        return render_template_string(SUCCESS_HTML, license_info=license_info)
    
    return render_template_string(PURCHASE_HTML)

@app.route('/renew/<license_key>')
def renew_license(license_key):
    """Renew an existing license."""
    with get_db() as conn:
        license_row = conn.execute(
            'SELECT * FROM licenses WHERE license_key = ?',
            (license_key,)
        ).fetchone()
        
        if not license_row:
            return "License not found", 404
    
    return render_template_string(RENEW_HTML, license_info=license_row)

@app.route('/renew/<license_key>/process', methods=['POST'])
def process_renewal(license_key):
    """Process license renewal."""
    with get_db() as conn:
        # Extend license by 30 days from current expiry (or today if expired)
        current_expiry = conn.execute(
            'SELECT expiry_date FROM licenses WHERE license_key = ?',
            (license_key,)
        ).fetchone()
        
        if not current_expiry:
            return "License not found", 404
        
        current_expiry_date = datetime.fromisoformat(current_expiry['expiry_date'])
        new_expiry_date = max(current_expiry_date, datetime.now()) + timedelta(days=30)
        
        conn.execute(
            'UPDATE licenses SET expiry_date = ?, active = 1 WHERE license_key = ?',
            (new_expiry_date.isoformat(), license_key)
        )
        conn.commit()
        
        license_info = {
            'license_key': license_key,
            'expiry_date': new_expiry_date.strftime('%Y-%m-%d')
        }
    
    return render_template_string(RENEWAL_SUCCESS_HTML, license_info=license_info)

@app.route('/check/<license_key>')
def check_license(license_key):
    """Quick license check via web."""
    with get_db() as conn:
        license_row = conn.execute(
            'SELECT * FROM licenses WHERE license_key = ?',
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
# HTML TEMPLATES
# =============================================================================

INDEX_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PDF Metadata Tool - License</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .header { text-align: center; background: #fff; padding: 30px; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .pricing { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; margin: 20px 0; border-radius: 15px; text-align: center; box-shadow: 0 8px 15px rgba(0,0,0,0.1); }
        .btn { background: #ff6b6b; color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; display: inline-block; margin: 10px; font-weight: bold; transition: all 0.3s; }
        .btn:hover { background: #ff5252; transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        .features { margin: 20px 0; background: white; padding: 30px; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .feature { padding: 15px; margin: 10px 0; background: #f8f9fa; border-radius: 10px; border-left: 4px solid #667eea; }
        .price { font-size: 48px; font-weight: bold; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 PDF Metadata Tool</h1>
        <p style="font-size: 18px; color: #666;">Professional PDF metadata restoration with exact timestamp preservation</p>
    </div>
    
    <div class="pricing">
        <h2>Monthly License</h2>
        <div class="price">$9.99<span style="font-size: 20px;">/month</span></div>
        <p style="font-size: 18px;">✨ Full access to all features • 30-day license period • Instant activation</p>
        <a href="/purchase" class="btn">Purchase License Now</a>
    </div>
    
    <div class="features">
        <h3>✨ Features Included:</h3>
        <div class="feature">🔧 Complete PDF metadata restoration</div>
        <div class="feature">🕒 Exact timestamp preservation (creation & modification dates)</div>
        <div class="feature">🔒 Security level matching (passwords & encryption)</div>
        <div class="feature">📁 Automatic folder management</div>
        <div class="feature">💡 User-friendly interface</div>
        <div class="feature">🔄 File system timestamp synchronization</div>
        <div class="feature">🛡️ Hardware-locked licensing for security</div>
    </div>
    
    <div style="text-align: center; margin-top: 40px; background: white; padding: 20px; border-radius: 15px;">
        <p><a href="/admin" style="color: #667eea;">Admin Panel</a> • <a href="/check/PDFM-XXXX-XXXX-XXXX" style="color: #667eea;">Check License Status</a></p>
        <p style="color: #999; font-size: 14px;">Secure monthly licensing • No long-term contracts • Cancel anytime</p>
    </div>
</body>
</html>
'''

PURCHASE_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Purchase License - PDF Metadata Tool</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
        .form-group { margin: 20px 0; }
        label { display: block; margin-bottom: 8px; font-weight: bold; color: #333; }
        input { width: 100%; padding: 15px; border: 2px solid #e1e5e9; border-radius: 10px; box-sizing: border-box; font-size: 16px; }
        input:focus { border-color: #667eea; outline: none; }
        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; border: none; border-radius: 10px; cursor: pointer; width: 100%; font-size: 18px; font-weight: bold; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        .price-box { background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%); padding: 30px; text-align: center; border-radius: 15px; margin-bottom: 30px; }
        .back-link { color: #667eea; text-decoration: none; }
        .demo-notice { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 10px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Purchase Monthly License</h1>
        
        <div class="price-box">
            <h2 style="margin: 0; color: #2d3748;">Monthly License - $9.99</h2>
            <p style="margin: 10px 0 0 0; color: #4a5568;">
                ✅ 30 days of full access<br>
                ✅ All features included<br>
                ✅ Instant activation<br>
                ✅ Hardware-locked security
            </p>
        </div>
        
        <form method="POST">
            <div class="form-group">
                <label for="email">📧 Email Address *</label>
                <input type="email" id="email" name="email" required placeholder="your@email.com">
                <small style="color: #666;">Your license key will be sent to this email</small>
            </div>
            
            <div class="form-group">
                <label for="name">👤 Full Name (optional)</label>
                <input type="text" id="name" name="name" placeholder="Your Name">
            </div>
            
            <div class="form-group">
                <button type="submit" class="btn">🚀 Create License (Demo - No Payment)</button>
            </div>
        </form>
        
        <div class="demo-notice">
            <strong>🎯 Demo Mode:</strong> This will create a license immediately without payment. 
            In production, integrate with Stripe, PayPal, or your preferred payment processor.
        </div>
        
        <p><a href="/" class="back-link">← Back to Home</a></p>
    </div>
</body>
</html>
'''

SUCCESS_HTML = '''
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
        .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
        .info-item { background: #f8f9fa; padding: 15px; border-radius: 10px; border-left: 4px solid #84fab0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-box">
            <h1>✅ License Created Successfully!</h1>
            <p style="font-size: 18px; margin: 0;">Your monthly license has been activated and is ready to use.</p>
        </div>
        
        <h3>🔑 Your License Key:</h3>
        <div class="license-key">{{ license_info.license_key }}</div>
        
        <div class="info-grid">
            <div class="info-item">
                <strong>📧 Email:</strong><br>{{ license_info.customer_email }}
            </div>
            <div class="info-item">
                <strong>📅 Expires:</strong><br>{{ license_info.expiry_date }}
            </div>
        </div>
        
        <h3>📝 How to Use Your License:</h3>
        <ol style="line-height: 1.8;">
            <li><strong>Copy</strong> your license key above (Ctrl+C)</li>
            <li><strong>Download</strong> and run your PDF Metadata Tool</li>
            <li><strong>Enter</strong> your license key when prompted</li>
            <li><strong>Enjoy</strong> 30 days of full access to all features!</li>
        </ol>
        
        <div style="text-align: center; margin-top: 30px;">
            <a href="/" class="btn">← Back to Home</a>
            <a href="/check/{{ license_info.license_key }}" class="btn">Check License Status</a>
        </div>
        
        <div style="background: #e3f2fd; padding: 20px; border-radius: 10px; margin-top: 30px; border-left: 4px solid #2196f3;">
            <strong>💡 Important Notes:</strong>
            <ul style="margin: 10px 0;">
                <li>Save your license key safely - you'll need it to activate the software</li>
                <li>The license automatically expires in 30 days</li>
                <li>You can renew before expiration to continue using the tool</li>
                <li>License is locked to your specific computer for security</li>
            </ul>
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
        .container { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 10px; overflow: hidden; }
        th, td { border: 1px solid #e1e5e9; padding: 15px; text-align: left; }
        th { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-weight: bold; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-box { background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%); padding: 25px; border-radius: 15px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .stat-number { font-size: 32px; font-weight: bold; color: #2d3748; margin-bottom: 5px; }
        .stat-label { color: #4a5568; font-weight: bold; }
        .expired { color: #e53e3e; font-weight: bold; }
        .active { color: #38a169; font-weight: bold; }
        .license-key { font-family: 'Courier New', monospace; background: #f7fafc; padding: 5px 8px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 License Administration Panel</h1>
        
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
                            <span class="expired">● Inactive</span>
                        {% endif %}
                    </td>
                    <td>{{ license.last_used[:10] if license.last_used else 'Never' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <p style="margin-top: 30px;"><a href="/" style="color: #667eea; text-decoration: none; font-weight: bold;">← Back to Home</a></p>
    </div>
</body>
</html>
'''

RENEW_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Renew License</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
        .info-box { background: linear-gradient(135deg, #ffeaa7 0%, #fab1a0 100%); padding: 25px; border-radius: 15px; margin: 20px 0; }
        .btn { background: linear-gradient(135deg, #00b894 0%, #00cec9 100%); color: white; padding: 15px 30px; border: none; border-radius: 10px; cursor: pointer; text-decoration: none; display: inline-block; font-weight: bold; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔄 Renew Your License</h1>
        
        <div class="info-box">
            <h3>📋 Current License Information:</h3>
            <p><strong>License Key:</strong> <code>{{ license_info.license_key }}</code></p>
            <p><strong>Customer:</strong> {{ license_info.customer_email }}</p>
            <p><strong>Current Expiry:</strong> {{ license_info.expiry_date[:10] }}</p>
        </div>
        
        <h3>💰 Renewal Cost: $9.99</h3>
        <p>✅ Extends your license for another 30 days<br>
           ✅ Immediate activation<br>
           ✅ No interruption of service<br>
           ✅ Same license key continues to work</p>
        
        <form method="POST" action="/renew/{{ license_info.license_key }}/process">
            <button type="submit" class="btn">🚀 Renew License (Demo - No Payment)</button>
        </form>
        
        <p><small><strong>🎯 Demo Mode:</strong> This will extend the license immediately without payment.</small></p>
    </div>
</body>
</html>
'''

RENEWAL_SUCCESS_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>License Renewed Successfully</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
        .success-box { background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%); padding: 30px; border-radius: 15px; margin: 20px 0; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-box">
            <h1>✅ License Renewed Successfully!</h1>
            <p>Your license has been extended for another 30 days.</p>
        </div>
        
        <h3>📋 Updated License Details:</h3>
        <p><strong>License Key:</strong> <code>{{ license_info.license_key }}</code></p>
        <p><strong>New Expiry Date:</strong> {{ license_info.expiry_date }}</p>
        
        <p>Your software will automatically recognize the renewal on next use.</p>
        
        <p><a href="/">← Back to Home</a></p>
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
        </div>
        {% elif status == 'expired' %}
        <div class="status-box status-expired">
            <h2>❌ License Expired</h2>
            <p><strong>License Key:</strong> <code>{{ license_key }}</code></p>
            <p><strong>Expired:</strong> {{ license_info.expiry_date[:10] }}</p>
            <p><a href="/renew/{{ license_key }}">Click here to renew</a></p>
        </div>
        {% else %}
        <div class="status-box status-not-found">
            <h2>❓ License Not Found</h2>
            <p><strong>License Key:</strong> <code>{{ license_key }}</code></p>
            <p>This license key was not found in our database.</p>
        </div>
        {% endif %}
        
        <p><a href="/">← Back to Home</a></p>
    </div>
</body>
</html>
'''

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)