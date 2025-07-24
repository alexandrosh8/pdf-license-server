# app_enhanced.py - Enhanced License Server with Encrypted License Keys
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
import hashlib
import json
import secrets
import string
from datetime import datetime, timedelta
import os
import sqlite3
from contextlib import contextmanager
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')

# Admin credentials
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

# Database setup
DATABASE = 'licenses.db'

# Encryption key for license keys - generate once and save
ENCRYPTION_KEY_FILE = '.encryption_key'

def get_or_create_encryption_key():
    """Get or create the encryption key for license keys."""
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        # Generate new key
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, 'wb') as f:
            f.write(key)
        return key

# Initialize encryption
ENCRYPTION_KEY = get_or_create_encryption_key()
fernet = Fernet(ENCRYPTION_KEY)

def encrypt_license_key(license_key):
    """Encrypt a license key for storage."""
    return fernet.encrypt(license_key.encode()).decode()

def decrypt_license_key(encrypted_key):
    """Decrypt a license key from storage."""
    try:
        return fernet.decrypt(encrypted_key.encode()).decode()
    except:
        # If decryption fails, assume it's not encrypted (migration)
        return encrypted_key

def get_real_ip():
    """Get the real client IP address, handling proxies."""
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    forwarded = request.headers.get('X-Forwarded')
    if forwarded:
        return forwarded.split(',')[0].strip()
    
    return request.remote_addr or 'unknown'

def init_db():
    """Initialize the license database with enhanced schema."""
    conn = sqlite3.connect(DATABASE)
    
    # Create licenses table with encrypted license key
    conn.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_encrypted TEXT UNIQUE NOT NULL,
            license_key_hash TEXT UNIQUE NOT NULL,
            hardware_id TEXT,
            customer_email TEXT,
            customer_name TEXT,
            created_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            payment_id TEXT,
            active INTEGER DEFAULT 1,
            last_used TEXT,
            notes TEXT,
            activation_count INTEGER DEFAULT 0,
            last_activation_date TEXT,
            previously_bound_hardware TEXT
        )
    ''')
    
    # Create validation logs table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS validation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT,
            hardware_id TEXT,
            timestamp TEXT,
            status TEXT,
            ip_address TEXT,
            user_agent TEXT,
            details TEXT
        )
    ''')
    
    # Create remembered licenses table (for tracking reactivations)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS license_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT,
            hardware_id TEXT,
            action TEXT,
            timestamp TEXT,
            ip_address TEXT,
            details TEXT
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

def hash_license_key(license_key):
    """Create a hash of the license key for lookups."""
    return hashlib.sha256(license_key.encode()).hexdigest()

def log_validation_attempt(license_key, hardware_id, status, details=None):
    """Log a validation attempt with enhanced information."""
    try:
        with get_db() as conn:
            conn.execute('''
                INSERT INTO validation_logs (license_key_hash, hardware_id, timestamp, status, ip_address, user_agent, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                hash_license_key(license_key) if license_key else None, 
                hardware_id, 
                datetime.now().isoformat(), 
                status, 
                get_real_ip(),
                request.headers.get('User-Agent', 'Unknown'),
                details
            ))
            conn.commit()
    except Exception as e:
        print(f"Failed to log validation attempt: {e}")

def log_license_history(license_key, hardware_id, action, details=None):
    """Log license history for tracking reactivations."""
    try:
        with get_db() as conn:
            conn.execute('''
                INSERT INTO license_history (license_key_hash, hardware_id, action, timestamp, ip_address, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                hash_license_key(license_key) if license_key else None,
                hardware_id,
                action,
                datetime.now().isoformat(),
                get_real_ip(),
                details
            ))
            conn.commit()
    except Exception as e:
        print(f"Failed to log license history: {e}")

def generate_license_key():
    """Generate a unique license key."""
    def random_segment():
        return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    
    return f"PDFM-{random_segment()}-{random_segment()}-{random_segment()}"

def create_monthly_license(customer_email, customer_name=None, hardware_id=None, payment_id=None, notes=None):
    """Create a new monthly license with encryption."""
    license_key = generate_license_key()
    created_date = datetime.now()
    expiry_date = created_date + timedelta(days=30)
    
    # Encrypt the license key for storage
    encrypted_key = encrypt_license_key(license_key)
    key_hash = hash_license_key(license_key)
    
    with get_db() as conn:
        conn.execute('''
            INSERT INTO licenses (license_key_encrypted, license_key_hash, hardware_id, customer_email, 
                                customer_name, created_date, expiry_date, payment_id, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (encrypted_key, key_hash, hardware_id, customer_email, customer_name, 
              created_date.isoformat(), expiry_date.isoformat(), payment_id, notes))
        conn.commit()
    
    log_license_history(license_key, hardware_id, 'CREATED', f'New license for {customer_email}')
    
    return {
        'license_key': license_key,
        'hardware_id': hardware_id,
        'expiry_date': expiry_date.strftime('%Y-%m-%d'),
        'customer_email': customer_email
    }

def require_admin():
    """Check if user is logged in as admin."""
    return session.get('admin_logged_in') == True

# =============================================================================
# PUBLIC API ENDPOINTS
# =============================================================================

@app.route('/api/validate', methods=['POST'])
def validate_license():
    """Enhanced validation that remembers previous hardware bindings."""
    try:
        data = request.get_json()
        license_key = data.get('license_key')
        hardware_id = data.get('hardware_id')
        
        if not license_key:
            log_validation_attempt('', hardware_id, 'MISSING_KEY', 'No license key provided')
            return jsonify({"valid": False, "reason": "Missing license key"}), 400
        
        if not hardware_id:
            log_validation_attempt(license_key, '', 'MISSING_HARDWARE_ID', 'No hardware ID provided')
            return jsonify({"valid": False, "reason": "Missing hardware ID"}), 400
        
        # Hash the license key for lookup
        key_hash = hash_license_key(license_key)
        
        with get_db() as conn:
            # Find license by hash
            license_row = conn.execute(
                'SELECT * FROM licenses WHERE license_key_hash = ?',
                (key_hash,)
            ).fetchone()
            
            if not license_row:
                log_validation_attempt(license_key, hardware_id, 'INVALID_KEY', 'License key not found')
                return jsonify({"valid": False, "reason": "Invalid license key"}), 400
            
            # Check if license is active
            if not license_row['active']:
                log_validation_attempt(license_key, hardware_id, 'DEACTIVATED', 'License deactivated')
                return jsonify({"valid": False, "reason": "License has been deactivated"}), 400
            
            # Check expiration
            expiry_date = datetime.fromisoformat(license_row['expiry_date'])
            current_date = datetime.now()
            
            if current_date > expiry_date:
                log_validation_attempt(license_key, hardware_id, 'EXPIRED', f"Expired on {license_row['expiry_date']}")
                return jsonify({
                    "valid": False,
                    "reason": "License expired",
                    "expired_date": license_row['expiry_date']
                }), 400
            
            # Check hardware binding
            stored_hw_id = license_row['hardware_id']
            previously_bound = license_row['previously_bound_hardware']
            
            # If no hardware ID set, bind to this one
            if not stored_hw_id:
                conn.execute('''
                    UPDATE licenses 
                    SET hardware_id = ?, last_used = ?, activation_count = activation_count + 1,
                        last_activation_date = ?
                    WHERE license_key_hash = ?
                ''', (hardware_id, datetime.now().isoformat(), datetime.now().isoformat(), key_hash))
                conn.commit()
                
                log_validation_attempt(license_key, hardware_id, 'VALID_FIRST_USE', 'License bound to hardware')
                log_license_history(license_key, hardware_id, 'BOUND', 'First hardware binding')
                
            # If hardware matches current or previous binding
            elif stored_hw_id == hardware_id or (previously_bound and hardware_id in previously_bound):
                # Update current hardware if it was previously bound
                if stored_hw_id != hardware_id and previously_bound and hardware_id in previously_bound:
                    conn.execute('''
                        UPDATE licenses 
                        SET hardware_id = ?, last_used = ?, activation_count = activation_count + 1,
                            last_activation_date = ?
                        WHERE license_key_hash = ?
                    ''', (hardware_id, datetime.now().isoformat(), datetime.now().isoformat(), key_hash))
                    conn.commit()
                    
                    log_validation_attempt(license_key, hardware_id, 'VALID_REACTIVATION', 'Previously bound hardware')
                    log_license_history(license_key, hardware_id, 'REACTIVATED', 'Hardware rebound')
                else:
                    # Just update last used
                    conn.execute(
                        'UPDATE licenses SET last_used = ? WHERE license_key_hash = ?',
                        (datetime.now().isoformat(), key_hash)
                    )
                    conn.commit()
                    log_validation_attempt(license_key, hardware_id, 'VALID', 'License validation successful')
                    
            else:
                # Hardware mismatch
                log_validation_attempt(
                    license_key, 
                    hardware_id, 
                    'HARDWARE_MISMATCH', 
                    f"Expected: {stored_hw_id}, Got: {hardware_id}"
                )
                return jsonify({
                    "valid": False,
                    "reason": "License not valid for this hardware"
                }), 400
            
            days_remaining = (expiry_date - current_date).days
            
            return jsonify({
                "valid": True,
                "message": "License is valid",
                "expiry_date": license_row['expiry_date'],
                "days_remaining": days_remaining,
                "customer_email": license_row['customer_email']
            })
            
    except Exception as e:
        log_validation_attempt(
            data.get('license_key', '') if 'data' in locals() else '',
            data.get('hardware_id', '') if 'data' in locals() else '',
            'SERVER_ERROR',
            f"Exception: {str(e)}"
        )
        return jsonify({
            "valid": False,
            "reason": "Server error",
            "message": "Internal server error occurred"
        }), 500

@app.route('/check/<license_key>')
def check_license(license_key):
    """Public license check for customer support."""
    key_hash = hash_license_key(license_key)
    
    with get_db() as conn:
        license_row = conn.execute(
            '''SELECT license_key_hash, customer_email, created_date, expiry_date, active, 
                      hardware_id, activation_count, last_activation_date
               FROM licenses WHERE license_key_hash = ?''',
            (key_hash,)
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
        
        # Enhanced info
        license_info_dict = dict(license_row)
        license_info_dict['license_key'] = license_key  # Add the actual key for display
        
        return render_template_string(CHECK_RESULT_HTML, 
                                    status=status, 
                                    license_info=license_info_dict,
                                    days_remaining=days_remaining,
                                    license_key=license_key)

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.1.0"
    })

# =============================================================================
# ADMIN AUTHENTICATION
# =============================================================================

@app.route('/')
def index():
    """Main page - redirect to admin login."""
    if require_admin():
        return redirect('/admin')
    return render_template_string(LOGIN_HTML, server_ip=get_real_ip())

@app.route('/login', methods=['POST'])
def login():
    """Handle admin login."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        return redirect('/admin')
    else:
        return render_template_string(LOGIN_HTML, error="Invalid credentials", server_ip=get_real_ip())

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
    """Enhanced admin dashboard."""
    if not require_admin():
        return redirect('/')
    
    try:
        with get_db() as conn:
            # Get licenses with decrypted keys
            licenses_raw = conn.execute('''
                SELECT license_key_encrypted, license_key_hash, hardware_id, customer_email, 
                       customer_name, created_date, expiry_date, active, last_used, notes,
                       activation_count, last_activation_date, previously_bound_hardware
                FROM licenses 
                ORDER BY created_date DESC
            ''').fetchall()
            
            # Process licenses
            licenses = []
            current_time = datetime.now()
            
            for license_row in licenses_raw:
                license_dict = dict(license_row)
                
                # Decrypt the license key
                try:
                    license_dict['license_key'] = decrypt_license_key(license_row['license_key_encrypted'])
                except:
                    license_dict['license_key'] = 'DECRYPTION_ERROR'
                
                # Calculate status
                expiry_date = datetime.fromisoformat(license_row['expiry_date'])
                if not license_row['active']:
                    license_dict['calculated_status'] = 'deactivated'
                elif current_time > expiry_date:
                    license_dict['calculated_status'] = 'expired'
                else:
                    license_dict['calculated_status'] = 'active'
                
                licenses.append(license_dict)
            
            # Get statistics
            stats = conn.execute('''
                SELECT 
                    COUNT(*) as total_licenses,
                    COUNT(CASE WHEN active = 1 THEN 1 END) as active_licenses,
                    COUNT(CASE WHEN datetime(expiry_date) > datetime('now') AND active = 1 THEN 1 END) as valid_licenses,
                    COUNT(CASE WHEN datetime(expiry_date) <= datetime('now') THEN 1 END) as expired_licenses,
                    SUM(activation_count) as total_activations
                FROM licenses
            ''').fetchone()
            
            # Recent validations
            recent_validations = conn.execute('''
                SELECT license_key_hash, hardware_id, timestamp, status, ip_address, user_agent, details
                FROM validation_logs 
                ORDER BY timestamp DESC 
                LIMIT 50
            ''').fetchall()
            
            # Process validations to show partial license keys
            validations = []
            for val_row in recent_validations:
                val_dict = dict(val_row)
                # Show first 20 chars of the hash as identifier
                val_dict['license_identifier'] = val_row['license_key_hash'][:20] if val_row['license_key_hash'] else 'N/A'
                validations.append(val_dict)
            
            # Security stats
            security_stats = conn.execute('''
                SELECT 
                    status,
                    COUNT(*) as count
                FROM validation_logs 
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY status
                ORDER BY count DESC
            ''').fetchall()
        
        return render_template_string(ADMIN_HTML, 
                                    licenses=licenses, 
                                    stats=stats, 
                                    validations=validations,
                                    security_stats=security_stats)
    except Exception as e:
        print(f"ERROR: Admin dashboard failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return f"Database error: {str(e)}", 500

@app.route('/admin/create', methods=['GET', 'POST'])
def admin_create_license():
    """Create new license."""
    if not require_admin():
        return redirect('/')
    
    if request.method == 'POST':
        customer_email = request.form.get('email')
        customer_name = request.form.get('name')
        hardware_id = request.form.get('hardware_id')
        payment_id = request.form.get('payment_id')
        notes = request.form.get('notes')
        
        if not customer_email:
            return render_template_string(CREATE_LICENSE_HTML, error="Email is required")
        
        if hardware_id and len(hardware_id) != 16:
            return render_template_string(CREATE_LICENSE_HTML, 
                                        error="Hardware ID must be exactly 16 characters")
        
        license_info = create_monthly_license(customer_email, customer_name, hardware_id, payment_id, notes)
        
        return render_template_string(LICENSE_CREATED_HTML, license_info=license_info)
    
    return render_template_string(CREATE_LICENSE_HTML)

@app.route('/admin/transfer/<license_key>', methods=['POST'])
def transfer_license(license_key):
    """Transfer license to new hardware (remember old hardware)."""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    new_hardware_id = request.form.get('new_hardware_id')
    if not new_hardware_id or len(new_hardware_id) != 16:
        return jsonify({'error': 'Invalid hardware ID'}), 400
    
    key_hash = hash_license_key(license_key)
    
    with get_db() as conn:
        # Get current hardware ID
        current = conn.execute(
            'SELECT hardware_id, previously_bound_hardware FROM licenses WHERE license_key_hash = ?',
            (key_hash,)
        ).fetchone()
        
        if not current:
            return jsonify({'error': 'License not found'}), 404
        
        old_hw_id = current['hardware_id']
        prev_bound = current['previously_bound_hardware'] or ''
        
        # Add old hardware to previously bound list
        if old_hw_id and old_hw_id not in prev_bound:
            if prev_bound:
                prev_bound += f",{old_hw_id}"
            else:
                prev_bound = old_hw_id
        
        # Update to new hardware
        conn.execute('''
            UPDATE licenses 
            SET hardware_id = ?, previously_bound_hardware = ?, 
                last_activation_date = ?
            WHERE license_key_hash = ?
        ''', (new_hardware_id, prev_bound, datetime.now().isoformat(), key_hash))
        conn.commit()
        
        log_license_history(license_key, new_hardware_id, 'TRANSFERRED', 
                          f'From {old_hw_id} to {new_hardware_id}')
    
    return redirect('/admin')

@app.route('/admin/extend/<license_key>', methods=['POST'])
def extend_license(license_key):
    """Extend license by 30 days."""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    key_hash = hash_license_key(license_key)
    
    with get_db() as conn:
        current_expiry = conn.execute(
            'SELECT expiry_date FROM licenses WHERE license_key_hash = ?',
            (key_hash,)
        ).fetchone()
        
        if not current_expiry:
            return jsonify({'error': 'License not found'}), 404
        
        current_expiry_date = datetime.fromisoformat(current_expiry['expiry_date'])
        new_expiry_date = max(current_expiry_date, datetime.now()) + timedelta(days=30)
        
        conn.execute(
            'UPDATE licenses SET expiry_date = ?, active = 1 WHERE license_key_hash = ?',
            (new_expiry_date.isoformat(), key_hash)
        )
        conn.commit()
        
        log_license_history(license_key, 'ADMIN', 'EXTENDED', 
                          f'Extended to {new_expiry_date.strftime("%Y-%m-%d")}')
    
    return redirect('/admin')

@app.route('/admin/deactivate/<license_key>', methods=['POST'])
def deactivate_license(license_key):
    """Deactivate license (can be reactivated)."""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    key_hash = hash_license_key(license_key)
    
    try:
        with get_db() as conn:
            existing = conn.execute(
                'SELECT license_key_hash, active FROM licenses WHERE license_key_hash = ?',
                (key_hash,)
            ).fetchone()
            
            if not existing:
                return jsonify({'error': 'License not found'}), 404
            
            conn.execute(
                'UPDATE licenses SET active = 0 WHERE license_key_hash = ?',
                (key_hash,)
            )
            conn.commit()
            
            log_validation_attempt(license_key, 'ADMIN', 'DEACTIVATED_BY_ADMIN', 
                                 f'Admin action from IP: {get_real_ip()}')
            log_license_history(license_key, 'ADMIN', 'DEACTIVATED', 'Admin deactivation')
        
        return redirect('/admin')
    except Exception as e:
        return jsonify({'error': f'Failed to deactivate: {str(e)}'}), 500

@app.route('/admin/activate/<license_key>', methods=['POST'])
def activate_license(license_key):
    """Activate/reactivate license."""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    key_hash = hash_license_key(license_key)
    
    try:
        with get_db() as conn:
            existing = conn.execute(
                'SELECT license_key_hash, active FROM licenses WHERE license_key_hash = ?',
                (key_hash,)
            ).fetchone()
            
            if not existing:
                return jsonify({'error': 'License not found'}), 404
            
            conn.execute(
                'UPDATE licenses SET active = 1 WHERE license_key_hash = ?',
                (key_hash,)
            )
            conn.commit()
            
            log_validation_attempt(license_key, 'ADMIN', 'ACTIVATED_BY_ADMIN', 
                                 f'Admin action from IP: {get_real_ip()}')
            log_license_history(license_key, 'ADMIN', 'ACTIVATED', 'Admin activation')
        
        return redirect('/admin')
    except Exception as e:
        return jsonify({'error': f'Failed to activate: {str(e)}'}), 500

@app.route('/admin/delete/<license_key>', methods=['POST'])
def delete_license(license_key):
    """Delete license permanently."""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    key_hash = hash_license_key(license_key)
    
    with get_db() as conn:
        log_validation_attempt(license_key, 'ADMIN', 'DELETED_BY_ADMIN', 
                             f'Permanent deletion from IP: {get_real_ip()}')
        log_license_history(license_key, 'ADMIN', 'DELETED', 'Permanently deleted')
        
        conn.execute('DELETE FROM licenses WHERE license_key_hash = ?', (key_hash,))
        conn.commit()
    
    return redirect('/admin')

# [Include all the HTML templates from the original, with minor modifications for the enhanced features]

# Enhanced templates would include:
# - Show activation count and last activation date
# - Option to transfer license to new hardware
# - Show previously bound hardware IDs
# - Enhanced security status display

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
        .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
        .version { background: #667eea; color: white; padding: 2px 8px; border-radius: 10px; font-size: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🔐 Admin Login</h2>
            <p>PDF License Server Administration</p>
            <span class="version">v1.1.0</span>
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
        
        <div class="footer">
            Admin access only • Authorized personnel only<br>
            Server IP: {{ server_ip }}<br>
            🔒 License keys encrypted at rest
        </div>
    </div>
</body>
</html>
'''

# [Include the rest of the HTML templates - they remain largely the same]
# The main changes would be in the ADMIN_HTML template to show:
# - Activation count
# - Previously bound hardware
# - Transfer license option

ADMIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard - PDF License Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: white; padding: 20px; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
        .container { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 13px; }
        th, td { border: 1px solid #e1e5e9; padding: 8px; text-align: left; }
        th { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-weight: bold; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-box { background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%); padding: 20px; border-radius: 15px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .stat-number { font-size: 28px; font-weight: bold; color: #2d3748; margin-bottom: 5px; }
        .stat-label { color: #4a5568; font-weight: bold; font-size: 14px; }
        .expired { color: #e53e3e; font-weight: bold; }
        .active { color: #38a169; font-weight: bold; }
        .inactive { color: #9ca3af; font-weight: bold; }
        .security-error { color: #e53e3e; font-weight: bold; }
        .valid { color: #38a169; font-weight: bold; }
        .license-key { font-family: 'Courier New', monospace; background: #f7fafc; padding: 4px 6px; border-radius: 4px; font-size: 11px; }
        .hardware-id { font-family: 'Courier New', monospace; background: #e6fffa; padding: 4px 6px; border-radius: 4px; font-size: 10px; color: #047857; }
        .btn { background: #667eea; color: white; padding: 6px 12px; text-decoration: none; border-radius: 4px; font-size: 11px; margin: 1px; display: inline-block; border: none; cursor: pointer; }
        .btn-success { background: #38a169; }
        .btn-warning { background: #d69e2e; }
        .btn-danger { background: #e53e3e; }
        .btn:hover { opacity: 0.8; }
        .logout-btn { background: #e53e3e; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
        .security-stats { display: flex; gap: 10px; flex-wrap: wrap; margin: 15px 0; }
        .security-stat { background: #f8f9fa; padding: 10px 15px; border-radius: 8px; border-left: 4px solid #667eea; }
        .ip-address { font-family: 'Courier New', monospace; background: #fff3cd; padding: 2px 4px; border-radius: 3px; font-size: 10px; }
        .activation-info { background: #e6f4ff; padding: 4px 8px; border-radius: 4px; font-size: 11px; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🔐 License Administration</h1>
            <p>PDF Metadata Tool License Management v1.1.0</p>
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
            <div class="stat-box">
                <div class="stat-number">{{ stats.expired_licenses }}</div>
                <div class="stat-label">Expired</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{{ stats.total_activations or 0 }}</div>
                <div class="stat-label">Total Activations</div>
            </div>
        </div>
        
        {% if security_stats %}
        <h3>📊 Security Events (Last 7 Days)</h3>
        <div class="security-stats">
            {% for stat in security_stats %}
            <div class="security-stat">
                <strong>{{ stat.status }}:</strong> {{ stat.count }}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        <h2>📋 All Licenses</h2>
        <table>
            <thead>
                <tr>
                    <th>License Key</th>
                    <th>Hardware ID</th>
                    <th>Customer</th>
                    <th>Email</th>
                    <th>Created</th>
                    <th>Expires</th>
                    <th>Status</th>
                    <th>Activations</th>
                    <th>Last Used</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for license in licenses %}
                <tr>
                    <td><span class="license-key">{{ license.license_key }}</span></td>
                    <td>
                        {% if license.hardware_id %}
                            <span class="hardware-id">{{ license.hardware_id }}</span>
                            {% if license.previously_bound_hardware %}
                                <br><small style="color: #999;">Previously: {{ license.previously_bound_hardware[:20] }}...</small>
                            {% endif %}
                        {% else %}
                            <span style="color: #999; font-style: italic;">Not Set</span>
                        {% endif %}
                    </td>
                    <td>{{ license.customer_name or 'N/A' }}</td>
                    <td>{{ license.customer_email }}</td>
                    <td>{{ license.created_date[:10] }}</td>
                    <td>{{ license.expiry_date[:10] }}</td>
                    <td>
                        {% if license.calculated_status == 'active' %}
                            <span class="active">● Active</span>
                        {% elif license.calculated_status == 'expired' %}
                            <span class="expired">● Expired</span>
                        {% else %}
                            <span class="inactive">● Deactivated</span>
                        {% endif %}
                    </td>
                    <td>
                        <span class="activation-info">
                            {{ license.activation_count or 0 }}x
                            {% if license.last_activation_date %}
                                <br><small>{{ license.last_activation_date[:10] }}</small>
                            {% endif %}
                        </span>
                    </td>
                    <td>{{ license.last_used[:10] if license.last_used else 'Never' }}</td>
                    <td>
                        {% if license.calculated_status == 'active' %}
                            <form method="POST" action="/admin/deactivate/{{ license.license_key }}" style="display: inline;">
                                <button type="submit" class="btn btn-warning" onclick="return confirm('⏸️ DEACTIVATE license {{ license.license_key[:20] }}...?\\n\\nThis will temporarily disable the license but keep it in the system.\\nUser will see a deactivation message and can be reactivated later.')">⏸️ Deactivate</button>
                            </form>
                        {% elif license.calculated_status == 'deactivated' %}
                            <form method="POST" action="/admin/activate/{{ license.license_key }}" style="display: inline;">
                                <button type="submit" class="btn btn-success" onclick="return confirm('▶️ ACTIVATE license {{ license.license_key[:20] }}...?\\n\\nThis will restore the license and allow the user to continue using it.')">▶️ Activate</button>
                            </form>
                        {% else %}
                            <form method="POST" action="/admin/activate/{{ license.license_key }}" style="display: inline;">
                                <button type="submit" class="btn btn-success">🔄 Reactivate</button>
                            </form>
                        {% endif %}
                        
                        <form method="POST" action="/admin/extend/{{ license.license_key }}" style="display: inline;">
                            <button type="submit" class="btn btn-warning" onclick="return confirm('📅 EXTEND license by 30 days?\\n\\nCurrent expiry: {{ license.expiry_date[:10] }}')">📅 +30 Days</button>
                        </form>
                        
                        <form method="POST" action="/admin/delete/{{ license.license_key }}" style="display: inline;">
                            <button type="submit" class="btn btn-danger" onclick="return confirm('🗑️ PERMANENTLY DELETE license {{ license.license_key }}?\\n\\n⚠️ WARNING: This CANNOT be undone!\\n⚠️ The license will be completely removed from the database!\\n⚠️ The user will lose access permanently!\\n\\nOnly do this for refunds or permanent bans.\\n\\nAre you absolutely sure?')" style="margin-left: 10px;">🗑️ DELETE</button>
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
                    <th>License ID</th>
                    <th>Hardware ID</th>
                    <th>Timestamp</th>
                    <th>Status</th>
                    <th>IP Address</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {% for validation in validations %}
                <tr>
                    <td><span class="license-key">{{ validation.license_identifier }}...</span></td>
                    <td>
                        {% if validation.hardware_id and validation.hardware_id != 'ADMIN' %}
                            <span class="hardware-id">{{ validation.hardware_id }}</span>
                        {% else %}
                            <span style="color: #999;">{{ validation.hardware_id or 'N/A' }}</span>
                        {% endif %}
                    </td>
                    <td>{{ validation.timestamp[:19] }}</td>
                    <td>
                        {% if validation.status in ['VALID', 'VALID_FIRST_USE', 'VALID_REACTIVATION'] %}
                            <span class="valid">{{ validation.status }}</span>
                        {% elif validation.status in ['HARDWARE_MISMATCH', 'EXPIRED', 'DEACTIVATED'] %}
                            <span class="security-error">{{ validation.status }}</span>
                        {% else %}
                            <span class="expired">{{ validation.status }}</span>
                        {% endif %}
                    </td>
                    <td><span class="ip-address">{{ validation.ip_address }}</span></td>
                    <td style="font-size: 11px; max-width: 200px; word-break: break-word;">{{ validation.details or '-' }}</td>
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
        input, textarea { width: 100%; padding: 15px; border: 2px solid #e1e5e9; border-radius: 10px; box-sizing: border-box; font-size: 16px; font-family: Arial, sans-serif; }
        input:focus, textarea:focus { border-color: #667eea; outline: none; }
        .hardware-id-input { font-family: 'Courier New', monospace !important; background: #f0fdf4; }
        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; border: none; border-radius: 10px; cursor: pointer; width: 100%; font-size: 18px; font-weight: bold; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        .back-link { color: #667eea; text-decoration: none; }
        .error { color: #e53e3e; margin: 10px 0; padding: 10px; background: #fed7d7; border-radius: 5px; }
        .help-text { font-size: 14px; color: #666; margin-top: 5px; }
        .example-box { background: #e6fffa; border: 1px solid #4fd1c7; border-radius: 8px; padding: 15px; margin: 10px 0; }
        .example-title { font-weight: bold; color: #047857; margin-bottom: 8px; }
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
                <label for="hardware_id">💻 Hardware ID (Optional)</label>
                <input type="text" id="hardware_id" name="hardware_id" class="hardware-id-input" 
                       placeholder="96CD9965574038B3" maxlength="16">
                <div class="help-text">
                    16-character hardware identifier from the client application. Leave empty if unknown - it will be set automatically when the license is first used.
                </div>
                <div class="example-box">
                    <div class="example-title">💡 How to get Hardware ID:</div>
                    Customer should run: <code>PDF_Metadata_Tool.exe --hardware-id</code><br>
                    Or it will be shown when they try to enter a license key.
                </div>
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
        .hardware-id { font-family: 'Courier New', monospace; background: #e6fffa; color: #047857; padding: 15px; border-radius: 10px; text-align: center; margin: 10px 0; border: 2px solid #4fd1c7; font-size: 16px; font-weight: bold; }
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
        function copyHardwareId() {
            const hardwareId = document.getElementById('hardwareId').textContent;
            navigator.clipboard.writeText(hardwareId).then(function() {
                alert('Hardware ID copied to clipboard!');
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
        
        {% if license_info.hardware_id %}
        <h3>💻 Hardware ID:</h3>
        <div class="hardware-id" id="hardwareId">{{ license_info.hardware_id }}</div>
        <div style="text-align: center;">
            <button onclick="copyHardwareId()" class="btn copy-btn">📋 Copy Hardware ID</button>
        </div>
        {% endif %}
        
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
                {% if license_info.hardware_id %}Hardware ID: <strong>{{ license_info.hardware_id }}</strong><br>{% endif %}
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
        .status-inactive { background: linear-gradient(135deg, #a8a8a8 0%, #d3d3d3 100%); color: #2d3748; }
        .status-box { padding: 30px; border-radius: 15px; margin: 20px 0; text-align: center; }
        .support-info { background: #e3f2fd; padding: 20px; border-radius: 10px; margin-top: 20px; border-left: 4px solid #2196f3; }
        .info-item { background: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 8px; }
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
            {% if license_info.hardware_id %}
            <p><strong>Bound to Hardware:</strong> {{ license_info.hardware_id }}</p>
            {% endif %}
            {% if license_info.activation_count %}
            <p><strong>Activations:</strong> {{ license_info.activation_count }}</p>
            {% endif %}
        </div>
        {% elif status == 'expired' %}
        <div class="status-box status-expired">
            <h2>❌ License Expired</h2>
            <p><strong>License Key:</strong> <code>{{ license_key }}</code></p>
            <p><strong>Expired:</strong> {{ license_info.expiry_date[:10] }}</p>
            <p><strong>Customer:</strong> {{ license_info.customer_email }}</p>
        </div>
        {% elif status == 'inactive' %}
        <div class="status-box status-inactive">
            <h2>⚠️ License Deactivated</h2>
            <p><strong>License Key:</strong> <code>{{ license_key }}</code></p>
            <p><strong>Customer:</strong> {{ license_info.customer_email }}</p>
            <p>This license has been temporarily deactivated by administrator.</p>
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
