#!/usr/bin/env python3
"""
PDF Metadata and Timestamp Preservation Web Application
=======================================================
Web-based PDF processing service with license key validation.
Processes PDF files to preserve metadata and timestamps while making the output
appear as if it was never opened, modified, or accessed.

This is a Flask web application that requires license validation from a license server.
"""

from flask import Flask, request, jsonify, render_template_string, send_file, flash, redirect, url_for
import os
import re
import sys
import json
import secrets
import string
import logging
import platform
import subprocess
import traceback
import requests
import hashlib
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple, Any, List
from werkzeug.utils import secure_filename
import zipfile

# Core PDF processing
try:
    import pikepdf
    from pikepdf import Pdf, Dictionary, Name, String
    PIKEPDF_AVAILABLE = True
except ImportError:
    PIKEPDF_AVAILABLE = False
    print("ERROR: pikepdf not installed. Install with: pip install pikepdf")

# Enhanced PDF analysis (optional)
try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

# Date parsing
try:
    from dateutil import parser as date_parser
except ImportError:
    print("ERROR: python-dateutil not installed. Install with: pip install python-dateutil")
    sys.exit(1)

# Platform-specific imports for Windows
if platform.system() == 'Windows':
    try:
        import pywintypes
        import win32file
        import win32con
        import win32api
        WIN32_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False
else:
    WIN32_AVAILABLE = False

# ============================================================================
# FLASK APPLICATION SETUP
# ============================================================================

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))

# Configure upload settings
UPLOAD_FOLDER = 'uploads'
PROCESSED_FOLDER = 'processed'
ALLOWED_EXTENSIONS = {'pdf'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROCESSED_FOLDER'] = PROCESSED_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('pdf_processor.log', mode='w', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# LICENSE VALIDATION
# ============================================================================

LICENSE_SERVER_URL = os.environ.get('LICENSE_SERVER_URL', 'https://pdf-license-server-dmyx.onrender.com')

class LicenseValidator:
    """License validation with the license server"""
    
    def __init__(self):
        self.server_url = LICENSE_SERVER_URL
        self.hardware_id = self._generate_hardware_id()
    
    def _generate_hardware_id(self):
        """Generate hardware fingerprint"""
        try:
            identifiers = []
            
            # MAC address
            import uuid
            mac = format(uuid.getnode(), 'x').upper()
            if mac and mac != "FFFFFFFFFFFF":
                identifiers.append(mac)
            
            # System info
            system_info = f"{platform.system()}{platform.node()}{platform.machine()}"
            identifiers.append(hashlib.md5(system_info.encode()).hexdigest()[:16])
            
            # Create hardware ID
            combined = '|'.join(identifiers)
            hardware_id = hashlib.sha256(combined.encode()).hexdigest()[:16].upper()
            return hardware_id
        except Exception:
            return hashlib.sha256(f"FALLBACK_{int(datetime.now().timestamp())}".encode()).hexdigest()[:16]
    
    def validate_license(self, license_key):
        """Validate license key with server"""
        try:
            validation_data = {
                "license_key": license_key,
                "hardware_id": self.hardware_id,
                "client_version": "1.0.0",
                "timestamp": int(datetime.now().timestamp()),
                "platform": platform.system()
            }
            
            response = requests.post(
                f"{self.server_url}/api/validate",
                json=validation_data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("valid", False), result
            else:
                return False, {"error": f"Server error: {response.status_code}"}
                
        except Exception as e:
            return False, {"error": f"Validation failed: {str(e)}"}

# Global validator instance
license_validator = LicenseValidator()

def require_license(f):
    """Decorator to require license validation"""
    def decorated_function(*args, **kwargs):
        license_key = request.headers.get('X-License-Key') or request.form.get('license_key')
        
        if not license_key:
            return jsonify({"error": "License key required"}), 401
        
        valid, result = license_validator.validate_license(license_key)
        if not valid:
            return jsonify({"error": "Invalid license", "details": result}), 403
        
        # Add license info to request for use in the function
        request.license_info = result
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

# ============================================================================
# PDF PROCESSING CLASSES
# ============================================================================

class PDFADetector:
    """PDF/A detection using multiple signals"""
    
    @staticmethod
    def detect_pdfa_heuristic(pdf_path: str) -> Dict[str, Any]:
        """Perform heuristic PDF/A detection"""
        result = {
            'is_pdfa': False,
            'pdfa_version': None,
            'conformance_level': None,
            'confidence': 0.0,
            'detection_methods': [],
            'signals': {},
            'errors': []
        }
        
        if not PIKEPDF_AVAILABLE:
            result['errors'].append("pikepdf not available")
            return result
        
        signals_found = 0
        total_signals = 0
        
        try:
            # Check XMP metadata for PDF/A markers
            xmp_result = PDFADetector._check_xmp_metadata(pdf_path)
            total_signals += 1
            result['signals']['xmp_metadata'] = xmp_result
            if xmp_result['found']:
                signals_found += 1
                result['detection_methods'].append('xmp_metadata')
                if xmp_result['version']:
                    result['pdfa_version'] = xmp_result['version']
                    result['conformance_level'] = xmp_result['conformance']
        except Exception as e:
            result['errors'].append(f"XMP check failed: {str(e)}")
        
        # Calculate confidence
        if total_signals > 0:
            result['confidence'] = signals_found / total_signals
        
        # Determine if PDF/A
        if result['confidence'] >= 0.6 or 'xmp_metadata' in result['detection_methods']:
            result['is_pdfa'] = True
        
        return result
    
    @staticmethod
    def _check_xmp_metadata(pdf_path: str) -> Dict[str, Any]:
        """Check XMP metadata for PDF/A markers"""
        result = {'found': False, 'version': None, 'conformance': None}
        
        try:
            with pikepdf.open(pdf_path) as pdf:
                if hasattr(pdf.Root, 'Metadata'):
                    xmp_data = pdf.Root.Metadata.read_bytes()
                    xmp_str = xmp_data.decode('utf-8', errors='ignore')
                    
                    # Look for PDF/A markers
                    patterns = [
                        (r'<pdfaid:part>(\d+)</pdfaid:part>', r'<pdfaid:conformance>([AaBbUu])</pdfaid:conformance>'),
                        (r'pdfaid:part="(\d+)"', r'pdfaid:conformance="([AaBbUu])"'),
                    ]
                    
                    for part_pattern, conf_pattern in patterns:
                        part_match = re.search(part_pattern, xmp_str)
                        conf_match = re.search(conf_pattern, xmp_str)
                        
                        if part_match:
                            result['version'] = part_match.group(1)
                        if conf_match:
                            result['conformance'] = conf_match.group(1).upper()
                        
                        if result['version'] and result['conformance']:
                            break
                    
                    if result['version'] in ['1', '2', '3', '4'] and result['conformance'] in ['A', 'B', 'U']:
                        result['found'] = True
        except Exception:
            pass
        
        return result

class MetadataHandler:
    """Handle PDF metadata extraction and application"""
    
    @staticmethod
    def extract_all_metadata(pdf_path: str, password: str = '') -> Dict[str, Any]:
        """Extract comprehensive metadata from PDF"""
        metadata = {
            'docinfo': {},
            'xmp': None,
            'dates': {},
            'pdf_version': None,
            'linearized': False,
            'page_count': 0,
            'file_size': 0,
            'encryption': None,
            'pdfa_info': None
        }
        
        if not PIKEPDF_AVAILABLE:
            return metadata
        
        try:
            metadata['file_size'] = os.path.getsize(pdf_path)
            
            with pikepdf.open(pdf_path, password=password) as pdf:
                metadata['pdf_version'] = str(pdf.pdf_version)
                metadata['linearized'] = pdf.is_linearized
                metadata['page_count'] = len(pdf.pages)
                
                # Document Info Dictionary
                if pdf.docinfo:
                    for key, value in pdf.docinfo.items():
                        clean_key = str(key).lstrip('/')
                        metadata['docinfo'][clean_key] = str(value)
                        
                        # Parse dates
                        if clean_key in ['CreationDate', 'ModDate']:
                            date_obj = MetadataHandler._parse_pdf_date(str(value))
                            if date_obj:
                                metadata['dates'][clean_key] = date_obj
                
                # XMP Metadata
                if hasattr(pdf.Root, 'Metadata'):
                    try:
                        metadata['xmp'] = pdf.Root.Metadata.read_bytes()
                    except:
                        pass
                
                # PDF/A detection
                metadata['pdfa_info'] = PDFADetector.detect_pdfa_heuristic(pdf_path)
                
        except Exception as e:
            logger.error(f"Error extracting metadata: {e}")
            
        return metadata
    
    @staticmethod
    def apply_all_metadata(pdf_path: str, metadata: Dict[str, Any], output_path: str) -> Dict[str, Any]:
        """Apply extracted metadata to PDF"""
        operation_details = {
            'success': False,
            'metadata_applied': [],
            'encryption_applied': False,
            'linearized': False
        }
        
        if not PIKEPDF_AVAILABLE:
            operation_details['error'] = "pikepdf not available"
            return operation_details
        
        try:
            with pikepdf.open(pdf_path) as pdf:
                # Apply document info
                if hasattr(pdf, 'docinfo'):
                    try:
                        del pdf.docinfo
                    except:
                        pass
                
                for key, value in metadata['docinfo'].items():
                    key_with_slash = Name(f'/{key}') if not key.startswith('/') else Name(key)
                    pdf.docinfo[key_with_slash] = String(str(value))
                    operation_details['metadata_applied'].append(key)
                
                # Apply XMP metadata
                if metadata.get('xmp'):
                    try:
                        pdf.Root.Metadata = pikepdf.Stream(pdf, metadata['xmp'])
                        operation_details['metadata_applied'].append('XMP')
                    except Exception as e:
                        logger.warning(f"Could not apply XMP metadata: {e}")
                
                # Save options
                save_options = {}
                if metadata.get('linearized'):
                    save_options['linearize'] = True
                    operation_details['linearized'] = True
                
                pdf.save(output_path, **save_options)
                operation_details['success'] = True
                
        except Exception as e:
            logger.error(f"Error applying metadata: {e}")
            operation_details['error'] = str(e)
        
        return operation_details
    
    @staticmethod
    def _parse_pdf_date(date_str: str) -> Optional[datetime]:
        """Parse PDF date format"""
        if not date_str:
            return None
        
        try:
            # Remove D: prefix and timezone
            date_str = date_str.lstrip('D:').rstrip('Z').split('+')[0].split('-')[0]
            
            # Parse components
            year = int(date_str[0:4])
            month = int(date_str[4:6]) if len(date_str) > 4 else 1
            day = int(date_str[6:8]) if len(date_str) > 6 else 1
            hour = int(date_str[8:10]) if len(date_str) > 8 else 0
            minute = int(date_str[10:12]) if len(date_str) > 10 else 0
            second = int(date_str[12:14]) if len(date_str) > 12 else 0
            
            return datetime(year, month, day, hour, minute, second)
        except:
            return None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def clean_filename(filename):
    """Clean filename for safe storage"""
    return secure_filename(filename)

# ============================================================================
# WEB ROUTES
# ============================================================================

@app.route('/')
def index():
    """Main page"""
    return render_template_string(INDEX_TEMPLATE)

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "pikepdf_available": PIKEPDF_AVAILABLE,
        "license_server": LICENSE_SERVER_URL
    })

@app.route('/api/validate-license', methods=['POST'])
def validate_license_endpoint():
    """Validate license key"""
    data = request.get_json()
    if not data or 'license_key' not in data:
        return jsonify({"error": "License key required"}), 400
    
    valid, result = license_validator.validate_license(data['license_key'])
    
    if valid:
        return jsonify({
            "valid": True,
            "hardware_id": license_validator.hardware_id,
            "details": result
        })
    else:
        return jsonify({
            "valid": False,
            "hardware_id": license_validator.hardware_id,
            "error": result.get("error", "Unknown error")
        }), 403

@app.route('/api/process-pdf', methods=['POST'])
@require_license
def process_pdf():
    """Process PDF files with metadata preservation"""
    try:
        # Check if files are present
        if 'original_pdf' not in request.files or 'edited_pdf' not in request.files:
            return jsonify({"error": "Both original_pdf and edited_pdf files are required"}), 400
        
        original_file = request.files['original_pdf']
        edited_file = request.files['edited_pdf']
        
        # Validate files
        if original_file.filename == '' or edited_file.filename == '':
            return jsonify({"error": "No files selected"}), 400
        
        if not (allowed_file(original_file.filename) and allowed_file(edited_file.filename)):
            return jsonify({"error": "Only PDF files are allowed"}), 400
        
        # Save uploaded files
        original_filename = clean_filename(original_file.filename)
        edited_filename = clean_filename(edited_file.filename)
        
        original_path = os.path.join(app.config['UPLOAD_FOLDER'], f"orig_{original_filename}")
        edited_path = os.path.join(app.config['UPLOAD_FOLDER'], f"edit_{edited_filename}")
        
        original_file.save(original_path)
        edited_file.save(edited_path)
        
        # Extract metadata from original
        logger.info("Extracting metadata from original PDF...")
        original_metadata = MetadataHandler.extract_all_metadata(original_path)
        
        if not original_metadata:
            return jsonify({"error": "Failed to extract metadata from original PDF"}), 500
        
        # Generate output filename
        output_filename = f"processed_{edited_filename}"
        output_path = os.path.join(app.config['PROCESSED_FOLDER'], output_filename)
        
        # Apply metadata to edited PDF
        logger.info("Applying metadata to edited PDF...")
        operation_details = MetadataHandler.apply_all_metadata(
            edited_path,
            original_metadata,
            output_path
        )
        
        if not operation_details['success']:
            return jsonify({
                "error": "Failed to process PDF", 
                "details": operation_details.get('error', 'Unknown error')
            }), 500
        
        # Clean up uploaded files
        try:
            os.remove(original_path)
            os.remove(edited_path)
        except:
            pass
        
        # Return success with download link
        return jsonify({
            "success": True,
            "message": "PDF processed successfully",
            "download_url": f"/download/{output_filename}",
            "operation_details": {
                "metadata_applied": operation_details['metadata_applied'][:10],  # Limit for response size
                "total_metadata_fields": len(operation_details['metadata_applied']),
                "linearized": operation_details['linearized']
            },
            "original_metadata": {
                "pdf_version": original_metadata.get('pdf_version'),
                "page_count": original_metadata.get('page_count'),
                "file_size": original_metadata.get('file_size'),
                "is_pdfa": original_metadata.get('pdfa_info', {}).get('is_pdfa', False)
            }
        })
        
    except Exception as e:
        logger.error(f"Error processing PDF: {e}")
        return jsonify({"error": f"Processing failed: {str(e)}"}), 500

@app.route('/download/<filename>')
@require_license
def download_file(filename):
    """Download processed file"""
    try:
        file_path = os.path.join(app.config['PROCESSED_FOLDER'], filename)
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
        
        return send_file(file_path, as_attachment=True, download_name=filename)
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return jsonify({"error": "Download failed"}), 500

# ============================================================================
# HTML TEMPLATES
# ============================================================================

INDEX_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF Metadata Processor</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        h1 {
            color: #4a5568;
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #4a5568;
        }
        input[type="text"], input[type="file"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus, input[type="file"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }
        .btn:disabled {
            background: #a0aec0;
            cursor: not-allowed;
            transform: none;
        }
        .status {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            display: none;
        }
        .status.success {
            background: #f0fff4;
            color: #2d7d32;
            border: 1px solid #c8e6c9;
        }
        .status.error {
            background: #fff5f5;
            color: #c62828;
            border: 1px solid #ffcdd2;
        }
        .hardware-id {
            background: #f7fafc;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-family: monospace;
            word-break: break-all;
        }
        .progress {
            width: 100%;
            height: 6px;
            background: #e2e8f0;
            border-radius: 3px;
            overflow: hidden;
            margin-top: 10px;
            display: none;
        }
        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            width: 0%;
            transition: width 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 PDF Metadata Processor</h1>
        
        <div class="hardware-id">
            <strong>Hardware ID:</strong> <span id="hardware-id">Loading...</span>
        </div>
        
        <form id="uploadForm" enctype="multipart/form-data">
            <div class="form-group">
                <label for="license_key">License Key:</label>
                <input type="text" id="license_key" name="license_key" 
                       placeholder="PDFM-XXXX-XXXX-XXXX" required>
            </div>
            
            <div class="form-group">
                <label for="original_pdf">Original PDF (with metadata to preserve):</label>
                <input type="file" id="original_pdf" name="original_pdf" accept=".pdf" required>
            </div>
            
            <div class="form-group">
                <label for="edited_pdf">Edited PDF (needs metadata):</label>
                <input type="file" id="edited_pdf" name="edited_pdf" accept=".pdf" required>
            </div>
            
            <button type="submit" class="btn" id="processBtn">Process PDF</button>
            
            <div class="progress" id="progress">
                <div class="progress-bar" id="progressBar"></div>
            </div>
        </form>
        
        <div class="status" id="status"></div>
    </div>

    <script>
        // Get hardware ID on page load
        fetch('/api/validate-license', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({license_key: 'dummy'})
        })
        .then(response => response.json())
        .then(data => {
            document.getElementById('hardware-id').textContent = data.hardware_id || 'Unknown';
        })
        .catch(error => {
            document.getElementById('hardware-id').textContent = 'Error loading';
        });

        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const statusDiv = document.getElementById('status');
            const progressDiv = document.getElementById('progress');
            const progressBar = document.getElementById('progressBar');
            const processBtn = document.getElementById('processBtn');
            
            // Reset status
            statusDiv.style.display = 'none';
            progressDiv.style.display = 'block';
            processBtn.disabled = true;
            processBtn.textContent = 'Processing...';
            
            // Simulate progress
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += Math.random() * 30;
                if progress > 90) progress = 90;
                progressBar.style.width = progress + '%';
            }, 500);
            
            try {
                const response = await fetch('/api/process-pdf', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-License-Key': formData.get('license_key')
                    }
                });
                
                clearInterval(progressInterval);
                progressBar.style.width = '100%';
                
                const result = await response.json();
                
                if (response.ok) {
                    statusDiv.className = 'status success';
                    statusDiv.innerHTML = `
                        <h3>✅ Success!</h3>
                        <p>${result.message}</p>
                        <p><strong>Metadata fields applied:</strong> ${result.operation_details.total_metadata_fields}</p>
                        <p><strong>PDF Version:</strong> ${result.original_metadata.pdf_version}</p>
                        <p><strong>Pages:</strong> ${result.original_metadata.page_count}</p>
                        <a href="${result.download_url}" class="btn" style="display: inline-block; text-decoration: none; margin-top: 10px;">
                            📥 Download Processed PDF
                        </a>
                    `;
                } else {
                    throw new Error(result.error || 'Unknown error');
                }
            } catch (error) {
                clearInterval(progressInterval);
                statusDiv.className = 'status error';
                statusDiv.innerHTML = `
                    <h3>❌ Error</h3>
                    <p>${error.message}</p>
                `;
            } finally {
                statusDiv.style.display = 'block';
                progressDiv.style.display = 'none';
                processBtn.disabled = false;
                processBtn.textContent = 'Process PDF';
            }
        });
    </script>
</body>
</html>
"""

# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting PDF Metadata Processor on port {port}")
    logger.info(f"License server: {LICENSE_SERVER_URL}")
    logger.info(f"pikepdf available: {PIKEPDF_AVAILABLE}")
    
    if not PIKEPDF_AVAILABLE:
        logger.error("WARNING: pikepdf not available - PDF processing will fail!")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
