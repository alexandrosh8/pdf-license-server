#!/usr/bin/env python3
"""
Server Extensions for Auto-Build System
======================================
Additional endpoints and functionality for the license server
"""

from flask import request, jsonify, render_template_string, flash, redirect, url_for
from werkzeug.utils import secure_filename
import os
import json
import logging
from datetime import datetime
from build_system import AutoBuildSystem, UpdateNotificationSystem

logger = logging.getLogger(__name__)

# Initialize build system
build_system = AutoBuildSystem()
update_system = UpdateNotificationSystem(build_system)

def add_build_routes(app, require_admin):
    """Add build-related routes to the Flask app"""
    
    @app.route('/admin/build')
    @require_admin
    def admin_build():
        """Build management page"""
        return render_template_string(BUILD_ADMIN_TEMPLATE)
    
    @app.route('/admin/upload-script', methods=['POST'])
    @require_admin
    def upload_script():
        """Upload Python script and trigger build"""
        try:
            # Check if file is present
            if 'script_file' not in request.files:
                flash('No script file provided', 'error')
                return redirect(url_for('admin_build'))
            
            file = request.files['script_file']
            version = request.form.get('version', '').strip()
            description = request.form.get('description', '').strip()
            
            # Validate inputs
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(url_for('admin_build'))
            
            if not version:
                flash('Version number is required', 'error')
                return redirect(url_for('admin_build'))
            
            if not file.filename.endswith('.py'):
                flash('Only Python (.py) files are allowed', 'error')
                return redirect(url_for('admin_build'))
            
            # Read script content
            script_content = file.read().decode('utf-8')
            script_name = secure_filename(file.filename)
            
            # Build configuration
            build_config = {
                'description': description,
                'build_date': datetime.now().isoformat(),
                'admin_user': 'admin'  # You might want to track which admin uploaded
            }
            
            # Trigger build
            result = build_system.upload_script_and_trigger_build(
                script_content, script_name, version, build_config
            )
            
            if result['success']:
                flash(f'Build triggered successfully for version {version}', 'success')
                # Store build info in session or database for tracking
                return redirect(url_for('admin_build'))
            else:
                flash(f'Build failed: {result["error"]}', 'error')
                return redirect(url_for('admin_build'))
                
        except Exception as e:
            logger.error(f"Script upload failed: {e}")
            flash(f'Upload failed: {str(e)}', 'error')
            return redirect(url_for('admin_build'))
    
    @app.route('/api/build-status')
    @require_admin
    def build_status():
        """Get build status"""
        version = request.args.get('version')
        status = build_system.get_build_status(version=version)
        return jsonify(status)
    
    @app.route('/api/latest-release')
    def latest_release():
        """Get latest release information (public endpoint)"""
        release_info = build_system.get_latest_release_info()
        if release_info:
            return jsonify(release_info)
        else:
            return jsonify({"error": "No release information available"}), 404
    
    @app.route('/api/check-updates', methods=['POST'])
    def check_updates():
        """Check for updates for a specific version"""
        data = request.get_json()
        current_version = data.get('current_version') if data else None
        
        if not current_version:
            return jsonify({"error": "current_version is required"}), 400
        
        update_info = update_system.check_for_updates(current_version)
        return jsonify(update_info)
    
    @app.route('/api/update-notification', methods=['POST'])
    def update_notification():
        """Generate update notification for client"""
        data = request.get_json()
        current_version = data.get('current_version') if data else None
        
        if not current_version:
            return jsonify({"error": "current_version is required"}), 400
        
        notification = update_system.generate_update_notification(current_version)
        return jsonify(notification)

# HTML Template for Build Management
BUILD_ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Build Management - PDF License Server</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .content {
            padding: 30px;
        }
        .section {
            margin-bottom: 40px;
            padding: 20px;
            border: 1px solid #e2e8f0;
            border-radius: 10px;
        }
        .section h2 {
            color: #4a5568;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
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
        input[type="text"], input[type="file"], textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus, input[type="file"]:focus, textarea:focus {
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
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }
        .btn-secondary {
            background: #6c757d;
        }
        .status-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .status-success {
            border-color: #28a745;
            background-color: #d4edda;
        }
        .status-error {
            border-color: #dc3545;
            background-color: #f8d7da;
        }
        .status-warning {
            border-color: #ffc107;
            background-color: #fff3cd;
        }
        .build-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .info-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .nav-link {
            color: white;
            text-decoration: none;
            margin-right: 20px;
            padding: 10px 15px;
            border-radius: 5px;
            background: rgba(255,255,255,0.1);
            transition: background 0.3s;
        }
        .nav-link:hover {
            background: rgba(255,255,255,0.2);
        }
        .flash-messages {
            margin-bottom: 20px;
        }
        .flash-message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        .flash-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .flash-error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏗️ Build Management System</h1>
            <p>Automatic EXE Generation & Update Management</p>
            <div>
                <a href="/admin" class="nav-link">← Back to Admin</a>
                <a href="/admin/licenses" class="nav-link">Licenses</a>
                <a href="/admin/logs" class="nav-link">Logs</a>
            </div>
        </div>
        
        <div class="content">
            <!-- Flash Messages -->
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    <div class="flash-messages">
                        {% for category, message in messages %}
                            <div class="flash-message flash-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    </div>
                {% endif %}
            {% endwith %}
            
            <!-- Upload Script Section -->
            <div class="section">
                <h2>📤 Upload Python Script</h2>
                <p>Upload a Python script to automatically build into an EXE file using GitHub Actions.</p>
                
                <form action="/admin/upload-script" method="post" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="script_file">Python Script File:</label>
                        <input type="file" id="script_file" name="script_file" accept=".py" required>
                        <small>Only .py files are allowed</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="version">Version Number:</label>
                        <input type="text" id="version" name="version" placeholder="e.g., 1.2.3" required>
                        <small>Semantic version format recommended (e.g., 1.2.3)</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="description">Build Description:</label>
                        <textarea id="description" name="description" rows="3" placeholder="Optional description of changes in this version"></textarea>
                    </div>
                    
                    <button type="submit" class="btn">🚀 Upload & Build</button>
                </form>
            </div>
            
            <!-- Build Status Section -->
            <div class="section">
                <h2>📊 Build Status</h2>
                <div id="buildStatus">
                    <button onclick="checkBuildStatus()" class="btn btn-secondary">🔄 Check Latest Build Status</button>
                </div>
                
                <div id="statusResult" style="margin-top: 20px;"></div>
            </div>
            
            <!-- Latest Release Section -->
            <div class="section">
                <h2>📦 Latest Release</h2>
                <div id="latestRelease">
                    <button onclick="checkLatestRelease()" class="btn btn-secondary">📋 Get Latest Release Info</button>
                </div>
                
                <div id="releaseResult" style="margin-top: 20px;"></div>
            </div>
            
            <!-- Configuration Help Section -->
            <div class="section">
                <h2>⚙️ Configuration Requirements</h2>
                <p>To use the auto-build system, ensure these environment variables are set:</p>
                
                <div class="build-info">
                    <div class="info-card">
                        <h4>Required Variables</h4>
                        <ul>
                            <li><code>GITHUB_TOKEN</code> - Personal Access Token</li>
                            <li><code>GITHUB_REPO</code> - Repository (username/repo)</li>
                        </ul>
                    </div>
                    
                    <div class="info-card">
                        <h4>Optional Variables</h4>
                        <ul>
                            <li><code>GITHUB_BRANCH</code> - Default: main</li>
                        </ul>
                    </div>
                    
                    <div class="info-card">
                        <h4>GitHub Actions</h4>
                        <p>The build system automatically creates GitHub Actions workflows to build EXE files on Windows runners.</p>
                    </div>
                    
                    <div class="info-card">
                        <h4>Update Notifications</h4>
                        <p>Old EXE versions automatically check for updates and notify users when new versions are available.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function checkBuildStatus() {
            const statusDiv = document.getElementById('statusResult');
            statusDiv.innerHTML = '<div class="status-card">⏳ Checking build status...</div>';
            
            try {
                const response = await fetch('/api/build-status');
                const data = await response.json();
                
                let statusClass = 'status-card';
                let statusIcon = '❓';
                
                if (data.status === 'completed') {
                    if (data.conclusion === 'success') {
                        statusClass += ' status-success';
                        statusIcon = '✅';
                    } else {
                        statusClass += ' status-error';
                        statusIcon = '❌';
                    }
                } else if (data.status === 'in_progress') {
                    statusClass += ' status-warning';
                    statusIcon = '⏳';
                }
                
                statusDiv.innerHTML = `
                    <div class="${statusClass}">
                        <h4>${statusIcon} Build Status</h4>
                        <p><strong>Status:</strong> ${data.status}</p>
                        ${data.conclusion ? `<p><strong>Result:</strong> ${data.conclusion}</p>` : ''}
                        ${data.html_url ? `<p><a href="${data.html_url}" target="_blank">View on GitHub</a></p>` : ''}
                        ${data.created_at ? `<p><strong>Started:</strong> ${new Date(data.created_at).toLocaleString()}</p>` : ''}
                        ${data.updated_at ? `<p><strong>Updated:</strong> ${new Date(data.updated_at).toLocaleString()}</p>` : ''}
                    </div>
                `;
            } catch (error) {
                statusDiv.innerHTML = `
                    <div class="status-card status-error">
                        <h4>❌ Error</h4>
                        <p>Failed to check build status: ${error.message}</p>
                    </div>
                `;
            }
        }
        
        async function checkLatestRelease() {
            const releaseDiv = document.getElementById('releaseResult');
            releaseDiv.innerHTML = '<div class="status-card">⏳ Fetching release info...</div>';
            
            try {
                const response = await fetch('/api/latest-release');
                const data = await response.json();
                
                if (response.ok) {
                    releaseDiv.innerHTML = `
                        <div class="status-card status-success">
                            <h4>📦 ${data.name || data.version}</h4>
                            <p><strong>Version:</strong> ${data.version}</p>
                            <p><strong>Published:</strong> ${new Date(data.published_at).toLocaleString()}</p>
                            <p><strong>Downloads:</strong> ${data.download_count}</p>
                            ${data.download_url ? `<p><a href="${data.download_url}" class="btn">📥 Download EXE</a></p>` : ''}
                            ${data.html_url ? `<p><a href="${data.html_url}" target="_blank">View Release on GitHub</a></p>` : ''}
                            ${data.body ? `<div><strong>Release Notes:</strong><br><pre>${data.body}</pre></div>` : ''}
                        </div>
                    `;
                } else {
                    throw new Error(data.error || 'Unknown error');
                }
            } catch (error) {
                releaseDiv.innerHTML = `
                    <div class="status-card status-error">
                        <h4>❌ Error</h4>
                        <p>Failed to fetch release info: ${error.message}</p>
                    </div>
                `;
            }
        }
        
        // Auto-refresh build status every 30 seconds if there's an active build
        setInterval(async () => {
            const statusResult = document.getElementById('statusResult');
            if (statusResult.innerHTML.includes('in_progress')) {
                checkBuildStatus();
            }
        }, 30000);
    </script>
</body>
</html>
"""
