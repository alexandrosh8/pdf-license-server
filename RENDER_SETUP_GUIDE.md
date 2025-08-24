# 🚀 Complete Render Deployment Guide with Auto-Build System

## Overview

This guide covers deploying your PDF License Server with automatic EXE generation and update notification system on Render.com.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  License Server │    │  GitHub Actions  │    │  Client EXE     │
│   (Render.com)  │◄───┤   (Auto Build)   │◄───┤ (Update Check)  │
│                 │    │                  │    │                 │
│ - Admin Panel   │    │ - Script Upload  │    │ - License Check │
│ - License CRUD  │    │ - EXE Generation │    │ - Update Notify │
│ - Build Trigger │    │ - Release Create │    │ - Auto Download │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │
         ▼                        ▼
┌─────────────────┐    ┌──────────────────┐
│   PostgreSQL    │    │  GitHub Releases │
│   Database      │    │  (EXE Storage)   │
└─────────────────┘    └──────────────────┘
```

## Prerequisites

### 1. GitHub Repository Setup

1. **Create GitHub Repository**:
   ```bash
   # Create a new repository on GitHub
   # Example: https://github.com/yourusername/pdf-license-server
   ```

2. **Generate GitHub Personal Access Token**:
   - Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Click "Generate new token (classic)"
   - Select scopes:
     - ✅ `repo` (Full control of private repositories)
     - ✅ `workflow` (Update GitHub Action workflows)
     - ✅ `write:packages` (Upload packages to GitHub Package Registry)
   - Copy the token (you'll need it for environment variables)

3. **Add GitHub Secrets** (for Actions):
   - Go to your repository → Settings → Secrets and variables → Actions
   - Add repository secret: `GITHUB_TOKEN` (use the token from step 2)

### 2. Render Account Setup

1. **Sign up for Render**: https://render.com
2. **Connect GitHub**: Link your GitHub account to Render

## Step-by-Step Deployment

### Phase 1: Deploy License Server

#### 1. Create Web Service on Render

1. **Go to Render Dashboard** → "New" → "Web Service"
2. **Connect Repository**: Select your GitHub repository
3. **Configure Service**:
   - **Name**: `pdf-license-server`
   - **Runtime**: `Python`
   - **Branch**: `main`
   - **Root Directory**: (leave blank)
   - **Build Command**: 
     ```bash
     pip install --upgrade pip && pip install -r requirements.txt && pip install PyYAML
     ```
   - **Start Command**: 
     ```bash
     gunicorn server:app --workers 1 --bind 0.0.0.0:$PORT --timeout 120
     ```

#### 2. Add PostgreSQL Database

1. **In Render Dashboard** → "New" → "PostgreSQL"
2. **Configure Database**:
   - **Name**: `pdf-license-db`
   - **Database Name**: `pdf_licenses`
   - **User**: `pdf_admin`
   - **Region**: Same as your web service
3. **Link to Web Service**: Connect the database to your web service

#### 3. Set Environment Variables

**In your web service settings → Environment**:

##### Required Variables:
```bash
# Admin Authentication
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-password-here

# Flask Security
SECRET_KEY=your-secret-key-here

# GitHub Integration (for auto-build)
GITHUB_TOKEN=ghp_your-github-token-here
GITHUB_REPO=yourusername/your-repo-name
GITHUB_BRANCH=main

# Database (auto-set by Render when you link PostgreSQL)
DATABASE_URL=postgresql://user:pass@host:port/dbname
```

##### Optional Variables:
```bash
# Debug mode (set to False for production)
DEBUG=False

# Python version (if needed)
PYTHON_VERSION=3.12.0

# Custom build settings
BUILD_TIMEOUT=600
MAX_FILE_SIZE=50MB
```

#### 4. Generate Secure Credentials

Use the provided script to generate secure credentials:

```bash
python setup_credentials.py
```

Copy the generated values to your Render environment variables.

### Phase 2: Configure Auto-Build System

#### 1. Add Build System Files to Repository

Add these files to your repository:

1. **`build_system.py`** - Auto-build functionality
2. **`server_extensions.py`** - Additional server endpoints
3. **`update_client.py`** - Client-side update checker
4. **`.github/workflows/build-exe.yml`** - GitHub Actions workflow

#### 2. Update requirements.txt

Add these dependencies:
```txt
# Existing dependencies...
PyYAML>=6.0
```

#### 3. Integrate Build System into Server

Add this to your `server.py`:

```python
# Add at the top with other imports
from server_extensions import add_build_routes

# Add after app initialization
add_build_routes(app, require_admin)
```

#### 4. Create Client Directory Structure

In your repository, create:
```
your-repo/
├── client/
│   ├── app.py              # Your Python script to build
│   ├── requirements.txt    # Client dependencies
│   └── icon.ico           # Application icon (optional)
├── .github/
│   └── workflows/
│       └── build-exe.yml  # GitHub Actions workflow
└── (other server files...)
```

### Phase 3: Test the System

#### 1. Verify License Server

1. **Visit your server**: `https://your-app.onrender.com`
2. **Check health**: `https://your-app.onrender.com/health`
3. **Access admin panel**: `https://your-app.onrender.com/admin`
4. **Login** with your admin credentials

#### 2. Test Build System

1. **Go to Build Management**: `https://your-app.onrender.com/admin/build`
2. **Upload a Python script** (your client application)
3. **Set version number** (e.g., 1.0.0)
4. **Click "Upload & Build"**
5. **Monitor build status** on the page

#### 3. Verify GitHub Actions

1. **Check GitHub Actions tab** in your repository
2. **Monitor build progress**
3. **Verify release creation** when build completes
4. **Download and test the generated EXE**

## Environment Variables Reference

### Complete List of Environment Variables

#### License Server Variables:
```bash
# Authentication (REQUIRED)
ADMIN_USERNAME=admin                    # Admin login username
ADMIN_PASSWORD=SecurePassword123!       # Admin login password

# Flask Security (REQUIRED)
SECRET_KEY=your-flask-secret-key-here   # Flask session encryption key

# Database (AUTO-SET by Render)
DATABASE_URL=postgresql://...           # PostgreSQL connection string

# GitHub Integration (REQUIRED for auto-build)
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx  # GitHub Personal Access Token
GITHUB_REPO=username/repository-name   # GitHub repository
GITHUB_BRANCH=main                      # Git branch (default: main)

# Optional Configuration
DEBUG=False                             # Debug mode (default: False)
PYTHON_VERSION=3.12.0                  # Python version
BUILD_TIMEOUT=600                       # Build timeout in seconds
MAX_FILE_SIZE=50MB                      # Max upload file size
```

#### Client Application Variables (for PDF app):
```bash
# License Server Connection
LICENSE_SERVER_URL=https://your-license-server.onrender.com

# Flask Security
SECRET_KEY=different-secret-key-here

# Optional
DEBUG=False
```

### How to Set Environment Variables in Render:

1. **Go to your service** in Render Dashboard
2. **Click "Environment"** tab
3. **Add each variable**:
   - Key: Variable name (e.g., `ADMIN_USERNAME`)
   - Value: Variable value (e.g., `admin`)
4. **Click "Save Changes"**
5. **Service will redeploy automatically**

## Using the Auto-Build System

### 1. Upload Python Script

1. **Access admin panel**: `https://your-server.onrender.com/admin`
2. **Go to Build Management**: Click "Build" in navigation
3. **Upload Python file**: Select your `.py` script
4. **Set version**: Use semantic versioning (e.g., 1.2.3)
5. **Add description**: Optional release notes
6. **Click "Upload & Build"**

### 2. Monitor Build Progress

- **Build status** updates automatically on the page
- **GitHub Actions** shows detailed build logs
- **Email notifications** from GitHub when build completes

### 3. Download Generated EXE

- **Automatic release** created on GitHub
- **Download link** provided in admin panel
- **Update notifications** sent to old versions

## Client Integration for Update Notifications

### Add to Your Python Application:

```python
from update_client import integrate_update_checker

# At application startup
current_version = "1.0.0"  # Your app version
server_url = "https://your-license-server.onrender.com"

# Integrate update checker
update_checker = integrate_update_checker(current_version, server_url)

# Manual check (optional)
# update_info = update_checker.check_for_updates()
```

### Build Your Application with Update Support:

```python
# In your main application file
import sys
import os

# Add version information
APP_VERSION = "1.0.0"
SERVER_URL = "https://your-license-server.onrender.com"

def main():
    # Initialize update checker
    from update_client import integrate_update_checker
    update_checker = integrate_update_checker(APP_VERSION, SERVER_URL)
    
    # Your application logic here
    # ...

if __name__ == "__main__":
    main()
```

## Troubleshooting

### Common Issues:

#### 1. Build Fails
**Problem**: GitHub Actions build fails
**Solutions**:
- Check `requirements.txt` has all dependencies
- Verify GitHub token has correct permissions
- Check build logs in GitHub Actions tab

#### 2. Update Notifications Not Working
**Problem**: Old EXE doesn't show update notifications
**Solutions**:
- Verify `LICENSE_SERVER_URL` is correct in client
- Check server `/api/check-updates` endpoint
- Ensure client has internet connection

#### 3. License Validation Fails
**Problem**: EXE shows "Invalid license" error
**Solutions**:
- Verify license server is running
- Check license key format: `PDFM-XXXX-XXXX-XXXX`
- Confirm hardware ID matches in database

#### 4. Database Connection Issues
**Problem**: "Database connection failed" error
**Solutions**:
- Verify PostgreSQL database is linked to service
- Check `DATABASE_URL` environment variable
- Run database repair: `/api/repair-db`

### Debug Commands:

```bash
# Test license server health
curl https://your-server.onrender.com/health

# Test update check
curl -X POST https://your-server.onrender.com/api/check-updates \
  -H "Content-Type: application/json" \
  -d '{"current_version": "1.0.0"}'

# Test latest release
curl https://your-server.onrender.com/api/latest-release
```

## Security Considerations

### 1. Environment Variables
- **Never commit** sensitive environment variables to Git
- **Use strong passwords** for admin accounts
- **Rotate GitHub tokens** regularly

### 2. License Security
- **Hardware ID binding** prevents license sharing
- **Server-side validation** prevents bypassing
- **Encrypted communication** with HTTPS

### 3. Build Security
- **GitHub token** has minimal required permissions
- **Build process** is isolated in GitHub Actions
- **Release artifacts** are signed and verified

## Monitoring and Maintenance

### 1. Server Monitoring
- **Health checks**: Render automatically monitors `/health`
- **Error logs**: Available in Render dashboard
- **Database metrics**: PostgreSQL monitoring included

### 2. Build Monitoring
- **GitHub Actions**: Build status and logs
- **Release notifications**: Email alerts from GitHub
- **Download statistics**: Track in GitHub releases

### 3. User Analytics
- **License usage**: Track in admin panel
- **Update adoption**: Monitor download counts
- **Error reporting**: Check server logs

## Next Steps

1. **Deploy license server** following this guide
2. **Test build system** with a sample Python script
3. **Create client application** with update notifications
4. **Generate license keys** for your users
5. **Monitor usage** and gather feedback

---

## Support

For technical support:
- **Email**: halexandros25@gmail.com
- **GitHub Issues**: Create issue in your repository
- **Documentation**: Refer to this guide

**Ready to deploy!** Follow this guide step-by-step for a complete auto-build system with update notifications.
