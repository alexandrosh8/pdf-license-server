# PDF License Server & Metadata Processor - Render Deployment Guide

## Overview

This project contains two Flask applications:

1. **License Server** (`server.py`) - Manages license keys and validation
2. **PDF Metadata Processor** (`app.py`) - Web application for processing PDF files with license validation

## Architecture

```
┌─────────────────┐    ┌──────────────────────┐
│  License Server │    │  PDF Metadata App    │
│   (server.py)   │◄───┤     (app.py)        │
│                 │    │                      │
│ - Admin panel   │    │ - File upload        │
│ - License CRUD  │    │ - PDF processing     │
│ - Validation    │    │ - License validation │
└─────────────────┘    └──────────────────────┘
         │
         ▼
┌─────────────────┐
│   PostgreSQL    │
│   Database      │
└─────────────────┘
```

## Deployment Options

### Option 1: Deploy Both Applications (Recommended)

Deploy both the license server and PDF processor as separate services:

1. **License Server**: Manages licenses, admin panel
2. **PDF App**: Processes PDFs, validates with license server

### Option 2: Deploy License Server Only

Deploy only the license server if you want to use desktop clients.

## Files Overview

### ✅ Keep These Files:
- `server.py` - License server application
- `app.py` - PDF metadata processor web application
- `requirements.txt` - Python dependencies
- `gunicorn.conf.py` - Production server configuration
- `render.yaml` - Render deployment configuration
- `repair_db.py` - Database maintenance tool
- `setup_credentials.py` - Credential generation helper
- `README.md` - Project documentation
- `.gitignore` - Git ignore rules

### ❌ Delete These Files:
- `runtime.txt` - Not needed for Render
- Any desktop client files

## Step-by-Step Deployment

### 1. Prepare Your Repository

```bash
# Clone or create your repository
git init
git add .
git commit -m "Initial deployment setup"
git branch -M main
git remote add origin https://github.com/yourusername/your-repo.git
git push -u origin main
```

### 2. Deploy to Render

#### A. License Server Deployment

1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click "New" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name**: `pdf-license-server`
   - **Runtime**: `Python`
   - **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command**: `gunicorn server:app --workers 1 --bind 0.0.0.0:$PORT --timeout 120`
   - **Health Check Path**: `/health`

5. Set Environment Variables:
   - `SECRET_KEY`: (Generate with setup_credentials.py)
   - `ADMIN_USERNAME`: `admin` (or your choice)
   - `ADMIN_PASSWORD`: (Generate with setup_credentials.py)
   - `DATABASE_URL`: (Will be auto-set when you add PostgreSQL)

6. Add PostgreSQL Database:
   - Click "New" → "PostgreSQL"
   - **Name**: `pdf-license-db`
   - **Database Name**: `pdf_licenses`
   - **User**: `pdf_admin`
   - Link to your web service

#### B. PDF Metadata App Deployment (Optional)

1. Create another web service
2. Configure:
   - **Name**: `pdf-metadata-app`
   - **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --workers 1 --bind 0.0.0.0:$PORT --timeout 120`
   - **Health Check Path**: `/health`

3. Set Environment Variables:
   - `SECRET_KEY`: (Generate new one)
   - `LICENSE_SERVER_URL`: `https://your-license-server.onrender.com`

### 3. Generate Credentials

Run locally to generate secure credentials:

```bash
python setup_credentials.py
```

Copy the generated values to Render's environment variables.

### 4. Initialize Database

After deployment, initialize the database:

1. Go to your license server URL: `https://your-license-server.onrender.com`
2. The database tables will be created automatically
3. Or use the repair endpoint: `POST /api/repair-db` with proper authorization

### 5. Access Your Applications

- **License Server**: `https://your-license-server.onrender.com`
  - Admin panel: `/admin`
  - API endpoints: `/api/*`

- **PDF Processor**: `https://your-pdf-app.onrender.com`
  - Main interface: `/`
  - Requires valid license key from license server

## Environment Variables Reference

### License Server (`server.py`)
```
SECRET_KEY=your-secret-key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-password
DATABASE_URL=postgresql://... (auto-set by Render)
GITHUB_TOKEN=your-token (optional)
GITHUB_REPO=username/repo-name (optional)
```

### PDF Metadata App (`app.py`)
```
SECRET_KEY=your-secret-key
LICENSE_SERVER_URL=https://your-license-server.onrender.com
DEBUG=False
```

## Testing Your Deployment

### 1. Test License Server
```bash
# Health check
curl https://your-license-server.onrender.com/health

# Admin login
# Visit: https://your-license-server.onrender.com/admin
```

### 2. Test PDF App
```bash
# Health check
curl https://your-pdf-app.onrender.com/health

# Test license validation
curl -X POST https://your-pdf-app.onrender.com/api/validate-license \
  -H "Content-Type: application/json" \
  -d '{"license_key": "PDFM-TEST-1234-5678"}'
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check `DATABASE_URL` environment variable
   - Ensure PostgreSQL database is linked to your service

2. **License Validation Failed**
   - Verify `LICENSE_SERVER_URL` is correct
   - Check license server is running
   - Ensure license key format is correct: `PDFM-XXXX-XXXX-XXXX`

3. **PDF Processing Failed**
   - Check if `pikepdf` installed correctly
   - Verify file upload limits
   - Check application logs in Render dashboard

### Logs and Monitoring

- View logs in Render dashboard
- Use health check endpoints for monitoring
- Check database connection with repair script

## Security Notes

1. **Never commit sensitive data**:
   - Use environment variables for secrets
   - Add `.env` files to `.gitignore`

2. **License key format**: `PDFM-XXXX-XXXX-XXXX`
   - Must start with `PDFM-`
   - 4 alphanumeric characters per section

3. **Database security**:
   - Use strong passwords
   - Enable SSL connections (Render does this automatically)

## Support

For issues with:
- **Deployment**: Check Render documentation
- **License system**: Check server logs and database
- **PDF processing**: Verify pikepdf installation

## Next Steps

1. Deploy license server first
2. Create test license keys via admin panel
3. Deploy PDF metadata app (optional)
4. Test end-to-end functionality
5. Set up monitoring and backups

---

**Ready to deploy!** Follow this guide step by step for a successful deployment.
