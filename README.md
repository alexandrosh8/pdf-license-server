# PDF License Server - Admin Only

🔐 A Flask-based license validation server for the PDF Metadata Processor EXE application.

## Features

- **Admin-Only Interface**: No public access - admin panel only
- **License Management**: Complete CRUD operations for license keys
- **Hardware Binding**: Licenses locked to specific computers for security
- **EXE Client Validation**: Real-time license verification for standalone client
- **Local Testing**: Easy local development setup
- **GitHub Integration**: Automated client build and deployment system

## Deployment

### Deploy to Render (Free)

1. **Fork this repository** to your GitHub account
2. **Connect to Render**:
   - Go to [render.com](https://render.com)
   - Create account and connect GitHub
   - Choose "Web Service" → Connect this repository
3. **Configure Settings**:
   - Language: Python
   - Build Command: `pip install --upgrade pip && pip install -r requirements.txt`
   - Start Command: `gunicorn server:app --workers 1 --bind 0.0.0.0:$PORT --timeout 120`
   - Instance Type: Free
4. **Add Environment Variables**:
   - `ADMIN_USERNAME`: your-admin-username
   - `ADMIN_PASSWORD`: your-secure-admin-password
   - `SECRET_KEY`: (auto-generated)
   - `GITHUB_TOKEN`: (optional - for automated builds)
   - `GITHUB_REPO`: your-username/your-repo-name
5. **Deploy**: Click "Create Web Service"

Your license server will be available at: `https://your-app-name.onrender.com`

### Deploy to Other Platforms

This Flask app can be deployed to:
- **Heroku**: Use included Procfile
- **Railway**: Connect GitHub repo directly  
- **Fly.io**: Deploy with Docker
- **PythonAnywhere**: Upload files and configure WSGI

## API Endpoints

### License Validation
```
POST /api/validate
Content-Type: application/json

{
  "license_key": "PDFM-XXXX-XXXX-XXXX",
  "hardware_id": "unique-hardware-identifier"
}
```

### Web Interface
- `/` - License purchase page
- `/admin` - Administration panel
- `/purchase` - License creation form
- `/check/{license_key}` - License status check
- `/renew/{license_key}` - License renewal
- `/health` - Health check endpoint

## Database Schema

### Licenses Table
- `license_key`: Unique license identifier (PDFM-XXXX-XXXX-XXXX)
- `hardware_id`: Computer hardware fingerprint
- `customer_email`: Customer email address
- `customer_name`: Customer name (optional)
- `created_date`: License creation timestamp
- `expiry_date`: License expiration timestamp
- `active`: License status (1=active, 0=disabled)
- `payment_id`: Payment processor transaction ID

### Validation Logs Table
- `license_key`: License being validated
- `hardware_id`: Computer attempting validation
- `timestamp`: Validation attempt time
- `status`: Result (VALID, INVALID_KEY, EXPIRED)
- `ip_address`: Client IP address

## Local Development

### Option 1: Use Provided Scripts
```bash
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File run_local_server.ps1

# Windows (Command Prompt)
run_local_server.bat
```

### Option 2: Manual Setup
```bash
# Clone repository
git clone https://github.com/your-username/pdf-license-server.git
cd pdf-license-server

# Install dependencies
pip install -r requirements.txt

# Set environment variables
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD=admin123
set FLASK_ENV=development

# Run development server
python server.py
```

Visit `http://localhost:5000/admin` to access the admin panel.
- Username: admin
- Password: admin123

## Configuration

### Environment Variables
- `ADMIN_USERNAME`: Admin panel username (required)
- `ADMIN_PASSWORD`: Admin panel password (required)
- `SECRET_KEY`: Flask secret key for sessions (auto-generated)
- `GITHUB_TOKEN`: GitHub Personal Access Token (optional)
- `GITHUB_REPO`: GitHub repository for auto-builds (optional)
- `DATABASE_URL`: PostgreSQL connection (uses SQLite if not set)

### Customization
- **License Duration**: Modify `timedelta(days=30)` in license creation
- **License Format**: Update `generate_license_key()` function
- **UI/Styling**: Modify HTML templates with custom CSS

## EXE Client Distribution

This server works with the standalone PDF Metadata Processor EXE client:

1. **Build EXE**: Use `build_client.py` to create standalone executable
2. **Distribute**: Send EXE file to customers
3. **License Keys**: Generate license keys via admin panel
4. **Validation**: EXE validates with server automatically

### Client Features:
- **Trial System**: 1 free use without license
- **License Validation**: Real-time server verification
- **Offline Caching**: Works when server temporarily unavailable
- **Timestamp Preservation**: Perfect file date/time maintenance

## Security Features

- **Hardware Binding**: Prevents license sharing between computers
- **Admin Authentication**: Basic HTTP auth for admin panel
- **Encrypted Keys**: License keys use cryptographically secure generation
- **Rate Limiting**: Built-in protection against validation spam
- **Audit Logging**: All validation attempts logged with timestamps

## File Structure

```
pdf-license-server/
├── server.py              # Main admin server
├── server_extensions.py   # Build system extensions  
├── client.py              # Standalone EXE client source
├── build_client.py        # EXE build script
├── requirements.txt       # Server dependencies
├── client_requirements.txt # Client dependencies
├── render.yaml           # Render deployment config
├── gunicorn.conf.py      # Production server config
├── run_local_server.ps1  # Local testing (PowerShell)
├── run_local_server.bat  # Local testing (Batch)
└── CLIENT_BUILD_GUIDE.md # EXE build instructions
```

## Support

For issues or questions:
1. Check the admin panel logs
2. Verify environment variables are set correctly
3. Test license validation endpoints manually
4. Review client build guide for EXE distribution

---

**PDF License Server** - Admin-only license management for EXE client distribution.