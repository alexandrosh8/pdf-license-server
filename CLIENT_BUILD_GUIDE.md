# PDF Metadata Processor - Complete System Guide

## 🎯 System Overview

**License Server:** https://pdf-license-server-dmyx.onrender.com  
**Admin Panel:** https://pdf-license-server-dmyx.onrender.com/admin

### System Components
1. **License Server** (deployed) - Manages licenses and validation
2. **Client EXE** (to be built) - Standalone PDF processor with license validation
3. **Admin Interface** - Create and manage license keys

---

## 🔐 1. Creating License Keys

### Access Admin Panel
**URL:** https://pdf-license-server-dmyx.onrender.com/admin
- **Username:** `Admin`
- **Password:** `Santamonica37!`

### License Duration Options
- **1 Day:** Perfect for testing
- **7 Days:** Weekly license  
- **30 Days:** Monthly license (most common)
- **365 Days:** Annual license
- **Custom:** Any number of days

### Steps to Create License
1. Go to admin panel and login
2. Scroll to "Create New License" section
3. Enter customer email
4. Enter customer name (optional)
5. Select duration in days
6. Click "Create License"
7. Copy the generated license key (format: `PDFM-XXXX-XXXX-XXXX`)

---

## 🖥️ 2. Building the Client EXE

### Requirements
- Windows 10/11
- Python 3.9+
- Internet connection (for initial build)

### Build Process
```bash
# 1. Install Python dependencies
pip install -r client_requirements.txt

# 2. Run build script
python build_client.py
```

### Output
- **Executable:** `dist/PDF-Metadata-Processor.exe`  
- **Size:** ~25-40 MB (includes all dependencies)
- **Self-contained:** No additional installation required

---

## 👤 3. End User Experience

### First Launch (Trial)
1. User runs `PDF-Metadata-Processor.exe`
2. Shows "✅ 1 Free Trial Available"
3. User can process 1 PDF set without license
4. After trial: "❌ Trial Used - License Required"

### Licensed Use
1. User enters license key: `PDFM-XXXX-XXXX-XXXX`
2. Clicks "Validate License" 
3. Shows "✅ Licensed version active"
4. Unlimited processing until license expires

### PDF Processing
1. Select "Original PDF" (has correct metadata/timestamps)
2. Select "Edited PDF" (needs metadata restored)
3. Click "🔄 Process PDF"
4. Output saved as `processed_[filename].pdf`

---

## ⚡ 4. Key Features

### ✅ Perfect Timestamp Preservation
- Preserves creation, modification, and access times
- Output file appears never modified
- Works on Windows with proper timestamp handling

### ✅ Comprehensive Metadata Transfer  
- Document properties (title, author, subject, etc.)
- XMP metadata
- PDF version and structure
- Creation and modification dates

### ✅ License Management
- Server-based validation
- Offline license caching (works without internet after first validation)
- Hardware-locked (prevents sharing)
- Configurable expiration

### ✅ Security
- Hardware fingerprinting
- Encrypted license validation
- Trial usage tracking
- Anti-tampering measures

---

## 🔧 5. Technical Details

### License Validation Flow
1. Client generates hardware fingerprint
2. Sends license + hardware ID to server
3. Server validates and responds
4. Client caches valid license for offline use
5. Cached license used when server unavailable

### Timestamp Preservation
- Uses Windows API (`pywin32`) for creation time
- Uses `os.utime()` for modification/access time
- PowerShell fallback for creation time
- Preserves exact microsecond precision

### File Processing
- `pikepdf` for PDF manipulation
- Extracts all metadata from original
- Applies to edited PDF
- Preserves PDF structure and version

---

## 🚀 6. Distribution

### For Customers
1. Build the EXE using `build_client.py`
2. Distribute `PDF-Metadata-Processor.exe`
3. Provide license keys from admin panel
4. Users get 1 free trial + full licensed version

### Revenue Model
- 1 free trial per computer (hardware-locked)
- License keys for full access
- Configurable duration (day/week/month/year)
- License renewal through admin panel

---

## 🛠️ 7. Server Management

### Environment Variables (Render.com)
```
ADMIN_USERNAME=Admin
ADMIN_PASSWORD=Santamonica37!
DATABASE_URL=postgresql://[your-db-url]
SECRET_KEY=J9xM2kP6zT8uW1vY4z0r7N3qL6jOqS9vZ2nR6tU8xA1dG4hK7...
GITHUB_REPO=alexandrosh8/pdf-license-server
GITHUB_TOKEN=ghp_AIDdrxkL0sjIsSy0dz2PInjATfKR92aRpV
```

### Database Tables
- `licenses` - License keys and customer info
- `validation_logs` - Usage tracking
- `admin_sessions` - Admin login tracking

---

## ⚠️ 8. Important Notes

### Security
- Never include license keys in the EXE
- Hardware fingerprinting prevents key sharing
- Server validates all requests
- Cached licenses expire with server validation

### Performance  
- EXE includes all dependencies (~25-40 MB)
- Fast startup and processing
- Offline capability after license validation
- Minimal system requirements

### Maintenance
- Server deployed on Render.com
- Automatic deployments from GitHub
- Database repair utilities included
- Admin panel for all management

---

## 📞 Support

### Admin Access
- **License Server:** https://pdf-license-server-dmyx.onrender.com/admin
- **Username:** Admin  
- **Password:** Santamonica37!

### Database Repair
If database issues occur:
- POST to `/api/repair-db` with token `emergency-repair-123`
- Or use `python repair_db.py` script

### Client Issues
- Check `pikepdf` installation
- Verify license server accessibility  
- Hardware ID displayed in client for support

---

**🎉 Complete PDF Metadata Processing System Ready!**
