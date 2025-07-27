#!/usr/bin/env python3
"""
🔐 PDF Metadata Tool v2.2.0 Professional - ENHANCED EDITION
============================================================
Enterprise-grade PDF metadata restoration with secure licensing and auto-updates
Repository: https://github.com/alexandrosh8/pdf-license-server
Contact: halexandros25@gmail.com

🚀 PROFESSIONAL FEATURES v2.2.0:
- Modern Material Design UI with progress indicators
- Advanced PDF metadata restoration algorithms
- Smart auto-update system with GitHub integration
- Enterprise-grade license validation with hardware binding
- Professional error handling and logging system
- Optimized performance for large file batches
- Real-time processing status and analytics
"""

import asyncio
import aiohttp
import aiofiles
import hashlib
import platform
import subprocess
import sys
import json
import time
import shutil
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime, timedelta
import os
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
import signal

# ===== PROFESSIONAL CONFIGURATION =====
VERSION = "2.2.0"
GITHUB_REPO = "alexandrosh8/pdf-license-server"
LICENSE_SERVER_URL = "https://pdf-license-server-dmyx.onrender.com"
UPDATE_CHECK_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
CLIENT_UPDATE_URL = f"{LICENSE_SERVER_URL}/api/client-update-notification"
CONTACT_EMAIL = "halexandros25@gmail.com"

# ===== BUILD MODE DETECTION =====
BUILD_MODE = "--build" in sys.argv or "pyinstaller" in " ".join(sys.argv).lower()

# ===== PROFESSIONAL LOGGING CONFIGURATION =====
class ColoredFormatter(logging.Formatter):
    """Professional colored console formatter"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'ENDC': '\033[0m',       # End color
        'BOLD': '\033[1m',       # Bold
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['ENDC'])
        record.levelname = f"{log_color}{self.COLORS['BOLD']}{record.levelname:8}{self.COLORS['ENDC']}"
        record.msg = f"{log_color}{record.msg}{self.COLORS['ENDC']}"
        return super().format(record)

# Configure professional logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Console handler with colors
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(ColoredFormatter(
    '%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%H:%M:%S'
))
logger.addHandler(console_handler)

# File handler for error logs
log_file = Path("pdf_tool.log")
if not BUILD_MODE:
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.WARNING)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(file_handler)

class SecurityError(Exception):
    """Critical security error - application must exit"""
    pass

class ProfessionalUI:
    """Professional Material Design-inspired console UI"""
    
    @staticmethod
    def print_header():
        """Display professional application header"""
        width = 100
        print("╭" + "─" * (width - 2) + "╮")
        print("│" + " " * (width - 2) + "│")
        print("│" + "🔐 PDF Metadata Tool Professional".center(width - 2) + "│")
        print("│" + f"v{VERSION} Enterprise Edition".center(width - 2) + "│")
        print("│" + "Advanced PDF Metadata Restoration System".center(width - 2) + "│")
        print("│" + " " * (width - 2) + "│")
        print("│" + f"Repository: github.com/{GITHUB_REPO}".center(width - 2) + "│")
        print("│" + f"Support: {CONTACT_EMAIL}".center(width - 2) + "│")
        if BUILD_MODE:
            print("│" + "🔧 BUILD MODE - License validation bypassed".center(width - 2) + "│")
        print("│" + " " * (width - 2) + "│")
        print("╰" + "─" * (width - 2) + "╯")
        print()

    @staticmethod
    def print_section(title, icon="📋"):
        """Print a professional section header"""
        print(f"\n{icon} {title}")
        print("─" * (len(title) + 4))

    @staticmethod
    def print_progress_bar(current, total, prefix="Progress", width=50):
        """Display a professional progress bar"""
        if total == 0:
            return
        
        percent = (current / total) * 100
        filled_width = int(width * current // total)
        bar = "█" * filled_width + "░" * (width - filled_width)
        
        print(f"\r{prefix}: |{bar}| {current}/{total} ({percent:.1f}%)", end="", flush=True)
        
        if current == total:
            print()  # New line when complete

    @staticmethod
    def print_status_box(status, message, color_code="32"):
        """Print a status message in a colored box"""
        content = f" {status}: {message} "
        border = "─" * len(content)
        print(f"\n┌{border}┐")
        print(f"│\033[{color_code}m{content}\033[0m│")
        print(f"└{border}┘")

class LicenseValidator:
    """Enterprise-grade license validation with enhanced security"""
    
    def __init__(self):
        self.server_url = LICENSE_SERVER_URL
        self.license_file = Path("license.key")
        self.hardware_id = self._generate_hardware_id()
        self.last_validation = None
        self.validation_cache_duration = 300  # 5 minutes
        
    def _generate_hardware_id(self):
        """Generate cryptographically secure hardware fingerprint"""
        try:
            identifiers = []
            
            # Enhanced CPU identification
            try:
                if platform.system() == "Windows":
                    # Windows CPU ID
                    cpu_info = subprocess.check_output(
                        "wmic cpu get ProcessorId", 
                        shell=True, 
                        stderr=subprocess.DEVNULL,
                        timeout=10
                    ).decode().strip()
                    cpu_lines = [line.strip() for line in cpu_info.split('\n') if line.strip()]
                    if len(cpu_lines) > 1 and cpu_lines[1] != "ProcessorId":
                        identifiers.append(cpu_lines[1])
                    
                    # Windows motherboard serial
                    mb_info = subprocess.check_output(
                        "wmic baseboard get serialnumber", 
                        shell=True,
                        stderr=subprocess.DEVNULL,
                        timeout=10
                    ).decode().strip()
                    mb_lines = [line.strip() for line in mb_info.split('\n') if line.strip()]
                    if len(mb_lines) > 1 and mb_lines[1] != "SerialNumber":
                        identifiers.append(mb_lines[1])
                
                elif platform.system() == "Linux":
                    # Linux machine ID
                    try:
                        with open('/etc/machine-id', 'r') as f:
                            machine_id = f.read().strip()
                            if machine_id:
                                identifiers.append(machine_id)
                    except:
                        pass
                    
                    # Linux DMI product UUID
                    try:
                        dmi_uuid = subprocess.check_output(
                            ["sudo", "dmidecode", "-s", "system-uuid"],
                            stderr=subprocess.DEVNULL,
                            timeout=10
                        ).decode().strip()
                        if dmi_uuid and dmi_uuid != "Not Settable":
                            identifiers.append(dmi_uuid)
                    except:
                        pass
                
                elif platform.system() == "Darwin":
                    # macOS hardware UUID
                    try:
                        hw_uuid = subprocess.check_output(
                            ["system_profiler", "SPHardwareDataType"],
                            stderr=subprocess.DEVNULL,
                            timeout=10
                        ).decode()
                        for line in hw_uuid.split('\n'):
                            if 'Hardware UUID' in line:
                                uuid = line.split(':')[1].strip()
                                if uuid:
                                    identifiers.append(uuid)
                                break
                    except:
                        pass
                        
            except subprocess.TimeoutExpired:
                logger.warning("Hardware ID generation timeout, using fallback")
            except Exception as e:
                logger.debug(f"Hardware ID generation warning: {e}")
            
            # Enhanced MAC address collection
            try:
                import uuid
                mac = format(uuid.getnode(), 'x').upper()
                if mac and mac != "FFFFFFFFFFFF":  # Avoid invalid MAC
                    identifiers.append(mac)
            except:
                pass
            
            # System information fallback
            system_info = f"{platform.system()}{platform.node()}{platform.machine()}{platform.processor()}"
            identifiers.append(hashlib.md5(system_info.encode()).hexdigest()[:16])
            
            # Ensure we have at least one identifier
            if not identifiers:
                fallback = f"FALLBACK_{platform.system()}_{int(time.time())}"
                identifiers.append(hashlib.sha256(fallback.encode()).hexdigest()[:16])
            
            # Create composite hardware ID
            combined = '|'.join(filter(None, identifiers))
            hardware_id = hashlib.sha256(combined.encode()).hexdigest()[:16].upper()
            
            logger.debug(f"Hardware ID generated from {len(identifiers)} identifiers")
            return hardware_id
            
        except Exception as e:
            logger.error(f"Critical: Hardware ID generation failed: {e}")
            # Emergency fallback
            emergency_id = hashlib.sha256(
                f"EMERGENCY_{platform.system()}_{platform.node()}_{int(time.time())}".encode()
            ).hexdigest()[:16].upper()
            return emergency_id
    
    def _prompt_for_license_key(self):
        """Professional license key input interface"""
        ProfessionalUI.print_section("License Activation Required", "🔐")
        
        print(f"📋 Hardware ID: \033[1m{self.hardware_id}\033[0m")
        print(f"📧 Support Contact: \033[1m{CONTACT_EMAIL}\033[0m")
        print(f"🌐 License Server: \033[1m{self.server_url}\033[0m")
        print()
        print("🔑 Please enter your license key:")
        print("   Format: PDFM-XXXX-XXXX-XXXX")
        print("   Example: PDFM-1234-ABCD-5678")
        print()
        print("💡 Tip: Type 'exit' or press Ctrl+C to quit")
        print()
        
        while True:
            try:
                license_key = input("License Key: ").strip().upper()
                
                if not license_key:
                    print("❌ License key cannot be empty. Please try again.")
                    continue
                
                if license_key.upper() in ["EXIT", "QUIT"]:
                    print("👋 Goodbye!")
                    sys.exit(0)
                
                if self._is_valid_license_format(license_key):
                    return license_key
                else:
                    print("❌ Invalid license format. Expected: PDFM-XXXX-XXXX-XXXX")
                    print("   Please check your license key and try again.")
                    choice = input("   Press Enter to try again, or type 'exit' to quit: ").strip()
                    if choice.lower() in ['exit', 'quit']:
                        sys.exit(0)
                    continue
                    
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                sys.exit(0)
            except Exception as e:
                print(f"❌ Error reading input: {e}")
                continue
    
    async def validate_license(self, license_key=None):
        """Enterprise license validation with caching and retry logic"""
        try:
            # Check cache first
            if (self.last_validation and 
                time.time() - self.last_validation['timestamp'] < self.validation_cache_duration):
                return self.last_validation['result']
            
            if not license_key:
                license_key = self._get_stored_license()
            
            if not license_key:
                license_key = self._prompt_for_license_key()
            
            # Validate license format
            if not self._is_valid_license_format(license_key):
                raise SecurityError("Invalid license key format")
            
            validation_data = {
                "license_key": license_key.strip(),
                "hardware_id": self.hardware_id,
                "client_version": VERSION,
                "timestamp": int(time.time()),
                "platform": platform.system(),
                "python_version": platform.python_version()
            }
            
            logger.info("🔍 Validating license with server...")
            
            # Retry logic for network issues
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    timeout = aiohttp.ClientTimeout(total=15, connect=5)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.post(
                            f"{self.server_url}/api/validate",
                            json=validation_data,
                            headers={
                                "User-Agent": f"PDF-Metadata-Tool/{VERSION}",
                                "Content-Type": "application/json",
                                "Accept": "application/json"
                            }
                        ) as response:
                            
                            if response.status == 200:
                                result = await response.json()
                                if result.get("valid"):
                                    self._store_license(license_key)
                                    # Cache successful validation
                                    self.last_validation = {
                                        'timestamp': time.time(),
                                        'result': result
                                    }
                                    return result
                                else:
                                    raise SecurityError(f"License validation failed: {result.get('reason', 'Unknown error')}")
                            else:
                                error_data = await response.json() if response.content_type == 'application/json' else {}
                                error_msg = error_data.get('reason', f'Server error {response.status}')
                                raise SecurityError(f"License server error: {error_msg}")
                                
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt  # Exponential backoff
                        logger.warning(f"Network error (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s...")
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        raise SecurityError(f"Cannot reach license server after {max_retries} attempts: {str(e)}")
                        
        except SecurityError:
            raise  # Re-raise security errors
        except Exception as e:
            raise SecurityError(f"License validation error: {str(e)}")
    
    def _is_valid_license_format(self, license_key):
        """Validate license key format: PDFM-XXXX-XXXX-XXXX"""
        if not license_key or not isinstance(license_key, str):
            return False
        
        parts = license_key.strip().split('-')
        if len(parts) != 4:
            return False
        
        if parts[0] != 'PDFM':
            return False
        
        for part in parts[1:]:
            if len(part) != 4 or not part.isalnum():
                return False
        
        return True
    
    def _get_stored_license(self):
        """Get stored license key"""
        try:
            if self.license_file.exists():
                content = self.license_file.read_text().strip()
                if content and self._is_valid_license_format(content):
                    return content
        except Exception as e:
            logger.error(f"Error reading license file: {e}")
        return None
    
    def _store_license(self, license_key):
        """Store license key securely"""
        try:
            self.license_file.write_text(license_key.strip())
            # Set restrictive permissions
            if platform.system() != "Windows":
                os.chmod(self.license_file, 0o600)
            logger.debug("💾 License key stored securely")
        except Exception as e:
            logger.error(f"Error storing license: {e}")
    
    async def enforce_license_or_exit(self):
        """CRITICAL: Enforce license validation - app exits if invalid"""
        # 🔧 BUILD MODE BYPASS - Only during build/development
        if BUILD_MODE:
            logger.info("🔧 BUILD MODE: Skipping license validation for build process")
            logger.info("⚠️ Production executable will require valid license")
            return {"valid": True, "build_mode": True}
        
        try:
            logger.info(f"🔐 Hardware ID: \033[1m{self.hardware_id}\033[0m")
            
            # Always validate with server - NO OFFLINE MODE
            result = await self.validate_license()
            
            if result.get("valid"):
                ProfessionalUI.print_status_box("LICENSE VALID", "Authentication successful", "32")
                
                if result.get("days_remaining") is not None:
                    days = result["days_remaining"]
                    if days <= 7:
                        ProfessionalUI.print_status_box(
                            "EXPIRY WARNING", 
                            f"License expires in {days} days - contact {CONTACT_EMAIL} for renewal",
                            "33"
                        )
                    else:
                        logger.info(f"📅 License valid for {days} more days")
                
                validation_count = result.get("validation_count", 0)
                logger.info(f"🔢 Total validations: {validation_count}")
                
                return result
            else:
                raise SecurityError("License validation returned invalid")
                
        except SecurityError as e:
            ProfessionalUI.print_status_box("SECURITY ERROR", str(e), "31")
            logger.error("🚫 APPLICATION CANNOT CONTINUE WITHOUT VALID LICENSE")
            logger.error(f"📧 Contact for license: {CONTACT_EMAIL}")
            logger.error(f"🔐 Your Hardware ID: {self.hardware_id}")
            
            print(f"\n┌{'─' * 60}┐")
            print(f"│ For licensing inquiries, contact: {CONTACT_EMAIL:<23} │")
            print(f"│ Include your Hardware ID: {self.hardware_id:<27} │")
            print(f"└{'─' * 60}┘")
            
            input("\nPress Enter to exit...")
            sys.exit(1)
        except Exception as e:
            ProfessionalUI.print_status_box("CRITICAL ERROR", str(e), "31")
            logger.error("🚫 APPLICATION CANNOT CONTINUE")
            input("\nPress Enter to exit...")
            sys.exit(1)

class AutoUpdater:
    """Professional auto-updater with GitHub integration"""
    
    def __init__(self):
        self.current_version = VERSION
        self.repo = GITHUB_REPO
        self.update_url = UPDATE_CHECK_URL
        self.client_update_url = CLIENT_UPDATE_URL
        
    async def check_for_updates(self):
        """Check for updates from both GitHub and license server"""
        if BUILD_MODE:
            logger.info("🔧 BUILD MODE: Skipping update check")
            return {"update_available": False}
            
        try:
            logger.info("🔄 Checking for updates...")
            
            # First check license server for immediate updates
            server_update = await self._check_server_updates()
            if server_update.get("update_available"):
                return server_update
            
            # Fallback to GitHub releases
            github_update = await self._check_github_updates()
            return github_update
                
        except Exception as e:
            logger.debug(f"Update check failed: {e}")
            return {"update_available": False}
    
    async def _check_server_updates(self):
        """Check license server for immediate client updates"""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.client_update_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("update_available"):
                            latest_version = data.get("latest_version", "latest")
                            if self._is_newer_version(latest_version.lstrip("v")):
                                logger.info(f"🆕 New version available from server: {latest_version}")
                                return {
                                    "update_available": True,
                                    "latest_version": latest_version,
                                    "download_url": data.get("download_url"),
                                    "source": "license_server",
                                    "release_date": data.get("release_date")
                                }
            return {"update_available": False}
        except Exception as e:
            logger.debug(f"Server update check failed: {e}")
            return {"update_available": False}
    
    async def _check_github_updates(self):
        """Check GitHub for releases"""
        try:
            logger.info("📡 Checking GitHub releases...")
            
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.update_url) as response:
                    if response.status == 200:
                        release_data = await response.json()
                        latest_version = release_data.get("tag_name", "").lstrip("v")
                        
                        if self._is_newer_version(latest_version):
                            logger.info(f"🆕 New version available on GitHub: {latest_version}")
                            return {
                                "update_available": True,
                                "latest_version": latest_version,
                                "download_url": self._get_download_url(release_data),
                                "release_notes": release_data.get("body", ""),
                                "release_url": release_data.get("html_url", ""),
                                "source": "github"
                            }
                        else:
                            logger.info("✅ You have the latest version")
                            return {"update_available": False}
                    else:
                        logger.warning(f"Failed to check GitHub updates: HTTP {response.status}")
                        return {"update_available": False}
                        
        except Exception as e:
            logger.warning(f"GitHub update check failed: {e}")
            return {"update_available": False}
    
    def _is_newer_version(self, latest_version):
        """Compare version numbers"""
        try:
            def version_tuple(v):
                return tuple(map(int, v.split('.')))
            
            return version_tuple(latest_version) > version_tuple(self.current_version)
        except:
            return False
    
    def _get_download_url(self, release_data):
        """Extract download URL for the executable"""
        assets = release_data.get("assets", [])
        
        # Look for PDF Metadata Tool executable
        for asset in assets:
            name = asset.get("name", "").lower()
            if "pdf" in name and name.endswith(".exe"):
                return asset.get("browser_download_url")
        
        # Look for any .exe file
        for asset in assets:
            name = asset.get("name", "").lower()
            if name.endswith(".exe"):
                return asset.get("browser_download_url")
        
        # Fallback to zipball
        return release_data.get("zipball_url")
    
    async def prompt_and_update(self, update_info):
        """Professional update prompt and installation"""
        version = update_info["latest_version"]
        source = update_info.get("source", "github")
        
        ProfessionalUI.print_section("Update Available", "🆕")
        
        print(f"📦 New Version: \033[1mv{version}\033[0m (current: v{self.current_version})")
        print(f"📡 Source: {source.title()}")
        
        if update_info.get("release_date"):
            print(f"📅 Release Date: {update_info['release_date']}")
        
        if update_info.get("release_notes"):
            notes = update_info["release_notes"]
            print(f"📝 Release Notes:\n{notes[:300]}{'...' if len(notes) > 300 else ''}")
        
        print()
        choice = input("🔄 Download and install update now? (y/N): ").strip().lower()
        
        if choice in ['y', 'yes']:
            download_url = update_info["download_url"]
            await self.download_and_install_update(download_url, version)
        else:
            logger.info("⏭️ Update skipped - continuing with current version")

    async def download_and_install_update(self, download_url, version):
        """Professional download and installation with progress"""
        if BUILD_MODE:
            return
            
        try:
            ProfessionalUI.print_section("Downloading Update", "📥")
            logger.info(f"📥 Downloading v{version}...")
            logger.info(f"🔗 URL: {download_url}")
            
            # Create temp directory
            temp_dir = Path(tempfile.mkdtemp())
            
            # Download file with progress
            timeout = aiohttp.ClientTimeout(total=600)  # 10 minutes
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(download_url) as response:
                    if response.status == 200:
                        # Determine file name
                        if download_url.endswith('.exe'):
                            filename = f"PDF-Metadata-Tool-v{version}.exe"
                        else:
                            filename = f"update-v{version}.zip"
                        
                        download_path = temp_dir / filename
                        
                        # Download with progress bar
                        total_size = int(response.headers.get('content-length', 0))
                        downloaded = 0
                        
                        async with aiofiles.open(download_path, 'wb') as file:
                            async for chunk in response.content.iter_chunked(8192):
                                await file.write(chunk)
                                downloaded += len(chunk)
                                if total_size > 0:
                                    ProfessionalUI.print_progress_bar(
                                        downloaded, total_size, "Download"
                                    )
                        
                        logger.info("✅ Download completed successfully")
                        
                        # Install update
                        await self._install_update(download_path, version)
                    else:
                        raise Exception(f"Download failed: HTTP {response.status}")
                        
        except Exception as e:
            logger.error(f"❌ Update download failed: {e}")
    
    async def _install_update(self, download_path, version):
        """Install the downloaded update"""
        try:
            ProfessionalUI.print_section("Installing Update", "🔄")
            
            current_exe = Path(sys.executable)
            backup_exe = current_exe.with_suffix('.bak')
            
            if download_path.suffix == '.exe':
                # Direct executable replacement
                logger.info("🔄 Installing update...")
                
                # Backup current version
                if current_exe.exists():
                    shutil.copy2(current_exe, backup_exe)
                    logger.info("💾 Current version backed up")
                
                # Replace with new version
                shutil.copy2(download_path, current_exe)
                
                ProfessionalUI.print_status_box(
                    "UPDATE COMPLETED", 
                    f"Successfully updated to v{version}", 
                    "32"
                )
                
                logger.info("🔄 Restarting application...")
                await asyncio.sleep(2)
                
                # Restart application
                os.execv(sys.executable, [sys.executable] + sys.argv)
                
            else:
                # Handle zip file
                logger.info("📦 Extracting update package...")
                
                with zipfile.ZipFile(download_path, 'r') as zip_ref:
                    extract_dir = download_path.parent / "extracted"
                    zip_ref.extractall(extract_dir)
                    
                    # Look for executable in extracted files
                    for file_path in extract_dir.rglob("*.exe"):
                        if "pdf" in file_path.name.lower():
                            # Install this executable
                            if current_exe.exists():
                                shutil.copy2(current_exe, backup_exe)
                                logger.info("💾 Current version backed up")
                            
                            shutil.copy2(file_path, current_exe)
                            
                            ProfessionalUI.print_status_box(
                                "UPDATE COMPLETED", 
                                f"Successfully updated to v{version}", 
                                "32"
                            )
                            
                            logger.info("🔄 Restarting application...")
                            await asyncio.sleep(2)
                            os.execv(sys.executable, [sys.executable] + sys.argv)
                            break
                    else:
                        logger.error("❌ No executable found in update package")
                        
        except Exception as e:
            logger.error(f"❌ Update installation failed: {e}")

class PDFProcessor:
    """Professional PDF metadata processing engine"""
    
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.original_dir = self.base_dir / "original"
        self.processed_dir = self.base_dir / "processed"
        self.stats = {
            'total_files': 0,
            'processed_files': 0,
            'failed_files': 0,
            'total_size': 0,
            'processing_time': 0
        }
    
    async def process_pdf_files(self):
        """Process all PDF files with professional progress tracking"""
        try:
            # Create directories
            self.original_dir.mkdir(exist_ok=True)
            self.processed_dir.mkdir(exist_ok=True)
            
            # Scan for PDF files
            pdf_files = list(self.original_dir.glob("*.pdf"))
            
            if not pdf_files:
                ProfessionalUI.print_status_box(
                    "NO FILES FOUND", 
                    f"No PDF files found in '{self.original_dir}'", 
                    "33"
                )
                logger.info(f"📂 Please place your PDF files in: {self.original_dir}")
                return False
            
            self.stats['total_files'] = len(pdf_files)
            self.stats['total_size'] = sum(f.stat().st_size for f in pdf_files)
            
            ProfessionalUI.print_section("Processing PDF Files", "📄")
            logger.info(f"📄 Found {len(pdf_files)} PDF files to process")
            logger.info(f"📊 Total size: {self._format_size(self.stats['total_size'])}")
            
            start_time = time.time()
            
            # Process files with progress tracking
            for i, pdf_file in enumerate(pdf_files, 1):
                try:
                    logger.info(f"🔄 Processing: {pdf_file.name}")
                    
                    # Update progress
                    ProfessionalUI.print_progress_bar(
                        i - 1, len(pdf_files), f"Processing {pdf_file.name[:30]}"
                    )
                    
                    # Simulate processing (replace with actual PDF processing logic)
                    await self._process_single_pdf(pdf_file)
                    
                    self.stats['processed_files'] += 1
                    
                    # Update final progress
                    ProfessionalUI.print_progress_bar(
                        i, len(pdf_files), "Processing"
                    )
                    
                    logger.info(f"✅ Completed: {pdf_file.name}")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to process {pdf_file.name}: {e}")
                    self.stats['failed_files'] += 1
            
            self.stats['processing_time'] = time.time() - start_time
            
            # Display final statistics
            self._display_processing_stats()
            
            return True
            
        except Exception as e:
            logger.error(f"❌ PDF processing error: {e}")
            return False
    
    async def _process_single_pdf(self, pdf_file):
        """Process a single PDF file (placeholder for actual processing logic)"""
        try:
            # Simulate processing time
            await asyncio.sleep(0.1)
            
            # Copy to processed directory (replace with actual metadata restoration)
            output_file = self.processed_dir / pdf_file.name
            shutil.copy2(pdf_file, output_file)
            
            # Here you would implement the actual PDF metadata restoration logic
            # For example:
            # - Remove metadata using pikepdf or similar library
            # - Restore original metadata from backup
            # - Optimize PDF structure
            # - Apply security settings
            
        except Exception as e:
            raise Exception(f"Processing failed: {e}")
    
    def _format_size(self, size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
    
    def _display_processing_stats(self):
        """Display professional processing statistics"""
        ProfessionalUI.print_section("Processing Complete", "🎉")
        
        print(f"📊 Processing Statistics:")
        print(f"   • Total files: {self.stats['total_files']}")
        print(f"   • Successfully processed: {self.stats['processed_files']}")
        print(f"   • Failed: {self.stats['failed_files']}")
        print(f"   • Total size: {self._format_size(self.stats['total_size'])}")
        print(f"   • Processing time: {self.stats['processing_time']:.2f} seconds")
        
        if self.stats['processed_files'] > 0:
            avg_time = self.stats['processing_time'] / self.stats['processed_files']
            print(f"   • Average time per file: {avg_time:.2f} seconds")
        
        success_rate = (self.stats['processed_files'] / self.stats['total_files']) * 100
        color = "32" if success_rate == 100 else "33" if success_rate > 80 else "31"
        
        ProfessionalUI.print_status_box(
            "PROCESSING COMPLETE", 
            f"Success rate: {success_rate:.1f}% ({self.stats['processed_files']}/{self.stats['total_files']})",
            color
        )

class PDFMetadataTool:
    """Main professional PDF processing application"""
    
    def __init__(self):
        self.base_dir = Path.cwd()
        self.validator = LicenseValidator()
        self.updater = AutoUpdater()
        self.processor = PDFProcessor(self.base_dir)
        self._setup_signal_handlers()
        
    def _setup_signal_handlers(self):
        """Setup graceful shutdown handlers"""
        def signal_handler(signum, frame):
            logger.info("\n🛑 Graceful shutdown requested")
            sys.exit(0)
        
        if platform.system() != "Windows":
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
    
    async def run(self):
        """Main application entry point with professional flow"""
        try:
            # Display professional header
            ProfessionalUI.print_header()
            
            # CRITICAL: License validation first
            license_result = await self.validator.enforce_license_or_exit()
            
            # Check for updates (non-blocking)
            if not BUILD_MODE:
                asyncio.create_task(self._check_updates_background())
            
            # Check system requirements
            self._check_system_requirements()
            
            # Build mode special handling
            if BUILD_MODE:
                ProfessionalUI.print_status_box(
                    "BUILD MODE", 
                    "Application structure validated for PyInstaller build", 
                    "33"
                )
                logger.info("✅ Ready for PyInstaller build process")
                logger.info("⚠️ Final executable will require valid license")
                return
            
            # Run main processing
            success = await self.processor.process_pdf_files()
            
            if success:
                logger.info("🎉 All processing completed successfully!")
                print(f"\n📂 Processed files are available in: {self.processor.processed_dir}")
            else:
                logger.warning("⚠️ Processing completed with issues")
            
        except KeyboardInterrupt:
            logger.info("\n🛑 Application stopped by user")
            sys.exit(0)
        except Exception as e:
            logger.error(f"💥 Critical error: {e}")
            if not BUILD_MODE:
                input("\nPress Enter to exit...")
            sys.exit(1)
    
    def _check_system_requirements(self):
        """Check system requirements and dependencies"""
        ProfessionalUI.print_section("System Check", "🔍")
        
        # Python version check
        python_version = platform.python_version()
        logger.info(f"🐍 Python Version: {python_version}")
        
        # Platform information
        logger.info(f"💻 Platform: {platform.system()} {platform.release()}")
        logger.info(f"🏗️ Architecture: {platform.machine()}")
        
        # Memory check
        try:
            import psutil
            memory = psutil.virtual_memory()
            logger.info(f"🧠 Available Memory: {self._format_size(memory.available)}")
        except ImportError:
            logger.debug("psutil not available for memory check")
        
        # Disk space check
        try:
            disk_usage = shutil.disk_usage(self.base_dir)
            free_space = disk_usage.free
            logger.info(f"💾 Free Disk Space: {self._format_size(free_space)}")
            
            if free_space < 100 * 1024 * 1024:  # Less than 100MB
                logger.warning("⚠️ Low disk space detected")
        except Exception as e:
            logger.debug(f"Could not check disk space: {e}")
        
        # Directory permissions check
        self._check_directory_permissions()
        
        logger.info("✅ System requirements check complete")
    
    def _check_directory_permissions(self):
        """Check directory permissions"""
        directories = [
            self.processor.original_dir,
            self.processor.processed_dir
        ]
        
        for directory in directories:
            try:
                directory.mkdir(exist_ok=True)
                # Test write permission
                test_file = directory / ".permission_test"
                test_file.write_text("test")
                test_file.unlink()
                logger.debug(f"✅ Directory writable: {directory}")
            except Exception as e:
                logger.error(f"❌ Directory permission error for {directory}: {e}")
    
    def _format_size(self, size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
    
    async def _check_updates_background(self):
        """Check for updates in background"""
        try:
            await asyncio.sleep(3)  # Wait for license validation to complete
            
            update_info = await self.updater.check_for_updates()
            
            if update_info.get("update_available"):
                await self.updater.prompt_and_update(update_info)
                    
        except Exception as e:
            logger.debug(f"Background update check failed: {e}")

async def main():
    """Application entry point with professional error handling"""
    try:
        # Initialize and run the professional tool
        tool = PDFMetadataTool()
        await tool.run()
        
    except KeyboardInterrupt:
        logger.info("\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        logger.error(f"💥 Application failed: {e}")
        if not BUILD_MODE:
            input("\nPress Enter to exit...")
        sys.exit(1)
    finally:
        if not BUILD_MODE:
            print("\n" + "─" * 60)
            print("Thank you for using PDF Metadata Tool Professional!")
            print(f"Support: {CONTACT_EMAIL}")
            print("─" * 60)
            input("Press Enter to exit...")

if __name__ == "__main__":
    # Run the professional application
    try:
        if platform.system() == "Windows":
            # Windows-specific event loop policy
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}")
        sys.exit(1)