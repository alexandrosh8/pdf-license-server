#!/usr/bin/env python3
"""
🔐 PDF Metadata Tool v2.4.0 Professional - CLEAN EDITION
============================================================
Enterprise-grade PDF metadata restoration with secure licensing and auto-updates
Contact: halexandros25@gmail.com

🚀 PROFESSIONAL FEATURES v2.4.0:
- CLEANED: Removed progress bars and visual clutter for professional appearance
- CLEANED: Removed anonymize option - focused on core metadata restoration
- IMPROVED: Clean, professional output with clear success/failure indicators
- FIXED: Custom settings now fully functional with interactive configuration
- FIXED: Integrated 3-folder workflow (original → edited → final)
- FIXED: Actual PDF metadata restoration with pikepdf
- Modern Material Design UI with clean status indicators
- Advanced PDF metadata restoration algorithms
- Smart auto-update system with GitHub integration
- Enterprise-grade license validation with hardware binding
- Professional error handling and logging system
- Optimized performance for large file batches
- Real-time processing status and analytics
- PyInstaller build compatibility optimizations
- Enhanced server integration with notification system
- File selection options (original vs edited)
- Professional continuation workflow

🔧 PYINSTALLER HIDDEN IMPORTS:
This file requires the following hidden imports for PyInstaller:
--hidden-import=aiohttp
--hidden-import=aiofiles
--hidden-import=asyncio
--hidden-import=json
--hidden-import=hashlib
--hidden-import=platform
--hidden-import=subprocess
--hidden-import=pathlib
--hidden-import=tempfile
--hidden-import=zipfile
--hidden-import=shutil
--hidden-import=logging
--hidden-import=threading
--hidden-import=requests
--hidden-import=psutil
--hidden-import=cryptography
--hidden-import=pkg_resources.extern
--hidden-import=win32api
--hidden-import=win32con
--hidden-import=win32gui
--hidden-import=pywintypes
--hidden-import=pikepdf
"""

# ===== CRITICAL IMPORTS - MUST BE FIRST =====
import sys
import os
import asyncio
import platform
import logging
import time
import json
import hashlib
import stat

# Ensure proper asyncio policy on Windows for PyInstaller
if platform.system() == "Windows":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:
        pass  # Fallback gracefully

# ===== FIXED BUILD MODE DETECTION - CRITICAL FOR PRODUCTION =====
def is_build_mode():
    """
    FIXED: Detect if we're in actual build mode vs production executable
    Returns True only during PyInstaller build process, not for end users
    """
    
    # Check if we're running as a PyInstaller executable
    if hasattr(sys, '_MEIPASS'):
        # We're running as a PyInstaller executable
        
        # Check for build environment indicators
        build_indicators = [
            'GITHUB_ACTIONS' in os.environ,  # GitHub Actions build
            'CI' in os.environ,              # Continuous Integration
            'BUILD_MODE' in os.environ,      # Explicit build mode flag
            '--build-mode' in sys.argv,      # Command line flag
            os.path.exists(os.path.join(sys._MEIPASS, 'BUILD_FLAG')),  # Build flag file
        ]
        
        # Only enter build mode if we detect actual build environment
        return any(build_indicators)
    
    # Not a PyInstaller executable - check for development mode
    return (
        'GITHUB_ACTIONS' in os.environ or
        'CI' in os.environ or
        'BUILD_MODE' in os.environ or
        '--build-mode' in sys.argv or
        "--build" in sys.argv or 
        "pyinstaller" in " ".join(sys.argv).lower()
    )

# Set BUILD_MODE using the fixed detection
BUILD_MODE = is_build_mode()

# ===== NETWORK AND FILE IMPORTS =====
try:
    import aiohttp
    import aiofiles
    import requests
except ImportError as e:
    if not BUILD_MODE:
        print(f"Critical import error: {e}")
        print("Please install required packages: pip install aiohttp aiofiles requests")
        sys.exit(1)

# ===== SYSTEM IMPORTS =====
try:
    import subprocess
    import shutil
    import tempfile
    import zipfile
    from pathlib import Path
    from datetime import datetime, timedelta, timezone
    import threading
    from concurrent.futures import ThreadPoolExecutor
    import signal
except ImportError as e:
    print(f"System import error: {e}")
    sys.exit(1)

# ===== OPTIONAL IMPORTS WITH GRACEFUL FALLBACK =====
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    if not BUILD_MODE:
        print("psutil not available - some system info features disabled")

try:
    import cryptography
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    if not BUILD_MODE:
        print("cryptography not available - some security features disabled")

# ===== WINDOWS-SPECIFIC IMPORTS =====
if platform.system() == "Windows":
    try:
        import win32api
        import win32con
        import win32gui
        import pywintypes
        import win32file
        WIN32_AVAILABLE = True
        WIN32_TIMESTAMP_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False
        WIN32_TIMESTAMP_AVAILABLE = False
        if not BUILD_MODE:
            print("Windows API modules not available - some Windows features disabled")
else:
    WIN32_AVAILABLE = False
    WIN32_TIMESTAMP_AVAILABLE = False

# ===== PROFESSIONAL CONFIGURATION - UPDATED TO v2.4.0 =====
VERSION = "v2.4.0"
__version__ = "2.4.0"  # For compatibility with GitHub workflow
BUILD_DATE = "2024-01-01"  # Auto-updated by GitHub workflow
BUILD_TYPE = "release"     # Auto-updated by GitHub workflow

APP_NAME = "PDF Metadata Tool"
APP_TITLE = f"{APP_NAME} {VERSION} Professional"

# ===== SERVER CONFIGURATION - UPDATED FOR ENHANCED INTEGRATION =====
GITHUB_REPO = "alexandrosh8/pdf-license-server"
LICENSE_SERVER_URL = "https://pdf-license-server-dmyx.onrender.com"
UPDATE_CHECK_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
CLIENT_UPDATE_URL = f"{LICENSE_SERVER_URL}/api/client-update-check"  # Updated endpoint
CONTACT_EMAIL = "halexandros25@gmail.com"

# ===== PDF PROCESSING IMPORTS =====
try:
    import pikepdf
    import secrets
    import string
    import re
    from xml.etree import ElementTree as ET
    PIKEPDF_AVAILABLE = True
except ImportError as e:
    PIKEPDF_AVAILABLE = False
    if not BUILD_MODE:
        print(f"PDF processing not available: {e}")
        print("Please install: pip install pikepdf")

# ===== ENHANCED LOGGING CONFIGURATION WITH UNICODE FIX =====
class ColoredFormatter(logging.Formatter):
    """Professional colored console formatter with PyInstaller and Unicode compatibility"""
    
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
        try:
            log_color = self.COLORS.get(record.levelname, self.COLORS['ENDC'])
            record.levelname = f"{log_color}{self.COLORS['BOLD']}{record.levelname:8}{self.COLORS['ENDC']}"
            
            # Sanitize message for Windows compatibility
            message = str(record.msg)
            safe_message = safe_log_message(message)
            record.msg = f"{log_color}{safe_message}{self.COLORS['ENDC']}"
            
            return super().format(record)
        except Exception:
            # Fallback for any formatting issues
            return super().format(record)

class UnicodeFileHandler(logging.FileHandler):
    """File handler that properly handles Unicode characters"""
    
    def __init__(self, filename, mode='a', encoding='utf-8', delay=False):
        super().__init__(filename, mode, encoding, delay)
    
    def emit(self, record):
        try:
            # Sanitize record message before writing to file
            if hasattr(record, 'msg'):
                record.msg = safe_log_message(str(record.msg))
            super().emit(record)
        except Exception:
            self.handleError(record)

def safe_log_message(message):
    """Remove or replace Unicode characters that cause Windows encoding issues"""
    # Replace problematic emojis with text equivalents for logging
    emoji_replacements = {
        '🚫': '[BLOCKED]',
        '📧': '[EMAIL]',
        '🔐': '[SECURITY]',
        '🔍': '[SEARCH]',
        '✅': '[OK]',
        '❌': '[ERROR]',
        '⚠️': '[WARNING]',
        '🔑': '[KEY]',
        '📋': '[INFO]',
        '🔧': '[BUILD]',
        '🚀': '[START]',
        '🎉': '[SUCCESS]',
        '💥': '[CRASH]',
        '🔄': '[PROCESS]',
        '📦': '[PACKAGE]',
        '📊': '[STATS]',
        '💾': '[SAVE]',
        '🆕': '[NEW]',
        '📥': '[DOWNLOAD]',
        '📁': '[FOLDER]',
        '🏗️': '[BUILD]',
        '💻': '[SYSTEM]',
        '🧠': '[MEMORY]',
        '💾': '[DISK]',
        '🖖': '[VERSION]',
        '🔖': '[TAG]',
        '🔔': '[NOTIFY]',
        '📡': '[NETWORK]',
        '🌐': '[WEB]',
        '🔮': '[CHECK]',
        '📈': '[STATS]',
        '⏰': '[TIME]',
        '🎯': '[TARGET]',
        '🛑': '[STOP]',
        '👋': '[GOODBYE]',
        '💡': '[TIP]',
        '📄': '[FILE]',
        '📂': '[FOLDER]',
        '🕒': '[TIME]',
        '📅': '[DATE]',
        '🔒': '[LOCK]',
        '🔓': '[UNLOCK]',
        '✨': '[SPARKLE]',
        '🤔': '[THINK]',
        '⚙️': '[GEAR]'
    }
    
    safe_message = str(message)
    for emoji, replacement in emoji_replacements.items():
        safe_message = safe_message.replace(emoji, replacement)
    
    return safe_message

# Enhanced logging setup with clean output
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)  # Only show warnings and errors by default

# Console handler with minimal formatting
console_handler = logging.StreamHandler(sys.stdout)
try:
    # Simple formatter without timestamps for clean output
    console_handler.setFormatter(logging.Formatter('%(message)s'))
except Exception:
    # Fallback to basic formatter
    console_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(console_handler)

# File handler for error logs with Unicode support (skip in build mode)
if not BUILD_MODE:
    try:
        log_file = Path("pdf_tool.log")
        # Use custom Unicode file handler
        file_handler = UnicodeFileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.WARNING)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"Could not setup file logging: {e}")

class SecurityError(Exception):
    """Critical security error - application must exit"""
    pass

class ProfessionalUI:
    """Professional Material Design-inspired console UI with PyInstaller compatibility"""
    
    @staticmethod
    def print_header():
        """Display professional application header"""
        try:
            width = 100
            print("╭" + "─" * (width - 2) + "╮")
            print("│" + " " * (width - 2) + "│")
            print("│" + f"{APP_TITLE}".center(width - 2) + "│")
            print("│" + "Advanced PDF Metadata Restoration System".center(width - 2) + "│")
            print("│" + " " * (width - 2) + "│")
            print("│" + f"Support: {CONTACT_EMAIL}".center(width - 2) + "│")
            if BUILD_MODE:
                print("│" + "BUILD MODE - License validation bypassed".center(width - 2) + "│")
            else:
                print("│" + "Production Mode - License validation active".center(width - 2) + "│")
            print("│" + " " * (width - 2) + "│")
            print("╰" + "─" * (width - 2) + "╯")
            print()
        except Exception as e:
            # Fallback for any Unicode display issues
            print("=" * 80)
            print(f"{APP_TITLE}")
            print(f"Support: {CONTACT_EMAIL}")
            if BUILD_MODE:
                print("BUILD MODE - License validation bypassed")
            else:
                print("Production Mode - License validation active")
            print("=" * 80)

    @staticmethod
    def print_section(title, icon=""):
        """Print a professional section header"""
        try:
            print(f"\n{icon} {title}")
            print("─" * (len(title) + 4))
        except Exception:
            print(f"\n{title}")
            print("-" * len(title))

    @staticmethod
    def print_status_box(status, message, color_code="32"):
        """Print a status message in a colored box"""
        try:
            content = f" {status}: {message} "
            border = "─" * len(content)
            print(f"\n┌{border}┐")
            print(f"│\033[{color_code}m{content}\033[0m│")
            print(f"└{border}┘")
        except Exception:
            # Fallback without colors/unicode
            print(f"\n{status}: {message}")

    @staticmethod
    def print_menu(title, options, icon=""):
        """Print a professional menu"""
        try:
            print(f"\n{icon} {title}")
            print("─" * (len(title) + 4))
            for i, option in enumerate(options, 1):
                print(f"   {i}. {option}")
            print()
        except Exception:
            print(f"\n{title}")
            print("-" * len(title))
            for i, option in enumerate(options, 1):
                print(f"   {i}. {option}")
            print()

    @staticmethod
    def get_user_choice(prompt, valid_choices):
        """Get user choice with validation"""
        while True:
            try:
                choice = input(f"{prompt}: ").strip()
                if choice.lower() in ['quit', 'exit', 'q']:
                    return 'quit'
                if choice in valid_choices:
                    return choice
                print(f"Invalid choice. Please enter one of: {', '.join(valid_choices)}")
            except (KeyboardInterrupt, EOFError):
                return 'quit'

class LicenseValidator:
    """Enterprise-grade license validation with enhanced security and PyInstaller compatibility"""
    
    def __init__(self):
        self.server_url = LICENSE_SERVER_URL
        self.license_file = Path("license.key")
        self.hardware_id = self._generate_hardware_id()
        self.last_validation = None
        self.validation_cache_duration = 300  # 5 minutes
        
    def _generate_hardware_id(self):
        """Generate cryptographically secure hardware fingerprint with enhanced compatibility"""
        try:
            identifiers = []
            
            # Enhanced CPU identification with better error handling
            try:
                if platform.system() == "Windows":
                    # Windows CPU ID with timeout and error handling
                    try:
                        cpu_info = subprocess.check_output(
                            "wmic cpu get ProcessorId", 
                            shell=True, 
                            stderr=subprocess.DEVNULL,
                            timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        ).decode('utf-8', errors='ignore').strip()
                        cpu_lines = [line.strip() for line in cpu_info.split('\n') if line.strip()]
                        if len(cpu_lines) > 1 and cpu_lines[1] != "ProcessorId":
                            identifiers.append(cpu_lines[1])
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError):
                        pass
                    
                    # Windows motherboard serial with better error handling
                    try:
                        mb_info = subprocess.check_output(
                            "wmic baseboard get serialnumber", 
                            shell=True,
                            stderr=subprocess.DEVNULL,
                            timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        ).decode('utf-8', errors='ignore').strip()
                        mb_lines = [line.strip() for line in mb_info.split('\n') if line.strip()]
                        if len(mb_lines) > 1 and mb_lines[1] != "SerialNumber" and mb_lines[1] != "To be filled by O.E.M.":
                            identifiers.append(mb_lines[1])
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError):
                        pass
                
                elif platform.system() == "Linux":
                    # Linux machine ID
                    try:
                        with open('/etc/machine-id', 'r') as f:
                            machine_id = f.read().strip()
                            if machine_id:
                                identifiers.append(machine_id)
                    except (IOError, OSError):
                        pass
                    
                    # Linux DMI product UUID
                    try:
                        dmi_uuid = subprocess.check_output(
                            ["sudo", "dmidecode", "-s", "system-uuid"],
                            stderr=subprocess.DEVNULL,
                            timeout=10
                        ).decode('utf-8', errors='ignore').strip()
                        if dmi_uuid and dmi_uuid != "Not Settable":
                            identifiers.append(dmi_uuid)
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError, FileNotFoundError):
                        pass
                
                elif platform.system() == "Darwin":
                    # macOS hardware UUID
                    try:
                        hw_uuid = subprocess.check_output(
                            ["system_profiler", "SPHardwareDataType"],
                            stderr=subprocess.DEVNULL,
                            timeout=10
                        ).decode('utf-8', errors='ignore')
                        for line in hw_uuid.split('\n'):
                            if 'Hardware UUID' in line:
                                uuid = line.split(':')[1].strip()
                                if uuid:
                                    identifiers.append(uuid)
                                break
                    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError, FileNotFoundError):
                        pass
                        
            except Exception as e:
                if not BUILD_MODE:
                    logger.debug(f"Hardware ID generation warning: {e}")
            
            # Enhanced MAC address collection with better error handling
            try:
                import uuid
                mac = format(uuid.getnode(), 'x').upper()
                if mac and mac != "FFFFFFFFFFFF" and len(mac) >= 12:  # Avoid invalid MAC
                    identifiers.append(mac)
            except Exception:
                pass
            
            # System information fallback
            try:
                system_info = f"{platform.system()}{platform.node()}{platform.machine()}{platform.processor()}"
                if system_info:
                    identifiers.append(hashlib.md5(system_info.encode('utf-8', errors='ignore')).hexdigest()[:16])
            except Exception:
                pass
            
            # Ensure we have at least one identifier
            if not identifiers:
                fallback = f"FALLBACK_{platform.system()}_{int(time.time())}"
                identifiers.append(hashlib.sha256(fallback.encode('utf-8')).hexdigest()[:16])
            
            # Create composite hardware ID
            combined = '|'.join(filter(None, identifiers))
            hardware_id = hashlib.sha256(combined.encode('utf-8')).hexdigest()[:16].upper()
            
            if not BUILD_MODE:
                logger.debug(f"Hardware ID generated from {len(identifiers)} identifiers")
            return hardware_id
            
        except Exception as e:
            if not BUILD_MODE:
                logger.error(f"Critical: Hardware ID generation failed: {e}")
            # Emergency fallback
            emergency_id = hashlib.sha256(
                f"EMERGENCY_{platform.system()}_{platform.node()}_{int(time.time())}".encode('utf-8')
            ).hexdigest()[:16].upper()
            return emergency_id
    
    def _prompt_for_license_key(self):
        """Professional license key input interface with enhanced error handling"""
        try:
            ProfessionalUI.print_section("License Activation Required", "🔐")
            
            print(f"Hardware ID: \033[1m{self.hardware_id}\033[0m")
            print(f"Support Contact: \033[1m{CONTACT_EMAIL}\033[0m")
            print(f"License Server: \033[1m{self.server_url}\033[0m")
            print()
            print("Please enter your license key:")
            print("   Format: PDFM-XXXX-XXXX-XXXX")
            print("   Example: PDFM-1234-ABCD-5678")
            print()
            print("Tip: Type 'exit' or press Ctrl+C to quit")
            print()
            
            while True:
                try:
                    license_key = input("License Key: ").strip().upper()
                    
                    if not license_key:
                        print("License key cannot be empty. Please try again.")
                        continue
                    
                    if license_key.upper() in ["EXIT", "QUIT"]:
                        print("Goodbye!")
                        sys.exit(0)
                    
                    if self._is_valid_license_format(license_key):
                        return license_key
                    else:
                        print("Invalid license format. Expected: PDFM-XXXX-XXXX-XXXX")
                        print("   Please check your license key and try again.")
                        try:
                            choice = input("   Press Enter to try again, or type 'exit' to quit: ").strip()
                            if choice.lower() in ['exit', 'quit']:
                                sys.exit(0)
                        except (KeyboardInterrupt, EOFError):
                            print("\nGoodbye!")
                            sys.exit(0)
                        continue
                        
                except KeyboardInterrupt:
                    print("\nGoodbye!")
                    sys.exit(0)
                except EOFError:
                    print("\nGoodbye!")
                    sys.exit(0)
                except Exception as e:
                    print(f"Error reading input: {e}")
                    continue
        except Exception as e:
            logger.error(f"License prompt error: {e}")
            sys.exit(1)
    
    async def validate_license(self, license_key=None):
        """Enterprise license validation with caching and retry logic - PyInstaller compatible"""
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
            
            # Validate with server silently
            
            # Retry logic for network issues with enhanced error handling
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # Check if aiohttp is available
                    if 'aiohttp' not in sys.modules:
                        raise SecurityError("Network module not available")
                    
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
                                try:
                                    error_data = await response.json() if response.content_type == 'application/json' else {}
                                    error_msg = error_data.get('reason', f'Server error {response.status}')
                                except Exception:
                                    error_msg = f'Server error {response.status}'
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
        try:
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
        except Exception:
            return False
    
    def _get_stored_license(self):
        """Get stored license key with enhanced error handling"""
        try:
            if self.license_file.exists():
                content = self.license_file.read_text(encoding='utf-8', errors='ignore').strip()
                if content and self._is_valid_license_format(content):
                    return content
        except Exception as e:
            if not BUILD_MODE:
                logger.error(f"Error reading license file: {e}")
        return None
    
    def _store_license(self, license_key):
        """Store license key securely with enhanced error handling"""
        try:
            self.license_file.write_text(license_key.strip(), encoding='utf-8')
            # Set restrictive permissions
            if platform.system() != "Windows":
                try:
                    os.chmod(self.license_file, 0o600)
                except OSError:
                    pass  # Ignore permission errors
            if not BUILD_MODE:
                logger.debug("License key stored securely")
        except Exception as e:
            if not BUILD_MODE:
                logger.error(f"Error storing license: {e}")
    
    async def enforce_license_or_exit(self):
        """CRITICAL: Enforce license validation - app exits if invalid - PyInstaller compatible with Unicode fix"""
        # BUILD MODE BYPASS - Only during actual build/CI
        if BUILD_MODE:
            print("BUILD MODE: Skipping license validation for build process")
            print("Production executable will require valid license")
            return {"valid": True, "build_mode": True}
        
        try:
            print(f"Hardware ID: {self.hardware_id}")
            
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
                        print(f"License valid for {days} more days")
                
                validation_count = result.get("validation_count", 0)
                print(f"Total validations: {validation_count}")
                
                return result
            else:
                raise SecurityError("License validation returned invalid")
                
        except SecurityError as e:
            ProfessionalUI.print_status_box("SECURITY ERROR", str(e), "31")
            # Use safe logging messages without emojis to avoid Unicode errors
            print("APPLICATION CANNOT CONTINUE WITHOUT VALID LICENSE")
            print(f"Contact for license: {CONTACT_EMAIL}")
            print(f"Your Hardware ID: {self.hardware_id}")
            
            try:
                print(f"\n┌{'─' * 60}┐")
                print(f"│ For licensing inquiries, contact: {CONTACT_EMAIL:<23} │")
                print(f"│ Include your Hardware ID: {self.hardware_id:<27} │")
                print(f"└{'─' * 60}┘")
            except Exception:
                print(f"\nFor licensing inquiries, contact: {CONTACT_EMAIL}")
                print(f"Include your Hardware ID: {self.hardware_id}")
            
            try:
                input("\nPress Enter to exit...")
            except (KeyboardInterrupt, EOFError):
                pass
            sys.exit(1)
        except Exception as e:
            ProfessionalUI.print_status_box("CRITICAL ERROR", str(e), "31")
            print("APPLICATION CANNOT CONTINUE")
            try:
                input("\nPress Enter to exit...")
            except (KeyboardInterrupt, EOFError):
                pass
            sys.exit(1)

class AutoUpdater:
    """Professional auto-updater with GitHub integration - Enhanced for server compatibility"""
    
    def __init__(self):
        self.current_version = VERSION.lstrip("v")  # Remove 'v' prefix for comparison
        self.repo = GITHUB_REPO
        self.update_url = UPDATE_CHECK_URL
        self.client_update_url = CLIENT_UPDATE_URL  # Updated to match server endpoint
        
    async def check_for_updates(self):
        """Check for updates from both license server and GitHub with enhanced integration"""
        if BUILD_MODE:
            return {"update_available": False}
            
        try:
            # First check license server for immediate updates (higher priority)
            server_update = await self._check_server_updates()
            if server_update.get("update_available"):
                return server_update
            
            # Fallback to GitHub releases
            github_update = await self._check_github_updates()
            if github_update.get("update_available"):
                return github_update
            
            return {"update_available": False}
                
        except Exception as e:
            return {"update_available": False}
    
    async def _check_server_updates(self):
        """Check license server for immediate client updates with enhanced error handling"""
        try:
            if 'aiohttp' not in sys.modules:
                return {"update_available": False}
                
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {
                    "User-Agent": f"PDF-Metadata-Tool/{VERSION}",
                    "Accept": "application/json"
                }
                
                async with session.get(self.client_update_url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("update_available"):
                            latest_version = data.get("latest_version", "latest").lstrip("v")
                            if self._is_newer_version(latest_version):
                                return {
                                    "update_available": True,
                                    "latest_version": latest_version,
                                    "download_url": data.get("download_url"),
                                    "source": "license_server",
                                    "release_date": data.get("release_date"),
                                    "filename": data.get("filename")
                                }
                        
            return {"update_available": False}
        except Exception as e:
            return {"update_available": False}
    
    async def _check_github_updates(self):
        """Check GitHub for releases with enhanced error handling"""
        try:
            if 'aiohttp' not in sys.modules:
                return {"update_available": False}
            
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {
                    "User-Agent": f"PDF-Metadata-Tool/{VERSION}",
                    "Accept": "application/vnd.github.v3+json"
                }
                
                async with session.get(self.update_url, headers=headers) as response:
                    if response.status == 200:
                        release_data = await response.json()
                        latest_version = release_data.get("tag_name", "").lstrip("v")
                        
                        if self._is_newer_version(latest_version):
                            return {
                                "update_available": True,
                                "latest_version": latest_version,
                                "download_url": self._get_download_url(release_data),
                                "release_notes": release_data.get("body", ""),
                                "release_url": release_data.get("html_url", ""),
                                "source": "github",
                                "published_at": release_data.get("published_at")
                            }
                        else:
                            return {"update_available": False}
                    else:
                        return {"update_available": False}
                        
        except Exception as e:
            return {"update_available": False}
    
    def _is_newer_version(self, latest_version):
        """Compare version numbers with enhanced error handling"""
        try:
            def version_tuple(v):
                # Handle both "1.2.3" and "v1.2.3" formats
                v = str(v).lstrip("v")
                return tuple(map(int, v.split('.')))
            
            current = self.current_version.lstrip("v")
            return version_tuple(latest_version) > version_tuple(current)
        except Exception as e:
            logger.debug(f"Version comparison error: {e}")
            return False
    
    def _get_download_url(self, release_data):
        """Extract download URL for the executable with enhanced detection"""
        try:
            assets = release_data.get("assets", [])
            
            # Look for PDF Metadata Tool executable (prioritize exact matches)
            for asset in assets:
                name = asset.get("name", "").lower()
                if "pdf-metadata-tool" in name and name.endswith(".exe"):
                    return asset.get("browser_download_url")
            
            # Look for any PDF-related executable
            for asset in assets:
                name = asset.get("name", "").lower()
                if "pdf" in name and name.endswith(".exe"):
                    return asset.get("browser_download_url")
            
            # Look for any .exe file as fallback
            for asset in assets:
                name = asset.get("name", "").lower()
                if name.endswith(".exe"):
                    return asset.get("browser_download_url")
            
            # Fallback to zipball
            return release_data.get("zipball_url")
        except Exception:
            return release_data.get("zipball_url", "")
    
    async def prompt_and_update(self, update_info):
        """Professional update prompt and installation with enhanced UI"""
        try:
            version = update_info["latest_version"]
            source = update_info.get("source", "github")
            
            ProfessionalUI.print_section("Update Available", "🆕")
            
            print(f"New Version: v{version} (current: {VERSION})")
            print(f"Source: {source.title()}")
            
            if update_info.get("release_date"):
                print(f"Release Date: {update_info['release_date']}")
            elif update_info.get("published_at"):
                print(f"Published: {update_info['published_at']}")
            
            if update_info.get("filename"):
                print(f"Filename: {update_info['filename']}")
            
            if update_info.get("release_notes"):
                notes = update_info["release_notes"]
                print(f"Release Notes:\n{notes[:300]}{'...' if len(notes) > 300 else ''}")
            
            print()
            try:
                choice = input("Download and install update now? (y/N): ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                choice = "n"
            
            if choice in ['y', 'yes']:
                download_url = update_info["download_url"]
                await self.download_and_install_update(download_url, version)
            else:
                print("Update skipped - continuing with current version")
        except Exception as e:
            print(f"Update prompt error: {e}")

    async def download_and_install_update(self, download_url, version):
        """Professional download and installation with progress - Enhanced for Windows compatibility"""
        if BUILD_MODE:
            return
            
        try:
            ProfessionalUI.print_section("Downloading Update", "📥")
            print(f"Downloading v{version}...")
            print(f"URL: {download_url}")
            
            # Get current executable directory
            if hasattr(sys, '_MEIPASS'):
                # Running as PyInstaller executable
                current_exe_path = Path(sys.executable)
                download_dir = current_exe_path.parent
            else:
                # Running as script
                download_dir = Path.cwd()
            
            # Download file with progress
            if 'aiohttp' not in sys.modules:
                print("Network module not available for updates")
                return
                
            timeout = aiohttp.ClientTimeout(total=600)  # 10 minutes
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {
                    "User-Agent": f"PDF-Metadata-Tool/{VERSION}",
                    "Accept": "application/octet-stream, */*"
                }
                
                async with session.get(download_url, headers=headers) as response:
                    if response.status == 200:
                        # Determine file name - download to same folder as current exe
                        if download_url.endswith('.exe'):
                            filename = f"PDF-Metadata-Tool-v{version}.exe"
                        else:
                            filename = f"PDF-Metadata-Tool-v{version}.zip"
                        
                        download_path = download_dir / filename
                        
                        # Download with simple progress
                        total_size = int(response.headers.get('content-length', 0))
                        downloaded = 0
                        
                        print(f"Downloading to: {download_path}")
                        
                        async with aiofiles.open(download_path, 'wb') as file:
                            async for chunk in response.content.iter_chunked(8192):
                                await file.write(chunk)
                                downloaded += len(chunk)
                                if total_size > 0:
                                    percent = (downloaded / total_size) * 100
                                    print(f"\rDownload progress: {percent:.1f}%", end="", flush=True)
                        
                        print("\nDownload completed successfully")
                        
                        # Install update
                        await self._install_update(download_path, version)
                    else:
                        raise Exception(f"Download failed: HTTP {response.status}")
                        
        except Exception as e:
            print(f"Update download failed: {e}")
    
    async def _install_update(self, download_path, version):
        """Install the downloaded update with Windows-compatible approach"""
        try:
            ProfessionalUI.print_section("Installing Update", "🔄")
            
            current_exe = Path(sys.executable)
            current_name = current_exe.name
            backup_name = f"{current_exe.stem}_backup{current_exe.suffix}"
            backup_path = current_exe.parent / backup_name
            
            if download_path.suffix == '.exe':
                # Windows-compatible update process
                print("Preparing update installation...")
                
                if platform.system() == "Windows":
                    # Create a batch script to handle the update after exit
                    batch_script = current_exe.parent / "update_pdf_tool.bat"
                    
                    script_content = f'''@echo off
echo PDF Metadata Tool Update Process
echo ================================
echo.
echo Backing up current version...
if exist "{current_name}" (
    copy "{current_name}" "{backup_name}" >nul 2>&1
    if errorlevel 1 (
        echo WARNING: Could not create backup
    ) else (
        echo Backup created: {backup_name}
    )
)

echo.
echo Installing new version...
timeout /t 2 /nobreak >nul 2>&1

copy "{download_path.name}" "{current_name}" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Update failed!
    echo Please manually replace {current_name} with {download_path.name}
    pause
    exit /b 1
) else (
    echo Update completed successfully!
    echo.
    echo Starting updated version...
    timeout /t 1 /nobreak >nul 2>&1
    start "" "{current_name}"
)

echo.
echo Cleaning up...
timeout /t 2 /nobreak >nul 2>&1
del "{download_path.name}" >nul 2>&1
del "%~f0" >nul 2>&1
'''
                    
                    try:
                        batch_script.write_text(script_content, encoding='utf-8')
                        print(f"Update script created: {batch_script}")
                        
                        ProfessionalUI.print_status_box(
                            "UPDATE READY", 
                            f"New version v{version} downloaded successfully", 
                            "32"
                        )
                        
                        print(f"\n📥 Downloaded: {download_path.name}")
                        print(f"📁 Location: {download_path.parent}")
                        print(f"🔄 Update script: {batch_script.name}")
                        print()
                        print("The application will now close and the update will be applied automatically.")
                        print("The new version will start automatically after update completion.")
                        print()
                        
                        try:
                            choice = input("Press Enter to apply update now, or Ctrl+C to cancel: ").strip()
                        except (KeyboardInterrupt, EOFError):
                            print("\nUpdate cancelled. You can manually run the update later.")
                            print(f"To update manually: run {batch_script.name}")
                            return
                        
                        print("Starting update process...")
                        print("Application will restart automatically with new version")
                        
                        # Start the batch script and exit
                        subprocess.Popen([str(batch_script)], 
                                       creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                                       cwd=str(current_exe.parent))
                        sys.exit(0)
                        
                    except Exception as e:
                        print(f"Failed to create update script: {e}")
                        # Fallback to manual instructions
                        await self._show_manual_update_instructions(download_path, version)
                
                else:
                    # Non-Windows systems - simpler approach
                    print("Installing update...")
                    
                    # Backup current version
                    if current_exe.exists():
                        try:
                            shutil.copy2(current_exe, backup_path)
                            print(f"Backup created: {backup_name}")
                        except Exception as e:
                            print(f"Backup failed: {e}")
                    
                    # Replace with new version
                    try:
                        shutil.copy2(download_path, current_exe)
                        os.chmod(current_exe, 0o755)  # Make executable
                        
                        ProfessionalUI.print_status_box(
                            "UPDATE COMPLETED", 
                            f"Successfully updated to v{version}", 
                            "32"
                        )
                        
                        print("Restarting application...")
                        await asyncio.sleep(1)
                        
                        # Restart application
                        subprocess.Popen([str(current_exe)])
                        sys.exit(0)
                        
                    except Exception as e:
                        print(f"Update installation failed: {e}")
                        await self._show_manual_update_instructions(download_path, version)
                
            else:
                # Handle zip file
                await self._handle_zip_update(download_path, version)
                        
        except Exception as e:
            print(f"Update installation failed: {e}")
            await self._show_manual_update_instructions(download_path, version)
    
    async def _show_manual_update_instructions(self, download_path, version):
        """Show manual update instructions to the user"""
        try:
            ProfessionalUI.print_section("Manual Update Required", "📋")
            
            print(f"✅ New version v{version} has been downloaded successfully!")
            print(f"📁 Location: {download_path}")
            print()
            print("📋 Manual Update Instructions:")
            print("   1. Close this application")
            print(f"   2. Rename the current executable to create a backup")
            print(f"   3. Rename '{download_path.name}' to '{Path(sys.executable).name}'")
            print("   4. Run the new executable")
            print()
            print("💡 The new version will be ready to use after following these steps.")
            
            try:
                input("\nPress Enter to continue...")
            except (KeyboardInterrupt, EOFError):
                pass
                
        except Exception as e:
            print(f"Error showing manual instructions: {e}")
    
    async def _handle_zip_update(self, download_path, version):
        """Handle zip file updates"""
        try:
            print("Extracting update package...")
            
            with zipfile.ZipFile(download_path, 'r') as zip_ref:
                extract_dir = download_path.parent / f"extracted_v{version}"
                zip_ref.extractall(extract_dir)
                
                # Look for executable in extracted files
                for file_path in extract_dir.rglob("*.exe"):
                    if "pdf" in file_path.name.lower():
                        # Move to main directory with version name
                        new_exe_path = download_path.parent / f"PDF-Metadata-Tool-v{version}.exe"
                        shutil.copy2(file_path, new_exe_path)
                        
                        # Clean up
                        shutil.rmtree(extract_dir, ignore_errors=True)
                        download_path.unlink(missing_ok=True)
                        
                        # Now handle as exe
                        await self._install_update(new_exe_path, version)
                        return
                        
                print("No executable found in update package")
                await self._show_manual_update_instructions(download_path, version)
                        
        except Exception as e:
            print(f"Zip extraction failed: {e}")
            await self._show_manual_update_instructions(download_path, version)

# ===== PDF PROCESSING CLASSES - INTEGRATED FROM SECOND SCRIPT =====

def generate_random_password(length=12):
    """Generate a random password for encryption."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def detect_pdf_security(pdf_file):
    """Detect both user password and owner password/permissions protection."""
    security_info = {
        'has_user_password': False,
        'has_owner_restrictions': False,
        'can_open': False,
        'can_modify': True,
        'encryption_present': False,
        'pdf_version': '1.4',
        'estimated_R': 4,
        'estimated_V': 2
    }
    
    try:
        # Try to open the file
        with pikepdf.open(pdf_file) as pdf:
            security_info['can_open'] = True
            security_info['pdf_version'] = pdf.pdf_version
            
            # Check if file has encryption dictionary
            if hasattr(pdf, 'encryption') and pdf.encryption:
                security_info['encryption_present'] = True
                try:
                    # Get encryption parameters
                    encryption = pdf.encryption
                    security_info['estimated_R'] = getattr(encryption, 'R', 4)
                    security_info['estimated_V'] = getattr(encryption, 'V', 2)
                except:
                    pass
            
            # Check for explicit encryption object
            if '/Encrypt' in pdf.trailer:
                security_info['encryption_present'] = True
            
            # Check actual permissions
            try:
                if hasattr(pdf, 'allow'):
                    perms = pdf.allow
                    if not (perms.modify_other and perms.modify_annotation and perms.modify_form):
                        security_info['has_owner_restrictions'] = True
                        security_info['can_modify'] = False
                    else:
                        security_info['has_owner_restrictions'] = False
                        security_info['can_modify'] = True
                else:
                    security_info['has_owner_restrictions'] = False
                    security_info['can_modify'] = True
            except Exception as e:
                if security_info['encryption_present']:
                    security_info['has_owner_restrictions'] = False
                    security_info['can_modify'] = True
                
    except pikepdf.PasswordError:
        security_info['has_user_password'] = True
        security_info['encryption_present'] = True
        
        # Try to get PDF version from header even if encrypted
        try:
            with open(pdf_file, 'rb') as f:
                header = f.read(1024).decode('utf-8', errors='ignore')
                version_match = re.search(r'%PDF-(\d+\.\d+)', header)
                if version_match:
                    security_info['pdf_version'] = version_match.group(1)
                    
                    # Estimate encryption based on PDF version
                    pdf_version = security_info['pdf_version']
                    if pdf_version >= '2.0':
                        security_info['estimated_R'] = 6
                        security_info['estimated_V'] = 5
                    elif pdf_version >= '1.7':
                        security_info['estimated_R'] = 6
                        security_info['estimated_V'] = 5
                    elif pdf_version >= '1.6':
                        security_info['estimated_R'] = 4
                        security_info['estimated_V'] = 4
                    elif pdf_version >= '1.4':
                        security_info['estimated_R'] = 3
                        security_info['estimated_V'] = 2
                    else:
                        security_info['estimated_R'] = 2
                        security_info['estimated_V'] = 1
        except:
            pass
    
    except Exception as e:
        logger.error(f"Error analyzing PDF security: {e}")
    
    has_meaningful_protection = (security_info['has_user_password'] or 
                                security_info['has_owner_restrictions'])
    
    security_info['needs_encryption'] = has_meaningful_protection
    
    return security_info

def extract_comprehensive_metadata(pdf_file, password=''):
    """Extract all types of metadata from a PDF file, including exact timestamps."""
    try:
        with pikepdf.open(pdf_file, password=password) as pdf:
            metadata = {
                'visible': {},
                'xmp': None,
                'has_digital_signatures': False,
                'has_form_fields': False,
                'pdf_version': pdf.pdf_version,
                'page_count': len(pdf.pages),
                'raw_dates': {}  # Store raw date strings
            }
            
            # Extract visible metadata (Document Info Dictionary)
            for k, v in pdf.docinfo.items():
                key = k[1:]  # Remove leading /
                value = str(v)
                metadata['visible'][key] = value
                
                # Store raw date values for exact preservation
                if key in ['CreationDate', 'ModDate']:
                    # pikepdf returns the raw string, which we want to preserve exactly
                    metadata['raw_dates'][key] = v
            
            # Extract XMP metadata
            if '/Metadata' in pdf.Root:
                try:
                    xmp_bytes = pdf.Root.Metadata.read_bytes()
                    metadata['xmp'] = xmp_bytes.decode('utf-8', errors='ignore')
                    metadata['xmp_bytes'] = xmp_bytes  # Store raw bytes for exact preservation
                except Exception:
                    pass
            
            # Check for digital signatures
            if '/AcroForm' in pdf.Root:
                acro_form = pdf.Root['/AcroForm']
                if '/SigFlags' in acro_form:
                    metadata['has_digital_signatures'] = True
                if '/Fields' in acro_form:
                    metadata['has_form_fields'] = True
            
            # Check for page-level metadata
            page_metadata = []
            for i, page in enumerate(pdf.pages):
                if '/Metadata' in page:
                    page_metadata.append(i)
            if page_metadata:
                metadata['pages_with_metadata'] = page_metadata
            
            return metadata
            
    except pikepdf.PasswordError:
        return None

def create_default_metadata():
    """Create default metadata when original cannot be accessed."""
    current_time = datetime.now(timezone.utc).strftime("D:%Y%m%d%H%M%S+00'00'")
    
    return {
        'Title': 'Document',
        'Author': 'Unknown',
        'Subject': '',
        'Keywords': '',
        'Creator': 'PDF Application',
        'Producer': 'PDF Library',
        'CreationDate': current_time,
        'ModDate': current_time,
        'Trapped': '/False'
    }

def update_xmp_dates(xmp_string, creation_date, mod_date):
    """Update XMP metadata to match the visible metadata dates."""
    if not xmp_string:
        return None
    
    try:
        # Parse XMP
        xmp_string = xmp_string.strip()
        
        # Convert PDF date format to XMP format
        # PDF: D:20240315120000+00'00'
        # XMP: 2024-03-15T12:00:00+00:00
        def pdf_to_xmp_date(pdf_date):
            # Remove D: prefix
            if pdf_date.startswith('D:'):
                pdf_date = pdf_date[2:]
            
            # Parse components
            year = pdf_date[0:4]
            month = pdf_date[4:6]
            day = pdf_date[6:8]
            hour = pdf_date[8:10] if len(pdf_date) > 8 else '00'
            minute = pdf_date[10:12] if len(pdf_date) > 10 else '00'
            second = pdf_date[12:14] if len(pdf_date) > 12 else '00'
            
            # Handle timezone
            tz = '+00:00'  # Default
            if '+' in pdf_date or '-' in pdf_date:
                tz_start = pdf_date.find('+') if '+' in pdf_date else pdf_date.find('-')
                tz_part = pdf_date[tz_start:]
                # Convert +00'00' to +00:00
                tz = tz_part.replace("'", ":")
            
            return f"{year}-{month}-{day}T{hour}:{minute}:{second}{tz}"
        
        # Replace dates in XMP
        if isinstance(creation_date, str):
            xmp_creation = pdf_to_xmp_date(creation_date)
            # Replace various date formats in XMP
            xmp_string = re.sub(
                r'<xmp:CreateDate>[^<]+</xmp:CreateDate>',
                f'<xmp:CreateDate>{xmp_creation}</xmp:CreateDate>',
                xmp_string
            )
            xmp_string = re.sub(
                r'xmp:CreateDate="[^"]+"',
                f'xmp:CreateDate="{xmp_creation}"',
                xmp_string
            )
        
        if isinstance(mod_date, str):
            xmp_mod = pdf_to_xmp_date(mod_date)
            # Replace various date formats in XMP
            xmp_string = re.sub(
                r'<xmp:ModifyDate>[^<]+</xmp:ModifyDate>',
                f'<xmp:ModifyDate>{xmp_mod}</xmp:ModifyDate>',
                xmp_string
            )
            xmp_string = re.sub(
                r'xmp:ModifyDate="[^"]+"',
                f'xmp:ModifyDate="{xmp_mod}"',
                xmp_string
            )
            # Also update MetadataDate
            xmp_string = re.sub(
                r'<xmp:MetadataDate>[^<]+</xmp:MetadataDate>',
                f'<xmp:MetadataDate>{xmp_mod}</xmp:MetadataDate>',
                xmp_string
            )
            xmp_string = re.sub(
                r'xmp:MetadataDate="[^"]+"',
                f'xmp:MetadataDate="{xmp_mod}"',
                xmp_string
            )
        
        return xmp_string
        
    except Exception as e:
        logger.warning(f"Could not update XMP dates: {e}")
        return xmp_string

def try_common_passwords(pdf_file):
    """Try common passwords that might work."""
    common_passwords = ['', '123456', 'password', 'admin', 'user', '1234', 'pdf']
    
    for password in common_passwords:
        try:
            with pikepdf.open(pdf_file, password=password) as pdf:
                return password
        except pikepdf.PasswordError:
            continue
    
    return None

def get_original_file_timestamps(filepath):
    """Extract file system timestamps from the original file as backup."""
    try:
        stat_result = os.stat(filepath)
        timestamps = {
            'creation': stat_result.st_ctime,
            'modification': stat_result.st_mtime, 
            'access': stat_result.st_atime
        }
        
        return timestamps
        
    except Exception as e:
        logger.warning(f"Could not read original file timestamps: {e}")
        return None

def pdf_date_to_timestamp(pdf_date_str):
    """Convert PDF date string to Unix timestamp for file system."""
    if not pdf_date_str:
        return None
    
    try:
        # Handle pikepdf date objects
        date_string = None
        
        # Try different ways to extract the date string
        try:
            date_string = str(pdf_date_str)
        except Exception:
            pass
        
        if not date_string and hasattr(pdf_date_str, 'for_pdf_string'):
            try:
                date_string = pdf_date_str.for_pdf_string()
            except Exception:
                pass
        
        if not date_string and hasattr(pdf_date_str, 'unbox'):
            try:
                unboxed = pdf_date_str.unbox()
                date_string = str(unboxed)
            except Exception:
                pass
        
        if not date_string and isinstance(pdf_date_str, str):
            date_string = pdf_date_str
        
        if not date_string:
            return None
        
        # Clean up the date string
        pdf_date_str = date_string
        
        # Remove D: prefix if present
        if pdf_date_str.startswith('D:'):
            pdf_date_str = pdf_date_str[2:]
        
        # Clean up the date string - remove extra quotes and normalize
        pdf_date_str = pdf_date_str.replace("''", "'").strip("'\"")
        
        # Parse the PDF date format: YYYYMMDDHHmmSSOHH'mm' or YYYYMMDDHHmmSSZ
        if len(pdf_date_str) < 14:
            return None
            
        year = int(pdf_date_str[0:4])
        month = int(pdf_date_str[4:6])
        day = int(pdf_date_str[6:8])
        hour = int(pdf_date_str[8:10]) if len(pdf_date_str) > 8 else 0
        minute = int(pdf_date_str[10:12]) if len(pdf_date_str) > 10 else 0
        second = int(pdf_date_str[12:14]) if len(pdf_date_str) > 12 else 0
        
        # Create datetime object - treat as local time regardless of timezone markers
        dt_local = datetime(year, month, day, hour, minute, second)
        
        # Convert local time to UTC timestamp for os.utime()
        local_timestamp = time.mktime(dt_local.timetuple())
        
        return local_timestamp
        
    except (ValueError, IndexError, AttributeError, TypeError) as e:
        logger.warning(f"Could not parse PDF date '{pdf_date_str}': {e}")
        return None

def set_file_timestamps(filepath, creation_date=None, modification_date=None, original_file_timestamps=None):
    """Set file system timestamps to match PDF metadata, with protection against modification."""
    if not os.path.exists(filepath):
        logger.error(f"File not found: {filepath}")
        return False
    
    try:
        # Convert PDF dates to timestamps
        creation_timestamp = None
        modification_timestamp = None
        
        if creation_date:
            creation_timestamp = pdf_date_to_timestamp(creation_date)
        
        if modification_date:
            modification_timestamp = pdf_date_to_timestamp(modification_date)
        
        # Use modification time for both access and modification if available
        # Otherwise fall back to creation time
        target_timestamp = modification_timestamp or creation_timestamp
        
        # Backup: use original file system timestamps if PDF timestamps failed
        if not target_timestamp and original_file_timestamps:
            target_timestamp = original_file_timestamps.get('modification') or original_file_timestamps.get('creation')
        
        if target_timestamp:
            # Store original file attributes
            original_mode = os.stat(filepath).st_mode
            
            try:
                # First, set only modification time
                current_stat = os.stat(filepath)
                os.utime(filepath, (current_stat.st_atime, target_timestamp))
                
                # On Windows, set creation time using win32file
                try:
                    if platform.system() == 'Windows' and WIN32_TIMESTAMP_AVAILABLE:
                        # Use creation timestamp if available, otherwise modification
                        creation_ts = creation_timestamp or modification_timestamp
                        if not creation_ts and original_file_timestamps:
                            creation_ts = original_file_timestamps.get('creation') or target_timestamp
                        
                        # Convert to Windows FILETIME (using local time)
                        dt_for_windows = datetime.fromtimestamp(creation_ts)
                        file_time = pywintypes.Time(dt_for_windows)
                        
                        # Open file handle with proper permissions
                        handle = win32file.CreateFile(
                            filepath,
                            win32file.GENERIC_WRITE,
                            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                            None,
                            win32file.OPEN_EXISTING,
                            win32file.FILE_ATTRIBUTE_NORMAL,
                            None
                        )
                        
                        # Set creation time only
                        win32file.SetFileTime(handle, file_time, None, None)
                        win32file.CloseHandle(handle)
                        
                except Exception as e:
                    logger.debug(f"Could not set Windows creation time: {e}")
                
                # Set access time last
                try:
                    os.utime(filepath, (target_timestamp, target_timestamp))
                except Exception as access_error:
                    logger.debug(f"Could not set final access time: {access_error}")
                
            except Exception as timestamp_error:
                logger.error(f"Error setting timestamps: {timestamp_error}")
                return False
            
            return True
        else:
            logger.warning("No valid timestamps found to set")
            return False
            
    except Exception as e:
        logger.error(f"Error setting file timestamps: {e}")
        return False

def safe_remove_file(filepath):
    """Safely remove a file if it exists."""
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
            return True
        except Exception as e:
            logger.error(f"Failed to remove existing file {filepath}: {e}")
            try:
                backup_name = filepath + '.backup'
                os.rename(filepath, backup_name)
                logger.info(f"Renamed existing file to: {backup_name}")
                return True
            except Exception as rename_error:
                logger.error(f"Failed to rename existing file: {rename_error}")
                return False
    return True

class PDFProcessor:
    """Professional PDF metadata processing engine with PyInstaller compatibility"""
    
    def __init__(self, base_dir):
        self.base_dir = Path(base_dir)
        self.original_dir = self.base_dir / "original"
        self.edited_dir = self.base_dir / "edited"
        self.final_dir = self.base_dir / "final"
        self.stats = {
            'total_files': 0,
            'processed_files': 0,
            'failed_files': 0,
            'total_size': 0,
            'processing_time': 0
        }
        # Processing options
        self.preserve_exact_timestamps = True
        self.use_exact_time_match = True
        self.permanent_read_only = False
        self.timestamp_source_priority = 1  # 1 = PDF metadata first, 2 = file system first
    
    def get_file_pair_options(self):
        """Get file pairs from original and edited folders"""
        try:
            # Get all PDF files from both directories
            original_files = list(self.original_dir.glob("*.pdf"))
            edited_files = list(self.edited_dir.glob("*.pdf"))
            
            # Create a mapping by filename
            original_map = {f.name: f for f in original_files}
            edited_map = {f.name: f for f in edited_files}
            
            # Find matching pairs
            pairs = []
            for filename in original_map:
                if filename in edited_map:
                    pairs.append({
                        'filename': filename,
                        'original': original_map[filename],
                        'edited': edited_map[filename],
                        'size': self._format_size(original_map[filename].stat().st_size)
                    })
            
            return pairs
        except Exception as e:
            logger.error(f"Error scanning for file pairs: {e}")
            return []
    
    def get_processing_options_menu(self):
        """Get processing options for the menu (cleaned - no anonymize option)"""
        return [
            "Preserve exact timestamps (file system + metadata)",
            "Standard processing (metadata only)",
            "Custom settings"
        ]
    
    def get_custom_settings_menu(self):
        """Get custom processing settings from user"""
        try:
            ProfessionalUI.print_section("Custom Processing Settings", "🛠️")
            
            print("Configure your custom processing options:")
            print()
            
            # Timestamp preservation
            timestamp_choice = ProfessionalUI.get_user_choice(
                "Preserve exact timestamps? (y/N)", 
                ['y', 'yes', 'n', 'no', '']
            )
            if timestamp_choice == 'quit':
                return None
            self.preserve_exact_timestamps = timestamp_choice.lower() in ['y', 'yes']
            
            # Time matching
            if self.preserve_exact_timestamps:
                time_match_choice = ProfessionalUI.get_user_choice(
                    "Use exact time matching? (Y/n)", 
                    ['y', 'yes', 'n', 'no', '']
                )
                if time_match_choice == 'quit':
                    return None
                self.use_exact_time_match = time_match_choice.lower() not in ['n', 'no']
            
            # Read-only setting
            readonly_choice = ProfessionalUI.get_user_choice(
                "Make final files read-only? (y/N)", 
                ['y', 'yes', 'n', 'no', '']
            )
            if readonly_choice == 'quit':
                return None
            self.permanent_read_only = readonly_choice.lower() in ['y', 'yes']
            
            # Timestamp source priority
            print("\nTimestamp source priority:")
            print("   1. PDF metadata first (recommended)")
            print("   2. File system timestamps first")
            priority_choice = ProfessionalUI.get_user_choice(
                "Choose timestamp priority (1/2)", 
                ['1', '2']
            )
            if priority_choice == 'quit':
                return None
            self.timestamp_source_priority = int(priority_choice)
            
            # Summary
            print("\n📋 Custom Settings Summary:")
            print(f"   • Preserve timestamps: {'Yes' if self.preserve_exact_timestamps else 'No'}")
            if self.preserve_exact_timestamps:
                print(f"   • Exact time matching: {'Yes' if self.use_exact_time_match else 'No'}")
            print(f"   • Read-only final files: {'Yes' if self.permanent_read_only else 'No'}")
            print(f"   • Timestamp priority: {'PDF metadata' if self.timestamp_source_priority == 1 else 'File system'}")
            
            confirm = ProfessionalUI.get_user_choice(
                "Apply these settings? (Y/n)", 
                ['y', 'yes', 'n', 'no', '']
            )
            return confirm.lower() not in ['n', 'no']
            
        except Exception as e:
            print(f"Error in custom settings: {e}")
            return False

    async def process_pdf_files(self):
        """Process PDF files with professional user interaction"""
        try:
            # Create directories with error handling
            try:
                self.original_dir.mkdir(exist_ok=True)
                self.edited_dir.mkdir(exist_ok=True)
                self.final_dir.mkdir(exist_ok=True)
            except Exception as e:
                logger.error(f"Failed to create directories: {e}")
                return False
            
            while True:  # Main processing loop
                # Scan for file pairs
                file_pairs = self.get_file_pair_options()
                
                if not file_pairs:
                    ProfessionalUI.print_status_box(
                        "NO MATCHING FILES", 
                        "No matching PDF files found in original and edited folders", 
                        "33"
                    )
                    print(f"\nPlease ensure:")
                    print(f"1. Original PDFs are in: {self.original_dir}")
                    print(f"2. Edited PDFs are in: {self.edited_dir}")
                    print(f"3. Files have the SAME FILENAME in both folders")
                    
                    choice = ProfessionalUI.get_user_choice(
                        "\nPress Enter to scan again, or type 'quit' to exit", 
                        ['', 'quit']
                    )
                    if choice == 'quit':
                        return False
                    continue
                
                # Display file pairs
                ProfessionalUI.print_section("Matched PDF File Pairs", "📁")
                options = []
                for i, pair in enumerate(file_pairs, 1):
                    options.append(f"{pair['filename']} ({pair['size']})")
                options.append("Process all file pairs")
                
                ProfessionalUI.print_menu("Select files to process:", options, "📄")
                
                # Get file selection
                valid_choices = [str(i) for i in range(1, len(options) + 1)]
                file_choice = ProfessionalUI.get_user_choice(
                    "Enter your choice", 
                    valid_choices
                )
                
                if file_choice == 'quit':
                    return False
                
                # Determine selected pairs
                file_choice_idx = int(file_choice) - 1
                if file_choice_idx == len(file_pairs):  # "Process all file pairs"
                    selected_pairs = file_pairs
                else:
                    selected_pairs = [file_pairs[file_choice_idx]]
                
                # Display processing options
                ProfessionalUI.print_section("Processing Options", "⚙️")
                processing_options = self.get_processing_options_menu()
                ProfessionalUI.print_menu("Select processing type:", processing_options, "🔧")
                
                # Get processing type
                valid_proc_choices = [str(i) for i in range(1, len(processing_options) + 1)]
                proc_choice = ProfessionalUI.get_user_choice(
                    "Enter your choice", 
                    valid_proc_choices
                )
                
                if proc_choice == 'quit':
                    return False
                
                # Configure processing based on choice (cleaned - no anonymize option)
                if proc_choice == '1':  # Preserve exact timestamps
                    self.preserve_exact_timestamps = True
                    self.use_exact_time_match = True
                elif proc_choice == '2':  # Standard processing
                    self.preserve_exact_timestamps = False
                    self.use_exact_time_match = False
                elif proc_choice == '3':  # Custom settings
                    settings_result = self.get_custom_settings_menu()
                    if settings_result is None:
                        continue  # User quit
                    elif not settings_result:
                        print("Custom settings cancelled, using standard processing")
                        self.preserve_exact_timestamps = False
                
                # Process selected pairs
                success = await self._process_selected_pairs(selected_pairs, proc_choice)
                
                if success:
                    # Ask what to do next
                    ProfessionalUI.print_section("What's Next?", "🤔")
                    next_options = [
                        "Process another file/batch",
                        "Exit application"
                    ]
                    ProfessionalUI.print_menu("Choose your next action:", next_options, "🎯")
                    
                    valid_next_choices = [str(i) for i in range(1, len(next_options) + 1)]
                    next_choice = ProfessionalUI.get_user_choice(
                        "Enter your choice", 
                        valid_next_choices
                    )
                    
                    if next_choice == 'quit' or next_choice == '2':
                        ProfessionalUI.print_status_box(
                            "SESSION COMPLETE", 
                            "Thank you for using PDF Metadata Tool!", 
                            "32"
                        )
                        return True
                    # Continue loop for option 1
                else:
                    # Processing failed, ask if they want to try again
                    choice = ProfessionalUI.get_user_choice(
                        "Processing failed. Try again? (y/N)", 
                        ['y', 'yes', 'n', 'no', '']
                    )
                    if choice in ['n', 'no', '', 'quit']:
                        return False
                    # Continue loop to try again
                        
        except Exception as e:
            print(f"PDF processing error: {e}")
            return False
    
    async def _process_selected_pairs(self, selected_pairs, processing_type):
        """Process the selected file pairs with clean, professional output"""
        try:
            self.stats = {
                'total_files': len(selected_pairs),
                'processed_files': 0,
                'failed_files': 0,
                'total_size': sum(p['original'].stat().st_size for p in selected_pairs),
                'processing_time': 0
            }
            
            ProfessionalUI.print_section("Processing PDF Files", "🔄")
            print(f"Files to process: {len(selected_pairs)}")
            print(f"Total size: {self._format_size(self.stats['total_size'])}")
            if self.preserve_exact_timestamps:
                print(f"Timestamp preservation: ENABLED")
            print()
            
            start_time = time.time()
            
            # Process files with clean output (NO PROGRESS BAR)
            for i, pair in enumerate(selected_pairs, 1):
                try:
                    print(f"Processing: {pair['filename']}")
                    
                    # Process the PDF pair
                    success = await self._process_single_pair(pair)
                    
                    if success:
                        self.stats['processed_files'] += 1
                        print(f"✅ Success: {pair['filename']}")
                    else:
                        self.stats['failed_files'] += 1
                        print(f"❌ Failed: {pair['filename']}")
                    
                except Exception as e:
                    print(f"❌ Error processing {pair['filename']}: {e}")
                    self.stats['failed_files'] += 1
            
            self.stats['processing_time'] = time.time() - start_time
            
            # Display final statistics
            self._display_processing_stats()
            
            return self.stats['processed_files'] > 0
            
        except Exception as e:
            print(f"Batch processing error: {e}")
            return False
    
    async def _process_single_pair(self, pair):
        """Process a single PDF file pair with clean output"""
        try:
            original_pdf = pair['original']
            edited_pdf = pair['edited']
            output_pdf = self.final_dir / pair['filename']
            
            # Check if output already exists
            if output_pdf.exists():
                if not safe_remove_file(output_pdf):
                    logger.error(f"Cannot overwrite existing output: {output_pdf}")
                    return False
            
            # Also check for existing password file
            password_file = output_pdf.with_suffix('.pdf.passwords.txt')
            if password_file.exists():
                safe_remove_file(password_file)
            
            # Detect security settings
            security_info = detect_pdf_security(original_pdf)
            
            # Try to find a working password if needed
            working_password = try_common_passwords(original_pdf) if security_info['has_user_password'] else ''
            
            # Get original file timestamps as backup
            original_file_timestamps = get_original_file_timestamps(original_pdf)
            
            # Extract metadata
            original_metadata = None
            original_visible_metadata = {}
            original_xmp_metadata = None
            raw_dates = {}
            
            if not security_info['has_user_password'] or working_password is not None:
                # We can access the original file
                original_metadata = extract_comprehensive_metadata(original_pdf, working_password)
                if original_metadata:
                    original_visible_metadata = original_metadata['visible']
                    original_xmp_metadata = original_metadata['xmp']
                    raw_dates = original_metadata.get('raw_dates', {})
                else:
                    original_visible_metadata = create_default_metadata()
            else:
                # Cannot access original, use defaults
                original_visible_metadata = create_default_metadata()
            
            # Generate passwords based on detected protection type
            new_user_password = ""
            new_owner_password = ""
            
            if security_info['needs_encryption']:
                if security_info['has_user_password']:
                    new_user_password = generate_random_password(12)
                    new_owner_password = generate_random_password(16)
                else:
                    new_user_password = ""
                    new_owner_password = generate_random_password(16)
            
            # Open edited PDF and apply metadata
            with pikepdf.open(edited_pdf) as pdf:
                # Clear existing metadata
                try:
                    pdf.docinfo.clear()
                except AttributeError:
                    for key in list(pdf.docinfo.keys()):
                        del pdf.docinfo[key]
                
                # Apply visible metadata with exact preservation if enabled
                for k, v in original_visible_metadata.items():
                    if self.preserve_exact_timestamps and k in ['CreationDate', 'ModDate'] and k in raw_dates:
                        # Use the raw date object directly to preserve exact format
                        pdf.docinfo[f'/{k}'] = raw_dates[k]
                    else:
                        pdf.docinfo[f'/{k}'] = v
                
                # Apply XMP metadata if available
                if original_xmp_metadata:
                    # Update XMP dates to match visible metadata if preserving timestamps
                    if self.preserve_exact_timestamps and raw_dates:
                        creation_date = original_visible_metadata.get('CreationDate', '')
                        mod_date = original_visible_metadata.get('ModDate', '')
                        updated_xmp = update_xmp_dates(original_xmp_metadata, creation_date, mod_date)
                        if updated_xmp:
                            pdf.Root.Metadata = pdf.make_stream(updated_xmp.encode('utf-8'))
                    else:
                        pdf.Root.Metadata = pdf.make_stream(original_xmp_metadata.encode('utf-8'))
                elif '/Metadata' in pdf.Root:
                    del pdf.Root.Metadata
                
                # Save with encryption if original had any protection
                if security_info['needs_encryption']:
                    estimated_R = security_info['estimated_R']
                    estimated_V = security_info['estimated_V']
                    pdf_version = security_info['pdf_version']
                    
                    try:
                        permissions = pikepdf.Permissions(
                            print_lowres=True,
                            print_highres=True,
                            modify_annotation=False,
                            modify_other=False,
                            extract=True,
                            modify_assembly=False,
                            modify_form=False,
                            accessibility=True
                        )

                        if estimated_R >= 6 or pdf_version >= '2.0':
                            encrypt_params = pikepdf.Encryption(owner=new_owner_password, user=new_user_password, R=6, allow=permissions, aes=True, metadata=True)
                        elif estimated_R >= 4:
                            encrypt_params = pikepdf.Encryption(owner=new_owner_password, user=new_user_password, R=4, allow=permissions, aes=True, metadata=True)
                        else:
                            encrypt_params = pikepdf.Encryption(owner=new_owner_password, user=new_user_password, R=estimated_R, allow=permissions)
                        
                        pdf.save(output_pdf, encryption=encrypt_params, compress_streams=False, preserve_pdfa=True)
                        
                        # Save password information
                        with open(password_file, 'w') as f:
                            f.write(f"PDF Security Information\n")
                            f.write(f"========================\n\n")
                            f.write(f"File: {pair['filename']}\n\n")
                            if new_user_password:
                                f.write(f"User Password: {new_user_password}\n")
                            else:
                                f.write(f"User Password: (None - no password needed to open)\n")
                            f.write(f"Owner Password: {new_owner_password}\n")
                            f.write(f"Encryption Method: R={estimated_R}, V={estimated_V}\n")
                            f.write(f"PDF Version: {pdf_version}\n")
                            if working_password:
                                f.write(f"Original Password (if found): {working_password}\n")
                            if self.preserve_exact_timestamps and raw_dates:
                                f.write(f"\nTimestamp preservation:\n")
                                f.write(f"- Exact timestamps preserved: Yes\n")
                                f.write(f"- Creation Date: {raw_dates.get('CreationDate', 'N/A')}\n")
                                f.write(f"- Modification Date: {raw_dates.get('ModDate', 'N/A')}\n")
                        
                    except Exception as e:
                        logger.error(f"Error applying encryption: {e}")
                        # Save without encryption as fallback
                        pdf.save(output_pdf, compress_streams=False, preserve_pdfa=True)
                else:
                    # No protection detected, save without encryption
                    pdf.save(output_pdf, compress_streams=False, preserve_pdfa=True)
            
            # Set file system timestamps to match PDF metadata if enabled
            if self.preserve_exact_timestamps and original_metadata and raw_dates:
                creation_date = raw_dates.get('CreationDate')
                mod_date = raw_dates.get('ModDate')
                
                if creation_date or mod_date:
                    success = set_file_timestamps(output_pdf, creation_date, mod_date, original_file_timestamps)
                    if not success:
                        logger.warning("Could not update file system timestamps")
            
            return True
            
        except Exception as e:
            logger.error(f"Error processing PDF pair: {e}")
            return False
    
    def _format_size(self, size_bytes):
        """Format file size in human-readable format"""
        try:
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size_bytes < 1024:
                    return f"{size_bytes:.1f} {unit}"
                size_bytes /= 1024
            return f"{size_bytes:.1f} TB"
        except Exception:
            return "Unknown"
    
    def _display_processing_stats(self):
        """Display professional processing statistics"""
        try:
            print()  # Add spacing
            ProfessionalUI.print_section("Processing Complete", "✅")
            
            # Success summary
            success_rate = (self.stats['processed_files'] / self.stats['total_files']) * 100 if self.stats['total_files'] > 0 else 0
            
            if success_rate == 100:
                status_color = "32"  # Green
                status_msg = "All files processed successfully"
            elif success_rate > 0:
                status_color = "33"  # Yellow  
                status_msg = f"Partial success - {self.stats['failed_files']} files failed"
            else:
                status_color = "31"  # Red
                status_msg = "Processing failed for all files"
            
            ProfessionalUI.print_status_box("PROCESSING COMPLETE", status_msg, status_color)
            
            # Detailed statistics
            print(f"\nProcessing Summary:")
            print(f"   • Files processed: {self.stats['processed_files']}/{self.stats['total_files']}")
            if self.stats['failed_files'] > 0:
                print(f"   • Failed files: {self.stats['failed_files']}")
            print(f"   • Total size: {self._format_size(self.stats['total_size'])}")
            print(f"   • Processing time: {self.stats['processing_time']:.1f} seconds")
            
            if self.stats['processed_files'] > 0:
                avg_time = self.stats['processing_time'] / self.stats['processed_files']
                print(f"   • Average per file: {avg_time:.1f} seconds")
            
            print(f"\n📁 Output location: {self.final_dir}")
            
            # Additional info based on processing type
            if self.preserve_exact_timestamps:
                print("🕒 File timestamps have been preserved to match PDF metadata")
            
        except Exception as e:
            print(f"Error displaying stats: {e}")

class PDFMetadataTool:
    """Main professional PDF processing application with enhanced server integration"""
    
    def __init__(self):
        self.base_dir = Path.cwd()
        self.validator = LicenseValidator()
        self.updater = AutoUpdater()
        self.processor = PDFProcessor(self.base_dir)
        self._setup_signal_handlers()
        
    def _setup_signal_handlers(self):
        """Setup graceful shutdown handlers with enhanced error handling"""
        def signal_handler(signum, frame):
            logger.info("\nGraceful shutdown requested")
            sys.exit(0)
        
        try:
            if platform.system() != "Windows":
                signal.signal(signal.SIGINT, signal_handler)
                signal.signal(signal.SIGTERM, signal_handler)
        except Exception as e:
            if not BUILD_MODE:
                logger.debug(f"Signal handler setup failed: {e}")
    
    async def run(self):
        """Main application entry point with professional flow and enhanced server integration"""
        try:
            # Display professional header
            ProfessionalUI.print_header()
            
            # Display version information (cleaned - removed executable message)
            print(f"Version: {VERSION}")
            
            # CRITICAL: License validation first
            license_result = await self.validator.enforce_license_or_exit()
            
            # Check for updates at startup only (silent check)
            if not BUILD_MODE:
                try:
                    update_info = await self.updater.check_for_updates()
                    if update_info.get("update_available"):
                        await self.updater.prompt_and_update(update_info)
                except Exception:
                    pass  # Silent failure - don't interrupt user experience
            
            # Check system requirements
            self._check_system_requirements()
            
            # Build mode special handling
            if BUILD_MODE:
                ProfessionalUI.print_status_box(
                    "BUILD MODE", 
                    "Application structure validated for PyInstaller build", 
                    "33"
                )
                print("Ready for PyInstaller build process")
                print("Final executable will require valid license")
                return
            
            # Run main processing with enhanced user interaction
            success = await self.processor.process_pdf_files()
            
            if success:
                print("\nSession completed successfully!")
            else:
                print("\nSession ended")
            
        except KeyboardInterrupt:
            print("\nApplication stopped by user")
            ProfessionalUI.print_status_box("INTERRUPTED", "Operation cancelled by user", "33")
            sys.exit(0)
        except Exception as e:
            print(f"Critical error: {e}")
            if not BUILD_MODE:
                try:
                    input("\nPress Enter to exit...")
                except (KeyboardInterrupt, EOFError):
                    pass
            sys.exit(1)
    
    def _check_system_requirements(self):
        """Check system requirements and dependencies with enhanced error handling"""
        try:
            ProfessionalUI.print_section("System Check", "🔍")
            
            # Python version check
            try:
                python_version = platform.python_version()
                print(f"Python Version: {python_version}")
            except Exception:
                print("Python Version: Unknown")
            
            # Platform information
            try:
                print(f"Platform: {platform.system()} {platform.release()}")
                print(f"Architecture: {platform.machine()}")
            except Exception:
                print("Platform: Unknown")
            
            # Check PDF processing capabilities
            if PIKEPDF_AVAILABLE:
                print("PDF Processing: Available (pikepdf)")
            else:
                print("PDF Processing: Not Available - install 'pip install pikepdf'")
            
            # Check Windows timestamp capabilities
            if platform.system() == "Windows" and WIN32_TIMESTAMP_AVAILABLE:
                print("Windows Timestamps: Full support (pywin32)")
            elif platform.system() == "Windows":
                print("Windows Timestamps: Basic support - install 'pip install pywin32' for full features")
            else:
                print("Timestamps: Basic support")
            
            # Memory check (if psutil available)
            if PSUTIL_AVAILABLE:
                try:
                    import psutil
                    memory = psutil.virtual_memory()
                    print(f"Available Memory: {self._format_size(memory.available)}")
                except Exception as e:
                    pass  # Skip memory info if failed
            
            # Disk space check
            try:
                disk_usage = shutil.disk_usage(self.base_dir)
                free_space = disk_usage.free
                print(f"Free Disk Space: {self._format_size(free_space)}")
                
                if free_space < 100 * 1024 * 1024:  # Less than 100MB
                    print("Warning: Low disk space detected")
            except Exception as e:
                pass  # Skip disk space if failed
            
            # Directory structure check
            self._check_directory_structure()
            
            print("System requirements check complete")
        except Exception as e:
            print(f"System check error: {e}")
    
    def _check_directory_structure(self):
        """Check and create directory structure for PDF processing"""
        print("\n📁 Directory Structure:")
        directories = [
            (self.processor.original_dir, "Original PDFs", "Place your original PDF files here"),
            (self.processor.edited_dir, "Edited PDFs", "Place your edited/modified PDF files here"), 
            (self.processor.final_dir, "Final Output", "Processed files with restored metadata")
        ]
        
        for directory, description, purpose in directories:
            try:
                directory.mkdir(exist_ok=True)
                # Test write permission
                test_file = directory / ".permission_test"
                test_file.write_text("test", encoding='utf-8')
                test_file.unlink()
                print(f"   ✅ {description:<15} ({directory.name}/) - {purpose}")
            except Exception as e:
                print(f"   ❌ {description:<15} ({directory.name}/) - Error: {e}")
        
        print(f"\n📂 Full paths:")
        print(f"   Original:  {self.processor.original_dir}")
        print(f"   Edited:    {self.processor.edited_dir}")  
        print(f"   Final:     {self.processor.final_dir}")
        
        # Check if we have the new workflow available
        if PIKEPDF_AVAILABLE:
            print(f"\n🔄 Workflow: Advanced 3-folder PDF metadata restoration")
        else:
            print(f"\n⚠️  Workflow: Basic processing only (install pikepdf for full features)")
            print(f"   📋 To install: pip install pikepdf")
    
    def _format_size(self, size_bytes):
        """Format file size in human-readable format"""
        try:
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size_bytes < 1024:
                    return f"{size_bytes:.1f} {unit}"
                size_bytes /= 1024
            return f"{size_bytes:.1f} TB"
        except Exception:
            return "Unknown"

async def main():
    """Application entry point with professional error handling and enhanced PyInstaller compatibility"""
    try:
        # Initialize and run the professional tool
        tool = PDFMetadataTool()
        await tool.run()
        
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"Application failed: {e}")
        if not BUILD_MODE:
            try:
                input("\nPress Enter to exit...")
            except (KeyboardInterrupt, EOFError):
                pass
        sys.exit(1)
    finally:
        if not BUILD_MODE:
            try:
                print("\n" + "─" * 60)
                print(f"Thank you for using {APP_TITLE}!")
                print(f"Support: {CONTACT_EMAIL}")
                print("─" * 60)
                input("Press Enter to exit...")
            except (KeyboardInterrupt, EOFError, Exception):
                pass

if __name__ == "__main__":
    # Run the professional application with enhanced PyInstaller compatibility
    try:
        # Set Windows-specific event loop policy for better PyInstaller compatibility
        if platform.system() == "Windows":
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            except Exception:
                pass  # Fallback gracefully
        
        # Run the main application
        asyncio.run(main())
        
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        if not BUILD_MODE:
            try:
                input("\nPress Enter to exit...")
            except (KeyboardInterrupt, EOFError):
                pass
        sys.exit(1)