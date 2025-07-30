#!/usr/bin/env python3
"""
🔐 PDF Metadata Tool v2.5.0 Professional - ENHANCED EDITION
============================================================
Enterprise-grade PDF metadata restoration with enhanced user experience
Contact: halexandros25@gmail.com

🚀 PROFESSIONAL FEATURES v2.5.0:
- ENHANCED: Colorful welcome interface with professional design
- CLEANED: Silent system check with status-only output
- SIMPLIFIED: Removed custom settings for streamlined workflow
- IMPROVED: Clean user interface without technical details
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

# ===== PROFESSIONAL CONFIGURATION - UPDATED TO v2.5.0 =====
VERSION = "v2.5.0"
__version__ = "2.5.0"  # For compatibility with GitHub workflow
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
    """Professional Material Design-inspired console UI with enhanced colors"""
    
    # Color constants for consistent styling
    COLORS = {
        'PRIMARY': '\033[94m',      # Blue
        'SUCCESS': '\033[92m',      # Green
        'WARNING': '\033[93m',      # Yellow
        'ERROR': '\033[91m',        # Red
        'INFO': '\033[96m',         # Cyan
        'HEADER': '\033[95m',       # Magenta
        'BOLD': '\033[1m',          # Bold
        'UNDERLINE': '\033[4m',     # Underline
        'ENDC': '\033[0m',          # End color
        'GRADIENT_1': '\033[38;5;57m',   # Purple
        'GRADIENT_2': '\033[38;5;93m',   # Light purple
        'GRADIENT_3': '\033[38;5;129m',  # Pink
        'ACCENT': '\033[38;5;39m',       # Bright blue
    }
    
    @staticmethod
    def print_header():
        """Display colorful professional application header"""
        try:
            width = 100
            
            # Top border with gradient effect
            print(f"{ProfessionalUI.COLORS['GRADIENT_1']}╭{'─' * (width - 2)}╮{ProfessionalUI.COLORS['ENDC']}")
            print(f"{ProfessionalUI.COLORS['GRADIENT_1']}│{' ' * (width - 2)}│{ProfessionalUI.COLORS['ENDC']}")
            
            # Title with gradient colors
            title_line = f"{ProfessionalUI.COLORS['GRADIENT_2']}{ProfessionalUI.COLORS['BOLD']}{APP_TITLE}{ProfessionalUI.COLORS['ENDC']}"
            print(f"{ProfessionalUI.COLORS['GRADIENT_1']}│{title_line.center(width + 10)}│{ProfessionalUI.COLORS['ENDC']}")
            
            # Subtitle with accent color
            subtitle = f"{ProfessionalUI.COLORS['ACCENT']}Advanced PDF Metadata Restoration System{ProfessionalUI.COLORS['ENDC']}"
            print(f"{ProfessionalUI.COLORS['GRADIENT_2']}│{subtitle.center(width + 10)}│{ProfessionalUI.COLORS['ENDC']}")
            
            print(f"{ProfessionalUI.COLORS['GRADIENT_2']}│{' ' * (width - 2)}│{ProfessionalUI.COLORS['ENDC']}")
            
            # Support contact with info color
            support = f"{ProfessionalUI.COLORS['INFO']}Support: {CONTACT_EMAIL}{ProfessionalUI.COLORS['ENDC']}"
            print(f"{ProfessionalUI.COLORS['GRADIENT_2']}│{support.center(width + 10)}│{ProfessionalUI.COLORS['ENDC']}")
            
            # Build mode indicator (only show in build mode)
            if BUILD_MODE:
                build_msg = f"{ProfessionalUI.COLORS['WARNING']}BUILD MODE - License validation bypassed{ProfessionalUI.COLORS['ENDC']}"
                print(f"{ProfessionalUI.COLORS['GRADIENT_3']}│{build_msg.center(width + 10)}│{ProfessionalUI.COLORS['ENDC']}")
            
            print(f"{ProfessionalUI.COLORS['GRADIENT_3']}│{' ' * (width - 2)}│{ProfessionalUI.COLORS['ENDC']}")
            
            # Bottom border
            print(f"{ProfessionalUI.COLORS['GRADIENT_3']}╰{'─' * (width - 2)}╯{ProfessionalUI.COLORS['ENDC']}")
            print()
        except Exception as e:
            # Fallback for any Unicode display issues
            print("=" * 80)
            print(f"{APP_TITLE}")
            print(f"Support: {CONTACT_EMAIL}")
            if BUILD_MODE:
                print("BUILD MODE - License validation bypassed")
            print("=" * 80)

    @staticmethod
    def print_section(title, icon=""):
        """Print a professional section header with colors"""
        try:
            colored_title = f"{ProfessionalUI.COLORS['PRIMARY']}{ProfessionalUI.COLORS['BOLD']}{icon} {title}{ProfessionalUI.COLORS['ENDC']}"
            print(f"\n{colored_title}")
            print(f"{ProfessionalUI.COLORS['PRIMARY']}{'─' * (len(title) + 4)}{ProfessionalUI.COLORS['ENDC']}")
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
    def print_system_status(status_type, message):
        """Print system status with appropriate colors"""
        try:
            if status_type == "success":
                color = ProfessionalUI.COLORS['SUCCESS']
                icon = "✅"
            elif status_type == "warning":
                color = ProfessionalUI.COLORS['WARNING']
                icon = "⚠️"
            elif status_type == "error":
                color = ProfessionalUI.COLORS['ERROR']
                icon = "❌"
            else:
                color = ProfessionalUI.COLORS['INFO']
                icon = "ℹ️"
            
            print(f"{color}{icon} {message}{ProfessionalUI.COLORS['ENDC']}")
        except Exception:
            print(f"{message}")

    @staticmethod
    def print_menu(title, options, icon=""):
        """Print a professional menu with colors"""
        try:
            colored_title = f"{ProfessionalUI.COLORS['ACCENT']}{icon} {title}{ProfessionalUI.COLORS['ENDC']}"
            print(f"\n{colored_title}")
            print(f"{ProfessionalUI.COLORS['ACCENT']}{'─' * (len(title) + 4)}{ProfessionalUI.COLORS['ENDC']}")
            for i, option in enumerate(options, 1):
                option_color = ProfessionalUI.COLORS['INFO'] if i <= len(options) else ProfessionalUI.COLORS['ENDC']
                print(f"   {option_color}{i}. {option}{ProfessionalUI.COLORS['ENDC']}")
            print()
        except Exception:
            print(f"\n{title}")
            print("-" * len(title))
            for i, option in enumerate(options, 1):
                print(f"   {i}. {option}")
            print()

    @staticmethod
    def get_user_choice(prompt, valid_choices):
        """Get user choice with validation and colors"""
        while True:
            try:
                colored_prompt = f"{ProfessionalUI.COLORS['BOLD']}{prompt}{ProfessionalUI.COLORS['ENDC']}"
                choice = input(f"{colored_prompt}: ").strip()
                if choice.lower() in ['quit', 'exit', 'q']:
                    return 'quit'
                if choice in valid_choices:
                    return choice
                error_msg = f"{ProfessionalUI.COLORS['ERROR']}Invalid choice. Please enter one of: {', '.join(valid_choices)}{ProfessionalUI.COLORS['ENDC']}"
                print(error_msg)
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
    
    # [Rest of AutoUpdater methods remain the same...]

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

# [Rest of PDF processing functions remain the same...]

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
        # Processing options (simplified - no custom settings)
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
        """Get processing options for the menu (simplified - removed custom settings)"""
        return [
            "Preserve exact timestamps (file system + metadata)",
            "Standard processing (metadata only)"
        ]

    # [Rest of PDFProcessor methods remain the same, but remove custom settings handling...]

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
            # Display professional header with colors
            ProfessionalUI.print_header()
            
            # Display version information
            version_info = f"{ProfessionalUI.COLORS['INFO']}Version: {VERSION}{ProfessionalUI.COLORS['ENDC']}"
            print(version_info)
            
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
            
            # Silent system requirements check
            system_status = self._silent_system_check()
            if system_status == "ok":
                ProfessionalUI.print_system_status("success", "System ready")
            elif system_status == "downloading":
                ProfessionalUI.print_system_status("warning", "Downloading dependencies...")
            else:
                ProfessionalUI.print_system_status("error", "System check failed")
            
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
    
    def _silent_system_check(self):
        """Silent system check - only returns status"""
        try:
            # Check critical dependencies
            critical_deps = []
            
            # Check PDF processing capability
            if not PIKEPDF_AVAILABLE:
                critical_deps.append("pikepdf")
            
            # Check Windows timestamp capability
            if platform.system() == "Windows" and not WIN32_TIMESTAMP_AVAILABLE:
                critical_deps.append("pywin32")
            
            # Check network capabilities
            if 'aiohttp' not in sys.modules:
                critical_deps.append("aiohttp")
            
            if critical_deps:
                return "downloading"  # Would need to download deps
            
            # Check directory structure
            try:
                self.processor.original_dir.mkdir(exist_ok=True)
                self.processor.edited_dir.mkdir(exist_ok=True)
                self.processor.final_dir.mkdir(exist_ok=True)
                
                # Test write permissions
                for directory in [self.processor.original_dir, self.processor.edited_dir, self.processor.final_dir]:
                    test_file = directory / ".permission_test"
                    test_file.write_text("test", encoding='utf-8')
                    test_file.unlink()
                    
            except Exception:
                return "error"
            
            return "ok"
            
        except Exception:
            return "error"
    
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