#!/usr/bin/env python3
"""
Build Script for PDF Metadata Processor EXE
============================================
Creates a standalone Windows executable with all dependencies.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def install_dependencies():
    """Install required packages"""
    packages = [
        "pikepdf>=9.0.0",
        "requests>=2.31.0", 
        "pyinstaller>=6.0.0",
        "win32-setctime>=1.1.0",  # For timestamp preservation on Windows
        "pywin32>=306"  # For Windows API access
    ]
    
    print("Installing dependencies...")
    for package in packages:
        print(f"Installing {package}...")
        subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)

def create_icon():
    """Create a basic icon file"""
    # This would create an icon file - for now we'll skip
    pass

def build_exe():
    """Build the standalone executable"""
    print("\nBuilding executable...")
    
    # PyInstaller command
    cmd = [
        "pyinstaller",
        "--onefile",                    # Single file
        "--windowed",                   # No console window (GUI app)
        "--name", "PDF-Metadata-Processor",
        "--add-data", "client.py;.",    # Include source
        "--hidden-import", "pikepdf",
        "--hidden-import", "win32file",
        "--hidden-import", "win32con", 
        "--hidden-import", "win32_setctime",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--collect-all", "pikepdf",
        "--noupx",                      # Don't use UPX compression
        "client.py"
    ]
    
    subprocess.run(cmd, check=True)
    print("\n✅ Build completed!")
    
    # Show result
    exe_path = Path("dist") / "PDF-Metadata-Processor.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"📦 Executable: {exe_path}")
        print(f"📏 Size: {size_mb:.1f} MB")
    else:
        print("❌ Executable not found!")

def main():
    """Main build process"""
    print("🔨 PDF Metadata Processor - Build Script")
    print("=" * 50)
    
    try:
        install_dependencies()
        build_exe()
        
        print("\n🎉 Build process completed!")
        print("\nInstructions:")
        print("1. The EXE file is in the 'dist' folder")
        print("2. Distribute the EXE file to users")
        print("3. Users get 1 free trial, then need a license key")
        print("4. Create license keys at: https://pdf-license-server-dmyx.onrender.com/admin")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
