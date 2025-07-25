"""
Client Auto-Update Module
========================
Integrate this into your PDF tool application for automatic updates.

Usage:
    from autoupdate import AutoUpdater
    
    updater = AutoUpdater(
        license_server_url="https://your-server.onrender.com",
        current_version="1.0.0",
        app_name="PDF Tool"
    )
    
    # Check for updates during license validation
    updater.check_and_update()
"""

import os
import sys
import json
import hashlib
import requests
import tempfile
import subprocess
import tkinter as tk
from tkinter import messagebox, ttk
from pathlib import Path
from threading import Thread
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AutoUpdater:
    def __init__(self, license_server_url: str, current_version: str, app_name: str = "App"):
        self.license_server_url = license_server_url.rstrip('/')
        self.current_version = current_version
        self.app_name = app_name
        self.update_check_url = f"{self.license_server_url}/api/check-updates"
        self.download_base_url = f"{self.license_server_url}/api/download"
        
    def check_for_updates(self) -> dict:
        """Check if updates are available"""
        try:
            response = requests.post(
                self.update_check_url,
                json={
                    "current_version": self.current_version,
                    "app_name": self.app_name
                },
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Update check failed: {response.status_code}")
                return {"update_available": False, "error": "Check failed"}
                
        except requests.RequestException as e:
            logger.error(f"Update check error: {e}")
            return {"update_available": False, "error": str(e)}
    
    def download_update(self, version: str, progress_callback=None) -> str:
        """Download update file and return path"""
        try:
            download_url = f"{self.download_base_url}/{version}"
            
            response = requests.get(download_url, stream=True, timeout=30)
            if response.status_code != 200:
                raise Exception(f"Download failed: {response.status_code}")
            
            # Get filename from header or use default
            filename = f"{self.app_name}_{version}.exe"
            if 'content-disposition' in response.headers:
                import re
                cd = response.headers['content-disposition']
                match = re.search('filename="?([^"]+)"?', cd)
                if match:
                    filename = match.group(1)
            
            # Download to temp directory
            temp_dir = Path(tempfile.gettempdir()) / "app_updates"
            temp_dir.mkdir(exist_ok=True)
            
            file_path = temp_dir / filename
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if progress_callback and total_size > 0:
                            progress = (downloaded / total_size) * 100
                            progress_callback(progress)
            
            logger.info(f"Update downloaded to: {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Download error: {e}")
            raise
    
    def verify_checksum(self, file_path: str, expected_checksum: str) -> bool:
        """Verify downloaded file integrity"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            actual_checksum = sha256_hash.hexdigest()
            return actual_checksum == expected_checksum
            
        except Exception as e:
            logger.error(f"Checksum verification error: {e}")
            return False
    
    def install_update(self, file_path: str):
        """Install the update"""
        try:
            # On Windows, we can use subprocess to run the installer
            if sys.platform == "win32":
                # Get current executable path
                current_exe = sys.executable if getattr(sys, 'frozen', False) else __file__
                
                # Create batch script for update
                batch_script = f"""
                @echo off
                echo Updating {self.app_name}...
                timeout /t 2 /nobreak > nul
                taskkill /f /im "{Path(current_exe).name}" 2>nul
                timeout /t 1 /nobreak > nul
                copy /y "{file_path}" "{current_exe}"
                start "" "{current_exe}"
                del "%~f0"
                """
                
                batch_path = Path(tempfile.gettempdir()) / "update.bat"
                with open(batch_path, 'w') as f:
                    f.write(batch_script)
                
                # Run batch script and exit
                subprocess.Popen([str(batch_path)], shell=True)
                sys.exit(0)
                
            else:
                # For other platforms, you might need different approaches
                logger.error("Auto-install not supported on this platform")
                messagebox.showinfo(
                    "Update Downloaded", 
                    f"Update downloaded to: {file_path}\nPlease install manually."
                )
                
        except Exception as e:
            logger.error(f"Install error: {e}")
            messagebox.showerror("Install Error", f"Failed to install update: {e}")

class UpdateDialog:
    def __init__(self, parent, update_info: dict, updater: AutoUpdater):
        self.update_info = update_info
        self.updater = updater
        self.result = None
        
        # Create dialog
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Update Available")
        self.dialog.geometry("500x400")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (400 // 2)
        self.dialog.geometry(f"500x400+{x}+{y}")
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_text = "Critical Update Available!" if self.update_info.get('is_critical') else "Update Available"
        title_label = ttk.Label(main_frame, text=title_text, font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 10))
        
        # Version info
        version_frame = ttk.Frame(main_frame)
        version_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(version_frame, text=f"Current Version: {self.update_info['current_version']}").pack(anchor=tk.W)
        ttk.Label(version_frame, text=f"Latest Version: {self.update_info['latest_version']}").pack(anchor=tk.W)
        
        # Release notes
        if self.update_info.get('release_notes'):
            ttk.Label(main_frame, text="Release Notes:", font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(10, 5))
            
            notes_frame = ttk.Frame(main_frame)
            notes_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
            
            text_widget = tk.Text(notes_frame, wrap=tk.WORD, height=8)
            scrollbar = ttk.Scrollbar(notes_frame, orient=tk.VERTICAL, command=text_widget.yview)
            text_widget.configure(yscrollcommand=scrollbar.set)
            
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            text_widget.insert(tk.END, self.update_info['release_notes'])
            text_widget.config(state=tk.DISABLED)
        
        # Progress bar (hidden initially)
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.progress_label = ttk.Label(self.progress_frame, text="")
        self.progress_label.pack()
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        self.progress_frame.pack_forget()  # Hide initially
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        if self.update_info.get('is_critical'):
            # Critical update - only allow update
            ttk.Button(button_frame, text="Update Now", command=self.update_now).pack(side=tk.RIGHT, padx=(5, 0))
        else:
            # Optional update
            ttk.Button(button_frame, text="Update Now", command=self.update_now).pack(side=tk.RIGHT, padx=(5, 0))
            ttk.Button(button_frame, text="Later", command=self.update_later).pack(side=tk.RIGHT, padx=(5, 0))
            ttk.Button(button_frame, text="Skip Version", command=self.skip_version).pack(side=tk.RIGHT)
    
    def update_progress(self, progress):
        """Update progress bar"""
        self.progress_bar['value'] = progress
        self.progress_label.config(text=f"Downloading... {progress:.1f}%")
        self.dialog.update()
    
    def update_now(self):
        """Download and install update"""
        self.result = "update"
        
        # Show progress
        self.progress_frame.pack(fill=tk.X, pady=(10, 0))
        self.progress_label.config(text="Starting download...")
        
        def download_and_install():
            try:
                # Download
                file_path = self.updater.download_update(
                    self.update_info['latest_version'],
                    progress_callback=self.update_progress
                )
                
                # Verify checksum if provided
                if 'checksum' in self.update_info:
                    self.progress_label.config(text="Verifying download...")
                    if not self.updater.verify_checksum(file_path, self.update_info['checksum']):
                        messagebox.showerror("Error", "Download verification failed!")
                        return
                
                # Install
                self.progress_label.config(text="Installing update...")
                self.updater.install_update(file_path)
                
            except Exception as e:
                messagebox.showerror("Update Error", f"Failed to update: {e}")
                self.dialog.destroy()
        
        # Run download in separate thread
        Thread(target=download_and_install, daemon=True).start()
    
    def update_later(self):
        """Postpone update"""
        self.result = "later"
        self.dialog.destroy()
    
    def skip_version(self):
        """Skip this version"""
        self.result = "skip"
        self.dialog.destroy()

def check_and_prompt_update(parent_window, updater: AutoUpdater) -> str:
    """Check for updates and show dialog if available"""
    update_info = updater.check_for_updates()
    
    if not update_info.get('update_available'):
        return "no_update"
    
    # Show update dialog
    dialog = UpdateDialog(parent_window, update_info, updater)
    parent_window.wait_window(dialog.dialog)
    
    return dialog.result or "later"

# Example integration
def example_usage():
    """Example of how to integrate auto-update into your app"""
    
    # Create main window
    root = tk.Tk()
    root.title("PDF Tool")
    root.geometry("600x400")
    
    # Initialize updater
    updater = AutoUpdater(
        license_server_url="https://your-server.onrender.com",
        current_version="1.0.0",
        app_name="PDF Tool"
    )
    
    def check_updates():
        """Button handler for manual update check"""
        result = check_and_prompt_update(root, updater)
        if result == "no_update":
            messagebox.showinfo("No Updates", "You have the latest version!")
    
    def validate_license():
        """Example license validation with auto-update check"""
        # Your existing license validation code here
        license_key = "SLIC-ABCD-EFGH-IJKL-MNOP"
        hardware_id = "unique-hardware-id"
        
        try:
            response = requests.post(
                f"{updater.license_server_url}/api/validate",
                json={
                    "license_key": license_key,
                    "hardware_id": hardware_id,
                    "app_version": updater.current_version,
                    "app_name": updater.app_name
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Check if update info is included in validation response
                if 'update_info' in data and data['update_info'].get('update_available'):
                    check_and_prompt_update(root, updater)
                
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"License validation error: {e}")
            return False
    
    # Create UI
    ttk.Label(root, text="PDF Tool", font=('Arial', 16, 'bold')).pack(pady=20)
    
    ttk.Button(root, text="Validate License", command=validate_license).pack(pady=10)
    ttk.Button(root, text="Check for Updates", command=check_updates).pack(pady=10)
    
    # Check for updates on startup (optional)
    root.after(1000, lambda: check_and_prompt_update(root, updater))
    
    root.mainloop()

if __name__ == "__main__":
    example_usage()
