#!/usr/bin/env python3
"""
PDF Metadata Processor - Standalone Client
===========================================
Standalone EXE with license validation and timestamp preservation.
- 1 Free trial use
- License validation with server
- Perfect timestamp preservation
- Offline license caching
"""

import os
import sys
import json
import hashlib
import platform
import subprocess
import tempfile
import shutil
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple, Any

# PDF Processing
try:
    import pikepdf
    from pikepdf import Pdf, Dictionary, Name, String
    PIKEPDF_AVAILABLE = True
except ImportError:
    PIKEPDF_AVAILABLE = False

VERSION = "1.0.0"
LICENSE_SERVER_URL = "https://pdf-license-server-dmyx.onrender.com"

class TrialManager:
    """Manages trial usage and license validation"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".pdf_processor"
        self.config_dir.mkdir(exist_ok=True)
        self.trial_file = self.config_dir / "trial.json"
        self.license_file = self.config_dir / "license.json"
        
    def get_hardware_id(self):
        """Generate hardware fingerprint"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['wmic', 'csproduct', 'get', 'uuid'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    uuid_line = [line for line in result.stdout.split('\n') if line.strip() and 'UUID' not in line.upper()]
                    if uuid_line:
                        return uuid_line[0].strip()
            
            # Fallback
            hardware_id = hashlib.sha256(f"{platform.node()}{platform.processor()}".encode()).hexdigest()[:16]
            return hardware_id
        except:
            return hashlib.sha256(f"FALLBACK_{int(datetime.now().timestamp())}".encode()).hexdigest()[:16]
    
    def check_trial_available(self):
        """Check if trial is still available"""
        if not self.trial_file.exists():
            return True
            
        try:
            with open(self.trial_file, 'r') as f:
                trial_data = json.load(f)
            return trial_data.get('uses', 0) < 1
        except:
            return True
    
    def use_trial(self):
        """Use one trial attempt"""
        trial_data = {'uses': 1, 'used_at': datetime.now().isoformat()}
        
        try:
            with open(self.trial_file, 'w') as f:
                json.dump(trial_data, f)
            return True
        except:
            return False
    
    def validate_license(self, license_key):
        """Validate license with server"""
        try:
            validation_data = {
                "license_key": license_key,
                "hardware_id": self.get_hardware_id(),
                "client_version": VERSION,
                "timestamp": int(datetime.now().timestamp()),
                "platform": platform.system()
            }
            
            response = requests.post(
                f"{LICENSE_SERVER_URL}/api/validate-license",
                json=validation_data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('valid'):
                    # Cache valid license
                    self.cache_license(license_key, result)
                    return True, result
                else:
                    return False, result.get('message', 'Invalid license')
            else:
                return False, f"Server error: {response.status_code}"
                
        except requests.RequestException as e:
            # Check cached license if server unavailable
            return self.check_cached_license(license_key)
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def cache_license(self, license_key, validation_result):
        """Cache valid license for offline use"""
        try:
            cache_data = {
                'license_key': license_key,
                'cached_at': datetime.now().isoformat(),
                'expires': validation_result.get('expires'),
                'customer_info': validation_result.get('customer_info', {})
            }
            
            with open(self.license_file, 'w') as f:
                json.dump(cache_data, f)
        except:
            pass
    
    def check_cached_license(self, license_key):
        """Check cached license when server unavailable"""
        if not self.license_file.exists():
            return False, "No cached license available"
        
        try:
            with open(self.license_file, 'r') as f:
                cache_data = json.load(f)
            
            if cache_data.get('license_key') == license_key:
                expires_str = cache_data.get('expires')
                if expires_str:
                    expires_date = datetime.fromisoformat(expires_str.replace('Z', '+00:00'))
                    if datetime.now(timezone.utc) < expires_date:
                        return True, "Valid cached license"
                    else:
                        return False, "Cached license expired"
                else:
                    return True, "Valid cached license (no expiration)"
            else:
                return False, "License key mismatch"
        except:
            return False, "Invalid cached license"

class TimestampPreserver:
    """Preserves file system timestamps"""
    
    @staticmethod
    def get_file_times(filepath):
        """Get file creation, modification, and access times"""
        stat = os.stat(filepath)
        return {
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'accessed': stat.st_atime
        }
    
    @staticmethod
    def set_file_times(filepath, times):
        """Restore file times"""
        try:
            # Set access and modification times
            os.utime(filepath, (times['accessed'], times['modified']))
            
            # On Windows, try to set creation time
            if platform.system() == "Windows":
                try:
                    import win32file
                    import win32con
                    from win32_setctime import setctime
                    setctime(filepath, times['created'])
                except ImportError:
                    # Fallback: use subprocess with powershell
                    try:
                        creation_time = datetime.fromtimestamp(times['created']).strftime('%m/%d/%Y %H:%M:%S')
                        cmd = f'powershell.exe "(Get-Item \\"{filepath}\\").CreationTime = \\"{creation_time}\\""'
                        subprocess.run(cmd, shell=True, capture_output=True)
                    except:
                        pass
        except Exception as e:
            print(f"Warning: Could not preserve timestamps: {e}")

class PDFProcessor:
    """PDF metadata processing with timestamp preservation"""
    
    @staticmethod
    def extract_metadata(pdf_path, password=''):
        """Extract comprehensive metadata from PDF"""
        if not PIKEPDF_AVAILABLE:
            raise Exception("pikepdf not available")
        
        metadata = {
            'docinfo': {},
            'xmp': None,
            'dates': {},
            'pdf_version': None,
            'page_count': 0,
            'file_size': os.path.getsize(pdf_path)
        }
        
        with pikepdf.open(pdf_path, password=password) as pdf:
            metadata['pdf_version'] = str(pdf.pdf_version)
            metadata['page_count'] = len(pdf.pages)
            
            # Document Info Dictionary
            if pdf.docinfo:
                for key, value in pdf.docinfo.items():
                    clean_key = str(key).lstrip('/')
                    metadata['docinfo'][clean_key] = str(value)
            
            # XMP Metadata
            if hasattr(pdf.Root, 'Metadata'):
                try:
                    metadata['xmp'] = pdf.Root.Metadata.read_bytes()
                except:
                    pass
        
        return metadata
    
    @staticmethod
    def apply_metadata(input_path, metadata, output_path):
        """Apply metadata to PDF"""
        if not PIKEPDF_AVAILABLE:
            raise Exception("pikepdf not available")
        
        with pikepdf.open(input_path) as pdf:
            # Apply document info
            if hasattr(pdf, 'docinfo'):
                try:
                    del pdf.docinfo
                except:
                    pass
            
            for key, value in metadata['docinfo'].items():
                key_with_slash = Name(f'/{key}') if not key.startswith('/') else Name(key)
                pdf.docinfo[key_with_slash] = String(str(value))
            
            # Apply XMP metadata
            if metadata.get('xmp'):
                try:
                    pdf.Root.Metadata = pikepdf.Stream(pdf, metadata['xmp'])
                except:
                    pass
            
            pdf.save(output_path)

class PDFProcessorGUI:
    """Main GUI application"""
    
    def __init__(self):
        self.trial_manager = TrialManager()
        self.current_license = None
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("🔐 PDF Metadata Processor")
        self.root.geometry("600x500")
        self.root.configure(bg='#f0f0f0')
        
        # Style
        style = ttk.Style()
        style.theme_use('clam')
        
        self.create_widgets()
        
    def create_widgets(self):
        """Create GUI widgets"""
        # Title
        title_frame = tk.Frame(self.root, bg='#f0f0f0')
        title_frame.pack(pady=20)
        
        title_label = tk.Label(title_frame, text="🔐 PDF Metadata Processor", 
                              font=('Arial', 18, 'bold'), bg='#f0f0f0')
        title_label.pack()
        
        # Hardware ID display
        hw_frame = tk.Frame(self.root, bg='#f0f0f0')
        hw_frame.pack(pady=5)
        
        hw_label = tk.Label(hw_frame, text=f"Hardware ID: {self.trial_manager.get_hardware_id()}", 
                           font=('Arial', 10), bg='#f0f0f0', fg='#666')
        hw_label.pack()
        
        # License section
        license_frame = tk.LabelFrame(self.root, text="License", padx=20, pady=20, bg='#f0f0f0')
        license_frame.pack(padx=20, pady=20, fill='x')
        
        tk.Label(license_frame, text="License Key:", bg='#f0f0f0').grid(row=0, column=0, sticky='w', pady=5)
        self.license_entry = tk.Entry(license_frame, width=30, font=('Arial', 10))
        self.license_entry.grid(row=0, column=1, padx=10, pady=5)
        self.license_entry.insert(0, "PDFM-XXXX-XXXX-XXXX")
        
        validate_btn = tk.Button(license_frame, text="Validate License", 
                               command=self.validate_license, bg='#4CAF50', fg='white')
        validate_btn.grid(row=0, column=2, padx=10, pady=5)
        
        # Trial info
        trial_available = self.trial_manager.check_trial_available()
        trial_text = "✅ 1 Free Trial Available" if trial_available else "❌ Trial Used"
        self.trial_label = tk.Label(license_frame, text=trial_text, 
                                   fg='green' if trial_available else 'red', bg='#f0f0f0')
        self.trial_label.grid(row=1, column=0, columnspan=3, pady=10)
        
        # File selection
        file_frame = tk.LabelFrame(self.root, text="PDF Files", padx=20, pady=20, bg='#f0f0f0')
        file_frame.pack(padx=20, pady=20, fill='x')
        
        tk.Label(file_frame, text="Original PDF (with metadata):", bg='#f0f0f0').grid(row=0, column=0, sticky='w', pady=5)
        self.original_path = tk.StringVar()
        tk.Entry(file_frame, textvariable=self.original_path, width=40, state='readonly').grid(row=0, column=1, padx=10, pady=5)
        tk.Button(file_frame, text="Browse", command=self.select_original).grid(row=0, column=2, pady=5)
        
        tk.Label(file_frame, text="Edited PDF (needs metadata):", bg='#f0f0f0').grid(row=1, column=0, sticky='w', pady=5)
        self.edited_path = tk.StringVar()
        tk.Entry(file_frame, textvariable=self.edited_path, width=40, state='readonly').grid(row=1, column=1, padx=10, pady=5)
        tk.Button(file_frame, text="Browse", command=self.select_edited).grid(row=1, column=2, pady=5)
        
        # Process button
        process_btn = tk.Button(self.root, text="🔄 Process PDF", font=('Arial', 12, 'bold'),
                               command=self.process_files, bg='#2196F3', fg='white', 
                               height=2, width=20)
        process_btn.pack(pady=30)
        
        # Status
        self.status_var = tk.StringVar()
        status_label = tk.Label(self.root, textvariable=self.status_var, 
                               font=('Arial', 10), bg='#f0f0f0', fg='#666')
        status_label.pack(pady=10)
        
    def validate_license(self):
        """Validate license key"""
        license_key = self.license_entry.get().strip()
        if not license_key or license_key == "PDFM-XXXX-XXXX-XXXX":
            messagebox.showerror("Error", "Please enter a valid license key")
            return
        
        self.status_var.set("Validating license...")
        self.root.update()
        
        valid, result = self.trial_manager.validate_license(license_key)
        
        if valid:
            self.current_license = license_key
            messagebox.showinfo("Success", "✅ License validated successfully!")
            self.status_var.set("✅ Licensed version active")
        else:
            messagebox.showerror("License Error", f"❌ {result}")
            self.status_var.set("❌ License validation failed")
    
    def select_original(self):
        """Select original PDF file"""
        filename = filedialog.askopenfilename(
            title="Select Original PDF",
            filetypes=[("PDF files", "*.pdf")]
        )
        if filename:
            self.original_path.set(filename)
    
    def select_edited(self):
        """Select edited PDF file"""  
        filename = filedialog.askopenfilename(
            title="Select Edited PDF", 
            filetypes=[("PDF files", "*.pdf")]
        )
        if filename:
            self.edited_path.set(filename)
    
    def process_files(self):
        """Process PDF files"""
        if not PIKEPDF_AVAILABLE:
            messagebox.showerror("Error", "PDF processing library not available")
            return
            
        # Check files
        original_file = self.original_path.get()
        edited_file = self.edited_path.get()
        
        if not original_file or not edited_file:
            messagebox.showerror("Error", "Please select both PDF files")
            return
        
        if not os.path.exists(original_file) or not os.path.exists(edited_file):
            messagebox.showerror("Error", "Selected files do not exist")
            return
        
        # Check authorization
        has_permission = False
        
        if self.current_license:
            has_permission = True
            auth_method = "licensed"
        elif self.trial_manager.check_trial_available():
            if messagebox.askyesno("Use Trial", 
                                 "This will use your free trial. Continue?"):
                self.trial_manager.use_trial()
                has_permission = True
                auth_method = "trial"
                # Update trial status
                self.trial_label.config(text="❌ Trial Used", fg='red')
        
        if not has_permission:
            messagebox.showerror("Authorization Required", 
                               "Please validate a license key or use your free trial")
            return
        
        # Process files
        try:
            self.status_var.set("Processing PDF files...")
            self.root.update()
            
            # Get original file timestamps
            original_times = TimestampPreserver.get_file_times(original_file)
            edited_times = TimestampPreserver.get_file_times(edited_file)
            
            # Extract metadata from original
            original_metadata = PDFProcessor.extract_metadata(original_file)
            
            # Create output file
            output_dir = os.path.dirname(edited_file)
            output_name = f"processed_{os.path.basename(edited_file)}"
            output_path = os.path.join(output_dir, output_name)
            
            # Apply metadata
            PDFProcessor.apply_metadata(edited_file, original_metadata, output_path)
            
            # Preserve timestamps on output file
            TimestampPreserver.set_file_times(output_path, original_times)
            
            # Success
            self.status_var.set(f"✅ Success! Processed file saved as: {output_name}")
            
            messagebox.showinfo("Success", 
                              f"✅ PDF processed successfully!\n\n"
                              f"Output: {output_name}\n"
                              f"Location: {output_dir}\n"
                              f"Authorization: {auth_method.title()}")
            
        except Exception as e:
            self.status_var.set(f"❌ Error: {str(e)}")
            messagebox.showerror("Processing Error", f"❌ {str(e)}")
    
    def run(self):
        """Start the GUI"""
        self.root.mainloop()

def main():
    """Main entry point"""
    if not PIKEPDF_AVAILABLE:
        print("ERROR: pikepdf not installed")
        print("This application requires pikepdf for PDF processing.")
        if hasattr(sys, '_MEIPASS'):  # Running as EXE
            input("Press Enter to exit...")
        sys.exit(1)
    
    app = PDFProcessorGUI()
    app.run()

if __name__ == "__main__":
    main()
