#!/usr/bin/env python3
"""
Setup Credentials Helper for PDF License Server
This script helps generate secure credentials for deployment
"""

import secrets
import string
import sys

def generate_secret_key():
    """Generate a secure secret key for Flask"""
    return secrets.token_urlsafe(32)

def generate_password(length=16):
    """Generate a secure password"""
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*"
    
    # Ensure password has at least one of each type
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]
    
    # Fill the rest with random characters
    all_chars = lowercase + uppercase + digits + symbols
    for _ in range(length - 4):
        password.append(secrets.choice(all_chars))
    
    # Shuffle the password
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

def main():
    print("🔐 PDF License Server - Deployment Credentials Generator")
    print("=" * 55)
    print()
    
    # Generate credentials
    secret_key = generate_secret_key()
    admin_password = generate_password(16)
    
    print("📋 Copy these environment variables to Render.com:")
    print()
    print(f"PYTHON_VERSION=3.12.0")
    print(f"SECRET_KEY={secret_key}")
    print(f"ADMIN_USERNAME=admin")
    print(f"ADMIN_PASSWORD={admin_password}")
    print()
    print("⚠️  IMPORTANT SECURITY NOTES:")
    print("1. Save these credentials securely")
    print("2. Never commit them to Git")
    print("3. Change admin username if desired")
    print("4. Use these exact values in Render's environment variables")
    print()
    
    # Optional: Save to .env file for local testing
    save_local = input("Save to .env file for local testing? (y/n): ").lower()
    if save_local == 'y':
        with open('.env', 'w') as f:
            f.write(f"SECRET_KEY={secret_key}\n")
            f.write(f"ADMIN_USERNAME=admin\n")
            f.write(f"ADMIN_PASSWORD={admin_password}\n")
            f.write(f"# DATABASE_URL will be set by Render\n")
        print("✅ Saved to .env file (remember to add .env to .gitignore!)")
    
    print()
    print("🚀 Ready to deploy! Follow the deployment guide.")

if __name__ == "__main__":
    main()