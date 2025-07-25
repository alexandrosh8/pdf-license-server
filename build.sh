#!/bin/bash
set -o errexit

echo "Starting build process..."

# Update pip to latest version
python -m pip install --upgrade pip

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Create releases directory if it doesn't exist
mkdir -p releases

echo "Build completed successfully"
