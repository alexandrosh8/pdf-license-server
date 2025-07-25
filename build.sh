#!/usr/bin/env bash
# Exit on error
set -o errexit

# Update pip to latest version
python -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Create releases directory if it doesn't exist
mkdir -p releases

echo "Build completed successfully"