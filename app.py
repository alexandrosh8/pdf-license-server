#!/usr/bin/env python3
"""
Entry Point for Render Deployment
=================================
Simple entry point that imports the main Flask application from server.py
This ensures compatibility with Render's deployment expectations.
"""

# Import the Flask app from server.py
from server import app

# For compatibility with various deployment platforms
application = app

if __name__ == '__main__':
    # This runs only during local development
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
