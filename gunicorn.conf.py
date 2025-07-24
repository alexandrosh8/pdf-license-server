# Gunicorn configuration for FastAPI async application
import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
backlog = 2048

# Worker processes
workers = int(os.getenv('WEB_CONCURRENCY', '1'))
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
preload_app = True

# Logging
loglevel = "info"
accesslog = "-"
errorlog = "-"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'pdf_license_server'

# Server mechanics
daemon = False
pidfile = None  # Don't use pidfile on Render
user = None
group = None
tmp_upload_dir = None

# SSL (not needed for Render)
keyfile = None
certfile = None

# Timeout settings
timeout = 30
keepalive = 5
graceful_timeout = 30

# Memory management
limit_request_line = 0
limit_request_field_size = 0

# Security
forwarded_allow_ips = "*"  # Allow Render's load balancer
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}

# Enable for debugging
# capture_output = True
# enable_stdio_inheritance = True
