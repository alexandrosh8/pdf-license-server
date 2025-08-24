import os

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"
backlog = 2048

# Worker processes - conservative for free tier
workers = 1
worker_class = "sync"  # Changed from uvicorn.workers.UvicornWorker to sync for Flask
worker_connections = 1000

# Timeouts optimized for Render
timeout = 120
keepalive = 5
graceful_timeout = 30

# Restart workers after this many requests (memory management)
max_requests = 1000
max_requests_jitter = 100

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Process naming
proc_name = "pdf_license_server"

# Worker temporary directory (use /tmp on Render)
worker_tmp_dir = "/tmp"

# Preload app for better memory usage
preload_app = True

# Security and limits
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Signal handling
forwarded_allow_ips = "*"
proxy_allow_ips = "*"

def when_ready(server):
    server.log.info("PDF License Server ready to accept connections")

def worker_exit(server, worker):
    server.log.info(f"Worker {worker.pid} exited")

def on_exit(server):
    server.log.info("PDF License Server shutting down")
