#!/bin/bash

# PDF License Server Start Script
# This script provides alternative startup methods for different environments

set -e

PORT=${PORT:-8000}
HOST=${HOST:-0.0.0.0}
WEB_CONCURRENCY=${WEB_CONCURRENCY:-1}

echo "Starting PDF License Server..."
echo "Port: $PORT"
echo "Host: $HOST"
echo "Workers: $WEB_CONCURRENCY"

# Method 1: Try Gunicorn with config file (preferred)
if [ -f "gunicorn.conf.py" ]; then
    echo "Using Gunicorn with configuration file..."
    exec gunicorn -c gunicorn.conf.py app:app
fi

# Method 2: Try Gunicorn without config file
if command -v gunicorn &> /dev/null; then
    echo "Using Gunicorn with inline configuration..."
    exec gunicorn app:app \
        --bind $HOST:$PORT \
        --workers $WEB_CONCURRENCY \
        --worker-class uvicorn.workers.UvicornWorker \
        --access-logfile - \
        --error-logfile - \
        --log-level info
fi

# Method 3: Fallback to Uvicorn (development)
echo "Falling back to Uvicorn..."
exec uvicorn app:app --host $HOST --port $PORT --log-level info