# ==============================================================================
# Gunicorn Production WSGI Server Configuration
# ==============================================================================
import multiprocessing
import os

# Server socket
bind = os.environ.get("GUNICORN_BIND", "0.0.0.0:5000")
backlog = 2048

# Worker processes & threading
# We use gthread (threaded workers) to properly support SSE streaming and async I/O
workers = int(os.environ.get("GUNICORN_WORKERS", 2))
threads = int(os.environ.get("GUNICORN_THREADS", 4))
worker_class = "gthread"
worker_connections = 1000
timeout = 120
keepalive = 5

# Process naming
proc_name = "ai_security_scanner_wsgi"

# Logging
accesslog = os.environ.get("GUNICORN_ACCESS_LOG", "logs/access.log")
errorlog = os.environ.get("GUNICORN_ERROR_LOG", "logs/error.log")
loglevel = os.environ.get("LOG_LEVEL", "info").lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sµs'

# Security & Limits
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
