# ==============================================================================
# AI Security Scanner - Production Dockerfile
# ==============================================================================
FROM python:3.11-slim as base

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SCANNER_TARGET_URL=http://localhost:11434 \
    SCANNER_TARGET_MODEL=llama3 \
    SCANNER_TIMEOUT=60 \
    WEB_PORT=5000 \
    WEB_HOST=0.0.0.0

# Install system dependencies (curl for health check)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt pyyaml pytest pytest-cov

# Copy application source code
COPY core/ ./core/
COPY modules/ ./modules/
COPY web/ ./web/
COPY data/ ./data/
COPY experiments/ ./experiments/
COPY docs/ ./docs/
COPY config.yaml .
COPY gunicorn.conf.py .
COPY main.py .

# Create non-root user and persistent directories
RUN useradd -m -u 1000 scanneruser && \
    mkdir -p logs reports data && \
    chown -R scanneruser:scanneruser /app

# Switch to non-root user
USER scanneruser

# Expose web dashboard port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Launch production WSGI server
CMD ["gunicorn", "--config", "gunicorn.conf.py", "web.app:app"]
