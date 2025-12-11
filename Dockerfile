# FQ51BBS Dockerfile
# Lightweight BBS for Meshtastic Mesh Networks
#
# Build: docker build -t fq51bbs .
# Run:   docker run -d --name fq51bbs \
#          --device=/dev/ttyUSB0 \
#          -v fq51bbs_data:/data \
#          -v ./config.toml:/app/config.toml:ro \
#          fq51bbs

FROM python:3.11-slim-bookworm

# Labels
LABEL maintainer="FQ51BBS Project"
LABEL description="Lightweight BBS for Meshtastic Mesh Networks"
LABEL version="0.1.0"

# Build arguments
ARG UID=1000
ARG GID=1000

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # For serial communication
    udev \
    # For Argon2 (native extension)
    libffi-dev \
    # For health checks
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g ${GID} fq51bbs && \
    useradd -u ${UID} -g ${GID} -m -s /bin/bash fq51bbs && \
    # Add to dialout group for serial access
    usermod -aG dialout fq51bbs

# Create directories
RUN mkdir -p /app /data /data/backups /var/log && \
    chown -R fq51bbs:fq51bbs /app /data /var/log

WORKDIR /app

# Install Python dependencies first (for layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=fq51bbs:fq51bbs fq51bbs/ /app/fq51bbs/
COPY --chown=fq51bbs:fq51bbs config.example.toml /app/
COPY --chown=fq51bbs:fq51bbs docker-entrypoint.sh /app/

# Switch to non-root user
USER fq51bbs

# Data volume mount point
VOLUME ["/data"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import sqlite3; sqlite3.connect('/data/fq51bbs.db').execute('SELECT 1')" || exit 1

# Entrypoint handles config validation
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["--config", "/app/config.toml"]
