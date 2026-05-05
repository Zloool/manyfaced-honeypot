FROM python:3.14-slim

LABEL maintainer="zhavoronkov.p@gmail.com"
LABEL description="Multi-faced honeypot - detects and logs bot activity"

# Avoid interactive prompts during install
ENV DEBIAN_FRONTEND=noninteractive

# Create non-root user
RUN groupadd --system honeypot && \
    useradd --system --gid honeypot --create-home honeypot

# Set working directory
WORKDIR /opt/manyfaced

# Install dependencies first (layer caching)
COPY pyproject.toml README.md LICENSE ./
RUN pip install --no-cache-dir .

# Copy application code
COPY manyfaced/ ./manyfaced/

# Create directories for runtime data
RUN mkdir -p /var/lib/manyfaced/bots && \
    mkdir -p /var/log/manyfaced && \
    chown -R honeypot:honeypot /var/lib/manyfaced /var/log/manyfaced

# Switch to non-root user
USER honeypot

# Environment variables
ENV HONEY_DB_PATH=/var/lib/manyfaced/bots/honeypot.sqlite
ENV HONEY_LOG_FILE=/var/log/manyfaced/honeypot.log
ENV PYTHONUNBUFFERED=1

# Expose default ports (client honeypot + server honeypot)
EXPOSE 8080 8081

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 8080)); s.close()" || exit 1

# Default command: run both client and server
CMD ["manyfaced", "--server", "8080", "--client", "8081"]
