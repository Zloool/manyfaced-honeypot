# syntax=docker/dockerfile:1
# Manyfaced honeypot — production-facing image.
# The honeypot binds privileged/low ports (top mode) and deliberately attracts
# hostile traffic, so the container is a natural blast-radius boundary and runs
# as a non-root user. Privileged ports are mapped to high container ports and
# redirected via iptables (see templates/setup-iptables-privileged-ports.sh),
# mirroring the existing droplet approach.

FROM python:3.12-slim

# Create a non-root user to run the honeypot.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin honeypot

# Tooling needed to pull pinned deps and verify the build.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy the full source first, then install. `pip install .` builds the
# `manyfaced` package via the setuptools backend, which must find the
# `manyfaced/` source tree at build time — so the source has to be present
# before install, not after.
COPY . .

# Install dependencies. cryptography is the only runtime dependency
# (pyproject.toml); the build backend (setuptools/wheel) is installed
# explicitly so `pip install .` works.
RUN pip install --upgrade pip setuptools wheel \
    && pip install .[postgres]

# Persisted capture data + logs live here (mount a named volume on this path).
RUN mkdir -p /opt/manyfaced/bots && chown -R honeypot:honeypot /opt/manyfaced /app
VOLUME ["/opt/manyfaced/bots"]

USER honeypot

# Container entrypoint: run the honeypot (both client + server by default).
# Use the installed console script (pip install . provides `manyfaced`).
ENTRYPOINT ["manyfaced"]
