# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project specification first for layer caching
COPY pyproject.toml ./

# Install python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir \
    PyYAML \
    requests \
    keyring \
    networkx \
    scikit-learn \
    pyvis \
    stix2 \
    typer \
    rich \
    reportlab

# Copy application source code
COPY core/ ./core/
COPY data/ ./data/
COPY cli/ ./cli/
COPY app/ ./app/

# Install mailintel package in editable mode
RUN pip install --no-cache-dir -e .

# Create workspace directory for volume mounting
RUN mkdir -p /workspace /reports /exports
WORKDIR /workspace

# Default command displays the MailIntel CLI help
ENTRYPOINT ["mailintel"]
CMD ["--help"]
