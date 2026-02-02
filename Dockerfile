# SecMutBench Docker Environment
# Provides reproducible evaluation environment

FROM python:3.11-slim

LABEL maintainer="SecMutBench Team"
LABEL description="SecMutBench: Security Mutation Testing Benchmark"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/benchmark

# Create working directory
WORKDIR /benchmark

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy benchmark files
COPY data/ data/
COPY operators/ operators/
COPY evaluation/ evaluation/
COPY scripts/ scripts/

# Generate difficulty splits
RUN python scripts/generate_splits.py

# Set entrypoint
ENTRYPOINT ["python", "evaluation/evaluate.py"]

# Default command (show help)
CMD ["--help"]
