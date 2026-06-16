FROM python:3.12-slim-bookworm AS builder

WORKDIR /app

# Install build deps for compiled wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies into a virtualenv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Production image
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS prod

WORKDIR /app

# Runtime-only libraries (psycopg2 needs libpq)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    yara \
    && rm -rf /var/lib/apt/lists/*

# Pull in compiled venv
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY backend /app/backend

# Create data directories
RUN mkdir -p /app/data/uploads /app/data/yara

EXPOSE 8000

# Use uvicorn directly (gunicorn+uvicorn workers for horizontal scaling)
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
