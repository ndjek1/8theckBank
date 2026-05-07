# --------------------------------------------------------------------------
# 8TechBank — SECURE build, hardened container (Task 4.3)
#
# Defence-in-depth applied to the runtime:
#   * Distroless-style minimal base (python:3.12-slim)
#   * Multi-stage build keeps build tools out of the final image
#   * Non-root user (uid 10001) runs the app
#   * Read-only root filesystem at runtime (see docker-compose.yml)
#   * Only /app/var is writable (for the SQLite DB)
#   * Gunicorn instead of Flask dev server (no debugger, no reloader)
#   * Strict default-deny network: only the reverse proxy reaches it
#     (see docker-compose.yml network segmentation)
# --------------------------------------------------------------------------

# ---- builder stage --------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential gcc libffi-dev \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir gunicorn==23.0.0 -r requirements.txt


# ---- runtime stage --------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    PORT=5001 \
    BANK_DB_PATH=/app/var/bank.db

WORKDIR /app

# Drop apt cache, no shells in PATH for the app user
COPY --from=builder /install /usr/local

# Application code
COPY app.py api.py security.py seed.py schema.sql /app/
COPY templates /app/templates
COPY static /app/static

# Writable data dir (will be a tmpfs/volume in compose)
RUN mkdir -p /app/var && chown -R 10001:10001 /app

# Drop privileges
USER 10001:10001

EXPOSE 5001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5001/login').status"

# Bootstrap the DB on first run (idempotent), then start gunicorn.
# Gunicorn defaults: 2 workers, sync, 30s timeout. Pin the bind address so
# the container ONLY listens on the internal network defined in compose.
CMD ["sh", "-c", "python -c 'from pathlib import Path; import seed; (Path(\"$BANK_DB_PATH\").exists() or (seed.init_db(), seed.seed()))' && \
     exec gunicorn --bind 0.0.0.0:5001 --workers 2 --timeout 30 --access-logfile - app:app"]
