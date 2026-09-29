# syntax=docker/dockerfile:1.7
# Production API image for API Sentinel / API Security Engine.
# Multi-stage: build deps stay out of the runtime layer.

ARG PYTHON_VERSION=3.11

# ── builder ──────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libpcap-dev \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt .

# Strip test-only / optional capture deps from the runtime venv.
RUN python - <<'PY'
from pathlib import Path
skip = {"pytest", "pytest-asyncio", "pytest-cov", "mitmproxy"}
out = []
for raw in Path("requirements.txt").read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    name = line.split("==")[0].split(">=")[0].split("<")[0].split("[")[0].strip().lower()
    if name in skip or name.startswith("pytest"):
        continue
    out.append(line)
Path("/tmp/requirements-runtime.txt").write_text("\n".join(out) + "\n", encoding="utf-8")
PY

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r /tmp/requirements-runtime.txt

# ── runtime ──────────────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_HOME=/app \
    TESTS_LIBRARY_PATH=/app/tests-library

LABEL org.opencontainers.image.title="api-sentinel" \
      org.opencontainers.image.description="API Security Engine API" \
      org.opencontainers.image.source="https://github.com/vediyappanm/API-Sentinel-Team"

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libpcap0.8 \
        libpq5 \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 appsentinel \
    && useradd --system --uid 10001 --gid appsentinel --home-dir /app --shell /usr/sbin/nologin appsentinel

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=appsentinel:appsentinel server/ ./server/
COPY --chown=appsentinel:appsentinel migrations/ ./migrations/
COPY --chown=appsentinel:appsentinel tests-library/ ./tests-library/
COPY --chown=appsentinel:appsentinel alembic.ini .

RUN mkdir -p /app/data/archives /app/models \
    && chown -R appsentinel:appsentinel /app

USER appsentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/health/live || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "server.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"]
