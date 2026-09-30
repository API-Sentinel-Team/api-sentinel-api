# syntax=docker/dockerfile:1.7
# API service image. Build (sentinel-core is private, so pass a token as a BuildKit secret):
#   DOCKER_BUILDKIT=1 docker build --secret id=gh_token,env=GH_TOKEN -t api-sentinel-api .
ARG PYTHON_VERSION=3.11

FROM python:${PYTHON_VERSION}-slim-bookworm AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc git libpcap-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /build
# sentinel-core is a private repo: the token comes from a BuildKit secret and never lands in a layer.
RUN --mount=type=secret,id=gh_token \
    git config --global url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf "https://github.com/" \
    && pip install "sentinel-core @ git+https://github.com/API-Sentinel-Team/api-sentinel-core.git@v0.3.0" \
    ; rc=$?; git config --global --unset-all url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadof || true; exit $rc

COPY pyproject.toml ./
COPY server/ ./server/
# Service-only runtime dependency (deliberately not part of sentinel-core):
RUN pip install "uvicorn[standard]==0.42.0"
RUN pip install --no-deps .
# Fail the build, not the deployment, if a required import is missing.
RUN python -c "import uvicorn, server.api.main"

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH" APP_HOME=/app
LABEL org.opencontainers.image.title="api-sentinel-api" \
      org.opencontainers.image.source="https://github.com/API-Sentinel-Team/api-sentinel-api"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libpcap0.8 libpq5 tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 appsentinel \
    && useradd --system --uid 10001 --gid appsentinel --home-dir /app --shell /usr/sbin/nologin appsentinel
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
RUN mkdir -p /app/data/archives /app/models && chown -R appsentinel:appsentinel /app
USER appsentinel
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/health/live || exit 1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "server.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"]
