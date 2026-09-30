#!/usr/bin/env bash
# Create API Sentinel secrets imperatively (idempotent). NEVER commit real values.
#
#   api-sentinel-db       POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB
#   api-sentinel-secrets  DATABASE_URL, REDIS_URL, JWT_SECRET, API_KEY,
#                         ENCRYPTION_KEY, SENSOR_KEY_HASH_PEPPER,
#                         CICD_GATE_SIGNING_SECRET
#   api-sentinel-sensor   api-key / pii-hash-key / account-id (eBPF DaemonSet)
#   harbor-finspot-pull   docker-registry creds for harbor.wecrew.in/finspot/*
#
# Precedence per value: exported env > existing live secret > generated default.
# Re-runs preserve existing keys unless you export an override.
set -euo pipefail

NS=api-sentinel
kubectl get namespace "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS"

rand_hex() { openssl rand -hex "${1:-32}"; }

declare -A CUR_SECRET_DATA=()
load_secret_cache() {
  local name="$1" k v
  while IFS=$'\t' read -r k v; do
    [[ -n "$k" ]] && CUR_SECRET_DATA["${name}/${k}"]="$v"
  done < <(kubectl -n "$NS" get secret "$name" \
             -o go-template='{{range $k,$v := .data}}{{$k}}{{"\t"}}{{$v}}{{"\n"}}{{end}}' \
             2>/dev/null || true)
}
load_secret_cache api-sentinel-db
load_secret_cache api-sentinel-secrets
load_secret_cache api-sentinel-sensor

resolve() {
  local var="$1" secret="$2" key="$3" default="$4" b64
  if [[ -v "$var" && -n "${!var}" ]]; then printf '%s' "${!var}"; return; fi
  b64="${CUR_SECRET_DATA["${secret}/${key}"]-}"
  if [[ -n "$b64" ]]; then printf '%s' "$b64" | base64 -d; return; fi
  printf '%s' "$default"
}

DB_NAME="$(resolve DB_NAME api-sentinel-db POSTGRES_DB api_security)"
DB_USER="$(resolve DB_USER api-sentinel-db POSTGRES_USER appsentinel)"
DB_PASSWORD="$(resolve DB_PASSWORD api-sentinel-db POSTGRES_PASSWORD "$(rand_hex 24)")"

DATABASE_URL="$(resolve DATABASE_URL api-sentinel-secrets DATABASE_URL \
  "postgresql+asyncpg://${DB_USER}:${DB_PASSWORD}@api-sentinel-postgres:5432/${DB_NAME}")"
REDIS_URL="$(resolve REDIS_URL api-sentinel-secrets REDIS_URL "redis://api-sentinel-redis:6379/0")"
JWT_SECRET="$(resolve JWT_SECRET api-sentinel-secrets JWT_SECRET "$(rand_hex 32)$(rand_hex 16)")"
API_KEY="$(resolve API_KEY api-sentinel-secrets API_KEY "$(rand_hex 24)")"
SENSOR_KEY_HASH_PEPPER="$(resolve SENSOR_KEY_HASH_PEPPER api-sentinel-secrets SENSOR_KEY_HASH_PEPPER "$(rand_hex 32)")"
CICD_GATE_SIGNING_SECRET="$(resolve CICD_GATE_SIGNING_SECRET api-sentinel-secrets CICD_GATE_SIGNING_SECRET "$(rand_hex 32)")"

ENCRYPTION_KEY="$(resolve ENCRYPTION_KEY api-sentinel-secrets ENCRYPTION_KEY "")"
if [[ -z "$ENCRYPTION_KEY" ]]; then
  ENCRYPTION_KEY="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
fi

# If DB password rotated via env, rebuild DATABASE_URL unless DATABASE_URL was also exported.
if [[ -v DB_PASSWORD && -n "${DB_PASSWORD}" ]] && [[ ! -v DATABASE_URL || -z "${DATABASE_URL:-}" ]]; then
  :
fi
# Keep DATABASE_URL in sync with resolved DB creds when it still points at the in-cluster service.
if [[ "$DATABASE_URL" == *"@api-sentinel-postgres:5432/"* ]]; then
  DATABASE_URL="postgresql+asyncpg://${DB_USER}:${DB_PASSWORD}@api-sentinel-postgres:5432/${DB_NAME}"
fi

kubectl -n "$NS" delete secret api-sentinel-db --ignore-not-found
kubectl -n "$NS" create secret generic api-sentinel-db \
  --from-literal=POSTGRES_DB="$DB_NAME" \
  --from-literal=POSTGRES_USER="$DB_USER" \
  --from-literal=POSTGRES_PASSWORD="$DB_PASSWORD"

kubectl -n "$NS" delete secret api-sentinel-secrets --ignore-not-found
kubectl -n "$NS" create secret generic api-sentinel-secrets \
  --from-literal=DATABASE_URL="$DATABASE_URL" \
  --from-literal=REDIS_URL="$REDIS_URL" \
  --from-literal=JWT_SECRET="$JWT_SECRET" \
  --from-literal=API_KEY="$API_KEY" \
  --from-literal=ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  --from-literal=SENSOR_KEY_HASH_PEPPER="$SENSOR_KEY_HASH_PEPPER" \
  --from-literal=CICD_GATE_SIGNING_SECRET="$CICD_GATE_SIGNING_SECRET"

# eBPF sensor (API-Sensor DaemonSet). Raw key is hashed into Postgres by register-sensor.sh.
SENSOR_API_KEY="$(resolve SENSOR_API_KEY api-sentinel-sensor api-key "$(rand_hex 32)")"
PII_HASH_KEY="$(resolve PII_HASH_KEY api-sentinel-sensor pii-hash-key "$(rand_hex 32)")"
SENSOR_ACCOUNT_ID="$(resolve SENSOR_ACCOUNT_ID api-sentinel-sensor account-id "1")"

kubectl -n "$NS" delete secret api-sentinel-sensor --ignore-not-found
kubectl -n "$NS" create secret generic api-sentinel-sensor \
  --from-literal=api-key="$SENSOR_API_KEY" \
  --from-literal=pii-hash-key="$PII_HASH_KEY" \
  --from-literal=account-id="$SENSOR_ACCOUNT_ID"

# Harbor pull secret
HARBOR_SERVER="${HARBOR_SERVER:-harbor.wecrew.in}"
HARBOR_USER="${HARBOR_USER:-}"
HARBOR_PASSWORD="${HARBOR_PASSWORD:-${HARBOR_PASS:-}}"

if [[ -z "$HARBOR_USER" || -z "$HARBOR_PASSWORD" ]] && [[ -f "${HOME}/.docker/config.json" ]]; then
  read -r HARBOR_USER HARBOR_PASSWORD < <(python3 - <<'PY'
import json, base64, os, sys
cfg = json.load(open(os.path.expanduser("~/.docker/config.json")))
entry = cfg.get("auths", {}).get("harbor.wecrew.in") or cfg.get("auths", {}).get("harbor.wecrew.in:8443")
if not entry or "auth" not in entry:
    sys.exit(0)
user, pwd = base64.b64decode(entry["auth"]).decode().split(":", 1)
print(user, pwd)
PY
)
fi

if [[ -z "$HARBOR_USER" || -z "$HARBOR_PASSWORD" ]]; then
  echo "WARN: Harbor pull secret skipped — set HARBOR_USER/HARBOR_PASSWORD or docker login." >&2
else
  kubectl -n "$NS" delete secret harbor-finspot-pull --ignore-not-found
  kubectl -n "$NS" create secret docker-registry harbor-finspot-pull \
    --docker-server="$HARBOR_SERVER" \
    --docker-username="$HARBOR_USER" \
    --docker-password="$HARBOR_PASSWORD"
fi

echo "Secrets created in namespace '$NS'."
