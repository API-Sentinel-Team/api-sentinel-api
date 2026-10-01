#!/usr/bin/env bash
# Generate deploy/.env.prod with fresh secrets. Refuses to overwrite an existing file.
# Usage: ./generate-secrets.sh <domain> <acme-email> <target-allowlist> [sentinel-version]
set -euo pipefail
umask 077
cd "$(dirname "$0")"

OUT=".env.prod"
[[ -e "$OUT" ]] && { echo "refusing to overwrite existing $OUT" >&2; exit 1; }
[[ $# -ge 3 ]] || { echo "usage: $0 <domain> <acme-email> <target-allowlist> [version]" >&2; exit 2; }
DOMAIN="$1"; EMAIL="$2"; ALLOW="$3"; VERSION="${4:-CHANGE_ME}"
[[ "$ALLOW" == *"*"* ]] && { echo "allowlist must not contain wildcards" >&2; exit 2; }

rand_hex() { openssl rand -hex "$1"; }
fernet() {
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import cryptography' 2>/dev/null; then
    python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
  else
    # A Fernet key is 32 random bytes, urlsafe-base64 encoded.
    openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'; echo
  fi
}

{
  echo "# Generated $(date -u +%FT%TZ) by generate-secrets.sh. Do not commit."
  echo "SENTINEL_VERSION=${VERSION}"
  echo "SENTINEL_DOMAIN=${DOMAIN}"
  echo "ACME_EMAIL=${EMAIL}"
  echo "PENTEST_TARGET_ALLOWLIST=${ALLOW}"
  echo "POSTGRES_PASSWORD=$(rand_hex 24)"
  echo "REDIS_PASSWORD=$(rand_hex 24)"
  echo "JWT_SECRET=$(rand_hex 48)"
  echo "API_KEY=$(rand_hex 32)"
  echo "ENCRYPTION_KEY=$(fernet)"
  echo "SENSOR_KEY_HASH_PEPPER=$(rand_hex 32)"
  echo "CICD_GATE_SIGNING_SECRET=$(rand_hex 32)"
} > "$OUT"
chmod 600 "$OUT"
echo "wrote $(pwd)/$OUT (mode 600). Back up ENCRYPTION_KEY and SENSOR_KEY_HASH_PEPPER somewhere safe."
