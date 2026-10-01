#!/usr/bin/env bash
# Post-`docker compose up` smoke test. Run on the VPS: ./verify.sh
# Env: VERIFY_TIMEOUT (default 300s), VERIFY_INSECURE=1 to skip TLS verification (ACME pending),
#      PUBLIC_IP=<ip> to also probe postgres/redis ports from the host's public address.
set -uo pipefail
cd "$(dirname "$0")"
DC=(docker compose --env-file .env.prod -f docker-compose.prod.yml)
DOMAIN="$(grep -E '^SENTINEL_DOMAIN=' .env.prod | head -1 | cut -d= -f2-)"
TIMEOUT="${VERIFY_TIMEOUT:-300}"
CURL=(curl -sS --max-time 15 --resolve "${DOMAIN}:443:127.0.0.1")
[[ "${VERIFY_INSECURE:-0}" == 1 ]] && CURL+=(-k)
BASE="https://${DOMAIN}"
FAIL=0
ok()  { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; FAIL=1; }

# 1. wait for health
SERVICES=(postgres redis api scheduler archiver worker frontend caddy)
deadline=$((SECONDS + TIMEOUT))
for s in "${SERVICES[@]}"; do
  while :; do
    cid="$("${DC[@]}" ps -q "$s" 2>/dev/null)"
    st=""
    [[ -n "$cid" ]] && st="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null)"
    [[ "$st" == healthy || "$st" == running ]] && { ok "$s $st"; break; }
    (( SECONDS > deadline )) && { bad "$s not healthy (status: ${st:-missing})"; break; }
    sleep 3
  done
done

# 2. migrate one-shot exited 0, schema at head
mid="$("${DC[@]}" ps -aq migrate 2>/dev/null)"
code=""
[[ -n "$mid" ]] && code="$(docker inspect -f '{{.State.ExitCode}}' "$mid")"
[[ "$code" == 0 ]] && ok "migrate exited 0" || bad "migrate exit code: ${code:-missing}"
cur="$("${DC[@]}" run --rm --no-deps -T migrate sentinel-migrate current 2>/dev/null | awk 'NF{print $1}' | sort -u | tr '\n' ' ')"
hd="$("${DC[@]}" run --rm --no-deps -T migrate sentinel-migrate heads 2>/dev/null | awk 'NF{print $1}' | sort -u | tr '\n' ' ')"
[[ -n "$cur" && "$cur" == "$hd" ]] && ok "migrations at head ($cur)" || bad "migrations not at head (current: '$cur' heads: '$hd')"

# 3. API health through the proxy
c="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/api/health/ready")"
[[ "$c" == 200 ]] && ok "GET /api/health/ready -> 200" || bad "GET /api/health/ready -> $c"

# 4. authenticated endpoint rejects anonymous callers
c="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/api/health/config-check")"
[[ "$c" == 401 ]] && ok "anonymous /api/health/config-check -> 401" || bad "anonymous /api/health/config-check -> $c (expected 401)"

# 5. WebSocket upgrade reachable (101, or an app-level 400/401/403 without a token; 5xx/404 = proxy broken)
c="$("${CURL[@]}" -o /dev/null -w '%{http_code}' --max-time 5 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$BASE/api/stream/live" || true)"
case "$c" in 101|400|401|403) ok "WebSocket /api/stream/live reachable ($c)";; *) bad "WebSocket /api/stream/live -> ${c:-no response}";; esac

# 6. nothing but caddy publishes ports; host listens only on the expected ports
for s in postgres redis api worker scheduler archiver frontend; do
  cid="$("${DC[@]}" ps -q "$s" 2>/dev/null)"
  pb="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$cid" 2>/dev/null)"
  [[ "$pb" == "{}" || "$pb" == "null" ]] && ok "$s publishes no host ports" || bad "$s publishes host ports: $pb"
done
if command -v ss >/dev/null 2>&1; then
  for p in 5432 6379 8000 8080; do
    if ss -ltn "sport = :$p" 2>/dev/null | grep -q LISTEN; then bad "host is listening on :$p"; else ok "nothing listening on host :$p"; fi
  done
fi
if [[ -n "${PUBLIC_IP:-}" ]] && command -v nc >/dev/null 2>&1; then
  for p in 5432 6379; do
    if nc -z -w3 "$PUBLIC_IP" "$p" 2>/dev/null; then bad "$PUBLIC_IP:$p reachable externally"; else ok "$PUBLIC_IP:$p not reachable"; fi
  done
fi

# 7. running containers are non-root
for s in "${SERVICES[@]}"; do
  u="$("${DC[@]}" exec -T "$s" id -u 2>/dev/null | tr -d '\r')"
  [[ -n "$u" && "$u" != 0 ]] && ok "$s runs as uid $u" || bad "$s uid: ${u:-unknown} (expected non-root)"
done

echo
if (( FAIL )); then echo "verify: FAILED"; exit 1; fi
echo "verify: all checks passed"
