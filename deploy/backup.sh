#!/usr/bin/env bash
# Nightly Postgres dump with retention. Cron example (as the deploy user):
#   15 2 * * * /opt/sentinel/deploy/backup.sh >> /var/log/sentinel-backup.log 2>&1
set -euo pipefail
cd "$(dirname "$0")"
DEST="${BACKUP_DIR:-/var/backups/sentinel}"
KEEP_DAYS="${KEEP_DAYS:-14}"
mkdir -p "$DEST"; umask 077
f="$DEST/api_security-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose --env-file .env.prod -f docker-compose.prod.yml exec -T postgres \
  pg_dump -U sentinel -d api_security -Fc > "$f.tmp"
mv "$f.tmp" "$f"
find "$DEST" -name 'api_security-*.dump' -mtime +"$KEEP_DAYS" -delete
echo "$(date -u +%FT%TZ) backup ok: $f ($(du -h "$f" | cut -f1))"
