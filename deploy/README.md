# Single-VPS production deploy

Stack: Caddy (80/443, automatic TLS) -> frontend (nginx) and api; Postgres 16 and Redis 7 on an internal-only network; one-shot `migrate`; scheduler, archiver, scan worker. Sized for 4 vCPU / 8 GB (sum of memory limits is about 6.7 GB; the worker is the largest at 2.5 GB). Only Caddy publishes ports.

## Prerequisites

- Ubuntu/Debian VPS, Docker Engine + Compose v2, `openssl`, `curl`.
- DNS A record for your domain pointing at the VPS (needed for ACME before first start).
- Images `ghcr.io/api-sentinel-team/api-sentinel-{api,scan-worker,scheduler,archiver,frontend}:<tag>` pullable (`docker login ghcr.io` if private), or build them locally (see the header of `docker-compose.prod.yml`; sentinel-core is private, so a `GH_TOKEN` BuildKit secret is required).

## Firewall

```bash
sudo ufw default deny incoming && sudo ufw default allow outgoing
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
sudo ufw enable
```

Docker publishes ports by editing iptables directly and bypasses ufw for published ports. This stack publishes only 80/443, so that is fine; do not add `ports:` to other services.

## First deploy

```bash
cd deploy
./generate-secrets.sh sentinel.example.com ops@example.com api.customer.com v1.0.0   # writes .env.prod (mode 600), refuses to overwrite
# or: cp .env.prod.example .env.prod && chmod 600 .env.prod && edit
DC="docker compose --env-file .env.prod -f docker-compose.prod.yml"
$DC config -q            # validates interpolation
$DC pull
$DC up -d                # migrate runs first; api/scheduler/archiver/worker wait for it
./verify.sh              # VERIFY_INSECURE=1 ./verify.sh while the certificate is still being issued
```

Back up `.env.prod` (password manager, not git). Losing `ENCRYPTION_KEY` makes stored credentials unreadable; changing `SENSOR_KEY_HASH_PEPPER` invalidates sensor keys.

## Upgrade

```bash
cd deploy
cp .env.prod .env.prod.bak.$(date +%F) && ./backup.sh          # always dump first
sed -i 's/^SENTINEL_VERSION=.*/SENTINEL_VERSION=v1.1.0/' .env.prod
$DC pull
$DC up -d            # recreates changed services; migrate re-runs `sentinel-migrate upgrade head` first
./verify.sh
```

## Rollback

Migrations are forward-only in practice. If the new version is bad:

1. Set `SENTINEL_VERSION` back to the previous tag, `$DC pull && $DC up -d`.
2. If the new release applied a schema change the old code cannot run on, restore the pre-upgrade dump (below) instead. Do not run `sentinel-migrate downgrade` in production unless the release notes say that revision is reversible.

## Backup and restore (Postgres)

`backup.sh` writes custom-format dumps to `/var/backups/sentinel` (14-day retention). Cron:

```
15 2 * * * /opt/sentinel/deploy/backup.sh >> /var/log/sentinel-backup.log 2>&1
```

Copy dumps off the host (rsync/rclone to object storage); a backup on the same disk is not a backup. The archive volume (`archive-data`) holds archived data; snapshot it with the VPS snapshot feature or `docker run --rm -v deploy_archive-data:/d -v $PWD:/b alpine tar czf /b/archive.tgz -C /d .`.

Restore test (do this once before go-live, then quarterly), on a scratch database so production is untouched:

```bash
$DC exec -T postgres createdb -U sentinel restore_test
$DC exec -T postgres pg_restore -U sentinel -d restore_test --no-owner < /var/backups/sentinel/<file>.dump
$DC exec -T postgres psql -U sentinel -d restore_test -c "select count(*) from alembic_version;"
$DC exec -T postgres dropdb -U sentinel restore_test
```

Real restore: `$DC stop api scheduler archiver worker`, `dropdb`/`createdb api_security`, `pg_restore -d api_security --no-owner < dump`, `$DC up -d`.

## Logs

- Container logs (json-file, 10 MB x 5 per service): `$DC logs -f --tail=200 api` (services: caddy, frontend, api, scheduler, archiver, worker, postgres, redis, migrate). Files live under `/var/lib/docker/containers/<id>/`.
- Migration output: `$DC logs migrate`.
- Caddy/ACME problems: `$DC logs caddy`.
- Backup log: `/var/log/sentinel-backup.log`.

## Resource notes

Limits are `mem_limit`/`cpus` in the compose file. CPU limits intentionally sum above 4 (burst sharing); memory limits do not oversubscribe the 8 GB host. The worker uses a disk-backed volume for scan scratch because tmpfs would count against its memory limit. The api/scheduler/archiver run with a read-only root filesystem plus tmpfs for `/tmp` and `/app/models`; if a service logs a "read-only file system" error, add a tmpfs or volume for that path rather than dropping `read_only`.

## Post-deploy checklist

- [ ] `./verify.sh` passes.
- [ ] Fresh migrate: on a scratch VPS or after `down -v`, `up -d` creates the schema from empty and `verify.sh` reports head.
- [ ] Scan -> findings -> retest: create a scan against an allowlisted target, confirm the worker picks it up, findings appear, a retest updates their state.
- [ ] Cancel: start a scan, cancel it, confirm the worker stops it and the run ends as cancelled.
- [ ] Worker restart: `$DC restart worker` mid-scan; the lease expires and the run is resumed or failed cleanly, not stuck.
- [ ] Archive job: trigger or wait for an archiver cycle (`ARCHIVE_INTERVAL_SECONDS`); check `$DC logs archiver` and files in the `archive-data` volume.
- [ ] Target guard: a scan against a non-allowlisted or private-IP host is rejected.
- [ ] Reboot test: `sudo reboot`; everything returns (restart policy) with no manual step, TLS still valid, `./verify.sh` passes.
- [ ] Backup cron ran once and the restore test above succeeded.
- [ ] External port scan from another machine shows only 22/80/443 open (`nmap -Pn <ip>`).
