# Nginx edge (production)

## TLS

Place PEM files under `ssl/` next to this README (or adjust paths in the config):

- `fullchain.pem`
- `privkey.pem`

## Run with Docker Compose (repo root)

```bash
docker compose -f docker-compose.yml -f infra/nginx/docker-compose.edge.yml up -d
```

Set `server_name` and TLS paths in `api-sentinel-production.conf`. The upstream expects the backend service name `fastapi` on port 8000 (matches root `docker-compose.yml`).

## Sensor (Argus) → backend

1. In API Sentinel, register a **Sensor** and copy the **sensor key** (maps to the container `API_KEY` / `Authorization: Bearer`).

2. Point the sensor at your public URL:

   ```text
   --ingest https://<your-nginx-host>/v1/events
   ```

3. The HTTP load goes to `POST /v1/events` on FastAPI; nginx should not strip `/v1` (config uses `proxy_pass http://api_sentinel_backend` without URI suffix, so the full path is preserved).

## Rate limits

Tune `limit_req` in `api-sentinel-production.conf` for your number of nodes and RPS. Bursts are set high for batch sensor posts.

## Kubernetes

For Ingress, forward `POST /v1/events` to the same Service as the API, or use this nginx config behind a LoadBalancer. See `../k8s/sensor-daemonset.example.yaml` for the DaemonSet.
