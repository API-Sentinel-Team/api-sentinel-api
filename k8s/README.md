# API Sentinel on Kubernetes (wecrew cluster)

Deploys API Sentinel (API Security Engine) to kind cluster `wecrew` at
**https://sentinel.wecrew.in/**.

## Topology

```
client ──TLS──▶ host Traefik (:443, SNI passthrough)
                  └─▶ 127.0.0.1:8443  = kind ingress-nginx (cert-manager LE)
                        └─▶ Service api-sentinel-frontend:80
                              ├─ SPA (nginx :8080)
                              └─ /api,/v1 ──proxy──▶ api-sentinel-backend:8000
                                    ├─ api-sentinel-postgres:5432
                                    └─ api-sentinel-redis:6379
```

## Images

```bash
./k8s/build-and-push.sh
# or: TAG=$(date +%Y%m%d-%H%M) ./k8s/build-and-push.sh
```

Pushes:

- `harbor.wecrew.in/finspot/api-sentinel-backend:latest`
- `harbor.wecrew.in/finspot/api-sentinel-frontend:latest`

Optional heavy scan worker: `./k8s/build-and-push.sh worker`

eBPF sensor (API-Sensor `session-4-production-fixes`): `./k8s/build-and-push.sh sensor`  
→ `harbor.wecrew.in/finspot/api-sentinel-sensor:latest`

## Deploy

```bash
kubectl apply -f k8s/00-namespace.yaml
./k8s/create-secrets.sh

kubectl apply -f k8s/10-postgres.yaml -f k8s/20-redis.yaml -f k8s/25-config.yaml
kubectl rollout status deploy/api-sentinel-postgres -n api-sentinel --timeout=180s
kubectl rollout status deploy/api-sentinel-redis -n api-sentinel --timeout=120s

kubectl apply -f k8s/30-backend.yaml -f k8s/40-frontend.yaml -f k8s/50-ingress.yaml
kubectl rollout status deploy/api-sentinel-backend -n api-sentinel --timeout=300s
kubectl rollout status deploy/api-sentinel-frontend -n api-sentinel --timeout=180s

# eBPF sensor (after backend is Ready)
./k8s/register-sensor.sh
kubectl apply -f k8s/35-sensor.yaml
kubectl rollout status ds/api-sentinel-sensor -n api-sentinel --timeout=180s
```

## Public reachability (ops host)

1. DNS A record `sentinel.wecrew.in` → `213.210.36.154` (Hostinger)
2. Add `|| HostSNI(\`sentinel.wecrew.in\`)` to `/docker/traefik/dynamic/cluster.yml`

TLS uses `letsencrypt-prod` (DNS-01). Verify:

```bash
kubectl -n api-sentinel get certificate api-sentinel-tls
curl -fsS https://sentinel.wecrew.in/healthz
curl -fsS https://sentinel.wecrew.in/api/health/ready
```

## Notes

- Secrets are imperative (`create-secrets.sh`); never commit live values.
- `finspot` Harbor project is private — `harbor-finspot-pull` is required.
- Postgres is RWO + `Recreate`; do not scale it.
- Kafka is off (`KAFKA_ENABLED=false`); in-process stream bus only.
- Pentest target allowlist is fail-closed; edit `25-config.yaml` for owned hosts.
