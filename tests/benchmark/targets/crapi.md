# crAPI benchmark target

crAPI is a multi-service app (web, identity, community, workshop, mailhog, mongo,
postgres). Unlike VAmPI it is **not a single image**, so we reference OWASP's
official compose rather than vendoring a stack we can't keep in sync.

## Start it (isolated / owned environment only — crAPI is deliberately insecure)

```bash
git clone https://github.com/OWASP/crAPI
cd crAPI/deploy/docker
docker compose pull
docker compose -f docker-compose.yml up -d
# Web UI:      http://localhost:8888
# API gateway: http://localhost:8080   <- corpus base_url
# MailHog:     http://localhost:8025   (OTP / email tokens land here)
```

Wait ~60-90s for all services to be healthy before running the benchmark.

## Run the benchmark

```bash
export PENTEST_ALLOW_PRIVATE_TARGETS=true   # localhost target (dev/benchmark only)
# Deterministic detectors + chains (no LLM needed):
python -m tests.benchmark.runner tests/benchmark/corpus/crapi.yaml
# Full agentic path with identities (needs AGENTIC_LLM_* + 2+ identities):
python -m tests.benchmark.runner tests/benchmark/corpus/crapi.yaml --agentic --with-crapi-auth
```

## Identities

crAPI uses email+password signup then JWT login. `crapi_auth.provision_crapi_identities`
registers two users (a "victim" and an "attacker") and returns them as TestAccounts
with bearer tokens, so multi-identity replay / chains can run. crAPI also has a
mechanic role and an admin — richer role modeling than VAmPI, which is the point:
this target is what makes Phase 2 (RBAC/tenant) and Phase 3 (business-logic) measurable.

NOTE: crAPI OTP/email-verification may gate full signup; the provisioner reads
MailHog when reachable. If signup is gated in your environment, supply tokens via
env (CRAPI_VICTIM_TOKEN / CRAPI_ATTACKER_TOKEN) and the provisioner uses those.
