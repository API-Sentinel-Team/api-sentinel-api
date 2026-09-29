#!/usr/bin/env bash
# Upsert the eBPF sensor row in Postgres so /v1/events accepts the DaemonSet key.
# Requires: backend Running, secret api-sentinel-sensor already created.
#
#   ./k8s/create-secrets.sh
#   ./k8s/register-sensor.sh
set -euo pipefail

NS="${NS:-api-sentinel}"
SENSOR_NAME="${SENSOR_NAME:-wecrew-ebpf}"
SENSOR_VERSION="${SENSOR_VERSION:-session-4}"

kubectl -n "$NS" get secret api-sentinel-sensor >/dev/null
kubectl -n "$NS" get deploy api-sentinel-backend >/dev/null

RAW_KEY="$(kubectl -n "$NS" get secret api-sentinel-sensor -o jsonpath='{.data.api-key}' | base64 -d)"
ACCOUNT_ID="$(kubectl -n "$NS" get secret api-sentinel-sensor -o jsonpath='{.data.account-id}' | base64 -d)"
HOST="$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo wecrew-control-plane)"

if [[ -z "$RAW_KEY" || -z "$ACCOUNT_ID" ]]; then
  echo "api-sentinel-sensor secret missing api-key or account-id" >&2
  exit 1
fi

# Hash with the live backend pepper, then upsert via ORM (no plaintext in SQL).
kubectl -n "$NS" exec -i deploy/api-sentinel-backend -c api -- python - <<PY
import asyncio
import os
import uuid

os.environ.setdefault("SENSOR_RAW_KEY", """${RAW_KEY}""")
os.environ.setdefault("SENSOR_NAME", """${SENSOR_NAME}""")
os.environ.setdefault("SENSOR_ACCOUNT_ID", """${ACCOUNT_ID}""")
os.environ.setdefault("SENSOR_HOST", """${HOST}""")
os.environ.setdefault("SENSOR_VERSION", """${SENSOR_VERSION}""")

from sqlalchemy import select
from server.models.core import Sensor
from server.modules.persistence.database import AsyncSessionLocal
from server.modules.sensors.keys import hash_sensor_key


async def main() -> None:
    raw = os.environ["SENSOR_RAW_KEY"]
    name = os.environ["SENSOR_NAME"]
    account_id = int(os.environ["SENSOR_ACCOUNT_ID"])
    host = os.environ["SENSOR_HOST"]
    version = os.environ["SENSOR_VERSION"]
    hashed = hash_sensor_key(raw)
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Sensor).where(Sensor.account_id == account_id, Sensor.name == name)
        )
        row = result.scalar_one_or_none()
        if row is None:
            db.add(
                Sensor(
                    id=str(uuid.uuid4()),
                    account_id=account_id,
                    name=name,
                    host=host,
                    sensor_key=hashed,
                    version=version,
                    status="OFFLINE",
                    log_path="ebpf",
                )
            )
            action = "created"
        else:
            row.sensor_key = hashed
            row.host = host
            row.version = version
            row.log_path = "ebpf"
            action = "updated"
        await db.commit()
        print(f"{action} sensor name={name} account_id={account_id} host={host}")


asyncio.run(main())
PY
