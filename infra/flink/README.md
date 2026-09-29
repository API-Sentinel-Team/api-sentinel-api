**Flink Job (Real-Time Pipeline)**
This directory provides a minimal Flink cluster for running the PyFlink job in
`server/modules/streaming/flink_job.py`.

**Run**
```bash
docker compose -f infra/flink/docker-compose.yml up -d
```

**Submit Job**
```bash
docker exec -it api-sec-flink-jobmanager bash -lc "flink run -py /opt/flink/usrlib/flink_job.py"
```

**Environment**
Set Kafka bootstrap servers before running:
```bash
export KAFKA_BOOTSTRAP_SERVERS=localhost:9092
```
