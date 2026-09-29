import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

import server.modules.ingestion.processors as processors
from server.models import core as models
from server.modules.ingestion.processors import process_event_batch, process_stream_lines
from server.modules.ingestion.schema import APIRequest, APIResponse, APITrafficEvent, EventBatch
from server.modules.vulnerability_detector.lifecycle import verify_vulnerability_evidence


@pytest.mark.asyncio
async def test_event_batch_response_pii_promotes_passive_vulnerability(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(processors, "AsyncSessionLocal", session_factory)

    async def noop_bump_cache_version(account_id):
        return None

    monkeypatch.setattr(processors, "bump_cache_version", noop_bump_cache_version)

    event = APITrafficEvent(
        account_id=1000000,
        observed_at=1710000000000,
        source_ip="198.51.100.9",
        request=APIRequest(
            method="GET",
            path="/profile",
            host="api.example.com",
            scheme="https",
            headers={"x-api-client-id": "user-1"},
        ),
        response=APIResponse(
            status_code=200,
            body={"name": "Ada", "ssn": "123-45-6789"},
        ),
    )

    await process_event_batch(
        "passive-pii-job",
        1000000,
        EventBatch(events=[event]).model_dump(mode="json"),
    )

    async with session_factory() as db:
        finding = (
            await db.execute(
                select(models.SensitiveDataFinding).where(
                    models.SensitiveDataFinding.endpoint_id.is_not(None),
                    models.SensitiveDataFinding.entity_type == "SSN",
                )
            )
        ).scalar_one()
        vulnerability = (
            await db.execute(
                select(models.Vulnerability).where(
                    models.Vulnerability.endpoint_id == finding.endpoint_id,
                    models.Vulnerability.type == "PASSIVE:SENSITIVE_DATA_EXPOSURE:SSN",
                )
            )
        ).scalar_one()

    assert vulnerability.template_id == "passive-sensitive-data-ssn-response"
    assert vulnerability.severity == "HIGH"
    assert vulnerability.evidence["sample"] == "****"
    assert vulnerability.evidence["evidence_hash"]
    assert verify_vulnerability_evidence(vulnerability.evidence)["verified"] is True
    assert "123-45-6789" not in str(vulnerability.evidence)


@pytest.mark.asyncio
async def test_stream_lines_promote_passive_attack_vulnerability(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(processors, "AsyncSessionLocal", session_factory)

    async def noop_bump_cache_version(account_id):
        return None

    monkeypatch.setattr(processors, "bump_cache_version", noop_bump_cache_version)

    line = (
        '198.51.100.10 - - [10/Mar/2024:12:00:00 +0000] '
        '"GET /search?q=UNION%20SELECT%20password%20FROM%20users&token=raw-token HTTP/1.1" '
        '200 512 "-" "sqlmap Authorization: Bearer raw-token"'
    )

    await process_stream_lines(
        "passive-stream-job",
        1000000,
        {"lines": [line]},
    )

    async with session_factory() as db:
        vulnerability = (
            await db.execute(
                select(models.Vulnerability).where(
                    models.Vulnerability.type == "PASSIVE:SQL_INJECTION",
                    models.Vulnerability.url == "/search?q=****&token=****",
                )
            )
        ).scalar_one()

    assert vulnerability.template_id == "passive-sql-injection"
    assert vulnerability.severity == "HIGH"
    assert vulnerability.confidence == "HIGH"
    assert vulnerability.evidence["source"] == "stream_line"
    assert vulnerability.evidence["response_code"] == 200
    assert verify_vulnerability_evidence(vulnerability.evidence)["verified"] is True
    assert "raw-token" not in str(vulnerability.evidence)


@pytest.mark.asyncio
async def test_stream_lines_update_sensor_health_by_id_without_secret(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(processors, "AsyncSessionLocal", session_factory)

    async def noop_bump_cache_version(account_id):
        return None

    monkeypatch.setattr(processors, "bump_cache_version", noop_bump_cache_version)

    async with session_factory() as db:
        db.add(
            models.Sensor(
                id="sensor-stream-worker-id",
                account_id=1000000,
                name="worker-sensor",
                sensor_key="raw-worker-sensor-key",
                lines_shipped=2,
                events_detected=0,
                status="OFFLINE",
            )
        )
        await db.commit()

    line = (
        '203.0.113.12 - - [10/Mar/2024:12:00:00 +0000] '
        '"GET /health HTTP/1.1" 200 128 "-" "curl"'
    )

    await process_stream_lines(
        "passive-stream-sensor-health-job",
        1000000,
        {"lines": [line], "sensor_id": "sensor-stream-worker-id"},
    )

    async with session_factory() as db:
        sensor = await db.get(models.Sensor, "sensor-stream-worker-id")

    assert sensor.lines_shipped == 3
    assert sensor.events_detected == 0
    assert sensor.status == "ONLINE"
    assert sensor.last_heartbeat is not None
