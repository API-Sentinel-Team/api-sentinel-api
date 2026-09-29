import asyncio

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

import server.modules.ingestion.processors as processors
import server.modules.ingestion.queue as queue_module
from server.models import core as models
from server.modules.ingestion.dead_letter import redact_dead_letter_error, redact_dead_letter_payload
from server.modules.ingestion.processors import process_event_batch
from server.modules.ingestion.queue import IngestionJobItem, IngestionQueue


def test_dead_letter_redactor_scrubs_nested_credentials_and_query_values():
    raw = {
        "url": "https://api.example.com/users?token=raw-token&account=123",
        "headers": {
            "Authorization": "Bearer raw-token",
            "Cookie": "sid=raw-cookie",
            "X-API-Key": "raw-api-key",
        },
        "lines": [
            'GET /search?token=raw-token HTTP/1.1 "Authorization: Bearer raw-token"',
        ],
    }

    redacted = redact_dead_letter_payload(raw)

    assert redacted["url"] == "https://api.example.com/users?token=****&account=****"
    assert redacted["headers"]["Authorization"] == "Bearer ****"
    assert redacted["headers"]["Cookie"] == "sid=****"
    assert redacted["headers"]["X-API-Key"] == "****"
    assert "raw-token" not in str(redacted)
    assert "raw-cookie" not in str(redacted)
    assert "raw-api-key" not in str(redacted)


def test_dead_letter_error_redactor_scrubs_exception_text_credentials():
    message = (
        "request failed Authorization: Bearer raw-error-token "
        "{'api_key': 'raw-error-key', 'password': 'raw-password'} "
        "https://api.example.com/users?token=raw-query-token"
    )

    redacted = redact_dead_letter_error(message)

    assert "Bearer ****" in redacted
    assert "api_key': ****" in redacted
    assert "password': ****" in redacted
    assert "token=****" in redacted
    assert "raw-error-token" not in redacted
    assert "raw-error-key" not in redacted
    assert "raw-password" not in redacted
    assert "raw-query-token" not in redacted


@pytest.mark.asyncio
async def test_event_validation_dead_letter_redacts_payload(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(processors, "AsyncSessionLocal", session_factory)

    async def noop_bump_cache_version(account_id):
        return None

    monkeypatch.setattr(processors, "bump_cache_version", noop_bump_cache_version)

    await process_event_batch(
        "dead-letter-invalid-event",
        1000000,
        {
            "events": [
                {
                    "event_type": "not_a_supported_event_type",
                    "account_id": 1000000,
                    "request": {
                        "headers": {"Authorization": "Bearer raw-invalid-token"},
                        "query": {"api_key": "raw-invalid-key"},
                        "body": {"password": "raw-password"},
                    },
                    "response": {"headers": {"Set-Cookie": "sid=raw-cookie"}},
                }
            ]
        },
    )

    async with session_factory() as db:
        row = (
            await db.execute(
                select(models.IngestionDeadLetter).where(
                    models.IngestionDeadLetter.job_id == "dead-letter-invalid-event",
                )
            )
        ).scalar_one()

    assert row.error_message.startswith("event_validation_failed:")
    assert "raw-invalid-token" not in row.error_message
    assert "raw-invalid-key" not in row.error_message
    assert "raw-password" not in row.error_message
    assert "raw-cookie" not in row.error_message
    assert "raw-invalid-token" not in str(row.payload)
    assert "raw-invalid-key" not in str(row.payload)
    assert "raw-password" not in str(row.payload)
    assert "raw-cookie" not in str(row.payload)


@pytest.mark.asyncio
async def test_low_quality_dead_letter_redacts_valid_event_payload(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(processors, "AsyncSessionLocal", session_factory)

    async def noop_bump_cache_version(account_id):
        return None

    monkeypatch.setattr(processors, "bump_cache_version", noop_bump_cache_version)

    await process_event_batch(
        "dead-letter-low-quality-event",
        1000000,
        {
            "events": [
                {
                    "event_type": "api_traffic",
                    "account_id": 1000000,
                    "request": {
                        "method": "GET",
                        "path": "/profile?token=raw-low-quality-token",
                        "headers": {"Authorization": "Bearer raw-low-quality-token"},
                        "body": {"api_key": "raw-low-quality-key"},
                    },
                    "response": {"status_code": 200},
                }
            ]
        },
    )

    async with session_factory() as db:
        row = (
            await db.execute(
                select(models.IngestionDeadLetter).where(
                    models.IngestionDeadLetter.job_id == "dead-letter-low-quality-event",
                )
            )
        ).scalar_one()

    assert row.error_message.startswith("low_quality_event:")
    assert "raw-low-quality-token" not in str(row.payload)
    assert "raw-low-quality-key" not in str(row.payload)
    assert row.payload["request"]["path"] == "/profile?token=****"


@pytest.mark.asyncio
async def test_worker_failure_dead_letter_redacts_queued_payload(test_engine, monkeypatch):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(queue_module, "AsyncSessionLocal", session_factory)

    async def fail_stream_lines(job_id, account_id, payload):
        raise RuntimeError(
            "parser failed Authorization: Bearer raw-worker-token api_key=raw-worker-key"
        )

    monkeypatch.setattr(queue_module, "process_stream_lines", fail_stream_lines)

    async with session_factory() as db:
        db.add(
            models.IngestionJob(
                id="dead-letter-worker-failure",
                account_id=1000000,
                job_type="stream_lines",
                status="QUEUED",
            )
        )
        await db.commit()

    ingestion_queue = IngestionQueue()
    ingestion_queue._running = True
    worker = asyncio.create_task(ingestion_queue._worker_loop(0))

    await ingestion_queue.enqueue(
        IngestionJobItem(
            job_id="dead-letter-worker-failure",
            account_id=1000000,
            job_type="stream_lines",
            payload={
                "lines": [
                    'GET /admin?token=raw-worker-token HTTP/1.1 "Authorization: Bearer raw-worker-token"',
                ],
                "headers": {"X-API-Key": "raw-worker-key"},
            },
        ),
        timeout_sec=1,
    )
    await ingestion_queue._queue.join()
    ingestion_queue._running = False
    await ingestion_queue._queue.put(IngestionJobItem("stop", 0, "stop", {}))
    await worker

    async with session_factory() as db:
        row = (
            await db.execute(
                select(models.IngestionDeadLetter).where(
                    models.IngestionDeadLetter.job_id == "dead-letter-worker-failure",
                )
            )
        ).scalar_one()
        job = await db.get(models.IngestionJob, "dead-letter-worker-failure")

    assert row.error_message == "parser failed Authorization: Bearer **** api_key=****"
    assert job.error_message == row.error_message
    assert job.status == "FAILED"
    assert "raw-worker-token" not in str(row.payload)
    assert "raw-worker-key" not in str(row.payload)
    assert "raw-worker-token" not in row.error_message
    assert "raw-worker-key" not in row.error_message
