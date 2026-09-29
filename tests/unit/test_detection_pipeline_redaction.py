from pathlib import Path

import pytest
from sqlalchemy import select

from server.config import settings
from server.models import core as models
from server.modules.detection.correlation_agent import correlation_agent
from server.modules.detection.models import DetectionEnvelope, DetectionSignal
from server.modules.detection.normalization_agent import normalization_agent
from server.modules.evidence.package import save_evidence_package


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("source_type", "raw_event", "expected_path"),
    [
        (
            "api_traffic",
            {
                "request": {
                    "method": "GET",
                    "path": "/v1/users?token=raw-api-token&api_key=raw-api-key",
                    "host": "api.example.com",
                },
                "response": {"status_code": 200},
            },
            "/v1/users?token=****&api_key=****",
        ),
        (
            "stream_ebpf",
            {
                "method": "GET",
                "path": "/admin?session=raw-ebpf-session&token=raw-ebpf-token",
                "status": 200,
                "source_ip": "198.51.100.41",
            },
            "/admin?session=****&token=****",
        ),
        (
            "gateway_log",
            {
                "ip": "198.51.100.42",
                "method": "GET",
                "path": "/gateway?authorization=raw-gateway-token",
                "status": 200,
            },
            "/gateway?authorization=****",
        ),
        (
            "http_traffic",
            {
                "method": "GET",
                "path": "/proxy?cookie=raw-cookie&token=raw-proxy-token",
                "statusCode": 200,
                "sourceIp": "198.51.100.43",
            },
            "/proxy?cookie=****&token=****",
        ),
    ],
)
async def test_normalization_persists_redacted_request_log_paths(
    db_session,
    source_type,
    raw_event,
    expected_path,
):
    result = await normalization_agent.normalize(
        db_session,
        1000000,
        source_type,
        raw_event,
        persist_request_log=True,
    )
    await db_session.commit()

    request_log = await db_session.get(models.RequestLog, result.envelope.request_log_id)
    assert request_log.path == expected_path
    assert "raw-" not in request_log.path
    assert result.envelope.path != request_log.path


@pytest.mark.asyncio
async def test_correlation_persists_redacted_events_alerts_and_evidence(
    db_session,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(settings, "ARCHIVE_DIR", str(tmp_path))
    raw_token = "raw-detection-token"
    raw_auth = "raw-detection-auth"
    raw_body_key = "raw-detection-body-key"
    raw_signal_token = "raw-detection-signal-token"

    envelope = DetectionEnvelope(
        source_type="http_traffic",
        account_id=1000000,
        observed_at_ms=1710000000000,
        actor_id="user-1",
        source_ip="198.51.100.44",
        method="POST",
        path=f"/admin?token={raw_token}&api_key=raw-query-key",
        endpoint_scope="/admin",
        status_code=500,
        request_headers={"authorization": f"Bearer {raw_auth}"},
        query_params={"token": raw_token, "account_id": "acct-123"},
        request_body_text=f'{{"api_key":"{raw_body_key}","ok":true}}',
        response_body_text=f"token={raw_token}",
    )
    signal = DetectionSignal(
        detector_id="unit.redaction",
        incident_type="SQL_INJECTION",
        category="SQL Injection",
        severity="HIGH",
        confidence=0.95,
        summary=f"Authorization: Bearer {raw_signal_token} on /admin?token={raw_token}",
        evidence={
            "url": f"https://api.example.com/admin?token={raw_token}",
            "headers": {"Authorization": f"Bearer {raw_signal_token}"},
        },
    )

    await correlation_agent.correlate(db_session, envelope, [signal], {}, persist=True)
    await db_session.commit()

    event = (
        await db_session.execute(
            select(models.MaliciousEventRecord).where(
                models.MaliciousEventRecord.ip == "198.51.100.44",
            )
        )
    ).scalar_one()
    alert = (
        await db_session.execute(
            select(models.Alert).where(models.Alert.source_ip == "198.51.100.44")
        )
    ).scalar_one()
    evidence = (
        await db_session.execute(
            select(models.EvidenceRecord).where(models.EvidenceRecord.ref_id == alert.id)
        )
    ).scalar_one()
    package = (
        await db_session.execute(
            select(models.EvidencePackage).where(models.EvidencePackage.detection_id == alert.id)
        )
    ).scalar_one()

    archive_blob = Path(package.path).read_text()
    stored_blob = str(
        {
            "event_url": event.url,
            "event_payload": event.payload,
            "alert_title": alert.title,
            "alert_message": alert.message,
            "alert_endpoint": alert.endpoint,
            "evidence_details": evidence.details,
            "archive": archive_blob,
        }
    )

    assert event.url == "/admin?token=****&api_key=****"
    assert alert.endpoint == "/admin"
    assert "token=****" in stored_blob
    assert raw_token not in stored_blob
    assert "raw-query-key" not in stored_blob
    assert raw_auth not in stored_blob
    assert raw_body_key not in stored_blob
    assert raw_signal_token not in stored_blob


@pytest.mark.asyncio
async def test_evidence_package_redacts_payload_and_metadata_at_archive_boundary(
    db_session,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(settings, "ARCHIVE_DIR", str(tmp_path))
    raw_token = "raw-package-token"
    raw_key = "raw-package-key"

    await save_evidence_package(
        db_session,
        account_id=1000000,
        detection_type="alert",
        detection_id="alert-1",
        payload={
            "url": f"https://api.example.com/debug?token={raw_token}",
            "headers": {"Authorization": f"Bearer {raw_token}"},
            "body": f'{{"api_key":"{raw_key}"}}',
        },
        metadata={
            "source": "unit",
            "debug_secret": raw_token,
            "external_ref": f"https://jira.example.com/browse/API-1?token={raw_token}",
        },
    )
    await db_session.commit()

    package = (
        await db_session.execute(
            select(models.EvidencePackage).where(models.EvidencePackage.detection_id == "alert-1")
        )
    ).scalar_one()
    archive_blob = Path(package.path).read_text()

    assert "token=****" in archive_blob
    assert "Bearer ****" in archive_blob
    assert "api_key" in archive_blob
    assert package.metadata_blob["debug_secret"] == "****"
    assert package.metadata_blob["external_ref"] == "https://jira.example.com/browse/API-1?token=****"
    assert raw_token not in archive_blob
    assert raw_key not in archive_blob
    assert raw_token not in str(package.metadata_blob)
    assert package.digest in package.path
