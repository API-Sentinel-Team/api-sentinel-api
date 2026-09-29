import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.passive.findings import (
    build_passive_attack_vulnerability_data,
    build_sensitive_data_exposure_vulnerability_data,
    persist_passive_attack_signal,
    persist_sensitive_data_exposure,
    should_promote_passive_attack,
)
from server.modules.vulnerability_detector.lifecycle import verify_vulnerability_evidence


def test_passive_attack_promotion_requires_exposure_signal():
    assert should_promote_passive_attack("SQL Injection", "HIGH", 200) is True
    assert should_promote_passive_attack("SQL Injection", "HIGH", 503) is True
    assert should_promote_passive_attack("SQL Injection", "HIGH", 403) is False
    assert should_promote_passive_attack("Scanning Tool", "MEDIUM", 200) is False


def test_build_passive_attack_vulnerability_data_redacts_evidence():
    payload = build_passive_attack_vulnerability_data(
        account_id=1000000,
        category="SQL Injection",
        severity="HIGH",
        response_code=200,
        url="/search?q=' OR 1=1&token=raw-token",
        method="GET",
        source="gateway_log",
        actor="198.51.100.10",
        evidence={"payload": "Authorization: Bearer raw-token"},
    )

    assert payload is not None
    assert payload["template_id"] == "passive-sql-injection"
    assert payload["type"] == "PASSIVE:SQL_INJECTION"
    assert payload["url"] == "/search?q=****&token=****"
    assert payload["evidence"]["engine"] == "passive_traffic"
    assert payload["evidence"]["finding_status"] == "UNCONFIRMED"
    assert payload["evidence"]["matched_rule"] == {
        "category": "SQL Injection",
        "detector": "passive_traffic",
    }
    assert payload["evidence"]["sent_request"] == {
        "method": "GET",
        "url": "/search?q=****&token=****",
    }
    assert payload["evidence"]["received_response"] == {"status_code": 200}
    assert payload["evidence"]["similarity"] == {
        "source": "passive_response_signal",
        "confidence": "HIGH",
    }
    assert "curl -i -X GET" in payload["evidence"]["reproduction"]["curl"]
    assert "Validate and encode untrusted input" in payload["evidence"]["remediation"]
    assert payload["evidence"]["evidence_completeness"]["complete"] is True
    assert payload["evidence"]["evidence_completeness"]["missing"] == []
    assert payload["evidence"]["evidence_hash"]
    assert verify_vulnerability_evidence(payload["evidence"])["verified"] is True
    assert "raw-token" not in str(payload["evidence"])


@pytest.mark.asyncio
async def test_persist_passive_attack_signal_merges_repeated_findings(db_session):
    first = await persist_passive_attack_signal(
        db_session,
        account_id=1000000,
        category="Path Traversal",
        severity="CRITICAL",
        response_code=200,
        url="/download?file=../../etc/passwd&token=raw-token",
        method="GET",
        actor="198.51.100.10",
    )
    second = await persist_passive_attack_signal(
        db_session,
        account_id=1000000,
        category="Path Traversal",
        severity="CRITICAL",
        response_code=200,
        url="/download?file=../../etc/passwd&token=raw-token",
        method="GET",
        actor="203.0.113.25",
    )
    await db_session.flush()

    assert first["created"] is True
    assert second["created"] is False
    assert second["occurrence_count"] == 2

    rows = (
        await db_session.execute(
            select(models.Vulnerability).where(models.Vulnerability.template_id == "passive-path-traversal")
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].occurrence_count == 2
    assert verify_vulnerability_evidence(rows[0].evidence)["verified"] is True


def test_build_sensitive_data_exposure_vulnerability_data():
    payload = build_sensitive_data_exposure_vulnerability_data(
        account_id=1000000,
        endpoint_id="ep-1",
        entity_type="JWT",
        source="response",
        path="/me?token=raw-token",
        method="GET",
    )

    assert payload["template_id"] == "passive-sensitive-data-jwt-response"
    assert payload["type"] == "PASSIVE:SENSITIVE_DATA_EXPOSURE:JWT"
    assert payload["severity"] == "HIGH"
    assert payload["url"] == "/me?token=****"
    assert payload["evidence"]["sample"] == "****"
    assert payload["evidence"]["finding_status"] == "UNCONFIRMED"
    assert payload["evidence"]["matched_rule"] == {
        "detector": "pii_scanner",
        "entity_type": "JWT",
    }
    assert payload["evidence"]["sent_request"] == {
        "method": "GET",
        "url": "/me?token=****",
    }
    assert payload["evidence"]["received_response"] == {
        "source": "response",
        "entity_type": "JWT",
    }
    assert payload["evidence"]["similarity"] == {
        "source": "sensitive_entity_detector",
        "confidence": "HIGH",
    }
    assert "curl -i -X GET" in payload["evidence"]["reproduction"]["curl"]
    assert "Avoid returning sensitive data" in payload["evidence"]["remediation"]
    assert payload["evidence"]["evidence_completeness"]["complete"] is True
    assert payload["evidence"]["evidence_hash"]
    assert verify_vulnerability_evidence(payload["evidence"])["verified"] is True
    assert "raw-token" not in str(payload["evidence"])


@pytest.mark.asyncio
async def test_persist_sensitive_data_exposure_merges_by_endpoint_entity_and_source(db_session):
    first = await persist_sensitive_data_exposure(
        db_session,
        account_id=1000000,
        endpoint_id="passive-pii-ep",
        entity_type="SSN",
        source="response",
        path="/profile",
        method="GET",
    )
    second = await persist_sensitive_data_exposure(
        db_session,
        account_id=1000000,
        endpoint_id="passive-pii-ep",
        entity_type="SSN",
        source="response",
        path="/profile",
        method="GET",
    )
    await db_session.flush()

    assert first["created"] is True
    assert second["created"] is False
    assert second["occurrence_count"] == 2
