import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.nuclei.findings import (
    build_nuclei_vulnerability_data,
    persist_nuclei_findings,
)
from server.modules.vulnerability_detector.lifecycle import (
    confirmation_status_from_evidence,
    verify_vulnerability_evidence,
)


def test_build_nuclei_vulnerability_data_redacts_secret_evidence():
    finding = {
        "template-id": "api-key-exposure",
        "name": "API Key Exposure",
        "severity": "high",
        "matched-at": "https://api.example.com/debug?session=raw-session",
        # Real nuclei output includes status-code and a parseable curl-command
        "status-code": 200,
        "curl-command": "curl -i -X GET 'https://api.example.com/debug?session=raw-session' -H 'Authorization: Bearer raw-token'",
        "info": {
            "description": "Sensitive token exposed",
            "remediation": "Disable debug endpoint",
        },
    }

    payload = build_nuclei_vulnerability_data(
        finding,
        account_id=1000000,
        target="https://api.example.com",
    )

    assert payload["template_id"] == "api-key-exposure"
    assert payload["severity"] == "HIGH"
    assert payload["type"] == "NUCLEI:api-key-exposure"
    assert payload["confidence"] == "MEDIUM"
    assert payload["url"] == "https://api.example.com/debug?session=****"
    assert payload["evidence"]["engine"] == "nuclei"
    assert payload["evidence"]["confirmation"] == {
        "confirmed": None,
        "status": "UNCONFIRMED",
        "reason": "external_engine_single_observation",
    }
    assert payload["evidence"]["scope_validation"] == {
        "validated": True,
        "policy": "target_guard",
        "scope": "same_origin_or_allowlisted",
        "target": "https://api.example.com",
        "evidence_url": "https://api.example.com/debug?session=****",
    }
    assert payload["evidence"]["finding_status"] == "UNCONFIRMED"
    assert payload["evidence"]["matched_rule"] == {
        "template_id": "api-key-exposure",
        "name": "API Key Exposure",
        "severity": "HIGH",
    }
    assert payload["evidence"]["sent_request"] == {
        "method": "GET",
        "url": "https://api.example.com/debug?session=****",
    }
    assert payload["evidence"]["received_response"]["status_code"] == 200
    assert payload["evidence"]["similarity"] == {
        "source": "nuclei_matcher",
        "confidence": "external_report",
    }
    assert "curl -i -X GET" in payload["evidence"]["reproduction"]["curl"]
    assert payload["evidence"]["remediation"] == "Disable debug endpoint"
    assert payload["evidence"]["evidence_completeness"]["complete"] is True
    assert payload["evidence"]["evidence_completeness"]["missing"] == []
    assert payload["evidence"]["evidence_reproducibility"] == {
        "redaction_policy": "api_sentinel_redactor",
        "raw_payload_persisted": False,
        "deterministic_hash": True,
        "hash_algorithm": "sha256",
        "reproduction_available": True,
        "scope_validated": True,
        "evidence_complete": True,
    }
    assert confirmation_status_from_evidence(payload["evidence"]) == "UNCONFIRMED"
    assert payload["evidence"]["evidence_hash"]
    assert verify_vulnerability_evidence(payload["evidence"])["verified"] is True
    assert payload["evidence"]["finding"]["matched-at"] == "https://api.example.com/debug?session=****"
    assert "raw-token" not in str(payload["evidence"])
    assert "raw-session" not in str(payload["evidence"])


@pytest.mark.asyncio
async def test_persist_nuclei_findings_merges_repeated_findings(db_session):
    finding = {
        "template-id": "admin-panel",
        "name": "Admin Panel Exposure",
        "severity": "medium",
        "matched-at": "https://api.example.com/admin",
        "info": {"description": "Admin panel is reachable"},
    }

    first = await persist_nuclei_findings(
        db_session,
        account_id=1000000,
        target="https://api.example.com",
        findings=[finding],
    )
    second = await persist_nuclei_findings(
        db_session,
        account_id=1000000,
        target="https://api.example.com",
        findings=[finding],
    )
    await db_session.flush()

    assert first["created_count"] == 1
    assert first["merged_count"] == 0
    assert second["created_count"] == 0
    assert second["merged_count"] == 1
    assert second["vulnerabilities"][0]["occurrence_count"] == 2

    rows = (await db_session.execute(select(models.Vulnerability))).scalars().all()
    matching = [row for row in rows if row.template_id == "admin-panel"]
    assert len(matching) == 1
    assert matching[0].occurrence_count == 2
    assert matching[0].evidence["engine"] == "nuclei"
    assert confirmation_status_from_evidence(matching[0].evidence) == "UNCONFIRMED"
    assert verify_vulnerability_evidence(matching[0].evidence)["verified"] is True
