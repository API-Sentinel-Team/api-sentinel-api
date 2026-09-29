import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.schemathesis.findings import (
    build_schemathesis_vulnerability_data,
    iter_schemathesis_junit_failures,
    persist_schemathesis_junit,
)
from server.modules.vulnerability_detector.lifecycle import (
    confirmation_status_from_evidence,
    verify_vulnerability_evidence,
)


def _junit_report(*, failure_type: str = "response_schema_conformance") -> str:
    # Failure text matches real schemathesis output: includes HTTP request+response block
    # so _extract_schemathesis_request_response can parse a real status_code.
    failure_text = (
        "AssertionError: Response violates schema\n"
        "GET /users/{user_id}?session=raw-session HTTP/1.1\n"
        "Authorization: Bearer raw-token\n\n"
        "HTTP/1.1 422 Unprocessable Entity\n"
        "Content-Type: application/json\n\n"
        '{"error": "schema violation"}'
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="schemathesis" tests="2" failures="1">
  <testcase classname="schemathesis" name="GET /users/{{user_id}}?session=raw-session">
    <failure type="{failure_type}" message="{failure_type}: Authorization: Bearer raw-token">{failure_text}</failure>
  </testcase>
  <testcase classname="schemathesis" name="POST /orders" />
</testsuite>
"""


def test_iter_schemathesis_junit_failures_extracts_operation_context():
    failures = list(
        iter_schemathesis_junit_failures(
            _junit_report(),
            target_url="https://api.example.com",
        )
    )

    assert len(failures) == 1
    assert failures[0]["method"] == "GET"
    assert failures[0]["url"] == "https://api.example.com/users/{user_id}?session=raw-session"
    assert failures[0]["check_name"] == "response_schema_conformance"


def test_build_schemathesis_vulnerability_data_redacts_evidence():
    failure = list(
        iter_schemathesis_junit_failures(
            _junit_report(),
            target_url="https://api.example.com",
        )
    )[0]

    payload = build_schemathesis_vulnerability_data(
        failure,
        account_id=1000000,
        target_url="https://api.example.com",
    )

    assert payload["template_id"] == "schemathesis-response_schema_conformance"
    assert payload["type"] == "SCHEMATHESIS:response_schema_conformance"
    assert payload["severity"] == "MEDIUM"
    assert payload["url"] == "https://api.example.com/users/{user_id}?session=****"
    assert payload["evidence"]["engine"] == "schemathesis"
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
        "evidence_url": "https://api.example.com/users/{user_id}?session=****",
    }
    assert payload["evidence"]["finding_status"] == "UNCONFIRMED"
    assert payload["evidence"]["matched_rule"] == {
        "check": "response_schema_conformance",
        "kind": "failure",
        "type": "response_schema_conformance",
    }
    assert payload["evidence"]["sent_request"] == {
        "method": "GET",
        "url": "https://api.example.com/users/{user_id}?session=****",
    }
    # Body contains the redacted failure text (HTTP block from fixture)
    body = payload["evidence"]["received_response"]["body"]
    assert "HTTP/1.1 422" in body
    assert "****" in body  # secrets are redacted
    assert payload["evidence"]["similarity"] == {
        "source": "schemathesis_check",
        "check": "response_schema_conformance",
    }
    assert "curl -i -X GET" in payload["evidence"]["reproduction"]["curl"]
    assert payload["evidence"]["remediation"] == (
        "Review the OpenAPI contract, API implementation, and auth expectations for this operation."
    )
    assert payload["evidence"]["evidence_completeness"]["complete"] is True
    assert payload["evidence"]["evidence_completeness"]["missing"] == []
    assert payload["evidence"]["content_minimization"] == {
        "raw_request_body_persisted": False,
        "raw_response_body_persisted": False,
        "matched_text_persisted": False,
        "secret_values_persisted": False,
        "body_content_persisted": True,
        "details_content_persisted": True,
        "business_logic_scenario_content_persisted": False,
        "persisted_material": [
            "metadata",
            "redacted_http_messages",
            "redacted_reproduction",
            "sha256_digests",
        ],
    }
    assert confirmation_status_from_evidence(payload["evidence"]) == "UNCONFIRMED"
    assert payload["evidence"]["evidence_hash"]
    assert verify_vulnerability_evidence(payload["evidence"])["verified"] is True
    assert payload["evidence"]["failure"]["failure_text"]
    assert "raw-token" not in str(payload["evidence"])
    assert "raw-session" not in str(payload["evidence"])


@pytest.mark.asyncio
async def test_persist_schemathesis_junit_merges_repeated_failures(db_session):
    report = _junit_report(failure_type="schema_merge_case")

    first = await persist_schemathesis_junit(
        db_session,
        account_id=1000000,
        target_url="https://api.example.com",
        junit_xml=report,
    )
    second = await persist_schemathesis_junit(
        db_session,
        account_id=1000000,
        target_url="https://api.example.com",
        junit_xml=report,
    )
    await db_session.flush()

    assert first["testcases_imported"] == 2
    assert first["failures_imported"] == 1
    assert first["created_count"] == 1
    assert first["merged_count"] == 0
    assert second["created_count"] == 0
    assert second["merged_count"] == 1
    assert second["vulnerabilities"][0]["occurrence_count"] == 2

    rows = (
        await db_session.execute(
            select(models.Vulnerability).where(models.Vulnerability.template_id == "schemathesis-schema-merge-case")
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].evidence["engine"] == "schemathesis"
    assert confirmation_status_from_evidence(rows[0].evidence) == "UNCONFIRMED"
    assert verify_vulnerability_evidence(rows[0].evidence)["verified"] is True
    assert rows[0].occurrence_count == 2


def test_schemathesis_junit_rejects_dtd_entities():
    with pytest.raises(ValueError, match="DTD"):
        list(
            iter_schemathesis_junit_failures(
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><testsuite />",
                target_url="https://api.example.com",
            )
        )
