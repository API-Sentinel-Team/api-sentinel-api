import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.zap.findings import (
    build_zap_vulnerability_data,
    iter_zap_alert_instances,
    persist_zap_report,
)
from server.modules.vulnerability_detector.lifecycle import (
    confirmation_status_from_evidence,
    verify_vulnerability_evidence,
)


def _sample_zap_report() -> dict:
    return {
        "site": [
            {
                "@name": "https://api.example.com",
                "alerts": [
                    {
                        "pluginid": "10020",
                        "alert": "X-Frame-Options Header Not Set",
                        "riskcode": "2",
                        "confidence": "Medium",
                        "desc": "X-Frame-Options header is missing",
                        "solution": "Set X-Frame-Options or CSP frame-ancestors",
                        "instances": [
                            {
                                "uri": "https://api.example.com/admin?session=raw-session",
                                "method": "GET",
                                "param": "X-Frame-Options",
                                "evidence": "Authorization: Bearer raw-token",
                            }
                        ],
                    }
                ],
            }
        ]
    }


def test_iter_zap_alert_instances_handles_site_report_shape():
    instances = list(iter_zap_alert_instances(_sample_zap_report()))

    assert len(instances) == 1
    alert, instance, site_url = instances[0]
    assert alert["pluginid"] == "10020"
    assert instance["method"] == "GET"
    assert site_url == "https://api.example.com"


def test_build_zap_vulnerability_data_redacts_report_evidence():
    alert, instance, site_url = list(iter_zap_alert_instances(_sample_zap_report()))[0]

    payload = build_zap_vulnerability_data(
        alert,
        instance,
        account_id=1000000,
        target_url="https://api.example.com",
        site_url=site_url,
    )

    assert payload["template_id"] == "zap-10020"
    assert payload["type"] == "ZAP:10020"
    assert payload["severity"] == "MEDIUM"
    assert payload["confidence"] == "MEDIUM"
    assert payload["url"] == "https://api.example.com/admin?session=****"
    assert payload["evidence"]["engine"] == "zap"
    assert payload["evidence"]["source_fingerprint"]
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
        "evidence_url": "https://api.example.com/admin?session=****",
    }
    assert payload["evidence"]["finding_status"] == "UNCONFIRMED"
    assert payload["evidence"]["matched_rule"] == {
        "plugin_id": "10020",
        "name": "X-Frame-Options Header Not Set",
        "risk": "MEDIUM",
    }
    assert payload["evidence"]["sent_request"] == {
        "method": "GET",
        "url": "https://api.example.com/admin?session=****",
    }
    assert payload["evidence"]["received_response"]["body"] == "Authorization: Bearer ****"
    assert payload["evidence"]["similarity"] == {
        "source": "zap_confidence",
        "confidence": "MEDIUM",
    }
    assert "curl -i -X GET" in payload["evidence"]["reproduction"]["curl"]
    assert payload["evidence"]["remediation"] == "Set X-Frame-Options or CSP frame-ancestors"
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
    assert "raw-token" not in str(payload["evidence"])
    assert "raw-session" not in str(payload["evidence"])


@pytest.mark.asyncio
async def test_persist_zap_report_merges_repeated_alert_instances(db_session):
    changed_report = _sample_zap_report()
    changed_report["site"][0]["alerts"][0]["instances"][0]["evidence"] = (
        "Authorization: Bearer different-token observed in a later scan"
    )
    changed_report["site"][0]["alerts"][0]["instances"][0]["attack"] = "<script>different()</script>"

    first = await persist_zap_report(
        db_session,
        account_id=1000000,
        target_url="https://api.example.com",
        report=_sample_zap_report(),
    )
    second = await persist_zap_report(
        db_session,
        account_id=1000000,
        target_url="https://api.example.com",
        report=changed_report,
    )
    await db_session.flush()

    assert first["created_count"] == 1
    assert first["merged_count"] == 0
    assert second["created_count"] == 0
    assert second["merged_count"] == 1
    assert first["vulnerabilities"][0]["source_fingerprint"] == second["vulnerabilities"][0]["source_fingerprint"]
    assert second["vulnerabilities"][0]["occurrence_count"] == 2

    rows = (
        await db_session.execute(
            select(models.Vulnerability).where(models.Vulnerability.template_id == "zap-10020")
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].evidence["engine"] == "zap"
    assert rows[0].evidence["source_fingerprint"] == second["vulnerabilities"][0]["source_fingerprint"]
    assert confirmation_status_from_evidence(rows[0].evidence) == "UNCONFIRMED"
    assert verify_vulnerability_evidence(rows[0].evidence)["verified"] is True
    assert rows[0].occurrence_count == 2
