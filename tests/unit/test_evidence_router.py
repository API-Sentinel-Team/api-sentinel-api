import uuid

import pytest

from server.models.core import EvidenceRecord


@pytest.mark.asyncio
async def test_evidence_list_is_scoped_validated_and_redacted(client, db_session, auth_headers):
    endpoint_id = str(uuid.uuid4())
    db_session.add_all(
        [
            EvidenceRecord(
                account_id=1000000,
                endpoint_id=endpoint_id,
                evidence_type="policy",
                severity="HIGH",
                summary="Authorization: Bearer raw-evidence-token observed",
                details={
                    "url": "https://api.example.com/evidence?token=raw-evidence-token",
                    "headers": {"Authorization": "Bearer raw-evidence-token"},
                    "body": "api_key=raw-evidence-key",
                },
            ),
            EvidenceRecord(
                account_id=2000000,
                endpoint_id=endpoint_id,
                evidence_type="policy",
                severity="CRITICAL",
                summary="Authorization: Bearer other-tenant-token observed",
                details={"headers": {"Authorization": "Bearer other-tenant-token"}},
            ),
        ]
    )
    await db_session.commit()

    response = await client.get(
        "/api/evidence",
        headers=auth_headers,
        params={"endpoint_id": endpoint_id, "evidence_type": "policy"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    item = body["evidence"][0]
    assert item["endpoint_id"] == endpoint_id
    assert item["summary"] == "Authorization: Bearer **** observed"
    assert item["details"]["headers"]["Authorization"] == "****"
    assert item["details"]["url"] == "https://api.example.com/evidence?token=****"
    assert item["details"]["body"] == "api_key=****"
    assert "raw-evidence-token" not in str(body)
    assert "raw-evidence-key" not in str(body)
    assert "other-tenant-token" not in str(body)


@pytest.mark.asyncio
async def test_evidence_list_preserves_redacted_safety_policy_details(client, db_session, auth_headers):
    endpoint_id = str(uuid.uuid4())
    db_session.add(
        EvidenceRecord(
            account_id=1000000,
            endpoint_id=endpoint_id,
            evidence_type="policy",
            severity="LOW",
            summary="Authorization: Bearer raw-policy-token blocked",
            details={
                "safety_policies": {
                    "auth_profile_scope_policy": {
                        "policy": "auth_profile_scope_guard",
                        "blocked": True,
                        "url": "https://api.example.com/evidence-policy?token=raw-policy-token",
                        "base_url": "https://api.example.com/evidence-policy?token=raw-policy-token",
                        "reason": "Authorization: Bearer raw-policy-token token=raw-policy-token",
                        "auth_profile_id": "auth-profile-1",
                    }
                },
                "sent_request": {
                    "url": "https://api.example.com/evidence-policy?token=raw-policy-token",
                    "headers": {"Authorization": "Bearer raw-policy-token"},
                },
            },
        )
    )
    await db_session.commit()

    response = await client.get(
        "/api/evidence",
        headers=auth_headers,
        params={"endpoint_id": endpoint_id, "evidence_type": "policy"},
    )

    assert response.status_code == 200
    body = response.json()
    item = body["evidence"][0]
    policy = item["details"]["safety_policies"]["auth_profile_scope_policy"]
    assert item["summary"] == "Authorization: Bearer **** blocked"
    assert item["details"]["sent_request"]["headers"]["Authorization"] == "****"
    assert policy["policy"] == "auth_profile_scope_guard"
    assert policy["url"] == "https://api.example.com/evidence-policy?token=****"
    assert policy["base_url"] == "https://api.example.com/evidence-policy?token=****"
    assert policy["reason"] == "Authorization: Bearer **** token=****"
    assert policy["auth_profile_id"] == "auth-profile-1"
    assert "raw-policy-token" not in str(body)


@pytest.mark.asyncio
async def test_evidence_list_rejects_invalid_filters(client, auth_headers):
    invalid_endpoint = await client.get(
        "/api/evidence",
        headers=auth_headers,
        params={"endpoint_id": "not-a-uuid"},
    )
    invalid_type = await client.get(
        "/api/evidence",
        headers=auth_headers,
        params={"evidence_type": "policy;DROP"},
    )

    assert invalid_endpoint.status_code == 400
    assert invalid_type.status_code == 400
