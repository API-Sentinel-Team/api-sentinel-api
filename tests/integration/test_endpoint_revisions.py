import pytest

from server.models.core import (
    APIEndpoint,
    EndpointRevision,
    EvidenceRecord,
    NucleiScan,
    OpenAPISpec,
    PolicyViolation,
    SourceCodeFinding,
    TestResult,
    Vulnerability,
)


@pytest.mark.asyncio
async def test_endpoint_revisions_api(client, auth_headers, db_session):
    endpoint = APIEndpoint(
        account_id=1000000,
        method="GET",
        path="/users/1",
        path_pattern="/users/{id}",
        host="example.com",
        protocol="https",
    )
    db_session.add(endpoint)
    await db_session.commit()

    rev = EndpointRevision(
        account_id=1000000,
        endpoint_id=endpoint.id,
        version_hash="abc123",
        schema_json={"type": "object"},
    )
    db_session.add(rev)
    await db_session.commit()

    resp = await client.get(f"/api/endpoints/{endpoint.id}/revisions", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1


@pytest.mark.asyncio
async def test_endpoint_lineage_api(client, auth_headers, db_session):
    endpoint = APIEndpoint(
        account_id=1000000,
        method="GET",
        path="/users",
        path_pattern="/users",
        host="api.example.com",
        protocol="https",
    )
    db_session.add(endpoint)
    await db_session.flush()

    db_session.add(
        EndpointRevision(
            account_id=1000000,
            endpoint_id=endpoint.id,
            version_hash="rev-1",
            schema_json={"type": "object"},
        )
    )
    db_session.add(
        Vulnerability(
            account_id=1000000,
            endpoint_id=endpoint.id,
            template_id="auth-check",
            type="BROKEN_AUTH",
            method="GET",
            severity="HIGH",
            status="OPEN",
            evidence={"request_id": "abc", "status_code": 200},
        )
    )
    db_session.add(
        PolicyViolation(
            account_id=1000000,
            endpoint_id=endpoint.id,
            rule_type="SCHEMA",
            severity="MEDIUM",
            status="OPEN",
            message="Missing response schema",
        )
    )
    db_session.add(
        EvidenceRecord(
            account_id=1000000,
            endpoint_id=endpoint.id,
            evidence_type="policy",
            severity="MEDIUM",
            summary="Schema drift detected",
        )
    )
    db_session.add(
        TestResult(
            endpoint_id=endpoint.id,
            template_id="auth-check",
            is_vulnerable=True,
            severity="HIGH",
            evidence="Access granted unexpectedly",
        )
    )
    db_session.add(
        SourceCodeFinding(
            account_id=1000000,
            repo_id="repo-1",
            endpoint_id=endpoint.id,
            file_path="app/routes.py",
            line_number=12,
            finding_type="ENDPOINT_DISCOVERED",
            severity="INFO",
            title="Endpoint: /users",
            status="OPEN",
        )
    )
    db_session.add(
        NucleiScan(
            account_id=1000000,
            target="https://api.example.com",
            status="COMPLETED",
            findings=[
                {
                    "template-id": "exposed-auth",
                    "name": "Auth Exposure",
                    "severity": "high",
                    "matched-at": "https://api.example.com/users",
                }
            ],
            total_found=1,
        )
    )
    db_session.add(
        OpenAPISpec(
            account_id=1000000,
            version="1.0.0",
            spec_json={
                "openapi": "3.0.0",
                "paths": {
                    "/users": {
                        "get": {"summary": "List users"},
                    }
                },
            },
        )
    )
    await db_session.commit()

    resp = await client.get(f"/api/endpoints/{endpoint.id}/lineage", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["endpoint"]["id"] == endpoint.id
    assert data["summary"]["revision_count"] == 1
    assert data["summary"]["vulnerability_count"] == 1
    assert data["summary"]["source_finding_count"] == 1
    assert data["summary"]["nuclei_match_count"] == 1
    assert data["summary"]["documented_in_latest_openapi"] is True
    assert data["documentation"]["documented"] is True
    assert data["vulnerabilities"][0]["fingerprint"]
    assert data["source_findings"][0]["fingerprint"]
