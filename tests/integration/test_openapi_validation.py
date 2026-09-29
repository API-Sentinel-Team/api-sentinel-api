import datetime

import pytest
from sqlalchemy import select

from server.models.core import APIEndpoint, EvidenceRecord, OpenAPISpec, PolicyViolation
from server.modules.auth.jwt_issuer import JWTIssuer


def _headers_for_role(role: str, account_id: int = 1000000) -> dict[str, str]:
    token = JWTIssuer.create_access_token(
        {
            "sub": f"{role.lower()}-{account_id}",
            "email": f"{role.lower()}-{account_id}@example.com",
            "account_id": account_id,
            "role": role,
        }
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_openapi_rebuild_and_validate(client, auth_headers):
    rebuild = await client.post("/api/openapi/rebuild", headers=auth_headers)
    assert rebuild.status_code == 200
    spec_id = rebuild.json().get("id")
    assert spec_id

    latest = await client.get("/api/openapi/latest", headers=auth_headers)
    assert latest.status_code == 200
    assert "spec" in latest.json()

    validate = await client.post("/api/openapi/validate", headers=auth_headers)
    assert validate.status_code == 200
    assert "violations_found" in validate.json()


@pytest.mark.asyncio
async def test_openapi_history_and_diff(client, db_session, auth_headers):
    base_spec = OpenAPISpec(
        account_id=1000000,
        version="1.0.0",
        spec_json={
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"id": {"type": "string"}, "email": {"type": "string"}},
                                        }
                                    }
                                },
                            }
                        }
                    }
                }
            },
        },
        created_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5),
    )
    revision_spec = OpenAPISpec(
        account_id=1000000,
        version="1.1.0",
        spec_json={
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {
                                "description": "ok",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"id": {"type": "string"}},
                                        }
                                    }
                                },
                            }
                        },
                    }
                }
            },
        },
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db_session.add_all([base_spec, revision_spec])
    await db_session.commit()

    history = await client.get("/api/openapi/history", headers=auth_headers)
    assert history.status_code == 200
    payload = history.json()
    assert payload["total"] >= 2

    diff = await client.post(
        "/api/openapi/diff",
        headers=auth_headers,
        json={"base_spec_id": base_spec.id, "revision_spec_id": revision_spec.id},
    )
    assert diff.status_code == 200
    diff_payload = diff.json()
    assert diff_payload["base_spec_id"] == base_spec.id
    assert diff_payload["revision_spec_id"] == revision_spec.id
    assert diff_payload["summary"]["total_breaking_changes"] >= 2


@pytest.mark.asyncio
async def test_openapi_import_populates_endpoint_inventory(client, db_session, auth_headers):
    resp = await client.post(
        "/api/openapi/import",
        headers=auth_headers,
        json={
            "version": "2026.06",
            "target_url": "https://api.example.com",
            "source": "openapi",
            "owner": "platform-team",
            "spec": {
                "openapi": "3.0.0",
                "security": [{"bearerAuth": []}],
                "paths": {
                    "/users/{id}": {
                        "get": {
                            "summary": "Get user",
                            "x-api-sentinel": {"sensitivity": "high"},
                        },
                    },
                    "/reports/{report_id}": {
                        "delete": {
                            "summary": "Delete report",
                            "deprecated": True,
                            "security": [],
                        },
                    },
                },
            },
        },
    )

    assert resp.status_code == 200
    payload = resp.json()
    assert payload["status"] == "imported"
    assert payload["endpoint_count"] == 2
    assert payload["spec_id"]

    result = await db_session.execute(
        select(APIEndpoint).where(
            APIEndpoint.account_id == 1000000,
            APIEndpoint.host == "api.example.com",
        )
    )
    endpoints = {
        (endpoint.method, endpoint.path_pattern): endpoint
        for endpoint in result.scalars().all()
    }

    user_endpoint = endpoints[("GET", "/users/{id}")]
    assert user_endpoint.is_sensitive is True
    assert user_endpoint.status == "ACTIVE"
    assert user_endpoint.tags["owner"] == "platform-team"
    assert user_endpoint.tags["auth_required"] is True
    assert user_endpoint.tags["sensitivity"] == "high"
    assert user_endpoint.tags["version"] == "2026.06"
    assert user_endpoint.tags["sources"] == ["openapi"]

    delete_endpoint = endpoints[("DELETE", "/reports/{report_id}")]
    assert delete_endpoint.status == "DEPRECATED"
    assert delete_endpoint.tags["auth_required"] is False
    assert delete_endpoint.tags["deprecated"] is True

    inventory_resp = await client.get(
        "/api/endpoints/?host=api.example.com",
        headers=auth_headers,
    )
    assert inventory_resp.status_code == 200
    inventory = {
        (endpoint["method"], endpoint["path_pattern"]): endpoint
        for endpoint in inventory_resp.json()["endpoints"]
    }
    listed_user_endpoint = inventory[("GET", "/users/{id}")]
    assert listed_user_endpoint["owner"] == "platform-team"
    assert listed_user_endpoint["auth_required"] is True
    assert listed_user_endpoint["sensitivity"] == "high"
    assert listed_user_endpoint["version"] == "2026.06"
    assert listed_user_endpoint["status"] == "ACTIVE"
    assert listed_user_endpoint["is_sensitive"] is True
    assert listed_user_endpoint["sources"] == ["openapi"]

    listed_delete_endpoint = inventory[("DELETE", "/reports/{report_id}")]
    assert listed_delete_endpoint["auth_required"] is False
    assert listed_delete_endpoint["deprecated"] is True
    assert listed_delete_endpoint["status"] == "DEPRECATED"


@pytest.mark.asyncio
async def test_openapi_scan_plan(client, db_session, auth_headers):
    spec = OpenAPISpec(
        account_id=1000000,
        version="2.0.0",
        spec_json={
            "openapi": "3.0.0",
            "security": [{"bearerAuth": []}],
            "paths": {
                "/users": {
                    "get": {"summary": "List users"},
                    "post": {"summary": "Create user"},
                },
                "/users/{id}": {
                    "get": {"summary": "Get user"},
                },
            },
        },
    )
    db_session.add(spec)
    await db_session.commit()

    resp = await client.post(
        "/api/openapi/scan-plan",
        headers=auth_headers,
        json={
            "spec_id": spec.id,
            "target_url": "https://api.example.com",
            "auth_header_name": "Authorization",
            "auth_header_site": "https://api.example.com",
            "extra_headers": {"X-Tenant": "${ZAP_TENANT_ID}"},
        },
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["summary"]["spec_id"] == spec.id
    assert payload["summary"]["operation_count"] == 2
    assert payload["summary"]["authenticated_operation_count"] == 2
    assert payload["summary"]["uses_header_auth_env"] is True
    assert payload["summary"]["uses_replacer_rules"] is True
    assert payload["summary"]["active_scan_included"] is True
    assert payload["summary"]["state_change_filtered"] is True
    assert payload["summary"]["blocked_destructive_operation_count"] == 1
    assert payload["state_change_policy"]["blocked_destructive_operations"] == [
        {"method": "POST", "path": "/users", "summary": "Create user"}
    ]
    assert "automation_yaml" in payload["artifacts"]
    automation_yaml = payload["artifacts"]["automation_yaml"]
    assert "openapi" in automation_yaml
    assert "activeScan" in automation_yaml
    assert "Create user" not in automation_yaml
    assert "${ZAP_AUTH_HEADER_VALUE}" in automation_yaml
    required_env_names = {env["name"] for env in payload["execution"]["required_env"]}
    assert {"ZAP_AUTH_HEADER", "ZAP_AUTH_HEADER_VALUE", "ZAP_AUTH_HEADER_SITE"} <= required_env_names
    replacer_rules = [
        rule
        for job in payload["plan"]["jobs"]
        if job["type"] == "replacer"
        for rule in job["rules"]
    ]
    assert {
        "matchString": "Authorization",
        "replacementString": "${ZAP_AUTH_HEADER_VALUE}",
    }.items() <= replacer_rules[0].items()


@pytest.mark.asyncio
async def test_openapi_scan_plan_blocks_target_guard_violations(client, auth_headers):
    resp = await client.post(
        "/api/openapi/scan-plan",
        headers=auth_headers,
        json={
            "spec": {
                "openapi": "3.0.0",
                "paths": {"/users": {"get": {"summary": "List users"}}},
            },
            "target_url": "http://169.254.169.254/latest/meta-data",
        },
    )

    assert resp.status_code == 400
    message = resp.json()["message"]
    assert message["reason"] == "target_guard_blocked"
    assert "metadata" in message["message"]
    assert message["target_guard_policy"]["policy"] == "target_guard"
    assert message["target_guard_policy"]["blocked"] is True
    assert message["target_guard_policy"]["url"] == "http://169.254.169.254/latest/meta-data"
    assert "metadata" in message["target_guard_policy"]["reason"]


@pytest.mark.asyncio
async def test_openapi_governance_permissions_and_redacted_outputs(client, db_session):
    account_id = 9411001
    raw_token = "openapi-raw-token"
    member_headers = _headers_for_role("MEMBER", account_id)
    viewer_headers = _headers_for_role("VIEWER", account_id)
    security_headers = _headers_for_role("SECURITY_ENGINEER", account_id)

    spec = OpenAPISpec(
        account_id=account_id,
        version="3.0.0",
        spec_json={
            "openapi": "3.0.0",
            "paths": {
                f"/documented?token={raw_token}": {
                    "get": {
                        "summary": f"Authorization: Bearer {raw_token}",
                        "responses": {"200": {"description": f"token={raw_token}"}},
                    }
                }
            },
        },
    )
    endpoint = APIEndpoint(
        account_id=account_id,
        method="GET",
        host="api.example.com",
        path=f"/undocumented?token={raw_token}",
        protocol="https",
    )
    db_session.add_all([spec, endpoint])
    await db_session.commit()

    denied_rebuild = await client.post("/api/openapi/rebuild", headers=viewer_headers)
    denied_scan_plan = await client.post(
        "/api/openapi/scan-plan",
        headers=viewer_headers,
        json={"spec_id": spec.id, "target_url": "https://api.example.com"},
    )
    denied_validate = await client.post("/api/openapi/validate", headers=member_headers)
    assert denied_rebuild.status_code == 403
    assert denied_scan_plan.status_code == 403
    assert denied_validate.status_code == 403

    latest_response = await client.get("/api/openapi/latest", headers=member_headers)
    assert latest_response.status_code == 200
    assert raw_token not in str(latest_response.json())
    assert "Bearer ****" in str(latest_response.json())
    assert "token=****" in str(latest_response.json())

    scan_plan_response = await client.post(
        "/api/openapi/scan-plan",
        headers=member_headers,
        json={
            "spec_id": spec.id,
            "target_url": "https://api.example.com",
            "extra_headers": {
                "X-API-Key": raw_token,
                "X-Tenant": "${ZAP_TENANT_ID}",
            },
        },
    )
    assert scan_plan_response.status_code == 200
    scan_plan = scan_plan_response.json()
    assert raw_token not in str(scan_plan)
    assert "${ZAP_EXTRA_HEADER_X_API_KEY}" in scan_plan["artifacts"]["automation_yaml"]
    assert "${ZAP_TENANT_ID}" in scan_plan["artifacts"]["automation_yaml"]
    assert {"name": "ZAP_EXTRA_HEADER_X_API_KEY", "value": "<set-in-ci>"} in scan_plan["execution"]["required_env"]

    validate_response = await client.post("/api/openapi/validate", headers=security_headers)
    assert validate_response.status_code == 200
    assert validate_response.json()["violations_found"] >= 1

    violation = (
        await db_session.execute(
            select(PolicyViolation).where(
                PolicyViolation.account_id == account_id,
                PolicyViolation.endpoint_id == endpoint.id,
            )
        )
    ).scalar_one()
    evidence = (
        await db_session.execute(
            select(EvidenceRecord).where(
                EvidenceRecord.account_id == account_id,
                EvidenceRecord.ref_id == violation.id,
            )
        )
    ).scalar_one()
    assert raw_token not in str({"message": violation.message, "summary": evidence.summary})
    assert "token=****" in str({"message": violation.message, "summary": evidence.summary})

    violations_response = await client.get("/api/openapi/violations", headers=member_headers)
    assert violations_response.status_code == 200
    assert raw_token not in str(violations_response.json())
