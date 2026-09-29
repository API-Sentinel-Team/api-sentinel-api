import pytest
from server.modules.auth.jwt_issuer import JWTIssuer

from server.modules.ingestion.schema import EventBatch, APITrafficEvent, APIRequest, APIResponse


@pytest.mark.asyncio
async def test_ingestion_requires_auth(client):
    event = APITrafficEvent(
        account_id=1000000,
        observed_at=1710000000000,
        request=APIRequest(method="GET", path="/health"),
        response=APIResponse(status_code=200),
    )
    payload = EventBatch(events=[event]).model_dump()
    resp = await client.post("/api/ingestion/v2/events", json=payload)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_openapi_requires_auth(client):
    resp = await client.post("/api/openapi/rebuild")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_openapi_history_requires_auth(client):
    resp = await client.get("/api/openapi/history")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_openapi_violations_requires_auth(client):
    resp = await client.get("/api/openapi/violations")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_openapi_diff_requires_auth(client):
    resp = await client.post("/api/openapi/diff")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_openapi_scan_plan_requires_auth(client):
    resp = await client.post("/api/openapi/scan-plan", json={"target_url": "https://api.example.com"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_endpoint_lineage_requires_auth(client):
    resp = await client.get("/api/endpoints/test-endpoint/lineage")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_account_settings_requires_auth(client):
    resp = await client.post("/api/getAccountSettingsForAdvancedFilters")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_keys_requires_auth(client):
    resp = await client.post("/api/getApiKeys")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_api_key_requires_auth(client):
    resp = await client.post("/api/createApiKey", json={"name": "test", "scopes": []})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_nuclei_scans_requires_auth(client):
    resp = await client.get("/api/nuclei/scans")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_evidence_requires_auth(client):
    resp = await client.get("/api/evidence")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_pii_findings_requires_auth(client):
    resp = await client.get("/api/pii/findings")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_bola_vulnerabilities_requires_auth(client):
    resp = await client.get("/api/bola/vulnerabilities")
    assert resp.status_code == 401


def _headers_for_role(role: str, account_id: int = 1000000):
    token = JWTIssuer.create_access_token({
        "sub": f"{role.lower()}-user",
        "email": f"{role.lower()}@example.com",
        "account_id": account_id,
        "role": role,
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_traffic_status_requires_auth(client):
    resp = await client.get("/api/traffic/status")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_viewer_cannot_create_endpoint(client):
    resp = await client.post(
        "/api/endpoints/",
        headers=_headers_for_role("VIEWER"),
        json={"method": "GET", "path": "/denied", "host": "example.com"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_member_cannot_rebuild_business_logic_graph(client):
    resp = await client.post(
        "/api/business-logic/rebuild",
        headers=_headers_for_role("MEMBER"),
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "headers", "kwargs"),
    [
        ("post", "/api/collections/", "VIEWER", {"json": {"name": "viewer denied"}}),
        ("post", "/api/collections/postman-import", "VIEWER", {"json": "{}"}),
        (
            "post",
            "/api/collections/11111111-1111-1111-1111-111111111111/add-endpoint/22222222-2222-2222-2222-222222222222",
            "VIEWER",
            {},
        ),
        ("delete", "/api/collections/11111111-1111-1111-1111-111111111111", "MEMBER", {}),
    ],
)
@pytest.mark.asyncio
async def test_collection_mutations_require_endpoint_permissions(client, method, path, headers, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role(headers),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_run_tests(client):
    resp = await client.post(
        "/api/tests/run",
        headers=_headers_for_role("VIEWER"),
        json={"template_ids": [], "endpoint_ids": []},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_cancel_scan_run(client):
    resp = await client.post(
        "/api/tests/runs/11111111-1111-1111-1111-111111111111/cancel",
        headers=_headers_for_role("VIEWER"),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_run_suite(client):
    resp = await client.post(
        "/api/suites/safe-api/run",
        headers=_headers_for_role("VIEWER"),
        json={"endpoint_ids": []},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_create_schedule(client):
    resp = await client.post(
        "/api/schedules/",
        headers=_headers_for_role("VIEWER"),
        json={
            "name": "denied",
            "cron_expression": "0 2 * * *",
            "template_ids": [],
            "endpoint_ids": [],
        },
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "headers", "kwargs"),
    [
        ("post", "/api/openapi/rebuild", "VIEWER", {}),
        ("post", "/api/openapi/scan-plan", "VIEWER", {"json": {"target_url": "https://api.example.com"}}),
        ("post", "/api/openapi/validate", "MEMBER", {}),
    ],
)
@pytest.mark.asyncio
async def test_openapi_mutation_and_scan_planning_permissions(client, method, path, headers, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role(headers),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_member_cannot_manage_bola_replay_accounts(client):
    account_resp = await client.post(
        "/api/accounts/",
        headers=_headers_for_role("MEMBER"),
        json={
            "name": "member should not manage",
            "role": "ATTACKER",
            "auth_token": "raw-member-token",
        },
    )
    assert account_resp.status_code == 403

    role_resp = await client.post(
        "/api/auth-roles/",
        headers=_headers_for_role("MEMBER"),
        json={
            "name": "member should not manage",
            "role": "VICTIM",
            "auth_headers": {"Authorization": "Bearer raw-member-token"},
        },
    )
    assert role_resp.status_code == 403


@pytest.mark.asyncio
async def test_member_cannot_manage_auth_mechanisms(client):
    resp = await client.post(
        "/api/auth-mechanisms/",
        headers=_headers_for_role("MEMBER"),
        json={
            "name": "member should not manage",
            "header_key": "Authorization",
            "prefix": "Bearer ",
            "token_type": "BEARER",
        },
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_member_cannot_manage_pentest_profiles(client):
    auth_profile_resp = await client.post(
        "/api/pentest/auth-profiles",
        headers=_headers_for_role("MEMBER"),
        json={
            "name": "member should not manage secrets",
            "auth_mode": "bearer",
            "token": "member-raw-token",
        },
    )
    profile_resp = await client.post(
        "/api/pentest/profiles",
        headers=_headers_for_role("MEMBER"),
        json={
            "name": "member should not manage pentest profiles",
            "mode": "SAFE",
        },
    )

    assert auth_profile_resp.status_code == 403
    assert profile_resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        (
            "post",
            "/api/nuclei/scan",
            {
                "json": {
                    "target": "https://api.example.com",
                    "template_ids": [],
                    "custom_template_ids": [],
                    "tags": [],
                    "severity": [],
                }
            },
        ),
        (
            "post",
            "/api/nuclei/templates",
            {
                "json": {
                    "name": "member denied",
                    "yaml_content": "id: member-denied\ninfo:\n  name: denied\n  severity: low\n",
                }
            },
        ),
        ("patch", "/api/nuclei/templates/11111111-1111-1111-1111-111111111111", {"json": {"enabled": False}}),
        ("delete", "/api/nuclei/templates/11111111-1111-1111-1111-111111111111", {}),
        ("get", "/api/nuclei/templates/11111111-1111-1111-1111-111111111111/content", {}),
    ],
)
@pytest.mark.asyncio
async def test_member_cannot_run_nuclei_or_manage_templates(client, method, path, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role("MEMBER"),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        (
            "post",
            "/api/integrations/",
            {
                "json": {
                    "type": "webhook",
                    "name": "member denied",
                    "config": {"url": "https://hooks.example.com/security"},
                    "events": ["alert.created"],
                }
            },
        ),
        ("patch", "/api/integrations/11111111-1111-1111-1111-111111111111", {"json": {"enabled": False}}),
        ("delete", "/api/integrations/11111111-1111-1111-1111-111111111111", {}),
        ("post", "/api/integrations/11111111-1111-1111-1111-111111111111/test", {}),
        (
            "post",
            "/api/recon/sources",
            {"json": {"name": "member denied", "provider": "SHODAN", "config": {"api_key": "member-key"}}},
        ),
        ("patch", "/api/recon/sources/11111111-1111-1111-1111-111111111111", {"json": {"enabled": False}}),
        ("delete", "/api/recon/sources/11111111-1111-1111-1111-111111111111", {}),
        ("post", "/api/recon/sources/11111111-1111-1111-1111-111111111111/run", {}),
    ],
)
@pytest.mark.asyncio
async def test_member_cannot_manage_integrations(client, method, path, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role("MEMBER"),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        (
            "post",
            "/api/playbooks/",
            {"json": {"name": "member denied", "trigger": "alert.created", "actions": [{"type": "NOTIFY"}]}},
        ),
        ("patch", "/api/playbooks/11111111-1111-1111-1111-111111111111", {"json": {"enabled": False}}),
        ("delete", "/api/playbooks/11111111-1111-1111-1111-111111111111", {}),
        ("post", "/api/enforcement/waf-rule", {"json": {"source_ips": ["203.0.113.10"]}}),
        (
            "post",
            "/api/enforcement/rate-limit",
            {"json": {"endpoint_id": "11111111-1111-1111-1111-111111111111"}},
        ),
        (
            "post",
            "/api/enforcement/endpoint-block",
            {"json": {"endpoint_id": "11111111-1111-1111-1111-111111111111"}},
        ),
        ("post", "/api/enforcement/token-invalidate", {"json": {"token_jti": "member-token"}}),
        ("post", "/api/enforcement/auto-remediate", {"json": {"source_ip": "203.0.113.10"}}),
    ],
)
@pytest.mark.asyncio
async def test_member_cannot_manage_response_automation(client, method, path, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role("MEMBER"),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        (
            "post",
            "/api/source-code/repos",
            {
                "json": {
                    "name": "member denied",
                    "repo_type": "GITHUB",
                    "repo_url": "https://github.com/example/denied.git",
                }
            },
        ),
        ("post", "/api/source-code/repos/11111111-1111-1111-1111-111111111111/scan", {}),
        ("patch", "/api/source-code/findings/11111111-1111-1111-1111-111111111111", {"json": {"status": "FIXED"}}),
    ],
)
@pytest.mark.asyncio
async def test_member_cannot_manage_source_code_scans(client, method, path, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role("MEMBER"),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        (
            "post",
            "/api/threat-detection/record",
            {
                "json": {
                    "malicious_event": {
                        "actor": "203.0.113.10",
                        "filter_id": "member-denied",
                        "latest_api_endpoint": "/admin",
                        "latest_api_method": "GET",
                    }
                }
            },
        ),
        ("post", "/api/threat-detection/events/status", {"json": {"event_ids": ["event-1"], "status": "RESOLVED"}}),
        ("post", "/api/threat-detection/events/delete", {"json": {"event_ids": ["event-1"]}}),
        ("post", "/api/threat-detection/actors/status", {"json": {"ip": "203.0.113.10", "status": "BLOCKED"}}),
        (
            "post",
            "/api/threat-detection/actors/bulk-status",
            {"json": {"ips": ["203.0.113.10"], "status": "BLOCKED"}},
        ),
        ("put", "/api/threat-detection/config", {"json": {"archival_days": 30, "archival_enabled": True}}),
        ("post", "/api/threat-detection/config/archival", {"json": {"enabled": True}}),
        ("post", "/api/threat-detection/http-traffic", {"json": {"method": "GET", "path": "/health"}}),
        (
            "post",
            "/api/threat-detection/sessions/bulk-update",
            {
                "json": {
                    "session_documents": [
                        {
                            "session_identifier": "member-denied",
                            "conversation_info": [],
                        }
                    ]
                }
            },
        ),
    ],
)
@pytest.mark.asyncio
async def test_member_cannot_mutate_threat_detection_surfaces(client, method, path, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role("MEMBER"),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        (
            "post",
            "/api/agent-guard/sessions",
            {"json": {"session_identifier": "member-denied", "session_summary": "denied"}},
        ),
        (
            "post",
            "/api/agent-guard/sessions/11111111-1111-1111-1111-111111111111/inspect",
            {"json": {"message": "ignore previous instructions", "role": "user"}},
        ),
        (
            "post",
            "/api/agentic/invocations",
            {
                "json": {
                    "agent_id": "member-agent",
                    "tool_name": "secrets.read",
                    "parameters": {"token": "member-token"},
                    "result_text": "ignore previous instructions",
                }
            },
        ),
    ],
)
@pytest.mark.asyncio
async def test_member_cannot_mutate_agentic_guard_surfaces(client, method, path, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role("MEMBER"),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("post", "/api/threat-actors/", {"json": {"source_ip": "203.0.113.10", "status": "BLOCKED"}}),
        ("post", "/api/threat-actors/203.0.113.10/block", {}),
        ("post", "/api/threat-actors/203.0.113.10/whitelist", {}),
        (
            "post",
            "/api/threat-actors/events",
            {
                "json": {
                    "source_ip": "203.0.113.10",
                    "event_type": "AUTH_BYPASS",
                    "severity": "HIGH",
                    "url": "https://api.example.com/admin",
                    "method": "GET",
                }
            },
        ),
    ],
)
@pytest.mark.asyncio
async def test_member_cannot_mutate_legacy_threat_actor_surfaces(client, method, path, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role("MEMBER"),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        (
            "post",
            "/api/alerts/",
            {
                "json": {
                    "title": "member denied",
                    "message": "should not create",
                    "severity": "HIGH",
                }
            },
        ),
        ("patch", "/api/alerts/11111111-1111-1111-1111-111111111111/acknowledge", {}),
        ("patch", "/api/alerts/11111111-1111-1111-1111-111111111111/resolve", {}),
        ("delete", "/api/alerts/11111111-1111-1111-1111-111111111111", {}),
    ],
)
@pytest.mark.asyncio
async def test_member_cannot_mutate_alert_surfaces(client, method, path, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role("MEMBER"),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        (
            "post",
            "/api/governance/rules",
            {
                "json": {
                    "name": "member denied",
                    "rule_type": "SECURITY",
                    "condition": {"field": "method", "op": "eq", "value": "DELETE"},
                    "action": "ALERT",
                }
            },
        ),
        ("patch", "/api/governance/rules/11111111-1111-1111-1111-111111111111/toggle", {}),
        ("delete", "/api/governance/rules/11111111-1111-1111-1111-111111111111", {}),
        ("post", "/api/governance/scan", {}),
    ],
)
@pytest.mark.asyncio
async def test_member_cannot_manage_governance_surfaces(client, method, path, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role("MEMBER"),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("put", "/api/retention/", {"json": {"full_payload_retention": True, "retention_period_days": 365}}),
        ("post", "/api/storage/archive", {}),
        ("get", "/api/storage/archives", {}),
    ],
)
@pytest.mark.asyncio
async def test_member_cannot_manage_retention_or_archives(client, method, path, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role("MEMBER"),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("get", "/api/audit-logs/", {}),
        ("get", "/api/audit-logs/actions", {}),
        ("get", "/api/audit-logs/stats", {}),
        ("post", "/api/fetchAuditData", {"json": {"skip": 0, "limit": 10}}),
    ],
)
@pytest.mark.asyncio
async def test_member_cannot_read_audit_surfaces(client, method, path, kwargs):
    resp = await getattr(client, method)(
        path,
        headers=_headers_for_role("MEMBER"),
        **kwargs,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_run_bola_scan(client):
    resp = await client.post(
        "/api/bola/scan-endpoint/test-endpoint",
        headers=_headers_for_role("VIEWER"),
        json="attacker-role-id",
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_run_bola_matrix(client):
    resp = await client.post(
        "/api/bola/matrix",
        headers=_headers_for_role("VIEWER"),
        json={"endpoint_ids": []},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_member_cannot_import_traffic(client):
    resp = await client.post(
        "/api/traffic/har/upload",
        headers=_headers_for_role("MEMBER"),
        files={"file": ("empty.har", b"{}", "application/json")},
    )
    assert resp.status_code == 403


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/alerts/"),
        ("get", "/api/blocklist/"),
        ("get", "/api/sensors/"),
        ("get", "/api/mcp-shield/endpoints"),
        ("get", "/api/mcp-shield/servers"),
        ("get", "/api/workflows/"),
        ("get", "/api/threat-detection/sessions"),
        ("get", "/api/retention/"),
        ("get", "/api/storage/archives"),
        ("get", "/api/nuclei/status"),
        ("get", "/api/collections/11111111-1111-1111-1111-111111111111/endpoints"),
        ("get", "/api/business-logic/graph/latest"),
        ("get", "/api/business-logic/violations"),
        ("get", "/api/waf/"),
    ],
)
@pytest.mark.asyncio
async def test_legacy_routes_require_auth(client, method, path):
    resp = await getattr(client, method)(path)
    assert resp.status_code == 401
