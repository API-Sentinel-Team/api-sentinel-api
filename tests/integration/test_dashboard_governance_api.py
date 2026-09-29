import datetime

import pytest

from server.models.core import APIEndpoint, PolicyViolation, TestRun, Vulnerability
from server.modules.auth.jwt_issuer import JWTIssuer


def _headers(account_id: int):
    token = JWTIssuer.create_access_token(
        {
            "sub": "dashboard-governance-user",
            "email": "dashboard-governance@example.com",
            "account_id": account_id,
            "role": "ADMIN",
        }
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_dashboard_governance_returns_tenant_scoped_rollups(client, db_session):
    now = datetime.datetime.now(datetime.timezone.utc)
    account_id = 51515101
    other_account = 51515102
    endpoint = APIEndpoint(
        id="endpoint-risk-1",
        account_id=account_id,
        method="POST",
        protocol="https",
        host="api.example.com",
        path="/checkout/apply-coupon?token=raw-token",
        risk_score=91,
    )
    db_session.add(endpoint)
    db_session.add_all(
        [
            Vulnerability(
                account_id=account_id,
                endpoint_id=endpoint.id,
                template_id="LLM_PROMPT_INJECTION_SYSTEM_PROMPT_LEAKAGE",
                url="https://api.example.com/v1/responses?token=raw-token",
                method="POST",
                severity="CRITICAL",
                type="LLM:SYSTEM_PROMPT_LEAKAGE",
                status="OPEN",
                sla_due_at=now - datetime.timedelta(days=1),
                evidence={
                    "engine": "template",
                    "security_category": "llm",
                    "llm_judge_validation": {"deterministic_evidence": True},
                },
            ),
            Vulnerability(
                account_id=account_id,
                endpoint_id=endpoint.id,
                template_id="business-logic-coupon-replay-123",
                url="https://api.example.com/checkout/apply-coupon?token=raw-token",
                method="POST",
                severity="HIGH",
                type="BUSINESS_LOGIC:COUPON_REPLAY",
                status="OPEN",
                sla_due_at=now + datetime.timedelta(days=1),
                evidence={"engine": "template", "security_category": "business_logic"},
            ),
            Vulnerability(
                account_id=other_account,
                severity="CRITICAL",
                type="OTHER",
                status="OPEN",
            ),
            PolicyViolation(
                account_id=account_id,
                endpoint_id=endpoint.id,
                rule_type="schema",
                severity="HIGH",
                status="OPEN",
                message="raw-token must not leak",
            ),
            TestRun(
                id="run-governance-1",
                account_id=account_id,
                status="COMPLETED",
                total_tests=8,
                vulnerable_count=2,
                error_count=0,
                pentest_profile_id="profile-1",
                test_intensity="standard",
                scan_plan={
                    "coverage_targets": {
                        "authorization": {"status": "ready"},
                        "llm_api": {"status": "available"},
                        "business_logic": {"status": "available"},
                    },
                    "engine_plan": [{"engine": "templates", "status": "ready"}],
                },
            ),
        ]
    )
    await db_session.commit()

    response = await client.get("/api/dashboard/governance", headers=_headers(account_id))

    assert response.status_code == 200
    payload = response.json()
    assert payload["account_id"] == account_id
    assert payload["executive"]["open_findings"] == 2
    assert payload["executive"]["critical_open_findings"] == 1
    assert payload["sla"]["overdue"] == 1
    assert payload["sla"]["due_soon"] == 1
    assert payload["coverage"]["llm_active_findings"] == 1
    assert payload["coverage"]["business_logic_active_findings"] == 1
    assert payload["governance"]["open_policy_violations"] == 1
    workstreams = {item["id"]: item for item in payload["north_star_readiness"]["p1_workstreams"]}
    assert workstreams["multi_identity_bola_bfla"]["owner"] == "AuthZ Engineer"
    assert workstreams["multi_identity_bola_bfla"]["evidence_status"] == "deterministic"
    assert workstreams["business_logic"]["owner"] == "Advanced Testing"
    assert workstreams["business_logic"]["status"] == "ready"
    assert workstreams["llm_api_security"]["owner"] == "AI Security"
    assert workstreams["governance_ui_reports"]["owner"] == "Frontend + PM"
    assert "production_blockers" in payload["north_star_readiness"]
    blocker_count = len(payload["north_star_readiness"]["production_blockers"])
    assert payload["reports"]["executive_summary"]["readiness_statement"] == (
        f"2 open findings with {blocker_count} production blockers."
    )
    assert payload["reports"]["executive_summary"]["owner_summary"] == "4 P1 workstream owners tracked."
    assert payload["reports"]["executive_summary"]["sla_health"] == "1 overdue / 1 due soon / 0 on track"
    assert payload["reports"]["technical_report"]["endpoint_risk"] == (
        "POST /checkout/apply-coupon?token=**** carries risk 100."
    )
    assert payload["reports"]["technical_report"]["artifact_status"] == (
        "1 engine accountability entries in latest scan plan."
    )
    assert payload["top_endpoint_risk"][0]["endpoint_id"] == endpoint.id
    assert "raw-token" not in str(payload)
