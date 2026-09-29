import json
import uuid

import pytest
from sqlalchemy import func, select

import server.api.routers.bola as bola_router
from server.models import core as models
from server.modules.vulnerability_detector.lifecycle import verify_vulnerability_evidence


class _FakeResponse:
    status_code = 200
    headers = {"content-type": "application/json"}
    text = '{"id":42,"email":"victim@example.com"}'


class _FakeAsyncClient:
    calls = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, **kwargs):
        self.calls.append(kwargs)
        return _FakeResponse()


async def _seed_endpoint_sample_and_accounts(db_session, *, method: str = "GET"):
    suffix = uuid.uuid4().hex[:8]
    victim_token = f"victim-token-{suffix}"
    attacker_token = f"attacker-token-{suffix}"
    endpoint = models.APIEndpoint(
        id=f"ep-{suffix}",
        account_id=1000000,
        method=method,
        path="/users/42",
        host="api.example.com",
        protocol="https",
        port=443,
    )
    victim = models.TestAccount(
        id=f"victim-{suffix}",
        account_id=1000000,
        name="Admin Victim",
        role="ADMIN",
        auth_headers={"Authorization": f"Bearer {victim_token}"},
    )
    attacker = models.TestAccount(
        id=f"attacker-{suffix}",
        account_id=1000000,
        name="Member Attacker",
        role="MEMBER",
        auth_headers={"Authorization": f"Bearer {attacker_token}"},
    )
    sample = models.SampleData(
        id=f"sample-{suffix}",
        account_id=1000000,
        endpoint_id=endpoint.id,
        request={
            "method": method,
            "url": f"https://api.example.com/users/42?token={victim_token}",
            "headers": {"Authorization": f"Bearer {victim_token}", "Accept": "application/json"},
            "body": "",
        },
        response={
            "status_code": 200,
            "body": {"id": 42, "email": "victim@example.com"},
            "headers": {"content-type": "application/json"},
        },
    )
    db_session.add_all([endpoint, victim, attacker, sample])
    await db_session.flush()
    return endpoint, victim, attacker


@pytest.mark.asyncio
async def test_bola_matrix_promotes_cross_role_replay_to_redacted_bfla(client, db_session, auth_headers, monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, victim, attacker = await _seed_endpoint_sample_and_accounts(db_session)

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["attackers_tested"] == 1
    assert payload["vulnerable_count"] == 1
    assert payload["vulnerabilities_created"] == 1
    assert payload["results"][0]["issue_type"] == "BFLA"
    assert payload["results"][0]["victim_id"] == victim.id
    assert _FakeAsyncClient.calls[0]["headers"]["Authorization"] == attacker.auth_headers["Authorization"]

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    assert vulnerability.template_id == "BFLA_AUTHZ_REPLAY_ADMIN_TO_MEMBER"
    assert vulnerability.confidence == "HIGH"
    assert vulnerability.url == "https://api.example.com/users/42?token=****"
    assert vulnerability.occurrence_count == 1
    assert vulnerability.evidence["engine"] == "authorization_replay"
    assert vulnerability.evidence["finding_status"] == "CONFIRMED"
    assert vulnerability.evidence["matched_rule"]["rule_id"] == "authorization_replay_successful_cross_identity"
    assert vulnerability.evidence["similarity"]["similarity_pct"] == 100.0
    assert vulnerability.evidence["evidence_completeness"]["complete"] is True
    assert vulnerability.evidence["evidence_completeness"]["missing"] == []
    assert vulnerability.evidence["scope_validation"] == {
        "validated": True,
        "policy": "target_guard",
        "scope": "same_origin_or_allowlisted",
        "target": "https://api.example.com/users/42?token=****",
        "evidence_url": "https://api.example.com/users/42?token=****",
    }
    assert vulnerability.evidence["evidence_hash"]
    assert verify_vulnerability_evidence(vulnerability.evidence)["verified"] is True
    assert vulnerability.evidence["captured_response"]["body_sha256"]
    assert vulnerability.evidence["replay_response"]["body_sha256"]
    assert "body" not in vulnerability.evidence["replay_response"]
    assert "duration_ms" not in vulnerability.evidence["replay_response"]
    assert vulnerability.evidence["observation_metadata"]["replay_response_duration_ms"] >= 0
    assert "victim-token" not in str(vulnerability.evidence)
    assert "attacker-token" not in str(vulnerability.evidence)
    assert "victim@example.com" not in str(vulnerability.evidence)

    test_result = (
        await db_session.execute(
            select(models.TestResult).where(
                models.TestResult.endpoint_id == endpoint.id,
                models.TestResult.is_vulnerable == True,
            )
        )
    ).scalar_one()
    result_evidence = json.loads(test_result.evidence)
    assert result_evidence["engine"] == "authorization_replay"
    assert result_evidence["scope_validation"]["validated"] is True
    assert result_evidence["evidence_completeness"]["complete"] is True
    assert result_evidence["finding_status"] == "CONFIRMED"
    assert result_evidence["evidence_hash"] == vulnerability.evidence["evidence_hash"]
    assert verify_vulnerability_evidence(result_evidence)["verified"] is True
    assert "victim-token" not in test_result.evidence
    assert "attacker-token" not in test_result.evidence


@pytest.mark.asyncio
async def test_bola_matrix_redacts_identity_metadata_in_api_and_storage(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, victim, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    victim_token = victim.auth_headers["Authorization"].split(" ", 1)[1]
    attacker_token = attacker.auth_headers["Authorization"].split(" ", 1)[1]
    victim.name = f"Admin Victim token={victim_token}"
    attacker.name = f"Member Attacker cookie={attacker_token}"
    attacker.role = f"MEMBER token={attacker_token}"
    await db_session.flush()

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["victim"]["name"] == "Admin Victim token=****"
    assert payload["results"][0]["attacker_role"] == "MEMBER token=****"
    assert victim_token not in str(payload)
    assert attacker_token not in str(payload)

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    assert vulnerability.evidence["identity_pair"]["victim"]["name"] == "Admin Victim token=****"
    assert vulnerability.evidence["identity_pair"]["attacker"]["role"] == "MEMBER token=****"
    assert vulnerability.template_id == "BFLA_AUTHZ_REPLAY_ADMIN_TO_MEMBER"
    assert victim_token not in vulnerability.template_id
    assert attacker_token not in vulnerability.template_id
    assert "TOKEN" not in vulnerability.template_id
    assert victim_token not in str(vulnerability.evidence)
    assert attacker_token not in str(vulnerability.evidence)
    assert victim_token not in vulnerability.description
    assert attacker_token not in vulnerability.description

    test_result = (
        await db_session.execute(
            select(models.TestResult).where(
                models.TestResult.endpoint_id == endpoint.id,
                models.TestResult.is_vulnerable == True,
            )
        )
    ).scalar_one()
    assert victim_token not in test_result.evidence
    assert attacker_token not in test_result.evidence


@pytest.mark.asyncio
async def test_bola_matrix_merges_repeated_authorization_replay(client, db_session, auth_headers, monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, _, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    body = {"attacker_role_ids": [attacker.id]}

    first = await client.post(f"/api/bola/scan-endpoint/{endpoint.id}/matrix", headers=auth_headers, json=body)
    second = await client.post(f"/api/bola/scan-endpoint/{endpoint.id}/matrix", headers=auth_headers, json=body)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["vulnerabilities_created"] == 1
    assert second.json()["vulnerabilities_created"] == 0
    assert second.json()["vulnerabilities_merged"] == 1
    assert second.json()["results"][0]["vulnerability"]["occurrence_count"] == 2


@pytest.mark.asyncio
async def test_bola_matrix_without_requested_ids_skips_inferred_victim(client, db_session, auth_headers, monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, victim, attacker = await _seed_endpoint_sample_and_accounts(db_session)

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["victim"]["id"] == victim.id
    attacker_ids = {result["attacker_id"] for result in payload["results"]}
    assert victim.id not in attacker_ids
    assert attacker.id in attacker_ids
    assert len(_FakeAsyncClient.calls) == payload["attackers_tested"]


@pytest.mark.asyncio
async def test_bola_replay_blocks_state_changing_samples_by_default(client, db_session, auth_headers, monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, _, attacker = await _seed_endpoint_sample_and_accounts(db_session, method="POST")

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    assert response.status_code == 400
    message = response.json()["message"]
    assert message["reason"] == "state_change_blocked"
    assert message["state_change_policy"]["policy"] == "state_change_guard"
    assert message["state_change_policy"]["blocked"] is True
    assert message["state_change_policy"]["method"] == "POST"
    assert message["state_change_policy"]["effective_method"] == "POST"
    assert message["state_change_policy"]["safe_method"] is False
    assert message["state_change_policy"]["destructive_method"] is True
    assert message["state_change_policy"]["allow_state_change"] is False
    assert message["state_change_policy"]["allow_destructive_methods"] is False
    assert "state_change_blocked" in message["state_change_policy"]["reason"]
    assert _FakeAsyncClient.calls == []


@pytest.mark.asyncio
async def test_bola_replay_blocks_target_guarded_samples_with_policy(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, _, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    sample = (
        await db_session.execute(
            select(models.SampleData).where(models.SampleData.endpoint_id == endpoint.id)
        )
    ).scalar_one()
    sample.request = {
        **sample.request,
        "url": "http://169.254.169.254/latest/meta-data?token=raw-token",
    }
    await db_session.commit()

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    assert response.status_code == 400
    message = response.json()["message"]
    assert message["reason"] == "target_guard_blocked"
    assert message["target_guard_policy"]["policy"] == "target_guard"
    assert message["target_guard_policy"]["blocked"] is True
    assert message["target_guard_policy"]["url"] == (
        "http://169.254.169.254/latest/meta-data?token=****"
    )
    assert "metadata" in message["target_guard_policy"]["reason"]
    assert "raw-token" not in str(message)
    assert _FakeAsyncClient.calls == []


@pytest.mark.asyncio
async def test_bola_endpoint_matrix_honors_kill_switch_before_replay(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr("server.modules.test_executor.kill_switch.settings.PENTEST_KILL_SWITCH_ENABLED", True)
    endpoint, _, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    run_count_before = await db_session.scalar(
        select(func.count()).select_from(models.TestRun).where(
            models.TestRun.trigger_source == "authorization_replay_matrix"
        )
    )

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    assert response.status_code == 503
    assert response.json()["message"] == "pentest_kill_switch_enabled"
    assert _FakeAsyncClient.calls == []
    test_results = (
        await db_session.execute(select(models.TestResult).where(models.TestResult.endpoint_id == endpoint.id))
    ).scalars().all()
    vulnerabilities = (
        await db_session.execute(select(models.Vulnerability).where(models.Vulnerability.endpoint_id == endpoint.id))
    ).scalars().all()
    assert test_results == []
    assert vulnerabilities == []


@pytest.mark.asyncio
async def test_account_bola_matrix_runs_sampled_endpoint_set_with_run_record(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    get_endpoint, victim, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    post_endpoint, _, _ = await _seed_endpoint_sample_and_accounts(db_session, method="POST")

    response = await client.post(
        "/api/bola/matrix",
        headers=auth_headers,
        json={
            "endpoint_ids": [get_endpoint.id, post_endpoint.id],
            "attacker_role_ids": [attacker.id],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed_with_errors"
    assert payload["endpoints_requested"] == 2
    assert payload["endpoints_completed"] == 1
    assert payload["endpoints_skipped_or_failed"] == 1
    assert payload["attackers_tested"] == 1
    assert payload["vulnerable_count"] == 1
    assert payload["vulnerabilities_created"] == 1
    assert payload["results"][0]["endpoint_id"] == get_endpoint.id
    assert payload["results"][0]["results"][0]["issue_type"] == "BFLA"
    assert payload["results"][1]["endpoint_id"] == post_endpoint.id
    assert "state_change_blocked" in str(payload["results"][1]["reason"])
    assert len(_FakeAsyncClient.calls) == 1

    run = await db_session.get(models.TestRun, payload["run_id"])
    assert run.status == "COMPLETED"
    assert run.trigger_source == "authorization_replay_matrix"
    assert run.endpoint_ids == [get_endpoint.id, post_endpoint.id]
    assert run.total_tests == 1
    assert run.vulnerable_count == 1
    assert run.error_count == 1

    test_results = (
        await db_session.execute(select(models.TestResult).where(models.TestResult.run_id == payload["run_id"]))
    ).scalars().all()
    assert len(test_results) == 1
    assert test_results[0].endpoint_id == get_endpoint.id
    result_evidence = json.loads(test_results[0].evidence)
    assert result_evidence["engine"] == "authorization_replay"
    assert result_evidence["scope_validation"]["validated"] is True
    assert result_evidence["retest_support"]["queued_scan_supported"] is True
    assert verify_vulnerability_evidence(result_evidence)["verified"] is True

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == get_endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    assert vulnerability.evidence["identity_pair"]["victim"]["id"] == victim.id
    assert vulnerability.evidence["retest_support"]["reason"] == "authorization_replay_matrix_available"
    assert "victim-token" not in str(vulnerability.evidence)
    assert "attacker-token" not in str(vulnerability.evidence)

    gate = await client.get(
        f"/api/cicd/gate/{payload['run_id']}?fail_on=CRITICAL&allow_policy_overrides=true",
        headers=auth_headers,
    )
    assert gate.status_code == 200
    gate_payload = gate.json()
    assert gate_payload["status"] == "PASSED"
    assert gate_payload["scan_context"]["authenticated"] is True
    assert gate_payload["scan_context"]["auth_context_reason"] == "authorization_replay_test_accounts"
    assert gate_payload["counts"]["missing_safety_policy_results"] == 0
    assert gate_payload["counts"]["incomplete_evidence_results"] == 0


@pytest.mark.asyncio
async def test_cicd_gate_reports_authorization_replay_identity_matrix_context(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, victim, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    victim.auth_headers["X-Tenant-ID"] = "tenant-a"
    attacker.auth_headers["X-Tenant-ID"] = "tenant-b"
    sample = (
        await db_session.execute(
            select(models.SampleData).where(models.SampleData.endpoint_id == endpoint.id)
        )
    ).scalar_one()
    sample.request = {
        **sample.request,
        "headers": {
            **sample.request["headers"],
            "X-Tenant-ID": "tenant-a",
        },
    }
    await db_session.flush()

    response = await client.post(
        "/api/bola/matrix",
        headers=auth_headers,
        json={
            "endpoint_ids": [endpoint.id],
            "attacker_role_ids": [attacker.id],
        },
    )

    assert response.status_code == 200
    run_id = response.json()["run_id"]
    gate = await client.get(
        f"/api/cicd/gate/{run_id}?fail_on=CRITICAL&allow_policy_overrides=true",
        headers=auth_headers,
    )

    assert gate.status_code == 200
    payload = gate.json()
    assert payload["scan_context"]["authenticated"] is True
    assert payload["scan_context"]["auth_context_reason"] == "authorization_replay_test_accounts"
    assert payload["scan_context"]["authorization_replay"] == {
        "identity_pair_count": 1,
        "vulnerable_identity_pair_count": 1,
        "results_with_identity_boundary": 1,
        "compared_boundary_field_count": 1,
        "changed_boundary_field_count": 1,
        "unchanged_boundary_field_count": 0,
        "boundary_kinds": ["cross_tenant"],
        "compared_boundary_fields": ["x-tenant-id"],
        "changed_boundary_fields": ["x-tenant-id"],
        "unchanged_boundary_fields": [],
        "issue_types": ["BFLA", "BOLA"],
    }
    assert "tenant-a" not in str(payload)
    assert "tenant-b" not in str(payload)


@pytest.mark.asyncio
async def test_bola_matrix_response_reports_cross_tenant_boundary_without_values(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, victim, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    victim.auth_headers["X-Tenant-ID"] = "tenant-a"
    attacker.auth_headers["X-Tenant-ID"] = "tenant-b"
    sample = (
        await db_session.execute(
            select(models.SampleData).where(models.SampleData.endpoint_id == endpoint.id)
        )
    ).scalar_one()
    sample.request["headers"]["X-Tenant-ID"] = "tenant-a"
    sample.response["body"] = {"id": 42, "email": "victim@example.com"}
    await db_session.flush()

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    assert response.status_code == 200
    payload = response.json()
    boundary = payload["results"][0]["identity_boundary"]
    assert boundary == {
        "boundary_kind": "cross_tenant",
        "same_boundary": False,
        "compared_fields": ["x-tenant-id"],
        "changed_fields": ["x-tenant-id"],
        "unchanged_fields": [],
    }
    assert _FakeAsyncClient.calls[0]["headers"]["X-Tenant-ID"] == "tenant-b"
    assert "tenant-a" not in str(payload)
    assert "tenant-b" not in str(payload)

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    assert vulnerability.evidence["matched_rule"]["identity_boundary"] == boundary
    assert "tenant-a" not in str(vulnerability.evidence)
    assert "tenant-b" not in str(vulnerability.evidence)


@pytest.mark.asyncio
async def test_bola_matrix_does_not_replay_victim_tenant_header_when_attacker_lacks_one(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, victim, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    sample = (
        await db_session.execute(
            select(models.SampleData).where(models.SampleData.endpoint_id == endpoint.id)
        )
    ).scalar_one()
    sample.request["headers"]["X-Tenant-ID"] = "tenant-victim"
    await db_session.flush()

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    assert response.status_code == 200
    payload = response.json()
    sent_headers = _FakeAsyncClient.calls[0]["headers"]
    assert sent_headers["Authorization"] == attacker.auth_headers["Authorization"]
    assert "X-Tenant-ID" not in sent_headers
    assert "tenant-victim" not in str(payload)
    boundary = payload["results"][0]["identity_boundary"]
    assert boundary == {
        "boundary_kind": "cross_tenant",
        "same_boundary": False,
        "compared_fields": ["x-tenant-id"],
        "changed_fields": ["x-tenant-id"],
        "unchanged_fields": [],
    }

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    assert vulnerability.evidence["matched_rule"]["identity_boundary"] == boundary
    assert vulnerability.evidence["replay_request"]["headers"]["Authorization"] == "Bearer ****"
    assert "X-Tenant-ID" not in vulnerability.evidence["replay_request"]["headers"]
    assert "tenant-victim" not in str(vulnerability.evidence)
    assert victim.auth_headers["Authorization"].split(" ", 1)[1] not in str(vulnerability.evidence)


@pytest.mark.asyncio
async def test_account_bola_matrix_honors_kill_switch_before_run_creation(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr("server.modules.test_executor.kill_switch.settings.PENTEST_KILL_SWITCH_ENABLED", True)
    endpoint, _, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    run_count_before = await db_session.scalar(
        select(func.count()).select_from(models.TestRun).where(
            models.TestRun.trigger_source == "authorization_replay_matrix"
        )
    )

    response = await client.post(
        "/api/bola/matrix",
        headers=auth_headers,
        json={"endpoint_ids": [endpoint.id], "attacker_role_ids": [attacker.id]},
    )

    assert response.status_code == 503
    assert response.json()["message"] == "pentest_kill_switch_enabled"
    assert _FakeAsyncClient.calls == []
    run_count_after = await db_session.scalar(
        select(func.count()).select_from(models.TestRun).where(
            models.TestRun.trigger_source == "authorization_replay_matrix"
        )
    )
    assert run_count_after == run_count_before


@pytest.mark.asyncio
async def test_single_bola_scan_accepts_legacy_raw_attacker_id_body(client, db_session, auth_headers, monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(bola_router.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, _, attacker = await _seed_endpoint_sample_and_accounts(db_session)

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}",
        headers=auth_headers,
        json=attacker.id,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "vulnerable"
    assert payload["issue_type"] == "BFLA"
