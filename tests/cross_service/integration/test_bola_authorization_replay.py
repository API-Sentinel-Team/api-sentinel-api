import json
import uuid

import pytest
from sqlalchemy import func, select

from sentinel_core.models import core as models
from sentinel_worker.modules.test_executor import scan_worker as worker
from sentinel_core.modules.vulnerability_detector.lifecycle import verify_vulnerability_evidence

# BOLA authorization replay is now a two-phase flow: the API validates and QUEUES an
# ``authorization_replay_matrix`` run; api-sentinel-scan-worker executes the replay.
# These tests therefore (1) assert the queued response shape at the route, then
# (2) drive ``worker.run_pending_scan_once`` (with httpx patched ON THE WORKER) and
# assert the worker-produced vulnerabilities / evidence / redaction / audit outcome.

ACCOUNT_ID = 1000000


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


def _assert_scan_queued(payload, *, endpoint_ids, attacker_role_ids=None):
    """Assert the new API contract: the route queues an authorization_replay_matrix run."""
    assert payload["status"] == "scan_queued"
    assert payload["execution_mode"] == "queued"
    assert payload["trigger_source"] == "authorization_replay_matrix"
    assert payload["run_id"]
    assert payload["endpoint_ids"] == endpoint_ids
    if attacker_role_ids is not None:
        assert payload["attacker_role_ids"] == attacker_role_ids


async def _run_worker(db_session):
    """Claim + execute + finalize one queued run on the test engine."""
    return await worker.run_pending_scan_once(db_bind=db_session.bind, account_id=ACCOUNT_ID)


async def _scan_run_failed_audits(db_session):
    return (
        await db_session.execute(
            select(models.AuditLog).where(
                models.AuditLog.account_id == ACCOUNT_ID,
                models.AuditLog.action == "SCAN_RUN_FAILED",
            )
        )
    ).scalars().all()


@pytest.mark.asyncio
async def test_bola_matrix_promotes_cross_role_replay_to_redacted_bfla(client, db_session, auth_headers, monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, victim, attacker = await _seed_endpoint_sample_and_accounts(db_session)

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    assert response.status_code == 200
    _assert_scan_queued(response.json(), endpoint_ids=[endpoint.id], attacker_role_ids=[attacker.id])

    # The replay itself runs in the worker; the route never replays inline.
    worker_result = await _run_worker(db_session)
    assert worker_result["status"] == "executed"
    assert _FakeAsyncClient.calls[0]["headers"]["Authorization"] == attacker.auth_headers["Authorization"]

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    assert vulnerability.evidence["identity_pair"]["victim"]["id"] == victim.id
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
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
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
    _assert_scan_queued(payload, endpoint_ids=[endpoint.id], attacker_role_ids=[attacker.id])
    # The queued response must never carry raw identity secrets.
    assert victim_token not in str(payload)
    assert attacker_token not in str(payload)

    await _run_worker(db_session)

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    # Identity metadata is redacted in the worker-produced evidence.
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
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, _, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    body = {"attacker_role_ids": [attacker.id]}

    # First queue + worker cycle creates the vulnerability.
    first = await client.post(f"/api/bola/scan-endpoint/{endpoint.id}/matrix", headers=auth_headers, json=body)
    assert first.status_code == 200
    _assert_scan_queued(first.json(), endpoint_ids=[endpoint.id], attacker_role_ids=[attacker.id])
    await _run_worker(db_session)

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    assert vulnerability.occurrence_count == 1

    # Second queue + worker cycle merges into the same finding.
    second = await client.post(f"/api/bola/scan-endpoint/{endpoint.id}/matrix", headers=auth_headers, json=body)
    assert second.status_code == 200
    _assert_scan_queued(second.json(), endpoint_ids=[endpoint.id], attacker_role_ids=[attacker.id])
    await _run_worker(db_session)

    await db_session.refresh(vulnerability)
    assert vulnerability.occurrence_count == 2

    total = await db_session.scalar(
        select(func.count())
        .select_from(models.Vulnerability)
        .where(
            models.Vulnerability.endpoint_id == endpoint.id,
            models.Vulnerability.type == "BFLA",
        )
    )
    assert total == 1


@pytest.mark.asyncio
async def test_bola_matrix_without_requested_ids_skips_inferred_victim(client, db_session, auth_headers, monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, victim, attacker = await _seed_endpoint_sample_and_accounts(db_session)

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={},
    )

    assert response.status_code == 200
    # No attacker ids requested: the worker infers the victim and replays every other identity.
    _assert_scan_queued(response.json(), endpoint_ids=[endpoint.id], attacker_role_ids=[])

    await _run_worker(db_session)

    sent_auth = [call["headers"].get("Authorization") for call in _FakeAsyncClient.calls]
    assert attacker.auth_headers["Authorization"] in sent_auth
    # The inferred victim identity must never be replayed as an attacker.
    assert victim.auth_headers["Authorization"] not in sent_auth
    assert len(_FakeAsyncClient.calls) == 1

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    assert vulnerability.evidence["identity_pair"]["victim"]["id"] == victim.id
    assert "victim-token" not in str(vulnerability.evidence)


@pytest.mark.asyncio
async def test_bola_replay_blocks_state_changing_samples_by_default(client, db_session, auth_headers, monkeypatch):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, _, attacker = await _seed_endpoint_sample_and_accounts(db_session, method="POST")

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    # The route no longer enforces the state-change guard at queue time; it queues.
    assert response.status_code == 200
    run_id = response.json()["run_id"]
    _assert_scan_queued(response.json(), endpoint_ids=[endpoint.id], attacker_role_ids=[attacker.id])

    # The state-change guard now fires inside the worker, which fails the run before
    # any request is sent and records a redacted failure reason.
    worker_result = await _run_worker(db_session)
    assert worker_result["status"] == "failed"
    assert _FakeAsyncClient.calls == []

    run = await db_session.get(models.TestRun, run_id)
    await db_session.refresh(run)
    assert run.status == "FAILED"

    test_results = (
        await db_session.execute(select(models.TestResult).where(models.TestResult.endpoint_id == endpoint.id))
    ).scalars().all()
    vulnerabilities = (
        await db_session.execute(select(models.Vulnerability).where(models.Vulnerability.endpoint_id == endpoint.id))
    ).scalars().all()
    assert test_results == []
    assert vulnerabilities == []

    reasons = [str(audit.details.get("reason")) for audit in await _scan_run_failed_audits(db_session)]
    assert any("state_change_blocked" in reason for reason in reasons)
    assert any("POST" in reason for reason in reasons)


@pytest.mark.asyncio
async def test_bola_replay_blocks_target_guarded_samples_with_policy(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
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
    await db_session.flush()

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    # The target guard now fires in the worker, not at queue time.
    assert response.status_code == 200
    run_id = response.json()["run_id"]
    _assert_scan_queued(response.json(), endpoint_ids=[endpoint.id], attacker_role_ids=[attacker.id])

    worker_result = await _run_worker(db_session)
    assert worker_result["status"] == "failed"
    assert _FakeAsyncClient.calls == []

    run = await db_session.get(models.TestRun, run_id)
    await db_session.refresh(run)
    assert run.status == "FAILED"

    test_results = (
        await db_session.execute(select(models.TestResult).where(models.TestResult.endpoint_id == endpoint.id))
    ).scalars().all()
    vulnerabilities = (
        await db_session.execute(select(models.Vulnerability).where(models.Vulnerability.endpoint_id == endpoint.id))
    ).scalars().all()
    assert test_results == []
    assert vulnerabilities == []

    audits = await _scan_run_failed_audits(db_session)
    reasons = [str(audit.details.get("reason")) for audit in audits]
    assert any("metadata" in reason for reason in reasons)
    # The raw sample token must never leak into the failure record or worker result.
    assert "raw-token" not in str([audit.details for audit in audits])
    assert "raw-token" not in str(worker_result)


@pytest.mark.asyncio
async def test_bola_endpoint_matrix_honors_kill_switch_before_replay(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr("sentinel_core.modules.test_executor.kill_switch.settings.PENTEST_KILL_SWITCH_ENABLED", True)
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

    # Kill switch rejects at the route BEFORE any run is queued.
    assert response.status_code == 503
    assert response.json()["message"] == "pentest_kill_switch_enabled"
    assert _FakeAsyncClient.calls == []

    run_count_after = await db_session.scalar(
        select(func.count()).select_from(models.TestRun).where(
            models.TestRun.trigger_source == "authorization_replay_matrix"
        )
    )
    assert run_count_after == run_count_before

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
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
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
    _assert_scan_queued(
        payload,
        endpoint_ids=[get_endpoint.id, post_endpoint.id],
        attacker_role_ids=[attacker.id],
    )
    run_id = payload["run_id"]

    # The worker replays the safe (GET) endpoint and blocks the state-changing (POST)
    # one; the state-change guard raises, so the run terminates FAILED with the GET
    # finding already persisted and exactly one replay request sent.
    worker_result = await _run_worker(db_session)
    assert worker_result["status"] == "failed"
    assert len(_FakeAsyncClient.calls) == 1

    run = await db_session.get(models.TestRun, run_id)
    await db_session.refresh(run)
    assert run.status == "FAILED"
    assert run.trigger_source == "authorization_replay_matrix"
    assert run.endpoint_ids == [get_endpoint.id, post_endpoint.id]
    assert run.total_tests == 1
    assert run.vulnerable_count == 1
    assert run.error_count == 1

    # The state-changing endpoint was blocked (never replayed) and recorded redacted.
    reasons = [str(audit.details.get("reason")) for audit in await _scan_run_failed_audits(db_session)]
    assert any("state_change_blocked" in reason for reason in reasons)

    test_results = (
        await db_session.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
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


@pytest.mark.asyncio
async def test_cicd_gate_reports_authorization_replay_identity_matrix_context(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
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
    _assert_scan_queued(response.json(), endpoint_ids=[endpoint.id], attacker_role_ids=[attacker.id])

    worker_result = await _run_worker(db_session)
    assert worker_result["status"] == "executed"

    run = await db_session.get(models.TestRun, run_id)
    await db_session.refresh(run)
    assert run.status == "COMPLETED"
    assert run.trigger_source == "authorization_replay_matrix"

    # The CI/CD gate reports the authorization-replay identity-matrix context for the
    # worker-completed run, without leaking any tenant values.
    gate = await client.get(
        f"/api/cicd/gate/{run_id}?fail_on=CRITICAL&allow_policy_overrides=true",
        headers=auth_headers,
    )
    assert gate.status_code == 200
    gate_payload = gate.json()
    assert gate_payload["scan_context"]["authenticated"] is True
    assert gate_payload["scan_context"]["auth_context_reason"] == "authorization_replay_test_accounts"
    assert gate_payload["scan_context"]["authorization_replay"] == {
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
    assert "tenant-a" not in str(gate_payload)
    assert "tenant-b" not in str(gate_payload)

    # The cross-tenant identity-matrix context is carried by the worker-produced
    # evidence, and tenant values must never leak into evidence or storage.
    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    identity_boundary = vulnerability.evidence["matched_rule"]["identity_boundary"]
    assert identity_boundary["boundary_kind"] == "cross_tenant"
    assert identity_boundary["compared_fields"] == ["x-tenant-id"]
    assert identity_boundary["changed_fields"] == ["x-tenant-id"]
    assert vulnerability.evidence["identity_pair"]["victim"]["id"] == victim.id
    assert "tenant-a" not in str(vulnerability.evidence)
    assert "tenant-b" not in str(vulnerability.evidence)

    test_result = (
        await db_session.execute(
            select(models.TestResult).where(
                models.TestResult.endpoint_id == endpoint.id,
                models.TestResult.is_vulnerable == True,
            )
        )
    ).scalar_one()
    assert "tenant-a" not in test_result.evidence
    assert "tenant-b" not in test_result.evidence


@pytest.mark.asyncio
async def test_bola_matrix_response_reports_cross_tenant_boundary_without_values(
    client,
    db_session,
    auth_headers,
    monkeypatch,
):
    _FakeAsyncClient.calls = []
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, victim, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    # Reassign JSON columns (rather than in-place mutation) so the change is persisted
    # and visible to the worker, which reloads these rows in its own session.
    victim.auth_headers = {**victim.auth_headers, "X-Tenant-ID": "tenant-a"}
    attacker.auth_headers = {**attacker.auth_headers, "X-Tenant-ID": "tenant-b"}
    sample = (
        await db_session.execute(
            select(models.SampleData).where(models.SampleData.endpoint_id == endpoint.id)
        )
    ).scalar_one()
    sample.request = {
        **sample.request,
        "headers": {**sample.request["headers"], "X-Tenant-ID": "tenant-a"},
    }
    sample.response = {**sample.response, "body": {"id": 42, "email": "victim@example.com"}}
    await db_session.flush()

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    assert response.status_code == 200
    payload = response.json()
    _assert_scan_queued(payload, endpoint_ids=[endpoint.id], attacker_role_ids=[attacker.id])
    assert "tenant-a" not in str(payload)
    assert "tenant-b" not in str(payload)

    await _run_worker(db_session)

    # The attacker tenant header is replayed; the boundary is reported by field name only.
    assert _FakeAsyncClient.calls[0]["headers"]["X-Tenant-ID"] == "tenant-b"

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    boundary = vulnerability.evidence["matched_rule"]["identity_boundary"]
    assert boundary == {
        "boundary_kind": "cross_tenant",
        "same_boundary": False,
        "compared_fields": ["x-tenant-id"],
        "changed_fields": ["x-tenant-id"],
        "unchanged_fields": [],
    }
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
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, victim, attacker = await _seed_endpoint_sample_and_accounts(db_session)
    sample = (
        await db_session.execute(
            select(models.SampleData).where(models.SampleData.endpoint_id == endpoint.id)
        )
    ).scalar_one()
    # Reassign the JSON column so the worker (separate session) reloads the header.
    sample.request = {
        **sample.request,
        "headers": {**sample.request["headers"], "X-Tenant-ID": "tenant-victim"},
    }
    await db_session.flush()

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}/matrix",
        headers=auth_headers,
        json={"attacker_role_ids": [attacker.id]},
    )

    assert response.status_code == 200
    payload = response.json()
    _assert_scan_queued(payload, endpoint_ids=[endpoint.id], attacker_role_ids=[attacker.id])
    assert "tenant-victim" not in str(payload)

    await _run_worker(db_session)

    sent_headers = _FakeAsyncClient.calls[0]["headers"]
    assert sent_headers["Authorization"] == attacker.auth_headers["Authorization"]
    # The victim's tenant header must not be carried over onto the attacker's request.
    assert "X-Tenant-ID" not in sent_headers

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    boundary = vulnerability.evidence["matched_rule"]["identity_boundary"]
    assert boundary == {
        "boundary_kind": "cross_tenant",
        "same_boundary": False,
        "compared_fields": ["x-tenant-id"],
        "changed_fields": ["x-tenant-id"],
        "unchanged_fields": [],
    }
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
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr("sentinel_core.modules.test_executor.kill_switch.settings.PENTEST_KILL_SWITCH_ENABLED", True)
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
    monkeypatch.setattr(worker.httpx, "AsyncClient", _FakeAsyncClient)
    endpoint, _, attacker = await _seed_endpoint_sample_and_accounts(db_session)

    response = await client.post(
        f"/api/bola/scan-endpoint/{endpoint.id}",
        headers=auth_headers,
        json=attacker.id,
    )

    assert response.status_code == 200
    # Legacy raw-string attacker id still queues a scan for that identity.
    _assert_scan_queued(response.json(), endpoint_ids=[endpoint.id], attacker_role_ids=[attacker.id])

    worker_result = await _run_worker(db_session)
    assert worker_result["status"] == "executed"

    vulnerability = (
        await db_session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.endpoint_id == endpoint.id,
                models.Vulnerability.type == "BFLA",
            )
        )
    ).scalar_one()
    assert vulnerability.type == "BFLA"
    assert vulnerability.evidence["issue_type"] == "BFLA"
