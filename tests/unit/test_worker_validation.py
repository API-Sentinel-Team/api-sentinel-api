import copy
import pytest

from server.config import settings
from server.modules.pentest.execution_artifacts import build_execution_artifact_payload
from server.modules.test_executor.worker_validation import (
    build_worker_runtime_validation,
    validate_worker_staging_scan_acceptance,
)


@pytest.mark.parametrize("artifact_run,status,accepted", [
    ("run-a", "COMPLETED", True),
    ("run-b", "COMPLETED", False),
    ("run-a", "FAILED_WITH_FINDINGS", True),
    ("run-a", "FAILED", False),
    ("run-a", "TIMEOUT", False),
    ("run-a", "SKIPPED", False),
])
def test_engine_acceptance_requires_successful_artifact_for_same_run(artifact_run, status, accepted):
    payload = build_execution_artifact_payload(
        engine="zap", target_url="https://api.example.test", profile_id=None,
        execution={"status": status}, engine_plan=[], run_id=artifact_run,
    )
    result = validate_worker_staging_scan_acceptance(
        {"run_id": "run-a", "engine_accountability": {"required_artifacts": [{"artifact_type": "zap_execution"}]}},
        payload, artifact_payloads=[payload],
    )
    assert result["checks"]["required_engine_artifacts"]["ready"] is accepted


def test_worker_runtime_validation_reports_kubernetes_queue_ready(monkeypatch):
    monkeypatch.setattr(settings, "PENTEST_SCAN_EXECUTION_MODE", "queued")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_ISOLATION_MODE", "k8s_job")
    monkeypatch.setattr(settings, "PENTEST_KILL_SWITCH_ENABLED", False)
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 120)
    monkeypatch.setattr(settings, "PENTEST_SCAN_MAX_CLAIMS", 4)
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_CPU", "750m")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_MEMORY", "768Mi")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_EPHEMERAL_STORAGE", "1536Mi")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_JOB_TTL_SECONDS", 1800)

    report = build_worker_runtime_validation(
        queue_health={
            "pending_count": 1,
            "expired_lease_count": 0,
            "dead_letter_ready_count": 0,
        }
    )

    assert report["ready"] is True
    assert report["status"] == "ready"
    assert report["blockers"] == []
    assert report["checks"]["queued_workers"]["ready"] is True
    assert report["checks"]["external_worker_mode"]["ready"] is True
    assert report["checks"]["kubernetes_job_mode"]["ready"] is True
    assert report["checks"]["lease_expiry"]["evidence"] == {
        "lease_seconds": 120,
        "max_claims": 4,
        "expired_lease_count": 0,
        "dead_letter_ready_count": 0,
    }
    assert report["checks"]["kill_switch"]["ready"] is True
    assert report["checks"]["resource_limits"]["evidence"] == {
        "cpu": "750m",
        "memory": "768Mi",
        "ephemeral_storage": "1536Mi",
    }
    assert report["checks"]["kubernetes_job_mode"]["evidence"]["job_ttl_seconds"] == 1800


def test_worker_runtime_validation_reports_blockers_for_background_or_paused_runtime(monkeypatch):
    monkeypatch.setattr(settings, "PENTEST_SCAN_EXECUTION_MODE", "background")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_ISOLATION_MODE", "background")
    monkeypatch.setattr(settings, "PENTEST_KILL_SWITCH_ENABLED", True)

    report = build_worker_runtime_validation()

    assert report["ready"] is False
    assert report["status"] == "blocked"
    blocker_ids = {item["id"] for item in report["blockers"]}
    assert blocker_ids == {
        "queued_workers_not_enabled",
        "external_worker_isolation_not_enabled",
        "kill_switch_paused",
    }
    assert report["checks"]["queued_workers"]["ready"] is False
    assert report["checks"]["external_worker_mode"]["ready"] is False
    assert report["checks"]["kill_switch"]["ready"] is False


def test_worker_staging_scan_acceptance_requires_cleaned_sandbox_and_verified_artifact():
    worker_result = {
        "status": "executed",
        "claimed": True,
        "run_id": "run-staging-worker",
        "worker_id": "worker-staging",
        "lease_expires_at": "2026-06-05T12:00:00+00:00",
        "engine_accountability": {
            "artifact_hash_required": True,
            "artifact_verification_required": True,
        },
        "worker_isolation": {
            "session": {
                "run_id": "run-staging-worker",
                "worker_id": "worker-staging",
                "mode": "kubernetes_job",
            },
            "sandbox": {
                "created": True,
                "path_confined_to_work_dir": True,
            },
            "resource_limits": {
                "cpu": "1000m",
                "memory": "1Gi",
                "ephemeral_storage": "2Gi",
            },
            "kubernetes_job": {"enabled": True},
            "cleanup": {
                "status": "removed",
                "removed": True,
                "path_confined_to_work_dir": True,
            },
        },
        "execution": {"status": "completed"},
    }
    artifact = build_execution_artifact_payload(
        engine="templates",
        target_url="https://api.example.com/staging-worker",
        profile_id="profile-staging",
        run_id="run-staging-worker",
        execution={"status": "COMPLETED", "executed": 1},
        engine_plan=[{"engine": "templates", "status": "ready"}],
        findings={"created_count": 0},
        worker_isolation=worker_result["worker_isolation"],
    )

    acceptance = validate_worker_staging_scan_acceptance(worker_result, artifact)

    assert acceptance["ready"] is True
    assert acceptance["status"] == "accepted"
    assert acceptance["blockers"] == []
    assert acceptance["checks"]["queued_worker_execution"]["ready"] is True
    assert acceptance["checks"]["sandbox_cleanup"]["ready"] is True
    assert acceptance["checks"]["resource_limits"]["ready"] is True
    assert acceptance["checks"]["artifact_generation"]["ready"] is True
    assert acceptance["evidence"]["artifact_hash"] == artifact["artifact_hash"]

    tampered = copy.deepcopy(artifact)
    tampered["execution"]["executed"] = 2

    rejected = validate_worker_staging_scan_acceptance(worker_result, tampered)

    assert rejected["ready"] is False
    assert rejected["status"] == "blocked"
    assert rejected["checks"]["artifact_generation"]["ready"] is False
    assert rejected["blockers"][0]["id"] == "worker_artifact_not_verified"
