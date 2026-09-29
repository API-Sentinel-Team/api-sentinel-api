import json
from pathlib import Path

import pytest

from server.config import settings
from server.modules.pentest.worker_isolation import (
    WorkerIsolationSession,
    cleanup_worker_isolation_session,
    configured_worker_isolation_mode,
    create_worker_isolation_session,
)


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("queued", "leased_external_worker"),
        ("external_worker", "leased_external_worker"),
        ("leased_external_worker", "leased_external_worker"),
        ("k8s", "kubernetes_job"),
        ("k8s_job", "kubernetes_job"),
        ("kubernetes_job", "kubernetes_job"),
        ("background", "background"),
    ],
)
def test_worker_isolation_mode_normalizes_external_and_k8s_aliases(configured, expected, monkeypatch):
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_ISOLATION_MODE", configured)

    assert configured_worker_isolation_mode() == expected


def test_worker_isolation_session_creates_confined_redacted_sandbox_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORK_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_ISOLATION_MODE", "kubernetes_job")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_IMAGE", "registry.example.com/api-sentinel/worker:2026.06")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_JOB_TTL_SECONDS", 900)
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_CPU", "750m")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_MEMORY", "768Mi")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_EPHEMERAL_STORAGE", "1536Mi")

    session = create_worker_isolation_session(
        run_id="run-token=raw-run-token",
        worker_id="worker Authorization: Bearer raw-worker-token",
        account_id=42,
        engine="nuclei",
        claim_count=2,
        timeout_seconds=123,
    )

    assert session.sandbox_path.exists()
    assert session.sandbox_path.is_dir()
    assert session.manifest_path.exists()
    assert session.sandbox_path.resolve().is_relative_to((tmp_path / "workers").resolve())

    manifest = json.loads(session.manifest_path.read_text(encoding="utf-8"))
    metadata = session.to_metadata()
    blob = f"{manifest} {metadata}"

    assert manifest["schema_version"] == "worker_isolation.v1"
    assert manifest["mode"] == "kubernetes_job"
    assert manifest["sandbox"]["path_confined_to_work_dir"] is True
    assert manifest["timeout_policy"] == {"timeout_seconds": 123, "kill_on_timeout": True}
    assert manifest["resource_limits"] == {
        "cpu": "750m",
        "memory": "768Mi",
        "ephemeral_storage": "1536Mi",
    }
    assert manifest["kubernetes_job"]["enabled"] is True
    assert manifest["kubernetes_job"]["job_ttl_seconds"] == 900
    assert manifest["kubernetes_job"]["pod_spec"]["service_account_name"] == "api-sentinel-scan-worker"
    assert manifest["kubernetes_job"]["pod_spec"]["containers"][0]["image"] == (
        "registry.example.com/api-sentinel/worker:2026.06"
    )
    assert manifest["kubernetes_job"]["job_spec"]["kind"] == "Job"
    assert manifest["kubernetes_job"]["job_spec"]["metadata"] == {
        "namespace": "api-sentinel",
        "generateName": "api-sentinel-scan-worker-",
    }
    assert manifest["kubernetes_job"]["job_spec"]["spec"]["ttlSecondsAfterFinished"] == 900
    assert manifest["kubernetes_job"]["job_spec"]["spec"]["backoffLimit"] == 0
    assert manifest["kubernetes_job"]["job_spec"]["spec"]["template"]["spec"]["restartPolicy"] == "Never"
    assert manifest["kubernetes_job"]["job_spec"]["spec"]["template"]["spec"]["containers"][0]["resources"] == {
        "limits": {
            "cpu": "750m",
            "memory": "768Mi",
            "ephemeral-storage": "1536Mi",
        }
    }
    assert manifest["kubernetes_job"]["pod_spec"]["containers"][0]["env"] == [
        {"name": "API_SENTINEL_RUN_ID"},
        {"name": "API_SENTINEL_WORKER_ID"},
        {"name": "API_SENTINEL_ENGINE"},
    ]
    assert metadata["manifest"]["sha256"]
    assert metadata["sandbox"]["created"] is True
    assert "raw-run-token" not in blob
    assert "raw-worker-token" not in blob
    assert "Bearer ****" in blob

    cleanup = cleanup_worker_isolation_session(session)

    assert cleanup["status"] == "removed"
    assert cleanup["path_confined_to_work_dir"] is True
    assert not session.sandbox_path.exists()


def test_worker_isolation_cleanup_refuses_unconfined_path(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "keep.txt"
    marker.write_text("do-not-delete", encoding="utf-8")
    session = WorkerIsolationSession(
        run_id="run-1",
        worker_id="worker-1",
        account_id=1,
        engine="templates",
        claim_count=1,
        mode="background",
        sandbox_id="sandbox-1",
        work_root=tmp_path / "work-root",
        sandbox_path=outside,
        manifest_path=outside / "worker-isolation.json",
        resource_limits={"cpu": "1000m", "memory": "1Gi", "ephemeral_storage": "2Gi"},
        timeout_seconds=15,
        created_at="2026-06-05T00:00:00+00:00",
        lease_expires_at=None,
    )

    cleanup = cleanup_worker_isolation_session(session)

    assert cleanup["status"] == "refused"
    assert cleanup["path_confined_to_work_dir"] is False
    assert marker.exists()


def test_worker_isolation_cleanup_reports_failed_removal(tmp_path, monkeypatch):
    sandbox = tmp_path / "workers" / "sandbox-1"
    sandbox.mkdir(parents=True)
    marker = sandbox / "keep.txt"
    marker.write_text("still-here", encoding="utf-8")
    session = WorkerIsolationSession(
        run_id="run-1",
        worker_id="worker-1",
        account_id=1,
        engine="templates",
        claim_count=1,
        mode="background",
        sandbox_id="sandbox-1",
        work_root=tmp_path / "workers",
        sandbox_path=sandbox,
        manifest_path=sandbox / "worker-isolation.json",
        resource_limits={"cpu": "1000m", "memory": "1Gi", "ephemeral_storage": "2Gi"},
        timeout_seconds=15,
        created_at="2026-06-05T00:00:00+00:00",
        lease_expires_at=None,
    )

    monkeypatch.setattr("server.modules.pentest.worker_isolation.shutil.rmtree", lambda *_args, **_kwargs: None)

    cleanup = cleanup_worker_isolation_session(session)

    assert cleanup["status"] == "failed"
    assert cleanup["removed"] is False
    assert cleanup["path_confined_to_work_dir"] is True
    assert marker.exists()


def test_worker_isolation_session_cleans_sandbox_when_manifest_write_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORK_DIR", str(tmp_path))
    original_write_text = Path.write_text

    def fail_manifest_write(self, *args, **kwargs):
        if self.name == "worker-isolation.json":
            raise OSError("disk full token=raw-token")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_manifest_write)

    with pytest.raises(OSError, match="disk full"):
        create_worker_isolation_session(
            run_id="run-1",
            worker_id="worker-1",
            account_id=1,
            engine="nuclei",
            claim_count=1,
        )

    workers_root = tmp_path / "workers"
    assert workers_root.exists()
    assert list(workers_root.iterdir()) == []
