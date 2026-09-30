from server.modules.pentest.north_star_readiness import build_north_star_readiness
from server.modules.pentest.orchestrator import (
    _north_star_governance_controls,
    _north_star_workflow_controls,
)


def _empty_runtime_facts() -> dict:
    """A tenant with no schedules, no worker runs, and no audit trail."""
    return {
        "account_id": 1000000,
        "evidence_observed": False,
        "schedules": {"active_schedule_count": 0, "authenticated_schedule_count": 0},
        "queued": {
            "execution_mode": "queued",
            "queued_execution_observed": False,
            "isolated_worker_observed": False,
            "isolated_worker_modes": [],
            "fresh_worker_count": 0,
            "stale_worker_count": 0,
            "heartbeat_max_age_seconds": 300,
        },
        "audit": {"entry_count": 0, "target_guard_block_count": 0},
        "worker_capabilities": {"advertised": False, "source": None, "engines": {}},
    }


def _observed_runtime_facts() -> dict:
    facts = _empty_runtime_facts()
    facts["evidence_observed"] = True
    facts["schedules"] = {"active_schedule_count": 2, "authenticated_schedule_count": 1}
    facts["queued"].update(
        {
            "queued_execution_observed": True,
            "isolated_worker_observed": True,
            "isolated_worker_modes": ["leased_external_worker"],
            "fresh_worker_count": 1,
        }
    )
    facts["audit"] = {"entry_count": 12, "target_guard_block_count": 1}
    return facts


def test_north_star_readiness_reports_ready_partial_and_gap_capabilities():
    readiness = build_north_star_readiness(
        auth_readiness={"authenticated": True, "status": "ready", "required": True},
        engine_plan=[
            {"engine": "templates", "status": "ready"},
            {"engine": "schemathesis", "status": "ready"},
            {"engine": "nuclei", "status": "ready"},
            {"engine": "zap", "status": "ready"},
            {"engine": "passive", "status": "available"},
        ],
        safety_controls={
            "target_guard": True,
            "state_change_guard": True,
            "destructive_method_arming": True,
        },
        lifecycle_controls={
            "confirmatory_retests": True,
            "ticketing": False,
            "sla_tracking": False,
        },
        evidence_controls={
            "reproducible_redacted_evidence": True,
            "evidence_completeness": True,
            "evidence_completeness_gate": True,
        },
        governance_controls={
            "isolated_workers": True,
            "audit_logs": True,
            "ci_cd_gates": True,
            "strict_policy_packs": True,
            "sarif_junit_artifacts": True,
            "engine_artifact_accountability": True,
            "rbac": True,
            "tenant_isolation": True,
        },
        coverage_controls={
            "bola_bfla": True,
            "business_logic": True,
            "llm_api": False,
            "context_aware_selection": False,
        },
    )

    capabilities = {item["id"]: item for item in readiness["capabilities"]}

    assert readiness["overall_status"] == "partial"
    assert readiness["ready_count"] == 6
    assert readiness["partial_count"] == 1
    assert readiness["gap_count"] == 3
    assert capabilities["continuous_authenticated_workflows"]["status"] == "gap"
    assert capabilities["authenticated_by_default"]["status"] == "ready"
    assert capabilities["multi_engine_execution"]["status"] == "ready"
    assert capabilities["reproducible_evidence_retests"]["status"] == "ready"
    assert "evidence_completeness_gate" in capabilities["reproducible_evidence_retests"]["ready"]
    assert capabilities["lifecycle_sla_ticketing"]["status"] == "partial"
    assert capabilities["context_aware_selection"]["status"] == "gap"
    assert capabilities["llm_api_security"]["status"] == "gap"
    assert "context_aware_selection" in readiness["next_gaps"]
    assert "llm_api_security" in readiness["next_gaps"]
    assert "ticketing" in capabilities["lifecycle_sla_ticketing"]["missing"]


def test_north_star_readiness_reports_continuous_authenticated_workflows():
    readiness = build_north_star_readiness(
        auth_readiness={"authenticated": True, "status": "ready"},
        engine_plan=[{"engine": "templates", "status": "ready"}],
        workflow_controls={
            "scheduled_scans": True,
            "authenticated_schedule_preflight": True,
            "queued_execution": True,
            "schedule_target_guard": True,
        },
    )

    capabilities = {item["id"]: item for item in readiness["capabilities"]}

    assert capabilities["continuous_authenticated_workflows"]["status"] == "ready"
    assert capabilities["continuous_authenticated_workflows"]["missing"] == []


def test_north_star_readiness_reports_partial_context_aware_selection():
    readiness = build_north_star_readiness(
        auth_readiness={"authenticated": True, "status": "ready"},
        engine_plan=[{"engine": "templates", "status": "ready"}],
        coverage_controls={
            "context_aware_selection": False,
            "partial_context_aware_selection": True,
        },
    )

    capability = {
        item["id"]: item
        for item in readiness["capabilities"]
    }["context_aware_selection"]

    assert capability["status"] == "partial"
    assert "some_context_signals_available" in capability["ready"]
    assert "required_context_signals_satisfied" in capability["missing"]


def test_north_star_readiness_reports_p1_workstream_owners_and_evidence_status():
    readiness = build_north_star_readiness(
        auth_readiness={"authenticated": True, "status": "ready"},
        engine_plan=[{"engine": "templates", "status": "ready"}],
        lifecycle_controls={
            "confirmatory_retests": True,
            "ticketing": True,
            "sla_tracking": True,
        },
        governance_controls={
            "ci_cd_gates": True,
            "audit_logs": True,
            "tenant_isolation": True,
        },
        evidence_controls={
            "reproducible_redacted_evidence": True,
            "evidence_completeness": True,
            "evidence_completeness_gate": True,
        },
        coverage_controls={
            "bola_bfla": True,
            "business_logic": False,
            "llm_api": True,
            "context_aware_selection": True,
        },
    )

    workstreams = {item["id"]: item for item in readiness["p1_workstreams"]}

    assert workstreams["multi_identity_bola_bfla"] == {
        "id": "multi_identity_bola_bfla",
        "name": "Multi-Identity BOLA/BFLA",
        "owner": "AuthZ Engineer",
        "priority": "P1",
        "status": "ready",
        "evidence_status": "deterministic",
        "ready_checks": ["bola_bfla"],
        "missing_checks": [],
        "blockers": [],
    }
    assert workstreams["business_logic"]["owner"] == "Advanced Testing"
    assert workstreams["business_logic"]["status"] == "blocked"
    assert workstreams["business_logic"]["evidence_status"] == "missing"
    assert workstreams["business_logic"]["blockers"] == ["business_logic"]
    assert workstreams["llm_api_security"]["evidence_status"] == "deterministic"
    assert workstreams["governance_ui_reports"]["ready_checks"] == [
        "ci_cd_gates",
        "audit_logs",
        "tenant_isolation",
        "sla_tracking",
    ]


def test_north_star_readiness_reports_score_blockers_and_next_actions():
    readiness = build_north_star_readiness(
        auth_readiness={"authenticated": False, "status": "blocked"},
        engine_plan=[
            {"engine": "templates", "status": "ready"},
            {"engine": "schemathesis", "status": "blocked"},
            {"engine": "nuclei", "status": "blocked"},
            {"engine": "zap", "status": "blocked"},
            {"engine": "passive", "status": "available"},
        ],
        safety_controls={
            "target_guard": True,
            "state_change_guard": True,
            "destructive_method_arming": False,
        },
        evidence_controls={
            "reproducible_redacted_evidence": True,
            "evidence_completeness": True,
            "evidence_completeness_gate": False,
        },
        governance_controls={
            "isolated_workers": False,
            "audit_logs": True,
            "ci_cd_gates": True,
            "strict_policy_packs": True,
            "sarif_junit_artifacts": True,
            "engine_artifact_accountability": False,
            "rbac": True,
            "tenant_isolation": True,
        },
    )

    capabilities = {item["id"]: item for item in readiness["capabilities"]}
    blocker_ids = {item["id"] for item in readiness["production_blockers"]}

    assert 0 < readiness["readiness_score"] < 100
    assert readiness["control_counts"]["missing"] > 0
    assert "authenticated_by_default.auth_ready" in blocker_ids
    assert "target_and_destructive_safety.destructive_method_arming" in blocker_ids
    assert "enterprise_governance.engine_artifact_accountability" in blocker_ids
    assert capabilities["enterprise_governance"]["status"] == "partial"
    assert "engine_artifact_accountability" in capabilities["enterprise_governance"]["missing"]
    assert capabilities["enterprise_governance"]["next_action"] == (
        "Require CI gates to verify every ready external engine emits a hashed execution artifact."
    )


def test_orchestrator_governance_controls_include_ci_artifact_accountability(monkeypatch):
    monkeypatch.setattr(
        "server.modules.pentest.orchestrator._configured_worker_isolation_mode",
        lambda: "leased_external_worker",
    )
    # tenant_isolation reports the actual TENANT_RLS_ENABLED configuration; this
    # test pins the control vocabulary with RLS enabled.
    monkeypatch.setattr("sentinel_core.config.settings.TENANT_RLS_ENABLED", True)

    controls = _north_star_governance_controls(_observed_runtime_facts())

    assert controls["isolated_workers"] is True
    assert controls["ci_cd_gates"] is True
    assert controls["strict_policy_packs"] is True
    assert controls["sarif_junit_artifacts"] is True
    assert controls["engine_artifact_accountability"] is True
    assert controls["rbac"] is True


def test_orchestrator_workflow_controls_require_persisted_runtime_facts(monkeypatch):
    """P0-7: scheduler functions existing and the mode being queued prove nothing."""
    monkeypatch.setattr("sentinel_core.config.settings.PENTEST_SCAN_EXECUTION_MODE", "queued")

    without_evidence = _north_star_workflow_controls(_empty_runtime_facts())

    assert without_evidence == {
        "scheduled_scans": False,
        "authenticated_schedule_preflight": False,
        "queued_execution": False,
        "schedule_target_guard": False,
    }

    with_evidence = _north_star_workflow_controls(_observed_runtime_facts())

    assert with_evidence == {
        "scheduled_scans": True,
        "authenticated_schedule_preflight": True,
        "queued_execution": True,
        "schedule_target_guard": True,
    }


def test_orchestrator_workflow_controls_default_to_no_evidence_without_facts(monkeypatch):
    """Fail closed: a caller that supplies no runtime facts cannot claim readiness."""
    monkeypatch.setattr("sentinel_core.config.settings.PENTEST_SCAN_EXECUTION_MODE", "queued")

    controls = _north_star_workflow_controls()

    assert controls == {
        "scheduled_scans": False,
        "authenticated_schedule_preflight": False,
        "queued_execution": False,
        "schedule_target_guard": False,
    }


def test_orchestrator_workflow_controls_keep_queued_execution_config_bound(monkeypatch):
    """Persisted worker runs do not make `queued_execution` true in background mode."""
    monkeypatch.setattr("sentinel_core.config.settings.PENTEST_SCAN_EXECUTION_MODE", "background")

    controls = _north_star_workflow_controls(_observed_runtime_facts())

    assert controls["queued_execution"] is False
    assert controls["scheduled_scans"] is True


def test_orchestrator_governance_controls_require_observed_worker_isolation(monkeypatch):
    """ISO-1/P0-7: a configured isolation mode is not an executed isolated run."""
    monkeypatch.setattr(
        "server.modules.pentest.orchestrator._configured_worker_isolation_mode",
        lambda: "leased_external_worker",
    )
    monkeypatch.setattr("sentinel_core.config.settings.TENANT_RLS_ENABLED", True)

    without_evidence = _north_star_governance_controls(_empty_runtime_facts())

    assert without_evidence["isolated_workers"] is False
    assert without_evidence["audit_logs"] is False
    assert without_evidence["tenant_isolation"] is True

    with_evidence = _north_star_governance_controls(_observed_runtime_facts())

    assert with_evidence["isolated_workers"] is True
    assert with_evidence["audit_logs"] is True


def test_north_star_readiness_uses_worker_advertisement_over_api_host_probe():
    """ISO-1: when a worker advertised capabilities, they are authoritative."""
    readiness = build_north_star_readiness(
        auth_readiness={"authenticated": True, "status": "ready"},
        engine_plan=[
            {"engine": "templates", "status": "ready"},
            {"engine": "schemathesis", "status": "ready"},
            {"engine": "nuclei", "status": "ready"},
            {"engine": "zap", "status": "ready"},
        ],
        runtime_evidence={
            "worker_capabilities": {
                "advertised": True,
                "source": "execution_artifact",
                "engines": {"schemathesis": True, "nuclei": False, "zap": False},
            }
        },
    )

    capabilities = {item["id"]: item for item in readiness["capabilities"]}
    multi_engine = capabilities["multi_engine_execution"]

    assert readiness["engine_runtime_authority"] == "worker_capability_advertisement"
    assert "schemathesis" in multi_engine["ready"]
    assert "nuclei" in multi_engine["missing"]
    assert "zap" in multi_engine["missing"]
    assert multi_engine["status"] == "partial"
    assert readiness["runtime_evidence"]["worker_capabilities"]["source"] == "execution_artifact"


def test_north_star_readiness_marks_the_api_host_probe_advisory_without_advertisement():
    readiness = build_north_star_readiness(
        auth_readiness={"authenticated": True, "status": "ready"},
        engine_plan=[
            {"engine": "templates", "status": "ready"},
            {"engine": "schemathesis", "status": "ready"},
        ],
        runtime_evidence={"worker_capabilities": {"advertised": False, "engines": {}}},
    )

    capabilities = {item["id"]: item for item in readiness["capabilities"]}

    assert readiness["engine_runtime_authority"] == "api_host_advisory"
    assert capabilities["multi_engine_execution"]["ready"] == ["templates", "schemathesis"]
