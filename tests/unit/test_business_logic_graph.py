import datetime
import pytest
from sqlalchemy import select

from server.models.core import RequestLog, BusinessLogicGraph, Vulnerability
from server.modules.business_logic.graph_builder import build_graph, detect_transition_violation
from server.modules.vulnerability_detector.lifecycle import verify_vulnerability_evidence


@pytest.mark.asyncio
async def test_build_graph_creates_edges(db_session):
    now = datetime.datetime.now(datetime.timezone.utc)
    logs = [
        RequestLog(
            account_id=1000000,
            source_ip="1.1.1.1",
            path="/login",
            created_at=now,
        ),
        RequestLog(
            account_id=1000000,
            source_ip="1.1.1.1",
            path="/orders",
            created_at=now + datetime.timedelta(seconds=1),
        ),
    ]
    for log in logs:
        db_session.add(log)
    await db_session.commit()

    graph = await build_graph(db_session, account_id=1000000, window_days=1, min_transitions=1)
    await db_session.commit()

    result = await db_session.execute(select(BusinessLogicGraph))
    stored = result.scalars().all()
    assert stored
    assert graph.edges_json


@pytest.mark.asyncio
async def test_build_graph_redacts_paths_before_persisting(db_session):
    now = datetime.datetime.now(datetime.timezone.utc)
    raw_token = "raw-graph-token"
    logs = [
        RequestLog(
            account_id=1000001,
            source_ip="1.1.1.2",
            path=f"/login?token={raw_token}",
            created_at=now,
        ),
        RequestLog(
            account_id=1000001,
            source_ip="1.1.1.2",
            path=f"/orders?api_key={raw_token}",
            created_at=now + datetime.timedelta(seconds=1),
        ),
    ]
    for log in logs:
        db_session.add(log)
    await db_session.commit()

    graph = await build_graph(db_session, account_id=1000001, window_days=1, min_transitions=1)
    await db_session.commit()

    graph_blob = str(graph.nodes_json) + str(graph.edges_json)
    assert raw_token not in graph_blob
    assert "token=****" in graph_blob
    assert "api_key=****" in graph_blob


@pytest.mark.asyncio
async def test_transition_violation_promotes_lifecycle_vulnerability(db_session):
    graph = BusinessLogicGraph(
        account_id=1000000,
        version=99,
        nodes_json=[{"path": "/login"}, {"path": "/orders"}],
        edges_json=[{"from": "/login", "to": "/orders", "count": 3}],
    )
    db_session.add(graph)
    await db_session.flush()

    violation = await detect_transition_violation(
        db_session,
        account_id=1000000,
        actor_id="actor-123",
        prev_path="/checkout",
        curr_path="/admin?token=raw-token",
    )
    await db_session.flush()

    assert violation is not None
    assert violation.to_path == "/admin?token=****"
    row = (
        await db_session.execute(
            select(Vulnerability).where(
                Vulnerability.type == "PASSIVE:BUSINESS_LOGIC:FORBIDDEN_TRANSITION"
            )
        )
    ).scalar_one()
    assert row.template_id == "passive-business-logic-transition"
    assert row.severity == "HIGH"
    assert row.url == "/admin?token=****"
    assert row.evidence["engine"] == "passive_traffic"
    assert row.evidence["detector"] == "business_logic_graph"
    assert row.evidence["finding_status"] == "UNCONFIRMED"
    assert row.evidence["matched_rule"] == {
        "detector": "business_logic_graph",
        "violation_type": "FORBIDDEN_TRANSITION",
    }
    assert row.evidence["sent_request"] == {
        "method": "GET",
        "url": "/admin?token=****",
    }
    assert row.evidence["received_response"] == {
        "transition": "/checkout -> /admin?token=****",
        "violation_type": "FORBIDDEN_TRANSITION",
    }
    assert row.evidence["similarity"] == {
        "source": "business_logic_graph",
        "confidence": 0.7,
    }
    assert "curl -i -X GET" in row.evidence["reproduction"]["curl"]
    assert "Enforce server-side workflow state checks" in row.evidence["remediation"]
    assert row.evidence["evidence_completeness"]["complete"] is True
    assert row.evidence["evidence_completeness"]["missing"] == []
    assert row.evidence["evidence_hash"]
    assert verify_vulnerability_evidence(row.evidence)["verified"] is True
    assert "raw-token" not in str(row.evidence)


@pytest.mark.asyncio
async def test_too_fast_transition_promotes_dedicated_business_logic_vulnerability(db_session):
    graph = BusinessLogicGraph(
        account_id=1000000,
        version=100,
        nodes_json=[{"path": "/cart"}, {"path": "/checkout"}],
        edges_json=[
            {
                "from": "/cart",
                "to": "/checkout?token=raw-token",
                "count": 8,
                "min_time_ms": 10_000,
                "max_time_ms": 60_000,
            }
        ],
    )
    db_session.add(graph)
    await db_session.flush()

    violation = await detect_transition_violation(
        db_session,
        account_id=1000000,
        actor_id="checkout-bot",
        prev_path="/cart",
        curr_path="/checkout?token=raw-token",
        elapsed_ms=500,
    )
    await db_session.flush()

    assert violation is not None
    assert violation.violation_type == "TOO_FAST_TRANSITION"
    assert violation.to_path == "/checkout?token=****"
    assert violation.details["observed_elapsed_ms"] == 500
    assert violation.details["expected_min_time_ms"] == 10_000

    row = (
        await db_session.execute(
            select(Vulnerability).where(
                Vulnerability.type == "PASSIVE:BUSINESS_LOGIC:TOO_FAST_TRANSITION"
            )
        )
    ).scalar_one()
    assert row.template_id == "passive-business-logic-too-fast-transition"
    assert row.url == "/checkout?token=****"
    assert row.evidence["violation_type"] == "TOO_FAST_TRANSITION"
    assert row.evidence["details"]["observed_elapsed_ms"] == 500
    assert row.evidence["details"]["expected_min_time_ms"] == 10_000
    assert verify_vulnerability_evidence(row.evidence)["verified"] is True
    assert "raw-token" not in str(row.evidence)


@pytest.mark.asyncio
async def test_direct_entry_to_stateful_step_promotes_missing_prerequisite_vulnerability(db_session):
    graph = BusinessLogicGraph(
        account_id=1000000,
        version=102,
        nodes_json=[{"path": "/cart"}, {"path": "/checkout?token=****"}],
        edges_json=[
            {
                "from": "/cart?session=raw-token",
                "to": "/checkout?token=raw-token",
                "count": 6,
                "min_time_ms": 15_000,
                "max_time_ms": 90_000,
            }
        ],
    )
    db_session.add(graph)
    await db_session.flush()

    violation = await detect_transition_violation(
        db_session,
        account_id=1000000,
        actor_id="direct-entry-actor",
        prev_path=None,
        curr_path="/checkout?token=raw-token",
    )
    await db_session.flush()

    assert violation is not None
    assert violation.violation_type == "MISSING_PREREQUISITE"
    assert violation.from_path is None
    assert violation.to_path == "/checkout?token=****"
    assert violation.details == {
        "graph_version": 102,
        "expected_predecessors": ["/cart?session=****"],
        "expected_predecessor_count": 1,
    }

    row = (
        await db_session.execute(
            select(Vulnerability).where(
                Vulnerability.type == "PASSIVE:BUSINESS_LOGIC:MISSING_PREREQUISITE"
            )
        )
    ).scalar_one()
    assert row.template_id == "passive-business-logic-missing-prerequisite"
    assert row.url == "/checkout?token=****"
    assert row.evidence["from_path"] == "direct_entry"
    assert row.evidence["violation_type"] == "MISSING_PREREQUISITE"
    assert row.evidence["details"]["expected_predecessors"] == ["/cart?session=****"]
    assert row.evidence["scope_validation"] == {
        "validated": True,
        "policy": "passive_traffic_scope",
        "scope": "captured_account_traffic",
        "target": "/checkout?token=****",
        "evidence_url": "/checkout?token=****",
    }
    assert row.evidence["received_response"] == {
        "transition": "direct_entry -> /checkout?token=****",
        "violation_type": "MISSING_PREREQUISITE",
    }
    assert row.evidence["evidence_reproducibility"] == {
        "redaction_policy": "api_sentinel_redactor",
        "raw_payload_persisted": False,
        "deterministic_hash": True,
        "hash_algorithm": "sha256",
        "reproduction_available": True,
        "scope_validated": True,
        "evidence_complete": True,
    }
    assert verify_vulnerability_evidence(row.evidence)["verified"] is True
    assert "raw-token" not in str(row.evidence)


@pytest.mark.asyncio
async def test_allowed_transition_at_normal_speed_is_not_a_violation(db_session):
    graph = BusinessLogicGraph(
        account_id=1000000,
        version=101,
        nodes_json=[{"path": "/cart"}, {"path": "/checkout"}],
        edges_json=[
            {
                "from": "/cart",
                "to": "/checkout",
                "count": 8,
                "min_time_ms": 10_000,
                "max_time_ms": 60_000,
            }
        ],
    )
    db_session.add(graph)
    await db_session.flush()

    violation = await detect_transition_violation(
        db_session,
        account_id=1000000,
        actor_id="normal-user",
        prev_path="/cart",
        curr_path="/checkout",
        elapsed_ms=8_000,
    )

    assert violation is None
