from types import SimpleNamespace

import pytest

from server.models.core import APIEndpoint, BusinessLogicGraph
from server.modules.business_logic.active_tests import (
    ACTIVE_BUSINESS_LOGIC_TEMPLATE_ID,
    build_active_business_logic_templates,
)


def _endpoint(**overrides):
    base = {
        "id": "endpoint-1",
        "account_id": 1000000,
        "method": "POST",
        "protocol": "https",
        "host": "api.example.com",
        "path": "/checkout/apply-coupon",
        "last_request_body": {"coupon_code": "VIP-raw-secret", "order_id": "order-123"},
        "last_query_string": "token=raw-token",
        "private_variable_count": 1,
    }
    base.update(overrides)
    return base


def test_active_business_logic_reserved_template_id_is_stable():
    assert ACTIVE_BUSINESS_LOGIC_TEMPLATE_ID == "ACTIVE_BUSINESS_LOGIC"


def test_active_business_logic_generates_bounded_coupon_otp_and_resource_templates_without_secrets():
    endpoints = [
        _endpoint(id="coupon-1", path="/checkout/apply-coupon"),
        _endpoint(id="otp-1", path="/auth/otp/verify", last_request_body={"phone": "+15555550123"}),
        _endpoint(id="search-1", path="/orders/search", last_query_string="limit=25&page=1"),
    ]

    templates = build_active_business_logic_templates(endpoints, test_intensity="standard")

    scenario_types = {template["active_business_logic"]["scenario_type"] for template in templates}
    assert {"coupon_replay", "otp_throttle_probe", "resource_limit_boundary"} <= scenario_types
    assert all(template["security_category"] == "business_logic" for template in templates)
    assert all(template["execute"]["max_active_requests_per_test"] <= 2 for template in templates)
    assert all(template["active_business_logic"]["safe_throttle"]["max_requests"] <= 2 for template in templates)
    assert "raw-secret" not in str(templates)
    assert "raw-token" not in str(templates)
    assert "+15555550123" not in str(templates)


def test_active_business_logic_templates_declare_deterministic_evidence_requirements():
    endpoints = [
        _endpoint(id="coupon-1", path="/checkout/apply-coupon"),
        _endpoint(id="otp-1", path="/auth/otp/verify"),
        _endpoint(id="search-1", path="/orders/search"),
    ]

    templates = build_active_business_logic_templates(endpoints, test_intensity="standard")

    by_scenario = {
        template["active_business_logic"]["scenario_type"]: template
        for template in templates
    }
    for scenario_type in ("coupon_replay", "otp_throttle_probe", "resource_limit_boundary"):
        template = by_scenario[scenario_type]
        metadata = template["active_business_logic"]["deterministic_evidence"]
        assert metadata["required"] == [
            "scenario_type",
            "safe_throttle",
            "sent_request",
            "received_response",
            "response_code",
            "matched_rule",
        ]
        assert metadata["body_content_persisted"] is False
        assert metadata["promotion_decision"] == "promote_unconfirmed_finding"


def test_active_business_logic_generates_bounded_monetary_boundary_template_without_values():
    endpoints = [
        _endpoint(
            id="refund-1",
            path="/payments/refund",
            last_request_body={
                "amount": "499.99",
                "currency": "USD",
                "order_id": "order-raw-secret",
                "token": "raw-refund-token",
            },
        )
    ]

    templates = build_active_business_logic_templates(endpoints, test_intensity="aggressive")

    monetary = [
        template
        for template in templates
        if template["active_business_logic"]["scenario_type"] == "monetary_amount_boundary"
    ]
    assert monetary
    template = monetary[0]
    assert template["info"]["severity"] == "HIGH"
    assert template["execute"]["allow_state_change"] is True
    assert template["execute"]["allow_destructive_methods"] is False
    assert template["execute"]["max_active_requests_per_test"] == 1
    assert template["active_business_logic"]["safe_throttle"]["max_requests"] == 1
    assert template["active_business_logic"]["deterministic_evidence"]["body_content_persisted"] is False
    rendered = repr(template)
    assert "raw-refund-token" not in rendered
    assert "order-raw-secret" not in rendered
    assert "499.99" not in rendered


def test_active_business_logic_maps_abuse_families_to_flow_graph_and_sensitive_flows():
    endpoints = [
        _endpoint(
            id="coupon-1",
            path="/checkout/apply-coupon?coupon=VIP-raw-secret",
            is_sensitive=True,
            private_variable_count=2,
        ),
        _endpoint(
            id="otp-1",
            path="/auth/otp/send",
            last_request_body={"phone": "+15555550123", "otp": "123456"},
        ),
        _endpoint(
            id="export-1",
            path="/reports/export?token=raw-export-token",
            is_sensitive=True,
        ),
        _endpoint(
            id="confirm-1",
            path="/checkout/confirm?token=raw-confirm-token",
            is_sensitive=True,
        ),
    ]
    graph = SimpleNamespace(
        version=12,
        nodes_json=[
            {"path": "/checkout/apply-coupon?coupon=VIP-raw-secret", "sensitive_flow": True},
            {"path": "/auth/otp/send", "sensitive_flow": True},
            {"path": "/reports/export?token=raw-export-token", "sensitive_flow": True},
            {"path": "/cart?session=raw-session", "sensitive_flow": False},
            {"path": "/checkout/confirm?token=raw-confirm-token", "sensitive_flow": True},
        ],
        edges_json=[
            {
                "from": "/cart?session=raw-session",
                "to": "/checkout/confirm?token=raw-confirm-token",
                "count": 6,
                "min_time_ms": 30_000,
            }
        ],
    )

    templates = build_active_business_logic_templates(endpoints, graph=graph, test_intensity="aggressive")

    expected_families = {"coupon_abuse", "otp_spam", "workflow_bypass", "resource_exhaustion"}
    by_family = {
        template["active_business_logic"].get("abuse_family"): template
        for template in templates
    }
    assert expected_families <= set(by_family)

    for family in expected_families:
        scenario = by_family[family]["active_business_logic"]
        assert scenario["deterministic_evidence"]["body_content_persisted"] is False
        assert scenario["deterministic_evidence"]["matched_text_persisted"] is False
        assert scenario["deterministic_evidence"]["promotion_decision"] == "promote_unconfirmed_finding"
        assert scenario["flow_mapping"]["graph_version"] == 12
        assert scenario["flow_mapping"]["sensitive_flow"] is True
        assert scenario["flow_mapping"]["sensitive_signals"]
        assert scenario["flow_mapping"]["node_path"].startswith("/")

    workflow_mapping = by_family["workflow_bypass"]["active_business_logic"]["flow_mapping"]
    assert workflow_mapping["expected_predecessor_count"] == 1
    assert workflow_mapping["expected_predecessors"] == ["/cart?session=****"]
    rendered = repr(templates)
    assert "raw-" not in rendered
    assert "+15555550123" not in rendered
    assert "123456" not in rendered


@pytest.mark.asyncio
async def test_active_business_logic_generates_workflow_direct_entry_from_latest_graph(db_session):
    endpoint = APIEndpoint(
        id="checkout-endpoint",
        account_id=1000000,
        method="POST",
        protocol="https",
        host="api.example.com",
        path="/checkout/confirm?token=raw-token",
        private_variable_count=1,
    )
    graph = BusinessLogicGraph(
        account_id=1000000,
        version=9,
        nodes_json=[{"path": "/cart"}, {"path": "/checkout/confirm?token=raw-token"}],
        edges_json=[
            {
                "from": "/cart?session=raw-session",
                "to": "/checkout/confirm?token=raw-token",
                "count": 5,
                "min_time_ms": 30_000,
            }
        ],
    )
    db_session.add(endpoint)
    db_session.add(graph)
    await db_session.flush()

    templates = build_active_business_logic_templates([endpoint], graph=graph, test_intensity="safe")

    workflow = [template for template in templates if template["active_business_logic"]["scenario_type"] == "workflow_direct_entry"]
    assert workflow
    assert workflow[0]["active_business_logic"]["graph_version"] == 9
    assert workflow[0]["execute"]["allow_state_change"] is False
    assert workflow[0]["execute"]["max_active_requests_per_test"] == 1
    assert "raw-token" not in str(workflow)
    assert "raw-session" not in str(workflow)
