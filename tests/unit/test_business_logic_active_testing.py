from server.modules.business_logic.active_testing import business_abuse_family_coverage


def test_business_abuse_family_coverage_maps_templates_and_endpoints_without_content():
    templates = [
        {
            "id": "coupon-workflow-abuse",
            "info": {"tags": ["Business logic", "coupon"]},
        },
        {
            "id": "otp-spam-guard",
            "info": {"tags": ["Business logic", "mfa"]},
        },
        {
            "id": "workflow-bypass-checkout",
            "security_category": "business_logic",
        },
        {
            "id": "monetary-amount-abuse",
            "info": {"tags": ["Business logic", "payment amount"]},
        },
        {
            "id": "resource-exhaustion-rate-limit",
            "info": {"name": "Resource exhaustion and rate limit abuse"},
        },
    ]
    endpoints = [
        {
            "method": "POST",
            "path": "/checkout/apply-coupon",
            "url": "https://api.example.test/checkout/apply-coupon?coupon=VIP-raw-secret",
            "last_request_body": {"coupon_code": "VIP-raw-secret", "order_id": "order-123"},
            "private_variable_count": 1,
        },
        {
            "method": "POST",
            "path": "/auth/otp/verify",
            "last_request_body": {"otp": "123456", "phone": "+15550123"},
        },
        {
            "method": "POST",
            "path": "/orders/123/confirm",
            "last_request_body": {"order_id": "order-123", "step": "confirm"},
            "private_variable_count": 1,
        },
        {
            "method": "POST",
            "path": "/payments/refund",
            "last_request_body": {"amount": "499.99", "currency": "USD", "token": "raw-refund-token"},
        },
        {
            "method": "POST",
            "path": "/reports/export",
            "last_request_body": {"format": "csv", "token": "raw-export-token"},
        },
    ]

    coverage = business_abuse_family_coverage(templates=templates, endpoints=endpoints)

    assert coverage == {
        "coupon_abuse": {
            "template_count": 1,
            "endpoint_signal_count": 1,
            "ready": True,
            "status": "ready",
            "signals": ["coupon"],
        },
        "otp_spam": {
            "template_count": 1,
            "endpoint_signal_count": 1,
            "ready": True,
            "status": "ready",
            "signals": ["otp"],
        },
        "workflow_bypass": {
            "template_count": 2,
            "endpoint_signal_count": 4,
            "ready": True,
            "status": "ready",
            "signals": ["coupon", "order", "otp", "payment"],
        },
        "monetary_abuse": {
            "template_count": 1,
            "endpoint_signal_count": 2,
            "ready": True,
            "status": "ready",
            "signals": ["amount", "currency", "payment"],
        },
        "resource_exhaustion": {
            "template_count": 1,
            "endpoint_signal_count": 1,
            "ready": True,
            "status": "ready",
            "signals": ["export"],
        },
    }
    rendered = repr(coverage)
    assert "VIP-raw-secret" not in rendered
    assert "raw-export-token" not in rendered
    assert "raw-refund-token" not in rendered
    assert "499.99" not in rendered
    assert "order-123" not in rendered
    assert "/checkout/apply-coupon" not in rendered


def test_business_abuse_family_coverage_reports_template_or_endpoint_gaps():
    coverage = business_abuse_family_coverage(
        templates=[{"id": "coupon-abuse"}],
        endpoints=[{"method": "POST", "path": "/auth/otp/verify"}],
    )

    assert coverage["coupon_abuse"]["status"] == "missing_endpoint_context"
    assert coverage["otp_spam"]["status"] == "missing_template"
    assert coverage["workflow_bypass"]["status"] == "missing_template"
    assert coverage["monetary_abuse"]["status"] == "missing_template"
    assert coverage["resource_exhaustion"]["status"] == "missing_template"
