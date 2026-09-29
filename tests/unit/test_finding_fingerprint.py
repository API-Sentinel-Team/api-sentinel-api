from server.modules.utils.finding_fingerprint import (
    collapse_by_fingerprint,
    nuclei_fingerprint,
    source_finding_fingerprint,
    vulnerability_fingerprint,
    zap_fingerprint,
)


def test_vulnerability_fingerprint_ignores_transient_evidence_fields():
    first = {
        "account_id": 1000000,
        "template_id": "auth-check",
        "endpoint_id": "ep-1",
        "method": "GET",
        "type": "BROKEN_AUTH",
        "evidence": {"request_id": "abc", "status_code": 200},
    }
    second = {
        "account_id": 1000000,
        "template_id": "auth-check",
        "endpoint_id": "ep-1",
        "method": "GET",
        "type": "BROKEN_AUTH",
        "evidence": {"request_id": "xyz", "status_code": 200},
    }

    assert vulnerability_fingerprint(first) == vulnerability_fingerprint(second)


def test_vulnerability_fingerprint_ignores_active_scan_proof_volatility():
    first = {
        "account_id": 1000000,
        "template_id": "auth-check",
        "endpoint_id": "ep-1",
        "method": "GET",
        "type": "BROKEN_AUTH",
        "evidence": {
            "engine": "template",
            "evidence_hash": "first-hash",
            "sent_request": {
                "url": "https://api.example.com/admin?token=****",
                "headers": {"Authorization": "Bearer ****"},
            },
            "received_response": {"status_code": 200, "body": '{"ok": true}'},
            "reproduction": {"curl": "curl -i -X GET 'https://api.example.com/admin?token=****'"},
            "results": [{"proof": "first response body"}],
            "context": ["baseline"],
        },
    }
    second = {
        **first,
        "evidence": {
            "engine": "template",
            "evidence_hash": "second-hash",
            "sent_request": {
                "url": "https://api.example.com/admin?token=****",
                "headers": {"Authorization": "Bearer ****", "X-Trace": "abc"},
            },
            "received_response": {"status_code": 503, "body": '{"transient": true}'},
            "reproduction": {"curl": "curl -i -X GET 'https://api.example.com/admin?token=****' -H 'X-Trace: abc'"},
            "results": [{"proof": "second response body"}],
            "context": ["baseline", "auth_context"],
        },
    }

    assert vulnerability_fingerprint(first) == vulnerability_fingerprint(second)


def test_vulnerability_fingerprint_ignores_safety_policy_metadata():
    first = {
        "account_id": 1000000,
        "template_id": "ssrf",
        "endpoint_id": "ep-1",
        "method": "GET",
        "type": "SSRF",
        "evidence": {
            "engine": "template",
            "safety_policies": {
                "target_guard_policy": {
                    "policy": "target_guard",
                    "blocked": True,
                    "url": "https://api.example.com/search?token=first",
                    "reason": "first target guard reason",
                }
            },
            "results": [{"vulnerable": True, "proof": "first volatile proof"}],
        },
    }
    second = {
        **first,
        "evidence": {
            "engine": "template",
            "safety_policies": {
                "target_guard_policy": {
                    "policy": "target_guard",
                    "blocked": True,
                    "url": "https://api.example.com/search?token=second",
                    "reason": "second target guard reason",
                }
            },
            "results": [{"vulnerable": True, "proof": "second volatile proof"}],
        },
    }

    assert vulnerability_fingerprint(first) == vulnerability_fingerprint(second)


def test_source_and_nuclei_fingerprints_are_stable():
    source_finding = {
        "account_id": 1000000,
        "repo_id": "repo-1",
        "file_path": "app/routes.py",
        "line_number": 12,
        "finding_type": "ENDPOINT_DISCOVERED",
        "title": "Endpoint: /users",
        "endpoint_id": "ep-1",
    }
    nuclei_findings = [
        {
            "template-id": "api-exposure",
            "name": "API Exposure",
            "severity": "high",
            "matched-at": "https://api.example.com/users",
        },
        {
            "template-id": "api-exposure",
            "name": "API Exposure",
            "severity": "high",
            "matched-at": "https://api.example.com/users",
        },
    ]

    assert source_finding_fingerprint(source_finding)
    unique, duplicates = collapse_by_fingerprint(
        nuclei_findings,
        lambda item: nuclei_fingerprint(item, target="https://api.example.com", account_id=1000000),
    )
    assert len(unique) == 1
    assert len(duplicates) == 1


def test_vulnerability_fingerprint_prefers_source_fingerprint_identity():
    first = {
        "account_id": 1000000,
        "template_id": "zap-10020",
        "url": "https://api.example.com/admin",
        "method": "GET",
        "type": "ZAP:10020",
        "evidence": {
            "engine": "zap",
            "source_fingerprint": "stable-source",
            "alert": {"evidence": "first volatile proof"},
            "instance": {"attack": "<script>one</script>"},
        },
    }
    second = {
        **first,
        "evidence": {
            "engine": "zap",
            "source_fingerprint": "stable-source",
            "alert": {"evidence": "second volatile proof"},
            "instance": {"attack": "<script>two</script>"},
        },
    }

    assert vulnerability_fingerprint(first) == vulnerability_fingerprint(second)


def test_zap_fingerprint_ignores_volatile_proof_text():
    alert = {
        "pluginid": "10020",
        "alert": "X-Frame-Options Header Not Set",
    }
    first_instance = {
        "uri": "https://api.example.com/admin?token=raw-token",
        "method": "GET",
        "param": "X-Frame-Options",
        "evidence": "first volatile proof",
    }
    second_instance = {
        **first_instance,
        "evidence": "second volatile proof",
        "attack": "<script>changed()</script>",
    }

    assert zap_fingerprint(
        alert,
        first_instance,
        target="https://api.example.com",
        account_id=1000000,
        site_url="https://api.example.com",
    ) == zap_fingerprint(
        alert,
        second_instance,
        target="https://api.example.com",
        account_id=1000000,
        site_url="https://api.example.com",
    )
