from server.modules.utils.redactor import Redactor


def test_redact_headers_masks_sensitive():
    headers = {
        "Authorization": "Bearer secret-token",
        "Content-Type": "application/json",
        "Cookie": "session=abc123; foo=bar",
    }
    redacted = Redactor.redact_headers(headers)
    assert redacted["Authorization"].startswith("Bearer ")
    assert Redactor.REDACT_VALUE in redacted["Authorization"]
    assert Redactor.REDACT_VALUE in redacted["Cookie"]
    assert redacted["Content-Type"] == "application/json"


def test_redact_headers_masks_known_auth_header_names():
    headers = {
        "X-Auth-Token": "raw-auth-token",
        "X-Access-Token": "raw-access-token",
        "API-Key": "raw-api-key",
        "PRIVATE-TOKEN": "raw-private-token",
        "X-Trace": "trace-id",
    }

    redacted = Redactor.redact_headers(headers)

    assert redacted["X-Auth-Token"] == Redactor.REDACT_VALUE
    assert redacted["X-Access-Token"] == Redactor.REDACT_VALUE
    assert redacted["API-Key"] == Redactor.REDACT_VALUE
    assert redacted["PRIVATE-TOKEN"] == Redactor.REDACT_VALUE
    assert redacted["X-Trace"] == "trace-id"


def test_redact_json_masks_sensitive_fields():
    payload = {"password": "p@ss", "nested": {"api_key": "secret"}, "ok": "value"}
    redacted = Redactor.redact_json(payload)
    assert redacted["password"] == Redactor.REDACT_VALUE
    assert redacted["nested"]["api_key"] == Redactor.REDACT_VALUE
    assert redacted["ok"] == "value"


def test_redact_http_message_masks_evidence_surfaces():
    message = {
        "url": "https://api.example.com/users?token=abc&safe=1",
        "headers": {"Authorization": "Bearer secret-token"},
        "body": '{"password":"secret","ok":"value"}',
    }
    redacted = Redactor.redact_http_message(message)
    assert redacted["url"] == "https://api.example.com/users?token=****&safe=****"
    assert redacted["headers"]["Authorization"] == "Bearer ****"
    assert "secret" not in redacted["body"]
    assert "value" in redacted["body"]


def test_redact_text_masks_inline_auth_values():
    redacted = Redactor.redact_text("Authorization: Bearer abc123 token=raw")
    assert "abc123" not in redacted
    assert "raw" not in redacted
    assert "Bearer ****" in redacted


def test_redact_text_masks_query_values_in_embedded_urls():
    redacted = Redactor.redact_text(
        "Failure at https://api.example.com/search?session=raw-session&debug=true)."
    )
    assert "raw-session" not in redacted
    assert "debug=true" not in redacted
    assert redacted == "Failure at https://api.example.com/search?session=****&debug=****)."


def test_redact_text_masks_query_values_in_embedded_paths():
    redacted = Redactor.redact_text("Case name: GET /admin/users?session=raw-session")
    assert "raw-session" not in redacted
    assert redacted == "Case name: GET /admin/users?session=****"


def test_redact_scan_result_preserves_structured_policy_evidence():
    result = {
        "error": "auth_profile_scope_blocked: Authorization: Bearer raw-token token=raw-token",
        "evidence": "target_guard checked https://api.example.com/search?token=raw-token",
        "auth_profile_scope_policy": {
            "policy": "auth_profile_scope_guard",
            "blocked": True,
            "url": "https://api.example.com/search?token=raw-token",
            "reason": "Authorization: Bearer raw-token token=raw-token",
            "auth_profile_id": "auth-profile-1",
            "scope_domain_count": 1,
        },
        "results": [
            {
                "error": "Authorization: Bearer raw-token token=raw-token",
                "auth_profile_scope_policy": {
                    "policy": "auth_profile_scope_guard",
                    "blocked": True,
                    "url": "https://api.example.com/search?token=raw-token",
                    "reason": "Authorization: Bearer raw-token token=raw-token",
                    "auth_profile_id": "auth-profile-1",
                    "scope_domain_count": 1,
                },
            }
        ],
    }

    redacted = Redactor.redact_scan_result(result)

    assert "raw-token" not in str(redacted)
    assert redacted["error"] == "auth_profile_scope_blocked: Authorization: Bearer **** token=****"
    assert redacted["auth_profile_scope_policy"]["url"] == "https://api.example.com/search?token=****"
    assert redacted["auth_profile_scope_policy"]["reason"] == "Authorization: Bearer **** token=****"
    assert redacted["auth_profile_scope_policy"]["auth_profile_id"] == "auth-profile-1"
    assert redacted["results"][0]["auth_profile_scope_policy"]["url"] == "https://api.example.com/search?token=****"
    assert redacted["results"][0]["auth_profile_scope_policy"]["reason"] == "Authorization: Bearer **** token=****"
