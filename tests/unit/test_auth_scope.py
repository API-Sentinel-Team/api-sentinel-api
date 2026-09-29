from types import SimpleNamespace

import pytest

from server.modules.pentest.auth_scope import (
    AuthScopeError,
    auth_scope_policy_for_error,
    blocked_auth_profile_targets,
    validate_auth_profile_scope,
)


def test_auth_profile_without_material_allows_missing_scope():
    validate_auth_profile_scope(
        SimpleNamespace(id="auth-1", scope_domains=[]),
        "https://api.example.com/v1/users",
    )


def test_auth_profile_with_secret_material_requires_explicit_scope():
    with pytest.raises(AuthScopeError, match="auth_profile_scope_required"):
        validate_auth_profile_scope(
            SimpleNamespace(
                id="auth-1",
                auth_mode="bearer",
                token="secret-token",
                header_value=None,
                static_headers={},
                scope_domains=[],
            ),
            "https://api.example.com/v1/users",
        )


def test_auth_profile_scope_supports_exact_url_port_and_wildcard_hosts():
    validate_auth_profile_scope(
        SimpleNamespace(id="auth-1", scope_domains=["https://api.example.com:8443"]),
        "https://api.example.com:8443/v1/users",
    )
    validate_auth_profile_scope(
        SimpleNamespace(id="auth-2", scope_domains=["*.example.com"]),
        "https://tenant.example.com/v1/users",
    )


def test_auth_profile_scope_rejects_global_wildcard_for_secret_material():
    with pytest.raises(AuthScopeError, match="auth_profile_scope_required"):
        validate_auth_profile_scope(
            SimpleNamespace(
                id="auth-1",
                auth_mode="bearer",
                token="secret-token",
                header_value=None,
                static_headers={},
                scope_domains=["*"],
            ),
            "https://api.example.com/v1/users",
        )


def test_auth_profile_scope_blocks_unapproved_target_host():
    with pytest.raises(AuthScopeError, match="auth_profile_scope_blocked"):
        validate_auth_profile_scope(
            SimpleNamespace(id="auth-1", scope_domains=["api.example.com"]),
            "https://evil.example.net/v1/users?token=raw-token",
        )


def test_blocked_auth_profile_targets_redacts_endpoint_urls():
    blocked = blocked_auth_profile_targets(
        SimpleNamespace(id="auth-1", scope_domains=["api.example.com"]),
        [
            {
                "id": "endpoint-1",
                "protocol": "https",
                "host": "evil.example.net",
                "path": "/v1/users?token=raw-token",
            }
        ],
    )

    assert blocked[0]["endpoint_id"] == "endpoint-1"
    assert blocked[0]["reason"].startswith("auth_profile_scope_blocked:")
    assert "raw-token" not in blocked[0]["url"]
    assert "raw-token" not in blocked[0]["reason"]


def test_blocked_auth_profile_targets_include_redacted_scope_policy():
    blocked = blocked_auth_profile_targets(
        SimpleNamespace(id="auth-1", scope_domains=["api.example.com"]),
        [
            {
                "id": "endpoint-1",
                "protocol": "https",
                "host": "evil.example.net",
                "path": "/v1/users?token=raw-token",
            }
        ],
    )

    policy = blocked[0]["auth_profile_scope_policy"]
    assert policy["policy"] == "auth_profile_scope_guard"
    assert policy["blocked"] is True
    assert policy["url"] == "https://evil.example.net/v1/users?token=****"
    assert policy["base_url"] == "https://evil.example.net/v1/users?token=****"
    assert policy["auth_profile_id"] == "auth-1"
    assert policy["scope_domains_configured"] is True
    assert policy["scope_domain_count"] == 1
    assert "raw-token" not in str(policy)


def test_auth_scope_policy_for_error_redacts_reason_and_counts_scopes():
    policy = auth_scope_policy_for_error(
        AuthScopeError("auth_profile_scope_blocked: token=raw-token"),
        auth_profile=SimpleNamespace(id="auth-2", scope_domains=["api.example.com", "*.example.net"]),
        target_url="https://evil.example.net/orders?token=raw-token",
        base_url="https://api.example.com/orders?token=raw-token",
    )

    assert policy == {
        "policy": "auth_profile_scope_guard",
        "blocked": True,
        "url": "https://evil.example.net/orders?token=****",
        "base_url": "https://api.example.com/orders?token=****",
        "reason": "auth_profile_scope_blocked: token=****",
        "auth_profile_id": "auth-2",
        "scope_domains_configured": True,
        "scope_domain_count": 2,
    }
