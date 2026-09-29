from types import SimpleNamespace

import pytest

from server.modules.test_executor.target_guard import (
    TargetGuard,
    TargetGuardError,
    blocked_endpoint_targets,
    endpoint_target_url,
)
from server.modules.pentest.target_policy import normalize_evidence_url, validate_pentest_evidence_url
from server.modules.pentest.target_policy import validated_pentest_evidence_scope


def test_target_guard_allows_same_origin_target():
    guard = TargetGuard(allow_private_targets=False)

    guard.validate_url(
        "https://api.example.com/v1/users?limit=1",
        base_url="https://api.example.com/v1/users",
    )


def test_target_guard_blocks_cross_origin_mutation_without_allowlist():
    guard = TargetGuard(allow_private_targets=False)

    with pytest.raises(TargetGuardError, match="leave the selected endpoint origin"):
        guard.validate_url(
            "https://evil.example.net/admin",
            base_url="https://api.example.com/v1/users",
        )


def test_target_guard_blocks_metadata_and_private_targets_by_default():
    guard = TargetGuard(allow_private_targets=False)

    with pytest.raises(TargetGuardError, match="metadata"):
        guard.validate_url(
            "http://169.254.169.254/latest/meta-data",
            base_url="http://169.254.169.254/latest/meta-data",
        )

    with pytest.raises(TargetGuardError, match="private"):
        guard.validate_url("http://127.0.0.1:9999/api", base_url="http://127.0.0.1:9999/api")


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://2130706433/admin", "private"),
        ("http://0x7f000001/admin", "private"),
        ("http://0xA9FEA9FE/latest/meta-data", "metadata"),
        ("http://0251.0376.0251.0376/latest/meta-data", "metadata"),
    ],
)
def test_target_guard_blocks_obfuscated_private_and_metadata_ipv4_hosts(url, reason):
    guard = TargetGuard(allow_private_targets=False, resolve_hosts=False)

    with pytest.raises(TargetGuardError, match=reason):
        guard.validate_url(url, base_url=url)


@pytest.mark.parametrize(
    "url",
    [
        "http://[::ffff:169.254.169.254]/latest/meta-data",
        "http://[::ffff:a9fe:a9fe]/latest/meta-data",
    ],
)
def test_target_guard_blocks_ipv4_mapped_ipv6_metadata_even_when_private_targets_allowed(url):
    guard = TargetGuard(allow_private_targets=True, resolve_hosts=False)

    with pytest.raises(TargetGuardError, match="metadata"):
        guard.validate_url(url, base_url=url)


@pytest.mark.parametrize(
    "url",
    [
        "http://[2002:a9fe:a9fe::]/latest/meta-data",
        "http://[2002:a9fe:aa02::]/latest/meta-data",
    ],
)
def test_target_guard_blocks_6to4_ipv6_metadata_even_when_private_targets_allowed(url):
    guard = TargetGuard(allow_private_targets=True, resolve_hosts=False)

    with pytest.raises(TargetGuardError, match="metadata"):
        guard.validate_url(url, base_url=url)


def test_target_guard_blocks_resolved_6to4_metadata_even_when_private_targets_allowed():
    guard = TargetGuard(
        allow_private_targets=True,
        resolve_hosts=True,
        resolver=lambda _host, _port: ["2002:a9fe:a9fe::"],
    )

    with pytest.raises(TargetGuardError, match="metadata"):
        guard.validate_url(
            "https://api.example.com/v1/users",
            base_url="https://api.example.com/v1/users",
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://[2001:0000:4136:e378:8000:63bf:5601:5601]/latest/meta-data",
        "http://[2001:0000:4136:e378:8000:63bf:5601:55fd]/latest/meta-data",
    ],
)
def test_target_guard_blocks_teredo_ipv6_metadata_even_when_private_targets_allowed(url):
    guard = TargetGuard(allow_private_targets=True, resolve_hosts=False)

    with pytest.raises(TargetGuardError, match="metadata"):
        guard.validate_url(url, base_url=url)


def test_target_guard_blocks_resolved_teredo_metadata_even_when_private_targets_allowed():
    guard = TargetGuard(
        allow_private_targets=True,
        resolve_hosts=True,
        resolver=lambda _host, _port: ["2001:0000:4136:e378:8000:63bf:5601:5601"],
    )

    with pytest.raises(TargetGuardError, match="metadata"):
        guard.validate_url(
            "https://api.example.com/v1/users",
            base_url="https://api.example.com/v1/users",
        )


def test_target_guard_supports_owned_subdomain_allowlist():
    guard = TargetGuard(allowlist=["*.example.com"], allow_private_targets=False)

    guard.validate_url(
        "https://api.example.com/v1/users",
        base_url="https://different-owned-host.test/api",
    )


def test_target_guard_allowlist_denies_unowned_host():
    guard = TargetGuard(allowlist=["api.example.com"], allow_private_targets=False)

    with pytest.raises(TargetGuardError, match="allowlist"):
        guard.validate_url(
            "https://evil.example.com/admin",
            base_url="https://api.example.com/v1/users",
        )


def test_target_guard_from_settings_does_not_allow_private_when_debug_true():
    settings_obj = SimpleNamespace(
        PENTEST_TARGET_ALLOWLIST="api.example.com",
        PENTEST_ALLOW_PRIVATE_TARGETS=False,
        PENTEST_ENFORCE_TARGET_GUARD=True,
        PENTEST_RESOLVE_TARGET_HOSTS=False,
        PENTEST_FAIL_CLOSED_ON_TARGET_DNS_ERROR=True,
        DEBUG=True,
    )
    guard = TargetGuard.from_settings(settings_obj)

    assert guard.allow_private_targets is False
    with pytest.raises(TargetGuardError, match="private"):
        guard.validate_url("http://127.0.0.1:9999/api", base_url="http://127.0.0.1:9999/api")


def test_target_guard_fails_closed_on_global_wildcard_allowlist():
    guard = TargetGuard(allowlist=["*"], allow_private_targets=False)

    with pytest.raises(TargetGuardError, match="unsafe wildcard"):
        guard.validate_url(
            "https://api.example.com/v1/users",
            base_url="https://different-owned-host.test/api",
        )


def test_target_guard_blocks_hostname_resolving_to_private_ip():
    guard = TargetGuard(
        allow_private_targets=False,
        resolve_hosts=True,
        resolver=lambda _host, _port: ["10.0.0.5"],
    )

    with pytest.raises(TargetGuardError, match="resolved to private"):
        guard.validate_url(
            "https://api.example.com/v1/users",
            base_url="https://api.example.com/v1/users",
        )


def test_target_guard_blocks_resolved_metadata_ip_even_when_private_targets_allowed():
    guard = TargetGuard(
        allow_private_targets=True,
        resolve_hosts=True,
        resolver=lambda _host, _port: ["169.254.169.254"],
    )

    with pytest.raises(TargetGuardError, match="metadata"):
        guard.validate_url(
            "https://api.example.com/v1/users",
            base_url="https://api.example.com/v1/users",
        )


def test_target_guard_fails_closed_on_dns_resolution_error():
    def resolver(_host, _port):
        raise OSError("dns unavailable")

    guard = TargetGuard(
        allow_private_targets=False,
        resolve_hosts=True,
        fail_closed_on_dns_error=True,
        resolver=resolver,
    )

    with pytest.raises(TargetGuardError, match="DNS resolution failed"):
        guard.validate_url(
            "https://api.example.com/v1/users",
            base_url="https://api.example.com/v1/users",
        )


def test_target_guard_fails_closed_when_dns_returns_no_addresses():
    guard = TargetGuard(
        allow_private_targets=False,
        resolve_hosts=True,
        fail_closed_on_dns_error=True,
        resolver=lambda _host, _port: [],
    )

    with pytest.raises(TargetGuardError, match="returned no addresses"):
        guard.validate_url(
            "https://api.example.com/v1/users",
            base_url="https://api.example.com/v1/users",
        )


def test_target_guard_can_fail_open_on_dns_resolution_error_for_legacy_mode():
    def resolver(_host, _port):
        raise OSError("dns unavailable")

    guard = TargetGuard(
        allow_private_targets=False,
        resolve_hosts=True,
        fail_closed_on_dns_error=False,
        resolver=resolver,
    )

    guard.validate_url(
        "https://api.example.com/v1/users",
        base_url="https://api.example.com/v1/users",
    )


def test_endpoint_target_helpers_build_and_redact_blocked_urls():
    endpoint = SimpleNamespace(
        id="endpoint-1",
        protocol="https",
        host="api.example.com",
        path="users?token=raw",
    )
    guard = TargetGuard(
        allow_private_targets=False,
        resolve_hosts=True,
        resolver=lambda _host, _port: ["127.0.0.1"],
    )

    assert endpoint_target_url(endpoint) == "https://api.example.com/users?token=raw"

    blocked = blocked_endpoint_targets([endpoint], guard=guard)

    assert blocked[0]["endpoint_id"] == "endpoint-1"
    assert blocked[0]["url"] == "https://api.example.com/users?token=****"
    assert "private" in blocked[0]["reason"]
    assert blocked[0]["target_guard_policy"]["policy"] == "target_guard"
    assert blocked[0]["target_guard_policy"]["blocked"] is True
    assert blocked[0]["target_guard_policy"]["url"] == "https://api.example.com/users?token=****"
    assert "private" in blocked[0]["target_guard_policy"]["reason"]
    assert "raw" not in str(blocked[0]["target_guard_policy"])


def test_target_guard_policy_redacts_url_credentials():
    endpoint = SimpleNamespace(
        id="endpoint-1",
        protocol="https",
        host="user:raw-password@api.example.com",
        path="/users?token=raw-token",
    )
    guard = TargetGuard(allow_private_targets=False)

    blocked = blocked_endpoint_targets([endpoint], guard=guard)

    assert blocked[0]["url"] == "https://****@api.example.com/users?token=****"
    assert blocked[0]["target_guard_policy"]["url"] == "https://****@api.example.com/users?token=****"
    assert "raw-password" not in str(blocked[0])
    assert "raw-token" not in str(blocked[0])


def test_pentest_evidence_scope_normalizes_paths_and_blocks_cross_origin_urls():
    guard = TargetGuard(allow_private_targets=False)

    assert (
        normalize_evidence_url("/v1/users?token=raw", target_url="https://api.example.com")
        == "https://api.example.com/v1/users?token=raw"
    )

    validate_pentest_evidence_url(
        "/v1/users",
        target_url="https://api.example.com",
        guard=guard,
    )
    with pytest.raises(TargetGuardError, match="leave the selected endpoint origin"):
        validate_pentest_evidence_url(
            "https://evil.example.net/v1/users",
            target_url="https://api.example.com",
            guard=guard,
        )


def test_pentest_evidence_scope_blocks_protocol_relative_cross_origin_urls():
    guard = TargetGuard(allow_private_targets=False)

    with pytest.raises(TargetGuardError, match="leave the selected endpoint origin"):
        validate_pentest_evidence_url(
            "//evil.example.net/v1/users?token=raw-token",
            target_url="https://api.example.com",
            guard=guard,
        )


def test_pentest_evidence_scope_returns_redacted_validation_attestation():
    guard = TargetGuard(allow_private_targets=False)

    evidence_url, scope = validated_pentest_evidence_scope(
        "/v1/users?token=raw-token",
        target_url="https://api.example.com/root?session=raw-session",
        guard=guard,
    )

    assert evidence_url == "https://api.example.com/v1/users?token=raw-token"
    assert scope == {
        "validated": True,
        "policy": "target_guard",
        "scope": "same_origin_or_allowlisted",
        "target": "https://api.example.com/root?session=****",
        "evidence_url": "https://api.example.com/v1/users?token=****",
    }
    assert "raw-token" not in str(scope)
    assert "raw-session" not in str(scope)
