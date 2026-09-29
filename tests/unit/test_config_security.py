import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from server.config import Settings


def _production_settings(**overrides):
    payload = {
        "DEBUG": False,
        "API_KEY": "prod-api-key-with-enough-entropy",
        "JWT_SECRET": "prod-jwt-secret-with-at-least-thirty-two-characters",
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "SENSOR_KEY_HASH_PEPPER": "prod-sensor-key-pepper-with-enough-entropy",
        "CICD_GATE_SIGNING_SECRET": "prod-cicd-gate-signing-secret-with-enough-entropy",
        "CORS_ORIGINS_OVERRIDE": "https://app.example.com",
        "PENTEST_TARGET_ALLOWLIST": "api.example.com,*.owned-api.example.com",
        "PENTEST_RESOLVE_TARGET_HOSTS": True,
        "STARTUP_BOOTSTRAP_SCHEMA": False,
        "STARTUP_ENABLE_DEMO_BOOTSTRAP": False,
    }
    payload.update(overrides)
    return Settings(**payload, _env_file=None)


def test_settings_accepts_valid_fernet_encryption_key_in_production():
    settings = _production_settings()

    assert settings.ENCRYPTION_KEY


def test_settings_rejects_invalid_encryption_key_format():
    with pytest.raises(ValidationError, match="ENCRYPTION_KEY"):
        _production_settings(ENCRYPTION_KEY="not-a-valid-fernet-key")


def test_settings_rejects_missing_encryption_key_in_production():
    with pytest.raises(ValidationError, match="ENCRYPTION_KEY must be set"):
        _production_settings(ENCRYPTION_KEY="")


def test_settings_rejects_missing_sensor_key_hash_pepper_in_production():
    with pytest.raises(ValidationError, match="SENSOR_KEY_HASH_PEPPER must be set"):
        _production_settings(SENSOR_KEY_HASH_PEPPER="")


def test_settings_rejects_missing_cicd_gate_signing_secret_in_production():
    with pytest.raises(ValidationError, match="CICD_GATE_SIGNING_SECRET must be set"):
        _production_settings(CICD_GATE_SIGNING_SECRET="")


def test_settings_require_authenticated_active_scans_in_production():
    with pytest.raises(ValidationError, match="PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS"):
        _production_settings(PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS=False)


def test_settings_require_target_guard_in_production():
    with pytest.raises(ValidationError, match="PENTEST_ENFORCE_TARGET_GUARD"):
        _production_settings(PENTEST_ENFORCE_TARGET_GUARD=False)


def test_settings_reject_private_pentest_targets_in_production():
    with pytest.raises(ValidationError, match="PENTEST_ALLOW_PRIVATE_TARGETS"):
        _production_settings(PENTEST_ALLOW_PRIVATE_TARGETS=True)


def test_settings_require_dns_resolution_for_pentest_targets_in_production():
    with pytest.raises(ValidationError, match="PENTEST_RESOLVE_TARGET_HOSTS"):
        _production_settings(PENTEST_RESOLVE_TARGET_HOSTS=False)


def test_settings_require_fail_closed_target_dns_in_production():
    with pytest.raises(ValidationError, match="PENTEST_FAIL_CLOSED_ON_TARGET_DNS_ERROR"):
        _production_settings(PENTEST_FAIL_CLOSED_ON_TARGET_DNS_ERROR=False)


def test_settings_require_owned_target_allowlist_in_production():
    with pytest.raises(ValidationError, match="PENTEST_TARGET_ALLOWLIST must list owned API hosts"):
        _production_settings(PENTEST_TARGET_ALLOWLIST="")


def test_settings_reject_wildcard_target_allowlist_in_production():
    with pytest.raises(ValidationError, match="PENTEST_TARGET_ALLOWLIST must not use a wildcard"):
        _production_settings(PENTEST_TARGET_ALLOWLIST="*")
