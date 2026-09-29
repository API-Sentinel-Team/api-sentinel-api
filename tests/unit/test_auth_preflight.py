from types import SimpleNamespace

import pytest

from server.modules.pentest.auth_preflight import (
    ActiveScanAuthError,
    active_scan_auth_required,
    auth_profile_has_runtime_material,
    _validate_profile_auth_readiness,
)


def test_active_scan_auth_is_required_by_default(monkeypatch):
    monkeypatch.setattr("server.modules.pentest.auth_preflight.settings.DEBUG", True)
    monkeypatch.setattr(
        "server.modules.pentest.auth_preflight.settings.PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS",
        True,
    )

    assert active_scan_auth_required() is True


def test_active_scan_auth_can_be_disabled_for_explicit_dev_opt_out(monkeypatch):
    monkeypatch.setattr("server.modules.pentest.auth_preflight.settings.DEBUG", True)
    monkeypatch.setattr(
        "server.modules.pentest.auth_preflight.settings.PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS",
        False,
    )

    assert active_scan_auth_required() is False


def test_active_scan_auth_is_required_when_not_debug_even_if_setting_is_disabled(monkeypatch):
    monkeypatch.setattr("server.modules.pentest.auth_preflight.settings.DEBUG", False)
    monkeypatch.setattr(
        "server.modules.pentest.auth_preflight.settings.PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS",
        False,
    )

    assert active_scan_auth_required() is True


def test_profile_auth_readiness_requires_auth_profile_by_default(monkeypatch):
    monkeypatch.setattr("server.modules.pentest.auth_preflight.settings.DEBUG", True)
    monkeypatch.setattr(
        "server.modules.pentest.auth_preflight.settings.PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS",
        True,
    )

    with pytest.raises(ActiveScanAuthError) as exc:
        _validate_profile_auth_readiness(SimpleNamespace(auth_profile_id=None), None)

    assert exc.value.reason == "auth_profile_required"
    assert "by default" in str(exc.value)


def test_auth_profile_runtime_material_accepts_static_headers():
    auth_profile = SimpleNamespace(auth_mode="header", token="", header_value="", static_headers={"X-Key": "secret"})

    assert auth_profile_has_runtime_material(auth_profile) is True


@pytest.mark.parametrize("static_headers", [{"X-Key": ""}, {"X-Key": None}, {"X-Key": "   "}])
def test_auth_profile_runtime_material_rejects_empty_static_headers(static_headers):
    auth_profile = SimpleNamespace(auth_mode="header", token="", header_value="", static_headers=static_headers)

    assert auth_profile_has_runtime_material(auth_profile) is False


def test_auth_profile_runtime_material_rejects_empty_cookie_values():
    auth_profile = SimpleNamespace(
        auth_mode="cookie",
        cookies=[{"key": "session", "value": "   "}],
        cookie_name="fallback",
        cookie_value="",
    )

    assert auth_profile_has_runtime_material(auth_profile) is False


def test_auth_profile_runtime_material_rejects_blank_basic_credentials():
    auth_profile = SimpleNamespace(auth_mode="basic", username="api-user", password="   ")

    assert auth_profile_has_runtime_material(auth_profile) is False


@pytest.mark.parametrize("value", ["Bearer ", "bearer\t", "Basic ", "ApiKey "])
def test_auth_profile_runtime_material_rejects_header_scheme_without_credential(value):
    auth_profile = SimpleNamespace(auth_mode="bearer", token=value, header_value="", static_headers={})

    assert auth_profile_has_runtime_material(auth_profile) is False


@pytest.mark.parametrize(
    "static_headers",
    [
        {"Authorization": "Bearer "},
        {"authorization": "Basic "},
        {"X-API-Key": "   "},
    ],
)
def test_auth_profile_runtime_material_rejects_static_auth_headers_without_credentials(static_headers):
    auth_profile = SimpleNamespace(auth_mode="header", token="", header_value="", static_headers=static_headers)

    assert auth_profile_has_runtime_material(auth_profile) is False


def test_auth_profile_runtime_material_rejects_dynamic_bearer_without_login_material():
    auth_profile = SimpleNamespace(
        auth_mode="dynamic_bearer",
        login_url="https://api.example.com/auth/token",
        token_json_path="/access_token",
        username=" ",
        password="",
        login_payload={},
        login_headers={},
    )

    assert auth_profile_has_runtime_material(auth_profile) is False


def test_auth_profile_runtime_material_accepts_oauth_client_credentials_material():
    auth_profile = SimpleNamespace(
        auth_mode="oauth",
        login_url="https://api.example.com/oauth/token",
        token_json_path="/access_token",
        login_payload={"client_id": "client-1", "client_secret": "secret-1"},
        login_headers={},
        username="",
        password="",
        token="",
        header_value="",
        static_headers={},
    )

    assert auth_profile_has_runtime_material(auth_profile) is True
