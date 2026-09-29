from server.models.core import AuthProfile
from server.modules.pentest.auth_profile_secrets import AuthProfileSecretCodec


def test_auth_profile_secret_codec_encrypts_and_decrypts_runtime_view():
    encrypted_payload = AuthProfileSecretCodec.encrypt_payload(
        {
            "name": "runtime auth",
            "auth_mode": "bearer",
            "token": "raw-token",
            "header_value": "raw-header",
            "username": "raw-user",
            "password": "raw-password",
            "cookie_value": "raw-cookie",
            "cookies": [{"key": "session", "value": "raw-session"}],
            "static_headers": {"X-API-Key": "raw-api-key"},
            "login_payload": {"username": "raw-user", "password": "raw-password"},
            "login_headers": {"X-Login-Key": "raw-login-key"},
        }
    )

    assert encrypted_payload["token"].startswith(AuthProfileSecretCodec.PREFIX)
    assert encrypted_payload["token"] != "raw-token"
    assert encrypted_payload["static_headers"]["X-API-Key"].startswith(AuthProfileSecretCodec.PREFIX)
    assert encrypted_payload["cookies"][0]["key"] == "session"
    assert encrypted_payload["cookies"][0]["value"].startswith(AuthProfileSecretCodec.PREFIX)

    profile = AuthProfile(account_id=1000000, **encrypted_payload)
    runtime = AuthProfileSecretCodec.decrypted_view(profile)

    assert runtime.token == "raw-token"
    assert runtime.header_value == "raw-header"
    assert runtime.username == "raw-user"
    assert runtime.password == "raw-password"
    assert runtime.cookie_value == "raw-cookie"
    assert runtime.cookies == [{"key": "session", "value": "raw-session"}]
    assert runtime.static_headers == {"X-API-Key": "raw-api-key"}
    assert runtime.login_payload == {"username": "raw-user", "password": "raw-password"}
    assert runtime.login_headers == {"X-Login-Key": "raw-login-key"}


def test_auth_profile_secret_codec_preserves_legacy_plaintext_values():
    profile = AuthProfile(
        account_id=1000000,
        name="legacy auth",
        auth_mode="bearer",
        token="legacy-token",
    )

    runtime = AuthProfileSecretCodec.decrypted_view(profile)

    assert runtime.token == "legacy-token"


def test_auth_profile_secret_codec_encrypts_non_string_json_secret_values():
    encrypted_payload = AuthProfileSecretCodec.encrypt_payload(
        {
            "name": "numeric dynamic auth",
            "auth_mode": "dynamic_bearer",
            "login_payload": {
                "client_id": 123456,
                "enabled": True,
                "nested": {"pin": 987654},
            },
            "static_headers": {"X-Numeric-Key": 424242},
            "login_headers": {"X-Login-Enabled": False},
        }
    )

    assert encrypted_payload["login_payload"]["client_id"].startswith(AuthProfileSecretCodec.PREFIX)
    assert encrypted_payload["login_payload"]["nested"]["pin"].startswith(AuthProfileSecretCodec.PREFIX)
    assert encrypted_payload["static_headers"]["X-Numeric-Key"].startswith(AuthProfileSecretCodec.PREFIX)
    assert encrypted_payload["login_headers"]["X-Login-Enabled"].startswith(AuthProfileSecretCodec.PREFIX)
    assert "123456" not in str(encrypted_payload)
    assert "987654" not in str(encrypted_payload)
    assert "424242" not in str(encrypted_payload)

    profile = AuthProfile(account_id=1000000, **encrypted_payload)
    runtime = AuthProfileSecretCodec.decrypted_view(profile)

    assert runtime.login_payload == {
        "client_id": 123456,
        "enabled": True,
        "nested": {"pin": 987654},
    }
    assert runtime.static_headers == {"X-Numeric-Key": 424242}
    assert runtime.login_headers == {"X-Login-Enabled": False}
