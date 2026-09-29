from types import SimpleNamespace

from server.modules.integrations.secrets import IntegrationSecretCodec


def test_integration_secret_codec_encrypts_nested_config_values():
    config = {
        "webhook_url": "https://hooks.example.com/raw-secret",
        "headers": {"x-api-key": "raw-api-key"},
        "routing": ["pager-duty-key"],
        "enabled": True,
        "retries": 3,
        "empty": "",
    }

    encrypted = IntegrationSecretCodec.encrypt_config(config)

    assert encrypted["webhook_url"].startswith(IntegrationSecretCodec.PREFIX)
    assert encrypted["headers"]["x-api-key"].startswith(IntegrationSecretCodec.PREFIX)
    assert encrypted["routing"][0].startswith(IntegrationSecretCodec.PREFIX)
    assert encrypted["enabled"] is True
    assert encrypted["retries"] == 3
    assert encrypted["empty"] == ""
    assert "raw-secret" not in str(encrypted)
    assert "raw-api-key" not in str(encrypted)

    assert IntegrationSecretCodec.decrypt_config(encrypted) == config


def test_integration_secret_codec_supports_legacy_plaintext_runtime_config():
    integration = SimpleNamespace(
        config={
            "base_url": "https://jira.example.com",
            "api_token": "legacy-token",
            "project_key": "API",
        }
    )

    assert IntegrationSecretCodec.runtime_config(integration) == integration.config
