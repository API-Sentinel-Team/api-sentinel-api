from types import SimpleNamespace

import pytest

from server.modules.recon.adapters import ReconAdapterRegistry
from server.modules.recon.secrets import ReconSourceSecretCodec


def test_recon_source_secret_codec_encrypts_and_decrypts_nested_config():
    config = {
        "api_key": "shodan-key",
        "query": "ssl.cert.subject.cn:api.example.com",
        "headers": {"Authorization": "Bearer raw-token"},
        "raw_urls": ["https://api.example.com/openapi.json"],
        "limit": 50,
    }

    encrypted = ReconSourceSecretCodec.encrypt_config(config)

    assert encrypted["api_key"].startswith(ReconSourceSecretCodec.PREFIX)
    assert encrypted["query"].startswith(ReconSourceSecretCodec.PREFIX)
    assert encrypted["headers"]["Authorization"].startswith(ReconSourceSecretCodec.PREFIX)
    assert encrypted["raw_urls"][0].startswith(ReconSourceSecretCodec.PREFIX)
    assert encrypted["limit"] == 50
    assert "shodan-key" not in str(encrypted)
    assert "raw-token" not in str(encrypted)
    assert ReconSourceSecretCodec.decrypt_config(encrypted) == config


def test_recon_source_secret_codec_supports_legacy_plaintext_runtime_config():
    source = SimpleNamespace(config={"api_key": "legacy-key", "query": "hostname:api.example.com"})

    assert ReconSourceSecretCodec.runtime_config(source) == source.config
    assert ReconSourceSecretCodec.redacted_config(source)["api_key"] == "****"


@pytest.mark.asyncio
async def test_recon_adapter_uses_decrypted_runtime_config(monkeypatch):
    captured = {}
    registry = ReconAdapterRegistry()

    async def fake_fetch_shodan(cfg):
        captured.update(cfg)
        return [], None

    monkeypatch.setattr(registry, "_fetch_shodan", fake_fetch_shodan)
    source = SimpleNamespace(
        provider="SHODAN",
        config=ReconSourceSecretCodec.encrypt_config(
            {"api_key": "shodan-key", "query": "hostname:api.example.com"}
        ),
    )

    items, error = await registry.fetch_items(source)

    assert items == []
    assert error is None
    assert captured == {"api_key": "shodan-key", "query": "hostname:api.example.com"}
