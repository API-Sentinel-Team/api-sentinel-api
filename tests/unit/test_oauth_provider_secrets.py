from types import SimpleNamespace

from server.modules.auth.oauth_secrets import OAuthProviderSecretCodec


def test_oauth_provider_secret_codec_encrypts_and_decrypts():
    encrypted = OAuthProviderSecretCodec.encrypt_secret("github-client-secret")

    assert encrypted.startswith(OAuthProviderSecretCodec.PREFIX)
    assert encrypted != "github-client-secret"
    assert OAuthProviderSecretCodec.decrypt_secret(encrypted) == "github-client-secret"


def test_oauth_provider_secret_codec_supports_legacy_plaintext():
    provider = SimpleNamespace(client_secret_enc="legacy-client-secret")

    assert OAuthProviderSecretCodec.client_secret(provider) == "legacy-client-secret"
