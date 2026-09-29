import pytest
from sqlalchemy import select

import server.api.routers.oauth as oauth_router
from server.models import core as models
from server.modules.auth.oauth_secrets import OAuthProviderSecretCodec


@pytest.mark.asyncio
async def test_create_oauth_provider_encrypts_client_secret(client, db_session, auth_headers):
    response = await client.post(
        "/api/oauth/providers",
        headers=auth_headers,
        json={
            "provider": "github",
            "client_id": "github-client-id",
            "client_secret": "github-client-secret",
            "allowed_domains": ["example.com"],
            "scopes": ["read:user"],
        },
    )

    assert response.status_code == 200
    row = (
        await db_session.execute(
            select(models.OAuthProvider).where(models.OAuthProvider.id == response.json()["id"])
        )
    ).scalar_one()

    assert row.client_secret_enc.startswith(OAuthProviderSecretCodec.PREFIX)
    assert row.client_secret_enc != "github-client-secret"
    assert OAuthProviderSecretCodec.client_secret(row) == "github-client-secret"

    listed = await client.get("/api/oauth/providers", headers=auth_headers)
    assert listed.status_code == 200
    assert "github-client-secret" not in str(listed.json())


def test_make_github_oauth_decrypts_runtime_secret():
    provider = models.OAuthProvider(
        account_id=1000000,
        provider="github",
        client_id="github-client-id",
        client_secret_enc=OAuthProviderSecretCodec.encrypt_secret("github-client-secret"),
    )

    oauth = oauth_router._make_github_oauth(provider)

    assert oauth.client_id == "github-client-id"
    assert oauth.client_secret == "github-client-secret"
