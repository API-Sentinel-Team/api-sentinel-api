import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.auth.jwt_issuer import JWTIssuer
from server.modules.recon.secrets import ReconSourceSecretCodec


def _headers_for_role(role: str, account_id: int = 1000000) -> dict[str, str]:
    token = JWTIssuer.create_access_token(
        {
            "sub": f"{role.lower()}-{account_id}",
            "email": f"{role.lower()}-{account_id}@example.com",
            "account_id": account_id,
            "role": role,
        }
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_recon_source_api_encrypts_config_at_rest_and_redacts_list_response(
    client,
    db_session,
    auth_headers,
):
    response = await client.post(
        "/api/recon/sources",
        headers=auth_headers,
        json={
            "name": "Shodan Owned APIs",
            "provider": "SHODAN",
            "enabled": True,
            "interval_seconds": 3600,
            "config": {
                "api_key": "shodan-key",
                "query": "ssl.cert.subject.cn:api.example.com",
                "limit": 25,
            },
        },
    )

    assert response.status_code == 200
    source_id = response.json()["id"]
    row = (
        await db_session.execute(
            select(models.ReconSourceConfig).where(models.ReconSourceConfig.id == source_id)
        )
    ).scalar_one()

    assert row.config["api_key"].startswith(ReconSourceSecretCodec.PREFIX)
    assert row.config["query"].startswith(ReconSourceSecretCodec.PREFIX)
    assert "shodan-key" not in str(row.config)
    assert ReconSourceSecretCodec.runtime_config(row)["api_key"] == "shodan-key"

    listed = await client.get("/api/recon/sources", headers=auth_headers)
    assert listed.status_code == 200
    item = next(item for item in listed.json()["items"] if item["id"] == source_id)
    assert item["config"]["api_key"] == "****"
    assert item["config"]["query"] == "ssl.cert.subject.cn:api.example.com"
    assert "shodan-key" not in str(listed.json())


@pytest.mark.asyncio
async def test_recon_source_api_encrypts_updated_config(client, db_session, auth_headers):
    source = models.ReconSourceConfig(
        account_id=1000000,
        name="Censys Owned APIs",
        provider="CENSYS",
        config={"api_id": "legacy-id", "api_secret": "legacy-secret", "query": "services.port:443"},
    )
    db_session.add(source)
    await db_session.commit()

    response = await client.patch(
        f"/api/recon/sources/{source.id}",
        headers=auth_headers,
        json={
            "config": {
                "api_id": "censys-id",
                "api_secret": "censys-secret",
                "query": "services.service_name:HTTP",
            }
        },
    )

    assert response.status_code == 200
    await db_session.refresh(source)
    assert source.config["api_secret"].startswith(ReconSourceSecretCodec.PREFIX)
    assert "censys-secret" not in str(source.config)
    assert ReconSourceSecretCodec.runtime_config(source)["api_secret"] == "censys-secret"


@pytest.mark.asyncio
async def test_recon_source_member_can_read_but_cannot_manage_or_run(client, db_session, auth_headers):
    create_response = await client.post(
        "/api/recon/sources",
        headers=auth_headers,
        json={
            "name": "Scoped External Recon",
            "provider": "SHODAN",
            "enabled": True,
            "interval_seconds": 3600,
            "config": {"api_key": "scoped-shodan-key", "query": "hostname:api.example.com"},
        },
    )
    assert create_response.status_code == 200
    source_id = create_response.json()["id"]
    member_headers = _headers_for_role("MEMBER")

    list_response = await client.get("/api/recon/sources", headers=member_headers)
    assert list_response.status_code == 200
    assert any(item["id"] == source_id for item in list_response.json()["items"])
    assert "scoped-shodan-key" not in str(list_response.json())

    denied_create = await client.post(
        "/api/recon/sources",
        headers=member_headers,
        json={
            "name": "Member Denied Recon",
            "provider": "SHODAN",
            "config": {"api_key": "member-recon-key"},
        },
    )
    denied_update = await client.patch(
        f"/api/recon/sources/{source_id}",
        headers=member_headers,
        json={"config": {"api_key": "member-updated-key"}},
    )
    denied_run = await client.post(f"/api/recon/sources/{source_id}/run", headers=member_headers)
    denied_delete = await client.delete(f"/api/recon/sources/{source_id}", headers=member_headers)

    assert denied_create.status_code == 403
    assert denied_update.status_code == 403
    assert denied_run.status_code == 403
    assert denied_delete.status_code == 403
