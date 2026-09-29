import pytest
from sqlalchemy import select

from server.models import core as models
from server.modules.identity.auth_rotator import AuthRotator
from server.modules.identity.authorization_replay import auth_headers_for_account, infer_victim_account
from server.modules.identity.roles_context import RolesContextBuilder
from server.modules.identity.test_account_secrets import TestAccountSecretCodec


def test_test_account_secret_codec_encrypts_and_decrypts_runtime_values():
    encrypted = TestAccountSecretCodec.encrypt_payload(
        {
            "auth_headers": {"Authorization": "Bearer raw-token", "X-API-Key": "raw-api-key"},
            "auth_token": "legacy-token",
        }
    )

    assert encrypted["auth_headers"]["Authorization"].startswith(TestAccountSecretCodec.PREFIX)
    assert encrypted["auth_headers"]["Authorization"] != "Bearer raw-token"
    assert encrypted["auth_token"].startswith(TestAccountSecretCodec.PREFIX)

    account = models.TestAccount(
        account_id=1000000,
        role="MEMBER",
        **encrypted,
    )

    assert TestAccountSecretCodec.auth_headers(account) == {
        "Authorization": "Bearer raw-token",
        "X-API-Key": "raw-api-key",
    }
    assert TestAccountSecretCodec.auth_token(account) == "legacy-token"
    assert auth_headers_for_account(account)["Authorization"] == "Bearer raw-token"


def test_test_account_secret_codec_supports_legacy_plaintext_rows():
    account = models.TestAccount(
        account_id=1000000,
        role="ATTACKER",
        auth_headers={"Authorization": "Bearer legacy-header"},
        auth_token="legacy-token",
    )

    assert TestAccountSecretCodec.auth_headers(account) == {"Authorization": "Bearer legacy-header"}
    assert TestAccountSecretCodec.auth_token(account) == "legacy-token"
    assert auth_headers_for_account(account)["Authorization"] == "Bearer legacy-header"


def test_test_account_secret_codec_encrypts_non_string_header_values():
    encrypted = TestAccountSecretCodec.encrypt_payload(
        {
            "auth_headers": {"X-Tenant-Key": 424242, "X-Enabled-Token": True},
            "auth_token": 123456,
        }
    )

    assert encrypted["auth_headers"]["X-Tenant-Key"].startswith(TestAccountSecretCodec.PREFIX)
    assert encrypted["auth_headers"]["X-Enabled-Token"].startswith(TestAccountSecretCodec.PREFIX)
    assert encrypted["auth_token"].startswith(TestAccountSecretCodec.PREFIX)
    assert "424242" not in str(encrypted)
    assert "123456" not in str(encrypted)

    account = models.TestAccount(
        account_id=1000000,
        role="MEMBER",
        **encrypted,
    )

    assert TestAccountSecretCodec.auth_headers(account) == {
        "X-Tenant-Key": "424242",
        "X-Enabled-Token": "True",
    }
    assert TestAccountSecretCodec.auth_token(account) == "123456"


def test_roles_context_builder_decrypts_encrypted_test_account_headers():
    account = models.TestAccount(
        account_id=1000000,
        role="ADMIN",
        **TestAccountSecretCodec.encrypt_payload(
            {"auth_headers": {"Authorization": "Bearer admin-token"}, "auth_token": None}
        ),
    )

    context = RolesContextBuilder().build([account])

    assert context == {"ADMIN": "Bearer admin-token"}


def test_roles_context_builder_uses_canonical_role_keys_for_secret_shaped_roles():
    member = models.TestAccount(
        account_id=1000000,
        role="MEMBER token=raw-member-role-token",
        auth_headers={"Authorization": "Bearer member-token"},
    )
    admin = {
        "role": "ADMIN cookie=raw-admin-role-cookie",
        "auth_headers": {"Authorization": "Bearer admin-token"},
    }
    builder = RolesContextBuilder()

    context = builder.build([member, admin])
    flattened = builder.flatten(context)

    assert context == {
        "MEMBER": "Bearer member-token",
        "ADMIN": "Bearer admin-token",
    }
    assert flattened == {
        "roles_access_context.MEMBER": "Bearer member-token",
        "roles_access_context.ADMIN": "Bearer admin-token",
    }
    assert builder.get_attacker_token(context, "MEMBER token=another-secret") == "Bearer member-token"
    assert builder.get_victim_token(context, "ADMIN cookie=another-secret") == "Bearer admin-token"
    assert "raw-member-role-token" not in str(context)
    assert "raw-admin-role-cookie" not in str(flattened)
    assert all("TOKEN" not in key and "COOKIE" not in key for key in flattened)


def test_infer_victim_account_matches_encrypted_auth_token_fallback():
    victim = models.TestAccount(
        id="victim",
        account_id=1000000,
        role="ADMIN",
        **TestAccountSecretCodec.encrypt_payload({"auth_headers": {}, "auth_token": "victim-token"}),
    )

    matched = infer_victim_account(
        [victim],
        {"headers": {"Authorization": "Bearer victim-token"}},
    )

    assert matched is victim


@pytest.mark.asyncio
async def test_auth_rotator_decrypts_test_account_headers(db_session):
    account = models.TestAccount(
        account_id=1000000,
        role="ATTACKER",
        **TestAccountSecretCodec.encrypt_payload(
            {"auth_headers": {"Authorization": "Bearer attacker-token"}, "auth_token": None}
        ),
    )
    db_session.add(account)
    await db_session.flush()

    headers = await AuthRotator().get_auth_headers(role="ATTACKER", account_id=1000000, db=db_session)

    assert headers == {"Authorization": "Bearer attacker-token"}


@pytest.mark.asyncio
async def test_auth_rotator_uses_canonical_role_key_for_secret_shaped_roles(db_session):
    account_id = 1000123
    account = models.TestAccount(
        account_id=account_id,
        role="ATTACKER token=raw-role-token",
        **TestAccountSecretCodec.encrypt_payload(
            {"auth_headers": {"Authorization": "Bearer attacker-runtime-token"}, "auth_token": None}
        ),
    )
    db_session.add(account)
    await db_session.flush()

    headers = await AuthRotator().get_auth_headers(
        role="ATTACKER token=another-role-token",
        account_id=account_id,
        db=db_session,
    )

    assert headers == {"Authorization": "Bearer attacker-runtime-token"}
    assert "raw-role-token" not in str(headers)
    assert "another-role-token" not in str(headers)


@pytest.mark.asyncio
async def test_auth_rotator_falls_back_to_encrypted_auth_token(db_session):
    account_id = 1000124
    account = models.TestAccount(
        account_id=account_id,
        role="ATTACKER",
        **TestAccountSecretCodec.encrypt_payload(
            {"auth_headers": {}, "auth_token": "legacy-runtime-token"}
        ),
    )
    db_session.add(account)
    await db_session.flush()

    headers = await AuthRotator().get_auth_headers(role="ATTACKER", account_id=account_id, db=db_session)

    assert headers == {"Authorization": "Bearer legacy-runtime-token"}


@pytest.mark.asyncio
async def test_encrypted_and_plaintext_test_account_rows_deduplicate_by_runtime_headers(db_session):
    encrypted = models.TestAccount(
        account_id=1000000,
        role="ADMIN",
        **TestAccountSecretCodec.encrypt_payload(
            {"auth_headers": {"Authorization": "Bearer same-token"}, "auth_token": None}
        ),
    )
    plaintext = models.TestAccount(
        account_id=1000000,
        role="MEMBER",
        auth_headers={"Authorization": "Bearer same-token"},
    )
    db_session.add_all([encrypted, plaintext])
    await db_session.flush()

    rows = (await db_session.execute(select(models.TestAccount))).scalars().all()
    assert [auth_headers_for_account(row)["Authorization"] for row in rows[-2:]] == [
        "Bearer same-token",
        "Bearer same-token",
    ]
