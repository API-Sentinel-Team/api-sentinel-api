import uuid
import os

import pytest
from sqlalchemy import select

import server.api.routers.source_code as source_code_router
from server.models import core as models
from server.modules.auth.encryption import Encryption
from server.modules.auth.jwt_issuer import JWTIssuer


def _headers_for_role(role: str, account_id: int = 1000000):
    token = JWTIssuer.create_access_token({
        "sub": f"{role.lower()}-user",
        "email": f"{role.lower()}@example.com",
        "account_id": account_id,
        "role": role,
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_create_source_repo_encrypts_token_and_redacts_read_surfaces(client, db_session, auth_headers):
    response = await client.post(
        "/api/source-code/repos",
        headers=auth_headers,
        json={
            "name": "Private API",
            "repo_type": "GITHUB",
            "repo_url": "https://github.com/example/private-api.git",
            "branch": "main",
            "languages": ["python"],
            "access_token": "fake-github-token-for-test-1234567890",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert "ghp_rawprivateapitoken" not in str(body)
    assert body["repo"]["access_token_configured"] is True
    assert body["repo"]["local_path"] is None

    row = (
        await db_session.execute(
            select(models.SourceCodeRepo).where(models.SourceCodeRepo.id == body["id"])
        )
    ).scalar_one()
    assert row.access_token != "fake-github-token-for-test-1234567890"
    assert Encryption.decrypt(row.access_token) == "fake-github-token-for-test-1234567890"

    list_response = await client.get("/api/source-code/repos", headers=auth_headers)
    assert list_response.status_code == 200
    assert "ghp_rawprivateapitoken" not in str(list_response.json())
    repo_payload = next(item for item in list_response.json()["repos"] if item["id"] == row.id)
    assert repo_payload["access_token_configured"] is True
    assert repo_payload["repo_url"] == "https://github.com/example/private-api.git"


@pytest.mark.asyncio
async def test_member_can_read_but_cannot_manage_source_code_repos(client, auth_headers):
    create = await client.post(
        "/api/source-code/repos",
        headers=auth_headers,
        json={
            "name": "Public API",
            "repo_type": "GITHUB",
            "repo_url": "https://github.com/example/public-api.git",
            "branch": "main",
        },
    )
    assert create.status_code == 200
    repo_id = create.json()["id"]

    member_headers = _headers_for_role("MEMBER")
    readable = await client.get("/api/source-code/repos", headers=member_headers)
    assert readable.status_code == 200

    denied_create = await client.post(
        "/api/source-code/repos",
        headers=member_headers,
        json={
            "name": "Denied",
            "repo_type": "GITHUB",
            "repo_url": "https://github.com/example/denied.git",
        },
    )
    denied_scan = await client.post(f"/api/source-code/repos/{repo_id}/scan", headers=member_headers)

    assert denied_create.status_code == 403
    assert denied_scan.status_code == 403


@pytest.mark.asyncio
async def test_create_source_repo_blocks_url_credentials_and_unsafe_destinations(client, auth_headers, monkeypatch):
    credential_response = await client.post(
        "/api/source-code/repos",
        headers=auth_headers,
        json={
            "name": "Credential URL",
            "repo_type": "GITHUB",
            "repo_url": "https://raw-token@github.com/example/private-api.git",
        },
    )
    assert credential_response.status_code == 400
    assert "Credentials must be stored" in credential_response.json()["message"]

    monkeypatch.setattr("server.api.routers.source_code.settings.DEBUG", False)
    monkeypatch.setattr("server.api.routers.source_code.settings.SOURCE_CODE_ALLOW_PRIVATE_REPOS", False)

    unsafe_response = await client.post(
        "/api/source-code/repos",
        headers=auth_headers,
        json={
            "name": "Unsafe URL",
            "repo_type": "GITHUB",
            "repo_url": "https://169.254.169.254/latest/meta-data",
        },
    )
    assert unsafe_response.status_code == 400
    message = unsafe_response.json()["message"]
    assert message["message"] == "Source repository destination blocked"
    assert message["target_guard_policy"]["policy"] == "target_guard"
    assert message["target_guard_policy"]["blocked"] is True
    assert message["target_guard_policy"]["url"] == "https://169.254.169.254/latest/meta-data"
    assert "metadata" in message["target_guard_policy"]["reason"]


@pytest.mark.asyncio
async def test_clone_repo_uses_askpass_without_token_in_process_args(monkeypatch, tmp_path):
    raw_token = "fake-private-clone-token-123"
    captured = {}

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return b"", b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        askpass_path = kwargs["env"]["GIT_ASKPASS"]
        captured["args"] = args
        captured["env"] = kwargs["env"]
        captured["askpass_path"] = askpass_path
        with open(askpass_path, encoding="utf-8") as askpass_file:
            captured["askpass_content"] = askpass_file.read()
        return FakeProcess()

    monkeypatch.setattr(
        "server.api.routers.source_code.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    cloned = await source_code_router._clone_repo(
        "https://github.com/example/private-api.git",
        "main",
        Encryption.encrypt(raw_token),
        str(tmp_path / "clone-target"),
    )

    command_blob = " ".join(str(item) for item in captured["args"])
    assert cloned is True
    assert "https://github.com/example/private-api.git" in captured["args"]
    assert raw_token not in command_blob
    assert "x-access-token" not in command_blob
    assert raw_token not in captured["askpass_content"]
    assert "API_SENTINEL_GIT_TOKEN" in captured["askpass_content"]
    assert captured["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert captured["env"]["API_SENTINEL_GIT_TOKEN"] == raw_token
    assert not os.path.exists(captured["askpass_path"])


@pytest.mark.asyncio
async def test_source_code_findings_are_redacted_on_storage_and_read(client, auth_headers, db_session, tmp_path):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_file = repo_path / "app.py"
    source_file.write_text(
        'password = "super-secret-password"\n',
        encoding="utf-8",
    )
    repo = models.SourceCodeRepo(
        id=str(uuid.uuid4()),
        account_id=1000000,
        name="local-secret-repo",
        repo_type="LOCAL",
        local_path=str(repo_path),
    )
    db_session.add(repo)
    await db_session.commit()

    scan = await client.post(f"/api/source-code/repos/{repo.id}/scan", headers=auth_headers)
    assert scan.status_code == 200

    row = (
        await db_session.execute(
            select(models.SourceCodeFinding).where(models.SourceCodeFinding.repo_id == repo.id)
        )
    ).scalars().first()
    assert row is not None
    assert "super-secret-password" not in str(row.description)
    assert "super-secret-password" not in str(row.code_snippet)

    response = await client.get(f"/api/source-code/findings?repo_id={repo.id}", headers=auth_headers)
    assert response.status_code == 200
    payload = response.json()
    assert "super-secret-password" not in str(payload)
    assert payload["findings"][0]["code_snippet_redacted"] is False
