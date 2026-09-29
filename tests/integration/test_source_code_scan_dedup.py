import uuid

import pytest

from server.models.core import APIEndpoint, SourceCodeRepo


@pytest.mark.asyncio
async def test_source_code_scan_deduplicates_and_links_endpoints(client, auth_headers, db_session, tmp_path):
    endpoint_path = f"/users-{uuid.uuid4().hex[:8]}"
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_file = repo_path / "app.py"
    source_file.write_text(
        '\n'.join(
            [
                f'@router.get("{endpoint_path}")',
                'def list_users():',
                '    password = "super-secret-password"',
                '    return {"ok": True}',
            ]
        ),
        encoding="utf-8",
    )

    endpoint = APIEndpoint(
        account_id=1000000,
        method="GET",
        path=endpoint_path,
        path_pattern=endpoint_path,
        host="api.example.com",
        protocol="https",
    )
    repo = SourceCodeRepo(
        id=str(uuid.uuid4()),
        account_id=1000000,
        name="local-repo",
        repo_type="LOCAL",
        local_path=str(repo_path),
    )
    db_session.add_all([endpoint, repo])
    await db_session.commit()

    first = await client.post(f"/api/source-code/repos/{repo.id}/scan", headers=auth_headers)
    assert first.status_code == 200
    first_payload = first.json()
    assert first_payload["findings_found"] >= 2
    assert first_payload["created_findings"] >= 2
    assert first_payload["deduplicated_findings"] == 0

    second = await client.post(f"/api/source-code/repos/{repo.id}/scan", headers=auth_headers)
    assert second.status_code == 200
    second_payload = second.json()
    assert second_payload["created_findings"] == 0
    assert second_payload["deduplicated_findings"] >= first_payload["created_findings"]

    findings_resp = await client.get(f"/api/source-code/findings?repo_id={repo.id}", headers=auth_headers)
    assert findings_resp.status_code == 200
    findings = findings_resp.json()["findings"]
    endpoint_findings = [finding for finding in findings if finding["finding_type"] == "ENDPOINT_DISCOVERED"]
    assert len(findings) == first_payload["created_findings"]
    assert endpoint_findings
    assert endpoint_findings[0]["endpoint_id"] == endpoint.id
    assert endpoint_findings[0]["fingerprint"]
