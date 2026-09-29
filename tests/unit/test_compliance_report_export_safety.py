import pytest
from fastapi import HTTPException

from server.api.routers import compliance
from server.modules.auth.rbac import Permission
from server.modules.compliance.pdf_renderer import PDFRenderer


def test_compliance_html_export_escapes_markup_and_redacts_secrets():
    report = {
        "framework": "<script>alert(1)</script>",
        "total_open": 1,
        "sections": {
            "<script>alert(1)</script>": [
                {
                    "severity": "<script>alert(1)</script>",
                    "title": "Leaked token=raw-token-123",
                    "endpoint": "GET https://api.example.test/users?access_token=raw-token-123",
                    "evidence": "Authorization: Bearer raw-token-123",
                }
            ]
        },
    }

    html = PDFRenderer().generate_html(report)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "raw-token-123" not in html
    assert "token=****" in html
    assert "access_token=****" in html
    assert "Authorization: Bearer ****" in html


@pytest.mark.asyncio
async def test_compliance_report_permission_helpers_require_existing_permissions():
    read_payload = await compliance.require_compliance_report_read({"role": "VIEWER"})
    assert read_payload["role"] == "VIEWER"

    export_payload = await compliance.require_compliance_report_export({"role": "AUDITOR"})
    assert export_payload["role"] == "AUDITOR"

    with pytest.raises(HTTPException) as exc_info:
        await compliance.require_compliance_report_export({"role": "VIEWER"})

    assert exc_info.value.status_code == 403
    assert Permission.COMPLIANCE_EXPORT in exc_info.value.detail
