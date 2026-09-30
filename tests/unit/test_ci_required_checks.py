from pathlib import Path


def test_ci_required_checks_maps_all_shared_contract_sections():
    root = Path(__file__).resolve().parents[2]
    mapping = (root / "docs" / "CI_REQUIRED_CHECKS.md").read_text(encoding="utf-8")
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    for section in ("§1 Scan status", "§2 Engine outcome", "§3 Finding confirmation", "§4 Evidence", "§5 Artifact ownership", "§6 Cancellation"):
        assert section in mapping
    for job in ("backend-unit:", "backend-integration:", "backend-security:", "backend-ci-gates:", "dependency-secret-scan:"):
        assert job in workflow
    assert "Validate SARIF structure" in workflow
    assert "python -m pip_audit" in workflow
    assert "python -m pip audit" not in workflow
    assert "gitleaks" in workflow
