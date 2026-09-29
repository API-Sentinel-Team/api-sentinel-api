import pytest
from server.modules.auth.rbac import get_role_permissions, Permission

def test_admin_has_all_permissions():
    perms = get_role_permissions("ADMIN")
    assert Permission.ENDPOINTS_READ in perms
    assert Permission.ACCOUNTS_MANAGE in perms
    # Check that it's a large set
    assert len(perms) > 20

def test_viewer_restricted_permissions():
    perms = get_role_permissions("VIEWER")
    assert Permission.ENDPOINTS_READ in perms
    assert Permission.ACCOUNTS_MANAGE not in perms
    assert Permission.TESTS_RUN not in perms

def test_role_case_insensitivity():
    assert get_role_permissions("admin") == get_role_permissions("ADMIN")
    assert get_role_permissions("Viewer") == get_role_permissions("VIEWER")
