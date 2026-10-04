import pytest
from fastapi import HTTPException

from server.api.routers.auth import _require_signup_enabled


@pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "off", " False "])
def test_signup_can_be_disabled(monkeypatch, value):
    monkeypatch.setenv("SIGNUP_ENABLED", value)
    with pytest.raises(HTTPException) as exc:
        _require_signup_enabled()
    assert exc.value.status_code == 403


@pytest.mark.parametrize("value", [None, "true", "1", "yes", ""])
def test_signup_is_enabled_by_default(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("SIGNUP_ENABLED", raising=False)
    else:
        monkeypatch.setenv("SIGNUP_ENABLED", value)
    _require_signup_enabled()
