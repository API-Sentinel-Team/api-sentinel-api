"""Tests for trusted client IP extraction."""
from unittest.mock import MagicMock

from server.modules.auth.client_ip import get_client_ip


def _req(headers: dict[str, str], host: str = "10.0.0.5") -> MagicMock:
    request = MagicMock()
    request.headers = headers
    request.client = MagicMock()
    request.client.host = host
    return request


def test_prefers_x_real_ip_over_spoofed_xff():
    request = _req({
        "x-real-ip": "203.0.113.9",
        "x-forwarded-for": "1.2.3.4, 203.0.113.9",
    })
    assert get_client_ip(request) == "203.0.113.9"


def test_rejects_invalid_x_real_ip_and_uses_rightmost_xff():
    request = _req({
        "x-real-ip": "not-an-ip",
        "x-forwarded-for": "8.8.8.8, 10.244.0.12",
    })
    assert get_client_ip(request) == "10.244.0.12"


def test_falls_back_to_peer_host():
    request = _req({})
    assert get_client_ip(request) == "10.0.0.5"
