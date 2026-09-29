"""Provision crAPI test identities for the agentic benchmark.

crAPI signup is email+password then JWT login (POST /identity/api/auth/login).
Unlike VAmPI, crAPI may gate signup behind email/OTP verification, so this
provisioner is best-effort and supports an env-token fallback:

  CRAPI_VICTIM_TOKEN / CRAPI_ATTACKER_TOKEN  — pre-obtained bearer tokens.

Returns two TestAccounts (victim, attacker) with tokens, or [] if neither the
signup flow nor env tokens yield credentials. Benchmark-only.
"""
from __future__ import annotations

import os

import httpx

from server.models.core import TestAccount

_USERS = [
    {"name": "Bench Victim", "email": "bench_victim@example.com", "password": "BenchPass123!", "number": "4156895423"},
    {"name": "Bench Attacker", "email": "bench_attacker@example.com", "password": "BenchPass123!", "number": "4156895424"},
]


def _login(client: httpx.Client, base: str, email: str, password: str) -> str | None:
    try:
        resp = client.post(
            f"{base}/identity/api/auth/login",
            json={"email": email, "password": password},
        )
        if resp.status_code == 200:
            return resp.json().get("token")
    except (httpx.HTTPError, ValueError):
        return None
    return None


def _signup_then_login(client: httpx.Client, base: str, user: dict) -> str | None:
    # Best-effort signup; ignore "already exists" and proceed to login.
    try:
        client.post(
            f"{base}/identity/api/auth/signup",
            json={
                "name": user["name"],
                "email": user["email"],
                "number": user["number"],
                "password": user["password"],
            },
        )
    except httpx.HTTPError:
        pass
    return _login(client, base, user["email"], user["password"])


def provision_crapi_identities(base_url: str, *, timeout: float = 15.0) -> list[TestAccount]:
    """Return [victim, attacker] TestAccounts with bearer tokens, or []."""
    base = base_url.rstrip("/")
    env_tokens = [os.environ.get("CRAPI_VICTIM_TOKEN"), os.environ.get("CRAPI_ATTACKER_TOKEN")]
    accounts: list[TestAccount] = []

    with httpx.Client(timeout=timeout) as client:
        for idx, user in enumerate(_USERS):
            token = env_tokens[idx] if idx < len(env_tokens) and env_tokens[idx] else None
            if not token:
                token = _signup_then_login(client, base, user)
            if not token:
                continue
            accounts.append(
                TestAccount(
                    id=idx + 1,
                    account_id=1000000,
                    name=user["email"],
                    role="USER",
                    auth_token=token,
                )
            )
    return accounts
