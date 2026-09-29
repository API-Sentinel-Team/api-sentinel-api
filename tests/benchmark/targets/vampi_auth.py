"""Provision VAmPI test identities for the agentic benchmark.

VAmPI needs its DB seeded (GET /createdb) and users registered before login
returns a JWT. This helper registers two users and returns them as in-memory
TestAccount objects the agentic multi-identity replay can use. Benchmark-only.
"""
from __future__ import annotations

import httpx

from server.models.core import TestAccount

_USERS = [
    {"username": "bench_alice", "password": "BenchPass123", "email": "bench_alice@example.com", "role": "USER"},
    {"username": "bench_bob", "password": "BenchPass123", "email": "bench_bob@example.com", "role": "USER"},
]


def provision_vampi_identities(base_url: str, *, timeout: float = 10.0) -> list[TestAccount]:
    """Seed VAmPI, register two users, return them as TestAccounts with tokens.

    Idempotent: re-registering an existing user is tolerated; we always re-login
    to obtain fresh tokens. Returns [] if the target is not a working VAmPI.
    """
    base = base_url.rstrip("/")
    accounts: list[TestAccount] = []
    with httpx.Client(timeout=timeout) as client:
        # Seed the DB (no-op if already seeded).
        try:
            client.get(f"{base}/createdb")
        except httpx.HTTPError:
            return []

        for idx, user in enumerate(_USERS, start=1):
            try:
                client.post(
                    f"{base}/users/v1/register",
                    json={"username": user["username"], "password": user["password"], "email": user["email"]},
                )
                login = client.post(
                    f"{base}/users/v1/login",
                    json={"username": user["username"], "password": user["password"]},
                )
                token = login.json().get("auth_token")
            except (httpx.HTTPError, ValueError):
                token = None
            if not token:
                continue
            accounts.append(
                TestAccount(
                    id=idx,
                    account_id=1000000,
                    name=user["username"],
                    role=user["role"],
                    auth_token=token,
                )
            )
    return accounts
