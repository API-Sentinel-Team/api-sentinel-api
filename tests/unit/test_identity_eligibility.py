"""COV-1: identity selection excludes expired, disabled, and credential-less accounts."""

import datetime
from types import SimpleNamespace

from server.modules.identity.eligibility import (
    account_is_eligible,
    eligibility_summary,
    eligible_test_accounts,
)


def _account(**overrides):
    base = dict(
        status="ACTIVE",
        expired_at=None,
        role="MEMBER",
        auth_headers={"Authorization": "Bearer live-token"},
        auth_token=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_active_credential_bearing_account_is_eligible():
    assert account_is_eligible(_account()) is True


def test_disabled_and_inactive_statuses_are_excluded():
    for status in ("EXPIRED", "DISABLED", "REVOKED", "INACTIVE"):
        assert account_is_eligible(_account(status=status)) is False, status


def test_expired_at_timestamp_excludes_account():
    expired = _account(expired_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
    future = _account(expired_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
    naive_past = _account(expired_at=datetime.datetime.now() - datetime.timedelta(days=1))
    assert account_is_eligible(expired) is False
    assert account_is_eligible(future) is True
    assert account_is_eligible(naive_past) is False


def test_credential_less_account_is_excluded_unless_anonymous_baseline():
    assert account_is_eligible(_account(auth_headers=None)) is False
    assert account_is_eligible(_account(auth_headers={})) is False
    # Anonymous roles are the deliberate unauthenticated baseline for replay.
    assert account_is_eligible(_account(role="ANONYMOUS", auth_headers=None)) is True


def test_eligible_test_accounts_filters_in_order():
    accounts = [
        _account(name="keeper"),
        _account(name="disabled", status="DISABLED"),
        _account(name="expired", expired_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)),
        _account(name="no-creds", auth_headers=None),
    ]
    eligible = eligible_test_accounts(accounts)
    assert [a.name for a in eligible] == ["keeper"]


def test_eligibility_summary_counts_each_exclusion_reason():
    accounts = [
        _account(name="ok"),
        _account(name="anon", role="ANONYMOUS", auth_headers=None),
        _account(name="expired", expired_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)),
        _account(name="disabled", status="DISABLED"),
        _account(name="no-creds", auth_headers=None),
    ]
    summary = eligibility_summary(accounts)
    assert summary == {
        "total": 5,
        "eligible": 2,
        "expired_excluded": 1,
        "disabled_excluded": 1,
        "credential_less_excluded": 1,
    }


def test_eligibility_summary_empty_is_zeroed():
    assert eligibility_summary([]) == {
        "total": 0,
        "eligible": 0,
        "expired_excluded": 0,
        "disabled_excluded": 0,
        "credential_less_excluded": 0,
    }
