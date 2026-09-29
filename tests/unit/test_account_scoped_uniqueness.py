import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from server.models.core import AgenticSession, BlockedIP, ThreatActor


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("model_cls", "field_name", "value"),
    [
        (ThreatActor, "source_ip", "198.51.100.10"),
        (AgenticSession, "session_identifier", "shared-session"),
        (BlockedIP, "ip", "203.0.113.4"),
    ],
)
async def test_account_scoped_unique_values_allow_same_value_across_accounts(
    db_session,
    model_cls,
    field_name,
    value,
):
    first = model_cls(id=str(uuid.uuid4()), account_id=1000000, **{field_name: value})
    second = model_cls(id=str(uuid.uuid4()), account_id=2000000, **{field_name: value})
    db_session.add_all([first, second])
    await db_session.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("model_cls", "field_name", "value"),
    [
        (ThreatActor, "source_ip", "198.51.100.20"),
        (AgenticSession, "session_identifier", "same-account-session"),
        (BlockedIP, "ip", "203.0.113.9"),
    ],
)
async def test_account_scoped_unique_values_reject_duplicates_within_same_account(
    db_session,
    model_cls,
    field_name,
    value,
):
    first = model_cls(id=str(uuid.uuid4()), account_id=1000000, **{field_name: value})
    second = model_cls(id=str(uuid.uuid4()), account_id=1000000, **{field_name: value})
    db_session.add(first)
    await db_session.commit()

    db_session.add(second)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()
