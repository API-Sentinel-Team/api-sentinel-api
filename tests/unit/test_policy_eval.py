import pytest
from sqlalchemy import select

from server.models.core import GovernanceRule, APIEndpoint, PolicyViolation
from server.modules.ingestion.processors import _apply_governance_rules


@pytest.mark.asyncio
async def test_apply_governance_rules_creates_violation(db_session):
    rule = GovernanceRule(
        account_id=1000000,
        name="No DELETE",
        rule_type="SECURITY",
        condition={"field": "method", "op": "eq", "value": "DELETE"},
        action="ALERT",
        enabled=True,
    )
    db_session.add(rule)
    endpoint = APIEndpoint(
        account_id=1000000,
        method="DELETE",
        path="/users/1",
        host="example.com",
        protocol="https",
    )
    db_session.add(endpoint)
    await db_session.commit()

    await _apply_governance_rules(db_session, 1000000, endpoint)
    await db_session.commit()

    result = await db_session.execute(
        select(PolicyViolation).where(
            PolicyViolation.account_id == 1000000,
            PolicyViolation.rule_id == rule.id,
            PolicyViolation.endpoint_id == endpoint.id,
        )
    )
    violations = result.scalars().all()
    assert len(violations) == 1
